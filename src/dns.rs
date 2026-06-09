use crate::cache::CnameCache;
use crate::config::Ruleset;
use std::net::Ipv4Addr;

pub struct SniffedDnsResponse {
    pub client_ip: Ipv4Addr,
    pub dns_payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct NftCommand {
    pub family: String,
    pub table: String,
    pub set_name: String,
    pub key: Vec<u8>, // 4 bytes for global, 8 bytes for pair
    pub timeout_secs: u32,
    pub domain: String,
    pub rule_pattern: String,
}

/// Parses a raw sniffed packet from pcap and extracts the DNS payload and client IP.
/// Supports Ethernet, Loopback, and Raw IP links.
pub fn parse_packet(packet_bytes: &[u8], linktype_val: i32) -> Option<SniffedDnsResponse> {
    use etherparse::SlicedPacket;

    let sliced = match linktype_val {
        1 => {
            // DLT_EN10MB (Ethernet)
            SlicedPacket::from_ethernet(packet_bytes).ok()?
        }
        12 | 101 | 128 => {
            // DLT_RAW / Raw IP
            SlicedPacket::from_ip(packet_bytes).ok()?
        }
        0 | 108 => {
            // DLT_NULL / Loopback
            if packet_bytes.len() < 4 {
                return None;
            }
            // Skip 4-byte NULL loopback header
            SlicedPacket::from_ip(&packet_bytes[4..]).ok()?
        }
        113 => {
            // DLT_LINUX_SLL (Linux Cooked Capture)
            if packet_bytes.len() < 16 {
                return None;
            }
            // Skip 16-byte SLL header
            SlicedPacket::from_ip(&packet_bytes[16..]).ok()?
        }
        _ => {
            // Fallback: try parsing as Ethernet, then raw IP
            if let Ok(sliced) = SlicedPacket::from_ethernet(packet_bytes) {
                sliced
            } else if let Ok(sliced) = SlicedPacket::from_ip(packet_bytes) {
                sliced
            } else {
                return None;
            }
        }
    };

    let ip_header = match sliced.net {
        Some(etherparse::NetSlice::Ipv4(ref ipv4_slice)) => ipv4_slice.header(),
        _ => return None,
    };

    let udp_slice = match sliced.transport {
        Some(etherparse::TransportSlice::Udp(ref udp)) => udp,
        _ => return None,
    };

    // Sniff only DNS responses (source port 53)
    if udp_slice.source_port() != 53 {
        return None;
    }

    let client_ip = ip_header.destination_addr();
    let dns_payload = udp_slice.payload().to_vec();

    Some(SniffedDnsResponse {
        client_ip,
        dns_payload,
    })
}

/// Processes a DNS response payload.
/// Performs two-pass parsing over CNAME and A records to resolve CNAME chains,
/// compares original query domains with rules, and emits NftCommands.
#[allow(clippy::too_many_arguments)]
pub fn process_dns_payload(
    client_ip: Ipv4Addr,
    dns_payload: &[u8],
    ruleset: &Ruleset,
    cname_cache: &mut CnameCache,
    tx: &tokio::sync::mpsc::Sender<NftCommand>,
    family: &str,
    table: &str,
    default_timeout: u32,
) {
    use dns_parser::{Packet, RData};

    let packet = match Packet::parse(dns_payload) {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!("Failed to parse DNS packet: {:?}", e);
            return;
        }
    };

    // First pass: insert CNAME mappings only if they are associated with configured domains
    for record in &packet.answers {
        if record.cls != dns_parser::Class::IN {
            continue;
        }
        if let RData::CNAME(ref cname) = record.data {
            let name = record.name.to_string();
            let target = cname.to_string();

            let original = cname_cache.resolve(&name);
            if ruleset.is_domain_matched(&original) {
                tracing::debug!(%name, %target, %original, "CNAME record associated and cached");
                cname_cache.insert(target, name, record.ttl);
            } else {
                tracing::trace!(%name, %target, %original, "CNAME record ignored (unassociated)");
            }
        }
    }

    // Second pass: process A records
    for record in &packet.answers {
        if record.cls != dns_parser::Class::IN {
            continue;
        }
        if let RData::A(ip) = record.data {
            let name = record.name.to_string();
            let original_domain = cname_cache.resolve(&name);
            if name != original_domain {
                tracing::debug!(%name, %original_domain, "CNAME trace resolved original domain");
            }

            let ttl = if record.ttl == 0 {
                default_timeout
            } else {
                record.ttl
            };

            // 1. Match Specific IP rules
            if let Some(ip_trie) = ruleset.ip_rules.get(&client_ip) {
                if let Some(matched) = ip_trie.match_domain(&original_domain) {
                    let mut key = Vec::with_capacity(8);
                    key.extend_from_slice(&client_ip.octets());
                    key.extend_from_slice(&ip.0.octets());

                    tracing::debug!(
                        %client_ip,
                        %original_domain,
                        query_name = %name,
                        resolved_ip = %ip.0,
                        set_name = %matched.set_name,
                        rule_pattern = %matched.pattern,
                        ttl,
                        "Matched specific IP rule, queuing addition"
                    );

                    let _ = tx.try_send(NftCommand {
                        family: family.to_string(),
                        table: table.to_string(),
                        set_name: matched.set_name.clone(),
                        key,
                        timeout_secs: ttl,
                        domain: original_domain.clone(),
                        rule_pattern: matched.pattern.clone(),
                    });
                }
            }

            // 2. Match Wildcard * rules (pair sets)
            if let Some(matched) = ruleset.wildcard_rules.match_domain(&original_domain) {
                let mut key = Vec::with_capacity(8);
                key.extend_from_slice(&client_ip.octets());
                key.extend_from_slice(&ip.0.octets());

                tracing::debug!(
                    %client_ip,
                    %original_domain,
                    query_name = %name,
                    resolved_ip = %ip.0,
                    set_name = %matched.set_name,
                    rule_pattern = %matched.pattern,
                    ttl,
                    "Matched wildcard rule, queuing addition"
                );

                let _ = tx.try_send(NftCommand {
                    family: family.to_string(),
                    table: table.to_string(),
                    set_name: matched.set_name.clone(),
                    key,
                    timeout_secs: ttl,
                    domain: original_domain.clone(),
                    rule_pattern: matched.pattern.clone(),
                });
            }

            // 3. Match Global *! rules (single IP sets)
            if let Some(matched) = ruleset.global_rules.match_domain(&original_domain) {
                let key = ip.0.octets().to_vec();

                tracing::debug!(
                    %client_ip,
                    %original_domain,
                    query_name = %name,
                    resolved_ip = %ip.0,
                    set_name = %matched.set_name,
                    rule_pattern = %matched.pattern,
                    ttl,
                    "Matched global rule, queuing addition"
                );

                let _ = tx.try_send(NftCommand {
                    family: family.to_string(),
                    table: table.to_string(),
                    set_name: matched.set_name.clone(),
                    key,
                    timeout_secs: ttl,
                    domain: original_domain.clone(),
                    rule_pattern: matched.pattern.clone(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CnameCache;
    use crate::config::parse_config;
    use std::net::Ipv4Addr;
    use tokio::sync::mpsc;

    fn write_name(buf: &mut Vec<u8>, domain: &str) {
        for part in domain.split('.') {
            if part.is_empty() {
                continue;
            }
            buf.push(part.len() as u8);
            buf.extend_from_slice(part.as_bytes());
        }
        buf.push(0);
    }

    fn write_cname_answer(buf: &mut Vec<u8>, name: &str, target: &str) {
        write_name(buf, name);
        buf.extend_from_slice(&[0x00, 0x05]); // TYPE: CNAME
        buf.extend_from_slice(&[0x00, 0x01]); // CLASS: IN
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x1e]); // TTL: 30
        let mut target_bytes = Vec::new();
        write_name(&mut target_bytes, target);
        buf.extend_from_slice(&(target_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&target_bytes);
    }

    fn write_a_answer(buf: &mut Vec<u8>, name: &str, ip: Ipv4Addr) {
        write_name(buf, name);
        buf.extend_from_slice(&[0x00, 0x01]); // TYPE: A
        buf.extend_from_slice(&[0x00, 0x01]); // CLASS: IN
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x1e]); // TTL: 30
        buf.extend_from_slice(&[0x00, 0x04]); // RDLENGTH: 4
        buf.extend_from_slice(&ip.octets());
    }

    #[test]
    fn test_cname_filtering_and_resolution() {
        let config_str = "
            * / apple.com / pair_dynamic
            *! / fb.com / global_dynamic
        ";
        let ruleset = parse_config(config_str).unwrap();
        let mut cname_cache = CnameCache::new(10);
        let (tx, mut rx) = mpsc::channel(10);

        // Build mock DNS response containing:
        // CNAME: oss.apple.com -> cdn.apple.com
        // CNAME: cdn.apple.com -> gslb.apple.com
        // CNAME: cdn.baidu.com -> gslb.baidu.com (not matching any rules)
        // A: gslb.apple.com -> 1.1.1.1
        // A: gslb.baidu.com -> 2.2.2.2
        let mut payload = Vec::new();
        // DNS Header
        payload.extend_from_slice(&[0x12, 0x34]); // ID
        payload.extend_from_slice(&[0x81, 0x80]); // Flags (Response)
        payload.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1
        payload.extend_from_slice(&[0x00, 0x05]); // ANCOUNT: 5
        payload.extend_from_slice(&[0x00, 0x00]); // NSCOUNT: 0
        payload.extend_from_slice(&[0x00, 0x00]); // ARCOUNT: 0

        // Question: oss.apple.com A IN
        write_name(&mut payload, "oss.apple.com");
        payload.extend_from_slice(&[0x00, 0x01]); // TYPE: A
        payload.extend_from_slice(&[0x00, 0x01]); // CLASS: IN

        // Answers
        write_cname_answer(&mut payload, "oss.apple.com", "cdn.apple.com");
        write_cname_answer(&mut payload, "cdn.apple.com", "gslb.apple.com");
        write_cname_answer(&mut payload, "cdn.baidu.com", "gslb.baidu.com");
        write_a_answer(&mut payload, "gslb.apple.com", Ipv4Addr::new(1, 1, 1, 1));
        write_a_answer(&mut payload, "gslb.baidu.com", Ipv4Addr::new(2, 2, 2, 2));

        // Process DNS payload
        process_dns_payload(
            Ipv4Addr::new(192, 168, 1, 100),
            &payload,
            &ruleset,
            &mut cname_cache,
            &tx,
            "ip",
            "filter",
            10,
        );

        // Verify that only the apple.com IP (1.1.1.1) was matched and sent
        let mut received = Vec::new();
        while let Ok(cmd) = rx.try_recv() {
            received.push(cmd);
        }

        assert_eq!(received.len(), 1);
        assert_eq!(received[0].set_name, "pair_dynamic");
        assert_eq!(received[0].domain, "oss.apple.com");
        assert_eq!(received[0].rule_pattern, "apple.com");
        assert_eq!(received[0].key, vec![192, 168, 1, 100, 1, 1, 1, 1]);

        // Verify that the CNAME cache contains associated domains but NOT the baidu one
        // oss.apple.com -> cdn.apple.com -> gslb.apple.com is associated and resolves to original
        assert_eq!(cname_cache.resolve("gslb.apple.com"), "oss.apple.com");
        // cdn.baidu.com -> gslb.baidu.com is unassociated and was discarded
        assert_eq!(cname_cache.resolve("gslb.baidu.com"), "gslb.baidu.com");
    }
}
