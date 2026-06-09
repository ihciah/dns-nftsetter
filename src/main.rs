mod cache;
mod config;
mod dns;
mod netlink;
mod nftables;
mod trie;

use crate::cache::CnameCache;
use crate::config::parse_config;
use crate::dns::{NftCommand, SniffedDnsResponse};
use clap::Parser;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "dns-nftsetter: sniffs DNS responses and updates nftables sets dynamically"
)]
struct Args {
    /// Interface to sniff on (e.g. eth0, any)
    #[arg(short, long, default_value = "any")]
    interface: String,

    /// Path to configuration file
    #[arg(short, long)]
    config: PathBuf,

    /// Target nftables table name
    #[arg(short, long, default_value = "filter")]
    table: String,

    /// Target nftables table family (ip or inet)
    #[arg(short, long, default_value = "ip")]
    family: String,

    /// Default timeout in seconds for DNS records with TTL = 0
    #[arg(short, long, default_value_t = 10)]
    default_timeout: u32,

    /// Maximum CNAME cache capacity
    #[arg(long, default_value_t = 1000)]
    cname_capacity: usize,

    /// Maximum number of nftables elements per batch flush
    #[arg(short = 'b', long = "batch-limit", default_value_t = 128)]
    batch_limit: usize,

    /// Dry-run mode: do not execute nftables updates
    #[arg(long)]
    dry_run: bool,

    /// Verbose mode: output debug logs
    #[arg(short, long)]
    verbose: bool,

    /// Optional IP address to filter captured packet's destination IP (client IP)
    #[arg(long)]
    filter_dst_ip: Option<std::net::Ipv4Addr>,
}

async fn flush_nft_commands(commands: Vec<NftCommand>, dry_run: bool) {
    if commands.is_empty() {
        return;
    }

    let mut grouped: HashMap<(String, String, String, usize), Vec<NftCommand>> = HashMap::new();
    for cmd in commands {
        grouped
            .entry((
                cmd.family.clone(),
                cmd.table.clone(),
                cmd.set_name.clone(),
                cmd.key.len(),
            ))
            .or_default()
            .push(cmd);
    }

    for ((family, table, set_name, _), group) in grouped {
        let element_count = group.len();
        let family_display = family.clone();
        let table_display = table.clone();
        let set_display = set_name.clone();

        for cmd in &group {
            let (client_ip_str, resolved_ip) = if cmd.key.len() == 8 {
                let client = std::net::Ipv4Addr::new(cmd.key[0], cmd.key[1], cmd.key[2], cmd.key[3]);
                let resolved = std::net::Ipv4Addr::new(cmd.key[4], cmd.key[5], cmd.key[6], cmd.key[7]);
                (format!("client {}", client), resolved)
            } else if cmd.key.len() == 4 {
                let resolved = std::net::Ipv4Addr::new(cmd.key[0], cmd.key[1], cmd.key[2], cmd.key[3]);
                ("global".to_string(), resolved)
            } else {
                ("unknown".to_string(), std::net::Ipv4Addr::new(0, 0, 0, 0))
            };

            if dry_run {
                tracing::info!(
                    domain = %cmd.domain,
                    rule = %cmd.rule_pattern,
                    %resolved_ip,
                    source = %client_ip_str,
                    set = %set_name,
                    "Dry run: skipping nftables update"
                );
            } else {
                tracing::info!(
                    domain = %cmd.domain,
                    rule = %cmd.rule_pattern,
                    %resolved_ip,
                    source = %client_ip_str,
                    set = %set_name,
                    "Adding element to nftables set"
                );
            }
        }

        if dry_run {
            continue;
        }

        let elements: Vec<crate::nftables::NftElement> = group
            .into_iter()
            .map(|cmd| crate::nftables::NftElement {
                key: cmd.key,
                timeout_secs: cmd.timeout_secs,
            })
            .collect();

        let res = tokio::task::spawn_blocking(move || {
            crate::nftables::nftables_add_elements(&family, &table, &set_name, &elements)
        })
        .await;

        match res {
            Ok(Ok(())) => {
                tracing::debug!(
                    family = %family_display,
                    table = %table_display,
                    set_name = %set_display,
                    element_count,
                    "Successfully applied nftables batch"
                );
            }
            Ok(Err(e)) => {
                tracing::error!(
                    family = %family_display,
                    table = %table_display,
                    set_name = %set_display,
                    element_count,
                    "Failed to apply nftables batch: {}",
                    e
                );
            }
            Err(e) => {
                tracing::error!(
                    family = %family_display,
                    table = %table_display,
                    set_name = %set_display,
                    element_count,
                    "Batched nftables worker panicked: {:?}",
                    e
                );
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Initialize tracing subscriber
    let log_level = if args.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(log_level).init();

    // 1. Load and parse config
    tracing::info!("Loading configuration from {:?}", args.config);
    let config_content = match fs::read_to_string(&args.config) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to read config file: {}", e);
            std::process::exit(1);
        }
    };
    let ruleset = match parse_config(&config_content) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to parse config file: {}", e);
            std::process::exit(1);
        }
    };
    tracing::info!("Configuration loaded successfully.");

    // 2. Setup Stage 3: Netlink batcher (single consumer, batched syscalls)
    let (nft_tx, mut nft_rx) = mpsc::channel::<NftCommand>(4096);
    let dry_run = args.dry_run;
    let batch_limit = args.batch_limit;

    tokio::spawn(async move {
        let mut pending: Vec<NftCommand> = Vec::with_capacity(batch_limit);

        loop {
            let first = match nft_rx.recv().await {
                Some(cmd) => cmd,
                None => break,
            };

            pending.push(first);

            while pending.len() < batch_limit {
                match nft_rx.try_recv() {
                    Ok(cmd) => pending.push(cmd),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => break,
                }
            }

            flush_nft_commands(std::mem::take(&mut pending), dry_run).await;
        }

        if !pending.is_empty() {
            flush_nft_commands(std::mem::take(&mut pending), dry_run).await;
        }
    });
    tracing::info!(
        "Executor batcher started: single consumer with batch limit {}",
        batch_limit
    );

    // 3. Setup Stage 1: Sniffer Thread (runs raw OS thread to not block tokio)
    let (packet_tx, mut packet_rx) = mpsc::channel::<SniffedDnsResponse>(4096);
    let interface = args.interface.clone();
    let filter_dst_ip = args.filter_dst_ip;

    std::thread::spawn(move || {
        tracing::info!(
            "Starting DNS sniffer thread on interface '{}'...",
            interface
        );
        let mut cap = match pcap::Capture::from_device(interface.as_str()) {
            Ok(builder) => {
                let promisc = interface != "any";
                match builder
                    .promisc(promisc)
                    .snaplen(65535)
                    .immediate_mode(true)
                    .open()
                {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!("Failed to open device '{}': {}", interface, e);
                        return;
                    }
                }
            }
            Err(e) => {
                tracing::error!("Device '{}' not found: {}", interface, e);
                return;
            }
        };

        let mut filter_exp = "udp src port 53".to_string();
        if let Some(ip) = filter_dst_ip {
            filter_exp.push_str(&format!(" and dst host {}", ip));
        }

        if let Err(e) = cap.filter(filter_exp.as_str(), true) {
            tracing::error!("Failed to set BPF filter '{}': {}", filter_exp, e);
            return;
        }

        let linktype = cap.get_datalink();
        tracing::info!(
            "DNS sniffer running successfully. Datalink type: {:?}",
            linktype
        );

        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    if let Some(parsed) = crate::dns::parse_packet(packet.data, linktype.0) {
                        if packet_tx.blocking_send(parsed).is_err() {
                            break; // channel closed
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Ignore and retry
                }
                Err(e) => {
                    tracing::error!("Sniffer error: {:?}", e);
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
    });

    // 4. Setup Stage 2: Main packet dispatcher (Single-threaded state owner)
    let mut cname_cache = CnameCache::new(args.cname_capacity);
    tracing::info!("Stage 2 packet processor started.");

    while let Some(response) = packet_rx.recv().await {
        crate::dns::process_dns_payload(
            response.client_ip,
            &response.dns_payload,
            &ruleset,
            &mut cname_cache,
            &nft_tx,
            &args.family,
            &args.table,
            args.default_timeout,
        );
    }
}
