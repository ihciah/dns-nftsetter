use crate::trie::TrieNode;
use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSource {
    Ip(Ipv4Addr),
    Wildcard, // *
    Global,   // *!
}

pub struct Ruleset {
    pub ip_rules: HashMap<Ipv4Addr, TrieNode>,
    pub wildcard_rules: TrieNode,
    pub global_rules: TrieNode,
}

impl Ruleset {
    pub fn new() -> Self {
        Self {
            ip_rules: HashMap::new(),
            wildcard_rules: TrieNode::new(),
            global_rules: TrieNode::new(),
        }
    }

    pub fn insert(&mut self, src: RuleSource, domain: &str, set_name: String) {
        match src {
            RuleSource::Ip(ip) => {
                let trie = self.ip_rules.entry(ip).or_default();
                trie.insert(domain, set_name);
            }
            RuleSource::Wildcard => {
                self.wildcard_rules.insert(domain, set_name);
            }
            RuleSource::Global => {
                self.global_rules.insert(domain, set_name);
            }
        }
    }

    /// Checks if a domain matches any configured rule (specific IP, wildcard, or global).
    pub fn is_domain_matched(&self, domain: &str) -> bool {
        if self.wildcard_rules.match_domain(domain).is_some() {
            return true;
        }
        if self.global_rules.match_domain(domain).is_some() {
            return true;
        }
        for ip_trie in self.ip_rules.values() {
            if ip_trie.match_domain(domain).is_some() {
                return true;
            }
        }
        false
    }
}

pub fn parse_config(content: &str) -> io::Result<Ruleset> {
    let mut ruleset = Ruleset::new();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = trimmed.split('/').collect();
        if parts.len() != 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "line {}: invalid rule format (expected src/domain/set_name)",
                    line_num
                ),
            ));
        }

        let src_str = parts[0].trim();
        let domain = parts[1].trim();
        let set_name = parts[2].trim().to_string();

        if domain.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("line {}: domain cannot be empty", line_num),
            ));
        }
        if set_name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("line {}: set name cannot be empty", line_num),
            ));
        }

        let src = match src_str {
            "*!" => RuleSource::Global,
            "*" => RuleSource::Wildcard,
            other => {
                if let Ok(ip) = other.parse::<Ipv4Addr>() {
                    RuleSource::Ip(ip)
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "line {}: invalid source IP or pattern '{}'",
                            line_num, src_str
                        ),
                    ));
                }
            }
        };

        ruleset.insert(src, domain, set_name);
    }

    Ok(ruleset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_config() {
        let config = "
            # Comment line
            192.168.0.100 / apple.com / my_set
            * / google.com / set_wild
            *! / facebook.com / set_global
        ";
        let ruleset = parse_config(config).unwrap();

        // Check Specific IP rule
        let ip_addr = "192.168.0.100".parse::<Ipv4Addr>().unwrap();
        let ip_trie = ruleset.ip_rules.get(&ip_addr).unwrap();
        assert_eq!(
            ip_trie.match_domain("apple.com"),
            Some(crate::trie::TrieMatch {
                set_name: "my_set".to_string(),
                pattern: "apple.com".to_string()
            })
        );

        // Check Wildcard rule
        assert_eq!(
            ruleset.wildcard_rules.match_domain("google.com"),
            Some(crate::trie::TrieMatch {
                set_name: "set_wild".to_string(),
                pattern: "google.com".to_string()
            })
        );

        // Check Global rule
        assert_eq!(
            ruleset.global_rules.match_domain("facebook.com"),
            Some(crate::trie::TrieMatch {
                set_name: "set_global".to_string(),
                pattern: "facebook.com".to_string()
            })
        );
    }

    #[test]
    fn test_parse_invalid_config() {
        assert!(parse_config("invalid_format").is_err());
        assert!(parse_config("192.168.0.999/apple.com/my_set").is_err());
        assert!(parse_config("192.168.0.100//my_set").is_err());
    }
}
