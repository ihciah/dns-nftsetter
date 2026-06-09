use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrieMatch {
    pub set_name: String,
    pub pattern: String,
}

#[derive(Default, Debug, Clone)]
pub struct TrieNode {
    children: HashMap<String, TrieNode>,
    set_name: Option<String>,
    pattern: Option<String>,
}

impl TrieNode {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a domain name with a trailing/wildcard matching context.
    /// E.g. `apple.com` maps to reversed labels `["com", "apple"]`.
    pub fn insert(&mut self, domain: &str, set_name: String) {
        let parts: Vec<&str> = domain
            .split('.')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        let mut current = self;
        for part in parts.into_iter().rev() {
            current = current.children.entry(part.to_lowercase()).or_default();
        }
        current.set_name = Some(set_name);
        current.pattern = Some(domain.to_string());
    }

    /// Returns the matched set_name and pattern for a domain query, using the longest-suffix match.
    /// E.g. If `apple.com` is configured, it matches `apple.com` and `www.apple.com`.
    /// If both `apple.com` and `sub.apple.com` are configured, `www.sub.apple.com` matches `sub.apple.com`.
    pub fn match_domain(&self, domain: &str) -> Option<TrieMatch> {
        let parts: Vec<&str> = domain
            .split('.')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        let mut current = self;
        let mut last_match = None;

        for part in parts.into_iter().rev() {
            if let (Some(ref val), Some(ref pat)) = (&current.set_name, &current.pattern) {
                last_match = Some(TrieMatch {
                    set_name: val.clone(),
                    pattern: pat.clone(),
                });
            }
            if let Some(next_node) = current.children.get(&part.to_lowercase()) {
                current = next_node;
            } else {
                return last_match;
            }
        }

        if let (Some(ref val), Some(ref pat)) = (&current.set_name, &current.pattern) {
            Some(TrieMatch {
                set_name: val.clone(),
                pattern: pat.clone(),
            })
        } else {
            last_match
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_and_wildcard_matching() {
        let mut trie = TrieNode::new();
        trie.insert("apple.com", "set_apple".to_string());
        trie.insert("sub.apple.com", "set_sub_apple".to_string());
        trie.insert("google.com", "set_google".to_string());

        // Exact match
        assert_eq!(
            trie.match_domain("apple.com"),
            Some(TrieMatch {
                set_name: "set_apple".to_string(),
                pattern: "apple.com".to_string()
            })
        );
        assert_eq!(
            trie.match_domain("google.com"),
            Some(TrieMatch {
                set_name: "set_google".to_string(),
                pattern: "google.com".to_string()
            })
        );

        // Wildcard match (subdomain)
        assert_eq!(
            trie.match_domain("www.apple.com"),
            Some(TrieMatch {
                set_name: "set_apple".to_string(),
                pattern: "apple.com".to_string()
            })
        );
        assert_eq!(
            trie.match_domain("www.sub.apple.com"),
            Some(TrieMatch {
                set_name: "set_sub_apple".to_string(),
                pattern: "sub.apple.com".to_string()
            })
        );

        // Longest-suffix specificity match
        assert_eq!(
            trie.match_domain("sub.apple.com"),
            Some(TrieMatch {
                set_name: "set_sub_apple".to_string(),
                pattern: "sub.apple.com".to_string()
            })
        );

        // No match cases
        assert_eq!(trie.match_domain("pineapple.com"), None);
        assert_eq!(trie.match_domain("apple.com.cn"), None);
        assert_eq!(trie.match_domain("com"), None);
    }
}
