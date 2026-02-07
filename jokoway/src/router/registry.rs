use crate::router::matcher::Matcher;
use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use psl::{List, Psl};
use std::collections::HashSet;
use std::sync::Arc;

// Define the type for a rule parser factory
pub type RouterRuleParser = Arc<
    dyn Fn(&mut &str) -> std::result::Result<Box<dyn Matcher>, winnow::error::ContextError>
        + Send
        + Sync,
>;

// Global registry for custom router rules using ArcSwap for lock-free reads
static ROUTER_REGISTRY: Lazy<ArcSwap<Vec<RouterRuleParser>>> =
    Lazy::new(|| ArcSwap::from_pointee(Vec::new()));

static HOST_REGISTRY: Lazy<ArcSwap<Vec<String>>> = Lazy::new(|| ArcSwap::from_pointee(Vec::new()));

/// Register a custom router rule parser
pub fn register_router_rule<F>(parser: F)
where
    F: Fn(&mut &str) -> std::result::Result<Box<dyn Matcher>, winnow::error::ContextError>
        + Send
        + Sync
        + 'static,
{
    let registry = &ROUTER_REGISTRY;
    let parser = Arc::new(parser);
    // rcu (Read-Copy-Update) allows atomic updates without locking readers
    registry.rcu(move |old| {
        let mut new = (**old).clone();
        new.push(parser.clone());
        new
    });
}

/// Try to parse input using registered custom rules
pub fn parse_custom_rules(
    input: &mut &str,
) -> std::result::Result<Box<dyn Matcher>, winnow::error::ContextError> {
    let registry = &ROUTER_REGISTRY;
    let parsers = registry.load();

    let mut last_err = None;
    // Iterate through registered parsers and return the first match
    for parser in parsers.iter() {
        let mut temp_input = *input;
        match parser(&mut temp_input) {
            Ok(matcher) => {
                *input = temp_input;
                return Ok(matcher);
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }

    if let Some(err) = last_err {
        Err(err)
    } else {
        Err(winnow::error::ContextError::default())
    }
}

pub fn register_hosts<I>(hosts: I)
where
    I: IntoIterator<Item = String>,
{
    let mut incoming: Vec<String> = Vec::new();
    for host in hosts {
        if host.is_empty() {
            continue;
        }

        let psl_domain = List.domain(host.as_bytes());
        match psl_domain {
            Some(d) => {
                // If we got a domain, check if the suffix is a known public suffix.
                // This filters out things like "invalid.tldnotexist" which psl might accept under wildcard rules but aren't real public suffixes.
                if d.suffix().is_known() {
                    incoming.push(host);
                } else {
                    log::warn!("Skipping invalid host '{}' - suffix not known", host);
                }
            }
            None => {
                log::warn!(
                    "Skipping invalid host '{}' - no valid registrable domain found",
                    host
                );
            }
        }
    }

    if incoming.is_empty() {
        return;
    }

    let registry = &HOST_REGISTRY;
    registry.rcu(move |old| {
        let mut set: HashSet<String> = old.iter().cloned().collect();
        for host in &incoming {
            set.insert(host.clone());
        }
        set.into_iter().collect::<Vec<String>>()
    });
}

pub fn get_registered_hosts() -> Vec<String> {
    HOST_REGISTRY.load().to_vec()
}

#[cfg(test)]
mod tests {
    use super::{get_registered_hosts, register_hosts};

    #[test]
    fn host_registry_collects_hosts() {
        register_hosts(vec![
            "a.example.com".to_string(),
            "b.example.com".to_string(),
        ]);
        let hosts = get_registered_hosts();
        assert!(hosts.contains(&"a.example.com".to_string()));
        assert!(hosts.contains(&"b.example.com".to_string()));
    }

    #[test]
    fn host_registry_filters_invalid_tlds() {
        register_hosts(vec![
            "valid.example.com".to_string(),
            "invalid.tldnotexist".to_string(),
            "notadomain".to_string(),
            "test.co.uk".to_string(),
        ]);
        let hosts = get_registered_hosts();
        assert!(hosts.contains(&"valid.example.com".to_string()));
        assert!(hosts.contains(&"test.co.uk".to_string()));
        // Invalid TLDs should be filtered out
        assert!(!hosts.contains(&"invalid.tldnotexist".to_string()));
        assert!(!hosts.contains(&"notadomain".to_string()));
    }
}
