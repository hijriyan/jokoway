use dashmap::DashMap;
use once_cell::sync::Lazy;
use pingora::http::RequestHeader;
use regex::Regex;
use std::fmt::Debug;
use std::sync::Arc;

pub trait Matcher: Send + Sync + Debug {
    fn matches(&self, req: &RequestHeader) -> bool;
    fn get_hosts(&self) -> Vec<String> {
        Vec::new()
    }
    /// Returns (hosts, is_wildcard).
    /// - `hosts`: List of specific hosts this rule matches.
    /// - `is_wildcard`: If true, rule matches other hosts too (must be in catch-all).
    fn get_required_hosts(&self) -> (Vec<String>, bool) {
        (Vec::new(), true) // Default to wildcard (safest)
    }
    fn clone_box(&self) -> Box<dyn Matcher>;
}

// Global regex compilation cache
static REGEX_CACHE: Lazy<DashMap<String, Arc<Regex>>> = Lazy::new(DashMap::new);

pub fn compile_cached_regex(pattern: &str) -> Result<Arc<Regex>, regex::Error> {
    let cache = &*REGEX_CACHE;

    // Fast path: check if already compiled
    if let Some(cached) = cache.get(pattern) {
        return Ok(cached.clone());
    }

    // Slow path: compile and cache
    match Regex::new(pattern) {
        Ok(regex) => {
            let arc_regex = Arc::new(regex);
            cache.insert(pattern.to_string(), arc_regex.clone());
            Ok(arc_regex)
        }
        Err(e) => Err(e),
    }
}

#[derive(Debug)]
pub struct HostMatcher {
    pub host: String,
}

impl Matcher for HostMatcher {
    #[inline]
    fn matches(&self, req: &RequestHeader) -> bool {
        req.uri.host().map(|h| h == self.host).unwrap_or(false)
            || req
                .headers
                .get("Host")
                .map(|h| h == self.host.as_str())
                .unwrap_or(false)
    }

    fn get_hosts(&self) -> Vec<String> {
        vec![self.host.clone()]
    }

    fn get_required_hosts(&self) -> (Vec<String>, bool) {
        (vec![self.host.clone()], false)
    }

    fn clone_box(&self) -> Box<dyn Matcher> {
        Box::new(HostMatcher {
            host: self.host.clone(),
        })
    }
}

#[derive(Debug)]
pub struct HostRegexpMatcher {
    pub regex: Regex,
}

impl Matcher for HostRegexpMatcher {
    #[inline]
    fn matches(&self, req: &RequestHeader) -> bool {
        req.uri
            .host()
            .map(|h| self.regex.is_match(h))
            .unwrap_or(false)
            || req
                .headers
                .get("Host")
                .and_then(|h| h.to_str().ok())
                .map(|h| self.regex.is_match(h))
                .unwrap_or(false)
    }

    fn clone_box(&self) -> Box<dyn Matcher> {
        Box::new(HostRegexpMatcher {
            regex: self.regex.clone(),
        })
    }
}

#[derive(Debug)]
pub struct PathMatcher {
    pub path: String,
}

impl Matcher for PathMatcher {
    #[inline]
    fn matches(&self, req: &RequestHeader) -> bool {
        req.uri.path() == self.path
    }

    fn clone_box(&self) -> Box<dyn Matcher> {
        Box::new(PathMatcher {
            path: self.path.clone(),
        })
    }
}

#[derive(Debug)]
pub struct PathRegexpMatcher {
    pub regex: Regex,
}

impl Matcher for PathRegexpMatcher {
    #[inline]
    fn matches(&self, req: &RequestHeader) -> bool {
        self.regex.is_match(req.uri.path())
    }

    fn clone_box(&self) -> Box<dyn Matcher> {
        Box::new(PathRegexpMatcher {
            regex: self.regex.clone(),
        })
    }
}

#[derive(Debug)]
pub struct PathPrefixMatcher {
    pub prefix: String,
}

impl Matcher for PathPrefixMatcher {
    #[inline]
    fn matches(&self, req: &RequestHeader) -> bool {
        req.uri.path().starts_with(&self.prefix)
    }

    fn clone_box(&self) -> Box<dyn Matcher> {
        Box::new(PathPrefixMatcher {
            prefix: self.prefix.clone(),
        })
    }
}

#[derive(Debug)]
pub struct MethodMatcher {
    pub method: String,
}

impl Matcher for MethodMatcher {
    #[inline]
    fn matches(&self, req: &RequestHeader) -> bool {
        req.method.as_str() == self.method
    }

    fn clone_box(&self) -> Box<dyn Matcher> {
        Box::new(MethodMatcher {
            method: self.method.clone(),
        })
    }
}

#[derive(Debug)]
pub struct HeaderRegexpMatcher {
    pub name: String,
    pub regex: Regex,
}

impl Matcher for HeaderRegexpMatcher {
    #[inline]
    fn matches(&self, req: &RequestHeader) -> bool {
        req.headers
            .get(&self.name)
            .and_then(|v| v.to_str().ok())
            .map(|v| self.regex.is_match(v))
            .unwrap_or(false)
    }

    fn clone_box(&self) -> Box<dyn Matcher> {
        Box::new(HeaderRegexpMatcher {
            name: self.name.clone(),
            regex: self.regex.clone(),
        })
    }
}

#[derive(Debug)]
pub struct QueryRegexpMatcher {
    pub key: String,
    pub regex: Regex,
}

impl Matcher for QueryRegexpMatcher {
    fn matches(&self, req: &RequestHeader) -> bool {
        if let Some(query) = req.uri.query() {
            for (k, v) in query.split('&').filter_map(|p| {
                let mut parts = p.splitn(2, '=');
                let k = parts.next()?;
                let v = parts.next().unwrap_or("");
                Some((k, v))
            }) {
                if k == self.key && self.regex.is_match(v) {
                    return true;
                }
            }
        }
        false
    }

    fn clone_box(&self) -> Box<dyn Matcher> {
        Box::new(QueryRegexpMatcher {
            key: self.key.clone(),
            regex: self.regex.clone(),
        })
    }
}

#[derive(Debug)]
pub struct AndMatcher {
    pub matchers: Vec<Box<dyn Matcher>>,
}

impl Matcher for AndMatcher {
    fn matches(&self, req: &RequestHeader) -> bool {
        self.matchers.iter().all(|m| m.matches(req))
    }

    fn get_hosts(&self) -> Vec<String> {
        self.matchers.iter().flat_map(|m| m.get_hosts()).collect()
    }

    fn get_required_hosts(&self) -> (Vec<String>, bool) {
        let mut hosts = Vec::new();
        // Logic for AND:
        // A specific && B specific -> specific (false)
        // A specific && B wildcard -> specific (false)
        // A wildcard && B wildcard -> wildcard (true)
        // So is_wildcard = all(children.is_wildcard)

        let mut all_wildcards = true;
        for m in &self.matchers {
            let (h, w) = m.get_required_hosts();
            hosts.extend(h);
            if !w {
                all_wildcards = false;
            }
        }
        (hosts, all_wildcards)
    }

    fn clone_box(&self) -> Box<dyn Matcher> {
        Box::new(AndMatcher {
            matchers: self.matchers.iter().map(|m| m.clone_box()).collect(),
        })
    }
}

#[derive(Debug)]
pub struct OrMatcher {
    pub matchers: Vec<Box<dyn Matcher>>,
}

impl Matcher for OrMatcher {
    fn matches(&self, req: &RequestHeader) -> bool {
        self.matchers.iter().any(|m| m.matches(req))
    }

    fn get_hosts(&self) -> Vec<String> {
        self.matchers.iter().flat_map(|m| m.get_hosts()).collect()
    }

    fn get_required_hosts(&self) -> (Vec<String>, bool) {
        let mut hosts = Vec::new();
        // Logic: specific || wildcard -> wildcard (true)
        // specific || specific -> specific (false)
        // So is_wildcard = any(children.is_wildcard)

        let mut any_wildcard = false;
        for m in &self.matchers {
            let (h, w) = m.get_required_hosts();
            hosts.extend(h);
            if w {
                any_wildcard = true;
            }
        }
        (hosts, any_wildcard)
    }

    fn clone_box(&self) -> Box<dyn Matcher> {
        Box::new(OrMatcher {
            matchers: self.matchers.iter().map(|m| m.clone_box()).collect(),
        })
    }
}

#[derive(Debug)]
pub struct NotMatcher {
    pub matcher: Box<dyn Matcher>,
}

impl Matcher for NotMatcher {
    fn matches(&self, req: &RequestHeader) -> bool {
        !self.matcher.matches(req)
    }

    fn get_hosts(&self) -> Vec<String> {
        self.matcher.get_hosts()
    }

    fn get_required_hosts(&self) -> (Vec<String>, bool) {
        // Negation makes it impossible to list specific allowed hosts
        (Vec::new(), true)
    }

    fn clone_box(&self) -> Box<dyn Matcher> {
        Box::new(NotMatcher {
            matcher: self.matcher.clone_box(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_matcher_required() {
        let m = HostMatcher {
            host: "example.com".to_string(),
        };
        assert_eq!(
            m.get_required_hosts(),
            (vec!["example.com".to_string()], false)
        );
        assert_eq!(m.get_hosts(), vec!["example.com"]);
    }

    #[test]
    fn test_and_matcher_required() {
        // Host("a") && Host("b") -> ["a", "b"], false
        let m = AndMatcher {
            matchers: vec![
                Box::new(HostMatcher {
                    host: "a".to_string(),
                }),
                Box::new(HostMatcher {
                    host: "b".to_string(),
                }),
            ],
        };
        let (req, w) = m.get_required_hosts();
        assert!(!w);
        assert!(req.contains(&"a".to_string()));
        assert!(req.contains(&"b".to_string()));
    }

    #[test]
    fn test_or_matcher_required_valid() {
        // Host("a") || Host("b") -> ["a", "b"], false
        let m = OrMatcher {
            matchers: vec![
                Box::new(HostMatcher {
                    host: "a".to_string(),
                }),
                Box::new(HostMatcher {
                    host: "b".to_string(),
                }),
            ],
        };
        let (req, w) = m.get_required_hosts();
        assert!(!w);
        assert_eq!(req.len(), 2);
        assert!(req.contains(&"a".to_string()));
        assert!(req.contains(&"b".to_string()));
    }

    #[test]
    fn test_or_matcher_required_wildcard() {
        // Host("a") || Path("/foo") -> ["a"], true
        // Because "a" allows efficient lookup for "a", but "true" means we need catch-all too.
        let m = OrMatcher {
            matchers: vec![
                Box::new(HostMatcher {
                    host: "a".to_string(),
                }),
                Box::new(PathMatcher {
                    path: "/foo".to_string(),
                }),
            ],
        };
        let (req, w) = m.get_required_hosts();
        assert!(w);
        assert!(req.contains(&"a".to_string()));
    }

    #[test]
    fn test_complex_rule_1() {
        // Host("a") || (Host("b") && Path("/foo")) -> ["a", "b"], false
        // Left: a, false. Right: b, false. Combined: a,b, false.
        let right = AndMatcher {
            matchers: vec![
                Box::new(HostMatcher {
                    host: "b".to_string(),
                }),
                Box::new(PathMatcher {
                    path: "/foo".to_string(),
                }),
            ],
        };
        let m = OrMatcher {
            matchers: vec![
                Box::new(HostMatcher {
                    host: "a".to_string(),
                }),
                Box::new(right),
            ],
        };
        let (req, w) = m.get_required_hosts();
        assert!(!w);
        assert_eq!(req.len(), 2);
        assert!(req.contains(&"a".to_string()));
        assert!(req.contains(&"b".to_string()));
    }

    #[test]
    fn test_not_matcher_required() {
        // !Host("a") -> [], true
        let m = NotMatcher {
            matcher: Box::new(HostMatcher {
                host: "a".to_string(),
            }),
        };
        let (req, w) = m.get_required_hosts();
        assert!(w);
        assert!(req.is_empty());
        // get_hosts should still return "a" for ACME usage
        assert_eq!(m.get_hosts(), vec!["a"]);
    }
}
