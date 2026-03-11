use crate::models::{ForwardedInfo, XFF, XFH, XFP};
use pingora::http::RequestHeader;
use std::net::IpAddr;

fn parse_host(val: &str, info: &mut ForwardedInfo) {
    if info.host.is_none() {
        info.host = Some(val.into());
    }
}

fn parse_proto(val: &str, info: &mut ForwardedInfo) {
    if info.proto.is_none() {
        info.proto = Some(val.into());
    }
}

pub fn parse_legacy_headers(
    req: &RequestHeader,
    client_ip: Option<&IpAddr>,
    trusted_proxies_is_empty: bool,
    client_proto: &str,
    current_host: Option<&str>,
) -> ForwardedInfo {
    let mut info = ForwardedInfo::default();

    if let Some(xff) = req.headers.get(XFF)
        && let Ok(s) = xff.to_str()
    {
        info.for_nodes = Some(s.into());
    }

    if let Some(xfh) = req.headers.get(XFH)
        && let Ok(s) = xfh.to_str()
    {
        parse_host(s.trim(), &mut info);
    }

    if let Some(xfp) = req.headers.get(XFP)
        && let Ok(s) = xfp.to_str()
    {
        parse_proto(s.trim(), &mut info);
    }

    if let Some(ip) = client_ip {
        let ip_str = ip.to_string();
        if let Some(nodes) = info.for_nodes.as_ref() {
            // Need to create a new String, append, then convert to Arc
            let mut new_nodes = nodes.to_string();
            new_nodes.push_str(", ");
            new_nodes.push_str(&ip_str);
            info.for_nodes = Some(new_nodes.into());
        } else {
            info.for_nodes = Some(ip_str.clone().into());
        }

        if trusted_proxies_is_empty {
            // replace xff header if trusted_proxies is empty
            // since it's edge proxy mode, we trust the client ip
            info.for_nodes = Some(ip_str.clone().into());
            // set client ip from pingora session
            info.client_ip = Some(ip_str.into());
        } else {
            // set client ip from xff header
            if let Some(nodes) = &info.for_nodes {
                info.client_ip = nodes.split(",").next().map(|s| s.into());
            }
        }
    }

    if let Some(s) = current_host {
        if trusted_proxies_is_empty {
            info.host = Some(s.into());
            log::debug!(
                "[trusted_proxies_is_empty] set X-Forwarded-Host from host header: {}",
                s
            );
        } else if info.host.is_none() {
            info.host = Some(s.into());
            log::debug!(
                "[trusted_proxies_is_not_empty] X-Forwarded-Host is none, set from host header: {}",
                s
            );
        } else {
            log::debug!(
                "[trusted_proxies_is_not_empty] X-Forwarded-Host is not none, skip set from host header: {}",
                s
            );
        }
    }

    if trusted_proxies_is_empty {
        info.proto = Some(client_proto.into());
        log::debug!(
            "[trusted_proxies_is_empty] set X-Forwarded-Proto from current connection: {}",
            client_proto
        );
    } else if info.proto.is_none() {
        info.proto = Some(client_proto.into());
        log::debug!(
            "[trusted_proxies_is_not_empty] X-Forwarded-Proto is none, set from current connection: {}",
            client_proto
        );
    } else {
        log::debug!(
            "[trusted_proxies_is_not_empty] X-Forwarded-Proto is not none, skip set from current connection: {}",
            client_proto
        );
    }

    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legacy_headers() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("x-forwarded-for", "1.2.3.4, 5.6.7.8")
            .unwrap();
        req.insert_header("x-forwarded-proto", "https").unwrap();
        req.insert_header("x-forwarded-host", "example.com")
            .unwrap();

        let info = parse_legacy_headers(&req, None, false, "http", None);
        assert_eq!(info.for_nodes, Some("1.2.3.4, 5.6.7.8".into()));
        assert_eq!(info.proto, Some("https".into()));
        assert_eq!(info.host, Some("example.com".into()));
    }

    #[test]
    fn test_edge_proxy() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("x-forwarded-for", "1.2.3.4, 5.6.7.8")
            .unwrap();
        req.insert_header("x-forwarded-proto", "https").unwrap();
        req.insert_header("x-forwarded-host", "example.com")
            .unwrap();

        let info = parse_legacy_headers(&req, None, true, "http", Some("custom.com"));
        assert_eq!(info.for_nodes, Some("1.2.3.4, 5.6.7.8".into()));
        assert_eq!(info.proto, Some("http".into()));
        assert_eq!(info.host, Some("custom.com".into()));
    }
}
