use crate::models::ForwardedInfo;
use pingora::http::RequestHeader;
use std::net::IpAddr;

fn parse_host(val: &str, info: &mut ForwardedInfo) {
    if info.host.is_none() {
        info.host = Some(val.to_string());
    }
}

fn parse_proto(val: &str, info: &mut ForwardedInfo) {
    if info.proto.is_none() {
        info.proto = Some(val.to_string());
    }
}

pub fn parse_legacy_headers(
    req: &RequestHeader,
    client_ip: Option<&IpAddr>,
    trusted_proxies_is_empty: bool,
    client_proto: &str,
) -> ForwardedInfo {
    let mut info = ForwardedInfo::default();

    if let Some(xff) = req.headers.get("x-forwarded-for") {
        if let Ok(s) = xff.to_str() {
            info.for_nodes = Some(s.to_string());
        }
    }

    if let Some(xfh) = req.headers.get("x-forwarded-host") {
        if let Ok(s) = xfh.to_str() {
            parse_host(s.trim(), &mut info);
        }
    }

    if let Some(xfp) = req.headers.get("x-forwarded-proto") {
        if let Ok(s) = xfp.to_str() {
            parse_proto(s.trim(), &mut info);
        }
    }

    if let Some(ip) = client_ip {
        let ip_str = ip.to_string();
        if let Some(ref mut nodes) = info.for_nodes {
            nodes.push_str(", ");
            nodes.push_str(&ip_str);
        } else {
            info.for_nodes = Some(ip_str.clone());
        }
        if trusted_proxies_is_empty {
            // replace xff header if trusted_proxies is empty
            // since it's edge proxy mode, we trust the client ip
            info.for_nodes = Some(ip_str.clone());
            // set client ip from pingora session
            info.client_ip = Some(ip_str);
        } else {
            // set client ip from xff header
            if let Some(nodes) = &info.for_nodes {
                info.client_ip = nodes.split(",").next().map(|s| s.to_string());
            }
        }
    }

    if let Some(s) = req.headers.get("host") {
        if let Ok(s) = s.to_str() {
            if trusted_proxies_is_empty {
                info.host = Some(s.to_string());
                log::debug!(
                    "[trusted_proxies_is_empty] set X-Forwarded-Host from host header: {}",
                    s
                );
            } else if info.host.is_none() {
                info.host = Some(s.to_string());
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
    }

    if trusted_proxies_is_empty {
        info.proto = Some(client_proto.to_string());
        log::debug!(
            "[trusted_proxies_is_empty] set X-Forwarded-Proto from current connection: {}",
            client_proto
        );
    } else if info.proto.is_none() {
        info.proto = Some(client_proto.to_string());
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

        let info = parse_legacy_headers(&req, None, false, "http");
        assert_eq!(info.for_nodes, Some("1.2.3.4, 5.6.7.8".to_string()));
        assert_eq!(info.proto, Some("https".to_string()));
        assert_eq!(info.host, Some("example.com".to_string()));
    }
}
