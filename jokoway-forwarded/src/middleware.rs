use crate::config::{ForwardedSettings, TrustedProxies};
use crate::models::{XFF, XFH, XFP};
use crate::parser::parse_legacy_headers;
use async_trait::async_trait;
use jokoway_core::{AppContext, Context, JokowayMiddleware, RequestContext};
use pingora::Error;
use pingora::proxy::Session;

pub struct ForwardedMiddleware {
    pub settings: ForwardedSettings,
    pub trusted_proxies: TrustedProxies,
}

#[async_trait]
impl JokowayMiddleware for ForwardedMiddleware {
    type CTX = ();

    fn name(&self) -> &'static str {
        "ForwardedMiddleware"
    }

    fn new_ctx(&self) -> Self::CTX {}

    fn order(&self) -> i16 {
        2014
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
        _app_ctx: &AppContext,
        request_ctx: &RequestContext,
    ) -> Result<bool, Box<Error>> {
        // Extract the direct client IP from the connection.
        let client_ip = session
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .map(|inet| inet.ip());

        // If trusted_proxies is empty, trust everyone (open mode).
        // If trusted_proxies is configured, only allow listed CIDRs.
        let trusted_proxies_is_empty = self.trusted_proxies.is_empty();
        let is_trusted = if trusted_proxies_is_empty {
            true
        } else {
            client_ip
                .as_ref()
                .map(|ip| self.trusted_proxies.contains(ip))
                .unwrap_or(false)
        };

        if !is_trusted {
            // Client IP is not in trusted_proxies — reject with 403 Forbidden.
            let header = pingora::http::ResponseHeader::build(403, None).unwrap();
            session
                .write_response_header(Box::new(header), true)
                .await?;
            return Ok(true);
        }

        let client_proto = if session.digest().is_some_and(|d| d.ssl_digest.is_some()) {
            "https"
        } else {
            "http"
        };
        // FIXME: Should we prioritize the host from the URI over the header?
        let uri_host = session.req_header().uri.host();
        let header_host = session
            .req_header()
            .headers
            .get("Host")
            .and_then(|v| v.to_str().ok());
        let current_host: Option<&str> = if let Some(host) = uri_host {
            Some(host)
        } else if let Some(host) = header_host {
            Some(host)
        } else {
            None
        };

        let info = parse_legacy_headers(
            session.req_header(),
            client_ip.as_ref(),
            trusted_proxies_is_empty,
            client_proto,
            current_host,
        );

        // Store info in request context for downstream consumers.
        request_ctx.insert(info.clone());

        // Strip ALL incoming forwarded headers — we re-inject our own below.
        let req_header = session.req_header_mut();
        req_header.remove_header(&XFF);
        req_header.remove_header(&XFH);
        req_header.remove_header(&XFP);

        // Legacy X-Forwarded-* headers.
        if let Some(nodes) = &info.for_nodes {
            req_header.insert_header(XFF, nodes.as_ref())?;
        }
        if let Some(host) = &info.host {
            req_header.insert_header(XFH, host.as_ref())?;
        }
        if let Some(proto) = &info.proto {
            req_header.insert_header(XFP, proto.as_ref())?;
        }

        Ok(false)
    }
}
