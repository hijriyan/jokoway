use std::fmt;

#[derive(Debug)]
pub enum JokowayError {
    Config(String),
    Upstream(String),
    Proxy(String),
    Tls(String),
    Acme(String),
    Io(std::io::Error),
    Network(String),
    Other(String),
}

impl std::error::Error for JokowayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            JokowayError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl fmt::Display for JokowayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JokowayError::Config(msg) => write!(f, "Configuration error: {}", msg),
            JokowayError::Upstream(msg) => write!(f, "Upstream error: {}", msg),
            JokowayError::Proxy(msg) => write!(f, "Proxy error: {}", msg),
            JokowayError::Tls(msg) => write!(f, "TLS error: {}", msg),
            JokowayError::Acme(msg) => write!(f, "ACME error: {}", msg),
            JokowayError::Io(err) => write!(f, "I/O error: {}", err),
            JokowayError::Network(msg) => write!(f, "Network error: {}", msg),
            JokowayError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl From<std::io::Error> for JokowayError {
    fn from(err: std::io::Error) -> Self {
        JokowayError::Io(err)
    }
}

impl From<Box<dyn std::error::Error>> for JokowayError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        JokowayError::Other(err.to_string())
    }
}

impl From<String> for JokowayError {
    fn from(s: String) -> Self {
        JokowayError::Other(s)
    }
}

impl From<&str> for JokowayError {
    fn from(s: &str) -> Self {
        JokowayError::Other(s.to_string())
    }
}
impl From<Box<dyn std::error::Error + Send + Sync>> for JokowayError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        JokowayError::Other(err.to_string())
    }
}
