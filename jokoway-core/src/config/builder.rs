use super::models::{JokowayConfig, RootConfig, ServerConf, Service, SslSettings, Upstream};
use serde_yaml;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

pub struct ConfigBuilder {
    config: JokowayConfig,
    server_conf: Option<ServerConf>,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigBuilder {
    pub fn new() -> Self {
        ConfigBuilder {
            config: JokowayConfig::default(),
            server_conf: Some(ServerConf::default()),
        }
    }

    /// Load configuration from a YAML file with optimized error handling.
    /// This will merge or overwrite existing configuration depending on implementation.
    /// Here we assume it loads the base config.
    pub fn from_file<P: AsRef<Path>>(
        mut self,
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let path_ref = path.as_ref();

        // Pre-validate file exists for better error messages
        if !path_ref.exists() {
            return Err(format!("Configuration file not found: {}", path_ref.display()).into());
        }

        let file = File::open(path_ref)?;
        let reader = BufReader::new(file);

        // Parse with better error context
        let root: RootConfig = serde_yaml::from_reader(reader).map_err(|e| {
            format!(
                "Failed to parse YAML config from {}: {}",
                path_ref.display(),
                e
            )
        })?;

        self.config = root.jokoway;
        if root.pingora.is_some() {
            self.server_conf = root.pingora;
        }
        Ok(self)
    }

    pub fn with_ssl(mut self, ssl: SslSettings) -> Self {
        self.config.ssl = Some(ssl);
        self
    }

    pub fn add_upstream(mut self, upstream: Upstream) -> Self {
        self.config.upstreams.push(upstream);
        self
    }

    pub fn add_service(mut self, service: Service) -> Self {
        self.config.services.push(std::sync::Arc::new(service));
        self
    }

    /// A generic extension point.
    /// Users can pass a closure to modify the internal config directly.
    /// This allows for arbitrary modifications without changing the Builder struct.
    ///
    /// Example:
    /// ```rust
    /// use jokoway_core::config::ConfigBuilder;
    ///
    /// let builder = ConfigBuilder::new();
    /// builder.configure(|cfg, _server_conf| {
    ///     cfg.http_listen = "0.0.0.0:8080".to_string();
    /// });
    /// ```
    pub fn configure<F>(mut self, func: F) -> Self
    where
        F: FnOnce(&mut JokowayConfig, &mut ServerConf),
    {
        if let Some(ref mut sc) = self.server_conf {
            func(&mut self.config, sc);
        }
        self
    }

    pub fn build(self) -> (JokowayConfig, Option<ServerConf>) {
        (self.config, self.server_conf)
    }
}
