use crate::config::ConfigBuilder;
use crate::prelude::*;
use crate::server::app::App;

pub fn jokoway_main(extensions: Vec<Box<dyn JokowayExtension>>) {
    env_logger::init();

    let opt = pingora::server::configuration::Opt::parse_args();
    let config_path = opt.conf.as_deref().unwrap_or("jokoway.yml");

    log::info!("Loading configuration from {}", config_path);

    let builder = match ConfigBuilder::new().from_file(config_path) {
        Ok(b) => b,
        Err(e) => {
            log::error!("Failed to load configuration file: {}", e);
            std::process::exit(1);
        }
    };

    let (config, server_conf) = builder.build();
    let app = App::new(config, server_conf, opt, extensions);
    log::info!("Starting Jokoway server...");
    if let Err(e) = app.run() {
        log::error!("Fatal error: {}", e);
        std::process::exit(1);
    }
}
