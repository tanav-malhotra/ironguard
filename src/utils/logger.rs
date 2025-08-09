use anyhow::Result;
use tracing::Level;
use tracing_subscriber::{
    filter::EnvFilter,
    fmt::{self, time::ChronoUtc},
    prelude::*,
};

pub fn init(verbosity: u8) -> Result<()> {
    let level = match verbosity {
        0 => Level::INFO,
        1 => Level::DEBUG,
        _ => Level::TRACE,
    };

    let env_filter = EnvFilter::from_default_env()
        .add_directive(format!("ironguard={}", level).parse()?)
        .add_directive("warn".parse()?);

    let fmt_layer = fmt::layer()
        .with_timer(ChronoUtc::rfc_3339())
        .with_target(false)
        .with_level(true)
        .compact();

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();

    Ok(())
}