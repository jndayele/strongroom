#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConfig {
    pub host: IpAddr,
    pub port: u16,
    pub database_url: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    MissingVar(&'static str),
    InvalidHost(String),
    InvalidPort(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingVar(name) => write!(f, "missing required environment variable: {name}"),
            Self::InvalidHost(val) => write!(f, "invalid API_HOST value: {val}"),
            Self::InvalidPort(val) => write!(f, "invalid API_PORT value: {val}"),
        }
    }
}

impl Error for ConfigError {}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let host_raw = env::var("API_HOST").unwrap_or_else(|_| String::from("127.0.0.1"));
        let host = host_raw
            .parse::<IpAddr>()
            .map_err(|_| ConfigError::InvalidHost(host_raw))?;

        let port_raw = env::var("API_PORT").unwrap_or_else(|_| String::from("8080"));
        let port = port_raw
            .parse::<u16>()
            .map_err(|_| ConfigError::InvalidPort(port_raw))?;

        let database_url =
            env::var("DATABASE_URL").map_err(|_| ConfigError::MissingVar("DATABASE_URL"))?;
        if database_url.trim().is_empty() {
            return Err(ConfigError::MissingVar("DATABASE_URL"));
        }

        Ok(Self {
            host,
            port,
            database_url,
        })
    }

    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.host, self.port)
    }
}
