#![forbid(unsafe_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use std::error::Error;
use std::io::{self, Write};
use strongroom_api::config::OpaqueServerSetup;

fn main() -> Result<(), Box<dyn Error>> {
    let setup = OpaqueServerSetup::from_env()?;
    let public_key_b64 = URL_SAFE_NO_PAD.encode(setup.static_public_key_bytes());

    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{public_key_b64}")?;
    stdout.flush()?;
    Ok(())
}
