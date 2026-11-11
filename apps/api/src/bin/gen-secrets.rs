#![forbid(unsafe_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use std::io::{self, Write};
use strongroom_api::config::{OpaqueServerSetup, CREDENTIAL_ID_KEY_LEN, EMAIL_HASH_KEY_LEN};

fn main() -> io::Result<()> {
    let mut rng = OsRng;

    let setup = OpaqueServerSetup::generate();
    let mut setup_bytes = setup.to_bytes();

    let mut cred_key_bytes = [0u8; CREDENTIAL_ID_KEY_LEN];
    rng.fill_bytes(&mut cred_key_bytes);

    let mut email_key_bytes = [0u8; EMAIL_HASH_KEY_LEN];
    rng.fill_bytes(&mut email_key_bytes);

    let setup_b64 = URL_SAFE_NO_PAD.encode(setup_bytes);
    let cred_b64 = URL_SAFE_NO_PAD.encode(cred_key_bytes);
    let email_b64 = URL_SAFE_NO_PAD.encode(email_key_bytes);

    setup_bytes.fill(0);
    cred_key_bytes.fill(0);
    email_key_bytes.fill(0);

    let mut stdout = io::stdout().lock();
    writeln!(stdout, "OPAQUE_SERVER_SETUP={setup_b64}")?;
    writeln!(stdout, "CREDENTIAL_ID_KEY={cred_b64}")?;
    writeln!(stdout, "EMAIL_HASH_KEY={email_b64}")?;
    stdout.flush()
}
