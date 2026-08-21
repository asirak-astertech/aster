//! Test-only command used by the official Go age interoperability harness.

#![forbid(unsafe_code)]

use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;

use aster_mesh::{
    MAX_PROTECTED_PROVISIONING_BYTES, MAX_UNPROTECTED_PROVISIONING_BYTES, ProvisioningProtector,
    ProvisioningUnprotector, UnprotectedProvisioning,
};
use aster_provisioning_age::{AgeX25519Protector, AgeX25519Unprotector, SecretString};
use zeroize::{Zeroize, Zeroizing};

const MAX_KEY_TEXT_BYTES: usize = 1024;

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let result = match arguments.as_slice() {
        [command, identity_path] if command == "public-key" => public_key(identity_path),
        [command, recipient, input_path, output_path] if command == "encrypt" => {
            encrypt(recipient, input_path, output_path)
        }
        [command, identity_path, input_path, output_path] if command == "decrypt" => {
            decrypt(identity_path, input_path, output_path)
        }
        _ => Err("invalid arguments"),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("age Rust interoperability helper: {message}");
            ExitCode::from(1)
        }
    }
}

fn public_key(identity_path: &str) -> Result<(), &'static str> {
    let unprotector = parse_identity(identity_path)?;
    writeln!(io::stdout().lock(), "{}", unprotector.recipient())
        .map_err(|_| "could not write recipient")
}

fn encrypt(recipient: &str, input_path: &str, output_path: &str) -> Result<(), &'static str> {
    if recipient.is_empty() || recipient.len() > MAX_KEY_TEXT_BYTES {
        return Err("recipient was rejected");
    }
    let mut protector =
        AgeX25519Protector::parse(recipient).map_err(|_| "recipient was rejected")?;
    let plaintext = read_bounded(input_path, MAX_UNPROTECTED_PROVISIONING_BYTES, true)?;
    let plaintext =
        UnprotectedProvisioning::new(plaintext).map_err(|_| "plaintext was rejected")?;
    let protected = protector
        .protect(&plaintext)
        .map_err(|_| "plaintext protection failed")?;
    write_new_private(output_path, &protected)
}

fn decrypt(identity_path: &str, input_path: &str, output_path: &str) -> Result<(), &'static str> {
    let mut unprotector = parse_identity(identity_path)?;
    let protected = read_bounded(input_path, MAX_PROTECTED_PROVISIONING_BYTES, false)?;
    let plaintext = unprotector
        .unprotect(&protected, MAX_UNPROTECTED_PROVISIONING_BYTES)
        .map_err(|_| "protected input was rejected")?;
    write_new_private(output_path, plaintext.expose())
}

fn parse_identity(path: &str) -> Result<AgeX25519Unprotector, &'static str> {
    let identity_bytes = Zeroizing::new(read_bounded(path, MAX_KEY_TEXT_BYTES, true)?);
    let identity_text = std::str::from_utf8(&identity_bytes)
        .map_err(|_| "identity was rejected")?
        .trim();
    if identity_text.is_empty() {
        return Err("identity was rejected");
    }
    let identity = SecretString::from(identity_text.to_owned());
    AgeX25519Unprotector::parse(&identity).map_err(|_| "identity was rejected")
}

fn read_bounded(path: &str, maximum: usize, secret: bool) -> Result<Vec<u8>, &'static str> {
    let input = File::open(path).map_err(|_| "input could not be opened")?;
    let limit = u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1);
    let mut contents = Vec::with_capacity(maximum.min(64 * 1024));
    if input.take(limit).read_to_end(&mut contents).is_err() {
        if secret {
            contents.zeroize();
        }
        return Err("input could not be read");
    }
    if contents.is_empty() || contents.len() > maximum {
        if secret {
            contents.zeroize();
        }
        return Err("input exceeded its interoperability bound");
    }
    Ok(contents)
}

fn write_new_private(path: &str, contents: &[u8]) -> Result<(), &'static str> {
    let path = Path::new(path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut output = options
        .open(path)
        .map_err(|_| "output could not be created")?;
    if output.write_all(contents).is_err() || output.flush().is_err() {
        drop(output);
        let _ = std::fs::remove_file(path);
        return Err("output could not be written");
    }
    Ok(())
}
