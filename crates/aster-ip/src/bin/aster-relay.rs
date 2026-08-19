//! Standalone opaque relay fallback.

use aster_ip::CipherRelayServer;
use std::env;
use std::net::SocketAddr;
use std::process::ExitCode;

fn main() -> ExitCode {
    let address = env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:4477".to_owned());
    let address: SocketAddr = match address.parse() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("invalid relay listen address: {error}");
            return ExitCode::FAILURE;
        }
    };
    match CipherRelayServer::bind(address).and_then(|server| server.serve(0)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("relay stopped: {error}");
            ExitCode::FAILURE
        }
    }
}
