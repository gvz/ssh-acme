#![no_main]

use libfuzzer_sys::fuzz_target;
use ssh_ca_server::certificat_authority::{AuthenticatedRequest, CaResponse};

fuzz_target!(|data: &[u8]| {
    // Fuzz AuthenticatedRequest deserialization from raw bytes
    let _ = serde_json::from_slice::<AuthenticatedRequest>(data);

    // Fuzz CaResponse deserialization
    let _ = serde_json::from_slice::<CaResponse>(data);

    // Fuzz UTF-8 parsing path (as the server does)
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<AuthenticatedRequest>(s);
    }
});
