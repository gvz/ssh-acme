#![no_main]

use libfuzzer_sys::fuzz_target;
use ssh_ca_server::certificat_authority::key_from_openssh;

fuzz_target!(|data: &[u8]| {
    // Mirror the exact pipeline used in user_key_signer::handler_sign_user_key:
    // raw channel bytes -> from_utf8_lossy -> key_from_openssh
    let openssh_key = String::from_utf8_lossy(data).to_string();
    let _ = key_from_openssh(&openssh_key);
});
