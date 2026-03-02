#![no_main]

use libfuzzer_sys::fuzz_target;
use ssh_ca_server::parse_exec_command;

fuzz_target!(|data: &[u8]| {
    let (command_name, args) = parse_exec_command(data);

    // Sanity invariants the parser must uphold regardless of input:
    // 1. command_name contains no ASCII whitespace
    assert!(!command_name.chars().any(|c| c.is_ascii_whitespace()));
    // 2. no argument token contains ASCII whitespace
    for arg in &args {
        assert!(!arg.chars().any(|c| c.is_ascii_whitespace()));
    }
});
