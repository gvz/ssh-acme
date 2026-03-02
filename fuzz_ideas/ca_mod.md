# Fuzzing Ideas: `certificat_authority/mod.rs`

**Current coverage:** 47.52% regions, 54.05% lines
**Target:** 90%

## Analysis

The file contains:
- `CertificateAuthority::new()` (lines 61-71): loads private key from file
- `sign_certificate()` (lines 83-126): signs a user SSH cert
- `check_public_key()` (lines 132-137): looks up host by public key
- `sign_host_certificate()` (lines 149-207): signs a host SSH cert with key verification
- `key_from_openssh()` (lines 219-221): thin wrapper around `PublicKey::from_openssh`
- Data types: `CaRequest`, `CaResponse`, `AuthenticatedRequest`, `CaError`
- `arbitrary_public_key()` (lines 246-257): only compiled with `arbitrary` feature

### Existing fuzz coverage

- `fuzz_cert_signing`: structured fuzzing of `CaRequest` via `Arbitrary` — exercises `sign_certificate`, `check_public_key`, and `sign_host_certificate` through `CaServer::handle_request`. However the harness uses an empty host inventory, so `sign_host_certificate` always fails at the host-config lookup stage (lines 162) and never reaches the key-comparison, cert-building, or signing code (lines 163-207).
- `fuzz_ipc_messages`: raw-byte deserialization of `AuthenticatedRequest`/`CaResponse` — exercises JSON parsing and token auth, then dispatches to `handle_request` with the same empty-inventory limitation.
- `fuzz_ssh_protocol`: exercises `PublicKey::from_bytes` and `key_from_openssh` with raw bytes.
- `fuzz_user_key_parsing`: exercises `key_from_openssh` via the `from_utf8_lossy` pipeline.

The main coverage gap is that **no fuzz target exercises `sign_host_certificate` past the config-lookup stage**. The key-comparison logic (lines 163-173), host cert builder (lines 174-196), and host cert signing (lines 199-206) are never reached by any fuzzer.

## Uncovered Code Paths

1. **`sign_host_certificate` key comparison** (lines 163-173): `CaError::WrongPublicKey` — never reached because no host config exists in any fuzz harness.
2. **`sign_host_certificate` cert building** (lines 174-196): principals, extensions, validity — never reached.
3. **`sign_host_certificate` signing success/failure** (lines 199-206): never reached.
4. **`sign_host_certificate` config public key parse failure** (lines 163-166): invalid key in config — never reached.
5. **`sign_certificate` with adversarial user strings** (lines 83-126): the existing `fuzz_cert_signing` exercises this, but the `user` field is a plain `String` from `Arbitrary` which may not produce interesting edge cases (empty strings, path traversal attempts, very long strings, null bytes).
6. **`CertificateAuthority::new()` error paths** (lines 62-66): file not found, invalid key format — not fuzzable in the traditional sense (requires filesystem interaction), but the invalid-key-data path can be exercised.

## Fuzzing Ideas to Reach 90%

### 1. Enhance `fuzz_cert_signing` to populate host inventory

**Problem:** The existing `fuzz_cert_signing` harness creates an empty host inventory directory. When the fuzzer generates a `SignHostCertificate` request, `read_host_config` fails immediately because no config file exists. This means lines 163-207 are never reached.

**Solution:** Before calling `handle_request`, check if the request is a `SignHostCertificate`. If so, write a host config TOML file into the inventory directory using the public key from the request. This ensures the host-config lookup succeeds and the fuzzer can reach the key-comparison, cert-building, and signing code.

```rust
// Inside fuzz_cert_signing.rs, after creating host_inventory:
match &request {
    CaRequest::SignHostCertificate { host_name, public_key } => {
        let pub_key_str = public_key.to_openssh().unwrap_or_default();
        // Sanitize host_name for filesystem use
        let safe_name = host_name.replace(['/', '\\', '\0'], "_");
        let safe_name = if safe_name.is_empty() || safe_name.contains("..") {
            "fuzz_host"
        } else {
            &safe_name
        };
        let host_config = format!(
            "public_key = \"{}\"\nvalidity_in_days = 30\nhostnames = [\"{}\"]\nextensions = []\n",
            pub_key_str, safe_name
        );
        let _ = fs::write(host_inventory.join(format!("{}.toml", safe_name)), host_config);
    }
    _ => {}
}
```

**Attack surface:** Host certificate signing — the cert-builder code handles fuzz-generated hostnames and public keys, exercising `CertBuilder`, `valid_principal`, `extension`, and `sign`.

**Exercises:** Lines 149-207 — config parsing, key comparison (both match and mismatch paths), cert type, key_id formatting, principal iteration, extension iteration, signing success/failure.

### 2. Enhance `fuzz_cert_signing` with mismatched host key variant

**Problem:** If we always write the correct public key into the host config (idea 1), the key-mismatch error path (lines 168-173) is never hit.

**Solution:** Use a byte from the fuzzer input to decide whether to write the matching key or a different key into the config:

```rust
// Alternate approach: derive a second key and sometimes use it
CaRequest::SignHostCertificate { host_name, public_key } => {
    let pub_key_str = public_key.to_openssh().unwrap_or_default();
    // Sometimes use correct key, sometimes use a different one to hit mismatch path
    let config_key = if host_name.len() % 2 == 0 {
        pub_key_str  // matching key → exercises lines 174-207
    } else {
        // Generate a different key for mismatch → exercises lines 168-173
        let other_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        other_key.public_key().to_openssh().unwrap()
    };
    // ... write host config with config_key
}
```

**Exercises:** `CaError::WrongPublicKey` error path (lines 168-173).

### 3. Enhance `fuzz_cert_signing` with invalid config key

**Problem:** The config-public-key parse failure path (lines 163-166) is never reached because we always write a valid OpenSSH key string into the config.

**Solution:** Occasionally write an invalid public key string into the host config TOML:

```rust
// Sometimes write garbage as the public key to hit the parse-failure path
let config_key = if host_name.len() % 3 == 0 {
    "not-a-valid-ssh-key".to_string()  // exercises lines 163-166
} else {
    pub_key_str  // valid key
};
```

**Exercises:** `PublicKey::from_openssh` error → `CaError::WrongPublicKey` mapping (lines 163-166).

### 4. Enhance `fuzz_ipc_messages` with populated host inventory

Apply the same host-inventory population strategy from idea 1 to `fuzz_ipc_messages`. Currently it has the same empty-inventory limitation.

### 5. New fuzz target: `fuzz_ca_new_invalid_key`

**Problem:** `CertificateAuthority::new()` with invalid key data (line 66) is never fuzzed.

**Solution:** Create a fuzz target that writes fuzzer-generated bytes to a temp file and attempts to construct a `CertificateAuthority` from it:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use ssh_ca_server::certificat_authority::CertificateAuthority;
use ssh_ca_server::certificat_authority::config::Ca as CaConfig;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

fuzz_target!(|data: &[u8]| {
    // Cap input to avoid wasting cycles
    if data.len() > 8192 {
        return;
    }

    let temp_dir = TempDir::new().expect("temp dir");
    let base_path = temp_dir.path();

    // Write fuzz data as if it were a CA private key file
    let key_path = base_path.join("ca_key");
    fs::write(&key_path, data).unwrap();

    let ca_config = CaConfig {
        user_list_file: PathBuf::from("/dev/null"),
        ca_key: key_path,
        default_user_template: PathBuf::from("/dev/null"),
        host_inventory: base_path.join("hosts"),
    };

    // Must not panic regardless of input
    let _ = CertificateAuthority::new(&ca_config);
});
```

**Attack surface:** `PrivateKey::from_openssh` parsing of untrusted data.

**Exercises:** Lines 62-66 — file read, key parsing error paths.

### 6. New fuzz target: `fuzz_host_cert_signing`

**Problem:** A dedicated target for `sign_host_certificate` allows the fuzzer to generate structured inputs (hostname, public key, config content) without going through the `CaServer` dispatch layer, giving the fuzzer more direct control.

**Solution:** Create a structured fuzz target that takes a hostname (String), public key (via `arbitrary_public_key`), and a fuzzed host-config TOML:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use ssh_ca_server::certificat_authority::CertificateAuthority;
use ssh_ca_server::certificat_authority::config::Ca as CaConfig;
use ssh_key::Algorithm;
use ssh_key::private::PrivateKey;
use ssh_key::rand_core::OsRng;
use ssh_key::PublicKey;
use std::fs;
use tempfile::TempDir;

#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzInput {
    host_name: String,
    #[arbitrary(with = ssh_ca_server::certificat_authority::arbitrary_public_key)]
    public_key: PublicKey,
    config_public_key: String,
    validity_in_days: u32,
    hostnames: Vec<String>,
    extensions: Vec<String>,
}

fuzz_target!(|input: FuzzInput| {
    if input.host_name.is_empty()
        || input.host_name.len() > 256
        || input.host_name.contains(['/', '\\', '\0'])
        || input.host_name.contains("..")
    {
        return;
    }

    let temp_dir = TempDir::new().expect("temp dir");
    let base_path = temp_dir.path();

    // Set up CA
    let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let ca_key_openssh = ca_key.to_openssh(ssh_key::LineEnding::LF).unwrap();
    let ca_key_path = base_path.join("ca_key");
    fs::write(&ca_key_path, ca_key_openssh.as_bytes()).unwrap();

    let user_list_path = base_path.join("user.toml");
    fs::write(&user_list_path, "[users]\n").unwrap();
    let default_path = base_path.join("user_default.toml");
    fs::write(&default_path, "validity_in_days = 1\nprincipals = []\nextensions = []\n").unwrap();

    let host_inventory = base_path.join("hosts");
    fs::create_dir(&host_inventory).unwrap();

    // Write fuzz-controlled host config
    let hostnames_toml: Vec<String> = input.hostnames.iter()
        .map(|h| format!("\"{}\"", h.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect();
    let extensions_toml: Vec<String> = input.extensions.iter()
        .map(|e| format!("\"{}\"", e.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect();
    let host_config = format!(
        "public_key = \"{}\"\nvalidity_in_days = {}\nhostnames = [{}]\nextensions = [{}]\n",
        input.config_public_key.replace('\\', "\\\\").replace('"', "\\\""),
        input.validity_in_days,
        hostnames_toml.join(", "),
        extensions_toml.join(", "),
    );
    let _ = fs::write(host_inventory.join(format!("{}.toml", input.host_name)), host_config);

    let ca_config = CaConfig {
        user_list_file: user_list_path,
        default_user_template: default_path,
        host_inventory,
        ca_key: ca_key_path,
    };

    if let Ok(ca) = CertificateAuthority::new(&ca_config) {
        let _ = ca.sign_host_certificate(&input.host_name, &input.public_key);
    }
});
```

**Attack surface:** Direct host certificate signing with adversarial config content, hostnames, extensions, and key mismatches.

**Exercises:** Lines 149-207 comprehensively — config parsing, key comparison (match/mismatch), invalid config key parsing, cert builder with fuzzed principals and extensions, signing.

**Note:** This requires `arbitrary_public_key` to be re-exported as `pub`. If that is undesirable, the target can replicate the function locally.

## Implementation Priority

| # | Idea | Impact | Effort | Priority |
|---|------|--------|--------|----------|
| 1 | Populate host inventory in `fuzz_cert_signing` | High (+20% lines) | Low | **High** |
| 2 | Key mismatch variant | Medium (+5% lines) | Low | **High** |
| 3 | Invalid config key variant | Medium (+3% lines) | Low | **High** |
| 4 | Same for `fuzz_ipc_messages` | Medium | Low | Medium |
| 5 | `fuzz_ca_new_invalid_key` target | Low (+3% lines) | Low | Medium |
| 6 | `fuzz_host_cert_signing` dedicated target | High (+25% lines) | Medium | Medium |

Ideas 1-3 can be combined into a single change to `fuzz_cert_signing.rs` and should be implemented first. Idea 6 is the most thorough but overlaps with 1-3 if those are implemented.

## Estimated Coverage Gain

| Change | Lines Covered | New Coverage |
|--------|--------------|-------------|
| Host inventory in fuzz_cert_signing (ideas 1-3) | 149-207 | +25% |
| Host inventory in fuzz_ipc_messages (idea 4) | 149-207 | +2% (overlap) |
| fuzz_ca_new_invalid_key (idea 5) | 62-66 | +3% |
| fuzz_host_cert_signing (idea 6) | 149-207 | +5% (overlap with 1-3) |

Ideas 1-3 alone should bring coverage from ~54% to ~79% lines. Adding ideas 4-6 should push past 85%. Combined with the existing unit tests, 90% line coverage is achievable.

## Cargo.toml changes

For idea 5, add to `fuzz/Cargo.toml`:

```toml
[[bin]]
name = "fuzz_ca_new_invalid_key"
path = "fuzz_targets/fuzz_ca_new_invalid_key.rs"
doc = false
```

For idea 6, add to `fuzz/Cargo.toml`:

```toml
[[bin]]
name = "fuzz_host_cert_signing"
path = "fuzz_targets/fuzz_host_cert_signing.rs"
doc = false
```

## Checklist

- [ ] Enhance `fuzz_cert_signing.rs` to populate host inventory with matching/mismatched/invalid keys (ideas 1-3)
- [ ] Enhance `fuzz_ipc_messages.rs` with same host inventory population (idea 4)
- [ ] Create `fuzz/fuzz_targets/fuzz_ca_new_invalid_key.rs` (idea 5)
- [ ] Create `fuzz/fuzz_targets/fuzz_host_cert_signing.rs` (idea 6)
- [ ] Add `[[bin]]` entries in `fuzz/Cargo.toml` for new targets
- [ ] Run `nix flake check` to verify nothing is broken
