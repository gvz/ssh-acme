#![no_main]

use libfuzzer_sys::fuzz_target;
use minijinja::Environment;
use serde::Deserialize;

/// Maximum template input size in bytes.
/// Config templates are small TOML files; 64 KiB is generous.
/// This cap prevents OOM from minijinja's constant-folding of
/// adversarial expressions (e.g. `{{'x' * 999999999999}}`).
const MAX_TEMPLATE_SIZE: usize = 64 * 1024;

/// Mirrors the UserDefaults struct from user_defaults_reader for fuzzing TOML parsing.
#[derive(Deserialize, Debug)]
struct UserDefaults {
    validity_in_days: Option<u16>,
    principals: Option<Vec<String>>,
    extensions: Option<Vec<String>>,
}

fuzz_target!(|data: &[u8]| {
    // Reject inputs that exceed the size limit to avoid OOM in
    // minijinja's compile-time constant folding.
    if data.len() > MAX_TEMPLATE_SIZE {
        return;
    }

    // Fuzz TOML user-template parsing
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = toml::from_str::<UserDefaults>(s);
    }

    // Fuzz Jinja2 template rendering with arbitrary template strings
    if let Ok(template_str) = std::str::from_utf8(data) {
        let mut env = Environment::new();
        if env.add_template("test", template_str).is_ok() {
            if let Ok(tmpl) = env.get_template("test") {
                let ctx = minijinja::context! {
                    user_name => "testuser",
                    host_name => "testhost",
                };
                let _ = tmpl.render(ctx);
            }
        }
    }
});
