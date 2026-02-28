#![no_main]

use libfuzzer_sys::fuzz_target;
use minijinja::Environment;
use serde::Deserialize;

/// Mirrors the UserDefaults struct from user_defaults_reader for fuzzing TOML parsing.
#[derive(Deserialize, Debug)]
struct UserDefaults {
    validity_in_days: Option<u16>,
    principals: Option<Vec<String>>,
    extensions: Option<Vec<String>>,
}

fuzz_target!(|data: &[u8]| {
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
