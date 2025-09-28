#[test]
fn example_config_parses_and_validates() {
    let toml = r#"
admins = ["Administrator", "root"]
users = ["student", "analyst"]
allowed_services = ["ssh", "w32time"]
    keep_packages = ["firefox", "nautilus"]

[firewall]
allowed_ports = [22]

[password_policy]
min_length = 12
require_uppercase = true
require_lowercase = true
require_number = true
require_symbol = true
"#;

    let cfg: ironguard_ai::cli::config::Config = toml::from_str(toml).unwrap();
    cfg.validate().unwrap();
}

