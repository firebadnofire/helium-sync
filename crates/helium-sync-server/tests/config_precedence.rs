use std::process::Command;

use rcgen::{CertifiedKey, generate_simple_self_signed};

#[test]
fn cli_then_environment_then_toml_then_defaults() {
    let temp = tempfile::tempdir().unwrap();
    let cert_path = temp.path().join("server.crt");
    let key_path = temp.path().join("server.key");
    let token_path = temp.path().join("token");
    let config_path = temp.path().join("server.toml");
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
    std::fs::write(&token_path, "cli-token-0123456789abcdef0123456789abcdef").unwrap();

    let portable = |path: &std::path::Path| path.to_string_lossy().replace('\\', "/");
    let file_data = temp.path().join("file-data");
    let file_socket = temp.path().join("file.sock");
    let file_database = temp.path().join("file.sqlite3");
    let config = format!(
        r#"
[server]
listen = "127.0.0.1:7001"
unix_socket = "{}"
data_dir = "{}"

[tls]
certificate = "{}"
private_key = "{}"

[auth]
token = "too-short-file-token"

[storage]
database = "{}"
"#,
        portable(&file_socket),
        portable(&file_data),
        portable(&cert_path),
        portable(&key_path),
        portable(&file_database),
    );
    std::fs::write(&config_path, config).unwrap();

    let env_socket = temp.path().join("environment.sock");
    let output = Command::new(env!("CARGO_BIN_EXE_helium-sync-server"))
        .arg("check")
        .arg("--config")
        .arg(&config_path)
        .arg("--listen")
        .arg("127.0.0.1:7003")
        .arg("--token-file")
        .arg(&token_path)
        .env("HELIUM_SYNC_LISTEN", "127.0.0.1:7002")
        .env("HELIUM_SYNC_UNIX_SOCKET", &env_socket)
        .env("HELIUM_SYNC_TOKEN", "too-short-environment-token")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("127.0.0.1:7003"));
    assert!(stdout.contains("environment.sock"));
    assert!(stdout.contains("file-data"));
    assert!(stdout.contains("log_level: \"info\""));
    assert!(!stdout.contains("cli-token"));
    assert!(!stdout.contains("environment-token"));
    assert!(!stdout.contains("file-token"));
}
