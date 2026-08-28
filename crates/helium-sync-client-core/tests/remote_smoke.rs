use std::{path::PathBuf, sync::Arc};

use helium_sync_client_core::{
    api::ApiClient,
    crypto::MasterKey,
    https::{CertificateMode, HttpsTransport},
    orchestration::ClientCore,
    ssh::{SshConfig, SshTransport},
};
use helium_sync_common::DeviceId;
use helium_sync_profile::DiscoveryOptions;
use secrecy::SecretString;
use url::Url;

#[tokio::test]
#[ignore = "requires an explicitly configured live Helium Sync server"]
async fn real_https_ssh_and_bookmark_round_trips() {
    let token = std::fs::read_to_string(required("HELIUM_SYNC_TEST_TOKEN_FILE"))
        .expect("read test token")
        .trim()
        .to_owned();
    let https = HttpsTransport::new(
        Url::parse(&required("HELIUM_SYNC_TEST_URL")).expect("parse test URL"),
        CertificateMode::CustomCa {
            pem_path: PathBuf::from(required("HELIUM_SYNC_TEST_CA")),
        },
    )
    .expect("create HTTPS transport");
    let https_core = ClientCore::new(
        Arc::new(ApiClient::new(
            Arc::new(https),
            SecretString::from(token.clone()),
        )),
        MasterKey::generate(),
        DeviceId::new(),
    );
    https_core
        .register_device("remote HTTPS smoke test")
        .await
        .expect("register HTTPS test device");
    assert!(
        https_core
            .synthetic_round_trip()
            .await
            .expect("HTTPS synthetic round trip")
            .plaintext_matches
    );

    let discovery = helium_sync_profile::discover(&DiscoveryOptions::from_environment())
        .expect("discover local Helium profile");
    let profile = discovery
        .profiles
        .iter()
        .find(|profile| profile.directory_name == "Default")
        .expect("find Default profile");
    let (bookmark_proof, _) = https_core
        .bookmark_round_trip(profile)
        .await
        .expect("HTTPS bookmark round trip");
    assert!(bookmark_proof.plaintext_matches);

    let temp = tempfile::tempdir().expect("create temporary known-host directory");
    let ssh = SshTransport::new(SshConfig {
        host: required("HELIUM_SYNC_TEST_SSH_HOST"),
        port: 22,
        username: required("HELIUM_SYNC_TEST_SSH_USER"),
        private_key: PathBuf::from(required("HELIUM_SYNC_TEST_SSH_KEY")),
        private_key_passphrase: None,
        remote_socket: required("HELIUM_SYNC_TEST_SSH_SOCKET"),
        application_known_hosts: temp.path().join("known_hosts"),
        trusted_fingerprint: None,
    })
    .expect("create SSH transport");
    let ssh_core = ClientCore::new(
        Arc::new(ApiClient::new(Arc::new(ssh), SecretString::from(token))),
        MasterKey::generate(),
        DeviceId::new(),
    );
    ssh_core
        .register_device("remote SSH smoke test")
        .await
        .expect("register SSH test device");
    assert!(
        ssh_core
            .synthetic_round_trip()
            .await
            .expect("SSH synthetic round trip")
            .plaintext_matches
    );
}

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set for the remote smoke test"))
}
