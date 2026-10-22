//! Verify authentication updates across the running CLI executor process.

use std::process::Stdio;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use app_test_support::ChatGptAuthFixture;
use app_test_support::write_chatgpt_auth;
use codex_exec_server::ExecServerClient;
use codex_exec_server::NoiseChannelIdentity;
use codex_exec_server::NoiseRendezvousConnectArgs;
use codex_exec_server::NoiseRendezvousConnectBundle;
use codex_http_client::HttpClientFactory;
use codex_http_client::OutboundProxyPolicy;
use codex_login::AuthCredentialsStoreMode;
use codex_protocol::shell_environment::OPENAI_FEDERATION_RULE_ID_ENV_VAR;
use codex_protocol::shell_environment::OPENAI_IDENTITY_TOKEN_FILE_ENV_VAR;
use pretty_assertions::assert_eq;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_tungstenite::accept_hdr_async;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::header;
use wiremock::matchers::method;
use wiremock::matchers::path;

use super::accept_parent_lifetime_websocket;
use super::proxy_parent_lifetime_relay;
use super::registered_parent_lifetime_executor_public_key;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::test]
async fn noise_executor_refreshes_on_401_and_reloads_rotated_credentials() -> Result<()> {
    let home = TempDir::new()?;
    let registry = MockServer::start().await;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    std::fs::write(
        home.path().join("config.toml"),
        "cli_auth_credentials_store = 'file'\n",
    )?;
    write_chatgpt_auth(
        home.path(),
        ChatGptAuthFixture::new("old-token").account_id("account"),
        AuthCredentialsStoreMode::File,
    )?;
    Mock::given(path("/refresh"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "refreshed-token", "refresh_token": "new-refresh-token",
        })))
        .expect(1)
        .mount(&registry)
        .await;
    Mock::given(path("/cloud/environment/env/register"))
        .and(header("authorization", "Bearer old-token"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&registry)
        .await;
    for token in ["refreshed-token", "rotated-token"] {
        Mock::given(path("/cloud/environment/env/register"))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "environment_id": "env", "url": format!("ws://{}", listener.local_addr()?),
                "executor_registration_id": "registration", "security_profile": "noise_hybrid_ik_v1",
            })))
            .with_priority(1)
            .up_to_n_times(1)
            .expect(1)
            .mount(&registry)
            .await;
    }
    // A later registry rejection reloads the rotated token from storage, without
    // another OAuth refresh or unconditional reloads on ordinary requests.
    Mock::given(path("/cloud/environment/env/register"))
        .and(header("authorization", "Bearer refreshed-token"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&registry)
        .await;
    let mut child = tokio::process::Command::new(codex_utils_cargo_bin::cargo_bin("codex")?)
        .current_dir(home.path())
        .env("CODEX_HOME", home.path())
        .env(
            "CODEX_APP_SERVER_MANAGED_CONFIG_PATH",
            home.path().join("managed_config.toml"),
        )
        .env_remove(OPENAI_FEDERATION_RULE_ID_ENV_VAR)
        .env_remove(OPENAI_IDENTITY_TOKEN_FILE_ENV_VAR)
        .env_remove("CODEX_API_KEY")
        .env_remove("OPENAI_API_KEY")
        .env_remove("CODEX_ACCESS_TOKEN")
        .env(
            "CODEX_REFRESH_TOKEN_URL_OVERRIDE",
            format!("{}/refresh", registry.uri()),
        )
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .args([
            "exec-server",
            "--remote",
            &registry.uri(),
            "--environment-id",
            "env",
            "--exit-on-stdin-close",
        ])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let stdin = child.stdin.take();
    let mut websocket = accept_parent_lifetime_websocket(&listener, TEST_TIMEOUT).await?;
    // Update storage while the executor is alive, then force a new registration.
    write_chatgpt_auth(
        home.path(),
        ChatGptAuthFixture::new("rotated-token").account_id("account"),
        AuthCredentialsStoreMode::File,
    )?;
    websocket.close(None).await?;
    drop(websocket);
    let (socket, _) = tokio::time::timeout(TEST_TIMEOUT, listener.accept())
        .await
        .context("executor did not reconnect for the rejected upgrade")??;
    let rejected = tokio::time::timeout(
        TEST_TIMEOUT,
        accept_hdr_async(socket, |_: &_, _: _| {
            Err(http::Response::builder().status(401).body(None).unwrap())
        }),
    )
    .await
    .context("executor did not complete the rejected upgrade")?;
    assert!(rejected.is_err());
    let _websocket = accept_parent_lifetime_websocket(&listener, TEST_TIMEOUT).await?;
    drop(stdin);
    let output = tokio::time::timeout(TEST_TIMEOUT, child.wait_with_output())
        .await
        .context("executor did not exit after stdin closed")??;
    anyhow::ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[tokio::test]
async fn noise_executor_refreshes_validation_auth_without_reconnecting() -> Result<()> {
    assert_validation_recovers_without_reconnecting(CredentialReplacement::OAuthRefresh).await
}

#[tokio::test]
async fn noise_executor_reloads_validation_auth_without_reconnecting() -> Result<()> {
    assert_validation_recovers_without_reconnecting(CredentialReplacement::AuthFileReload).await
}

#[derive(Clone, Copy)]
enum CredentialReplacement {
    OAuthRefresh,
    AuthFileReload,
}

async fn assert_validation_recovers_without_reconnecting(
    replacement: CredentialReplacement,
) -> Result<()> {
    const ENVIRONMENT_ID: &str = "environment-validation-refresh";
    const EXECUTOR_REGISTRATION_ID: &str = "registration-validation-refresh";
    const HARNESS_AUTHORIZATION: &str = "validation-refresh-harness";

    let home = TempDir::new()?;
    let registry = MockServer::start().await;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let rendezvous_url = format!("ws://{}", listener.local_addr()?);
    std::fs::write(
        home.path().join("config.toml"),
        "cli_auth_credentials_store = 'file'\n",
    )?;
    write_chatgpt_auth(
        home.path(),
        ChatGptAuthFixture::new("old-token")
            .account_id("account")
            .chatgpt_account_id("account")
            .chatgpt_user_id("user"),
        AuthCredentialsStoreMode::File,
    )?;

    // The executor starts with accepted credentials and keeps this registration
    // and physical relay connection throughout the subsequent validation.
    Mock::given(method("POST"))
        .and(path(format!(
            "/cloud/environment/{ENVIRONMENT_ID}/register"
        )))
        .and(header("authorization", "Bearer old-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "environment_id": ENVIRONMENT_ID,
            "url": format!("{rendezvous_url}/relay?role=environment"),
            "executor_registration_id": EXECUTOR_REGISTRATION_ID,
            "security_profile": "noise_hybrid_ik_v1",
        })))
        .expect(1)
        .mount(&registry)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/cloud/environment/{ENVIRONMENT_ID}/validate"
        )))
        .and(header("authorization", "Bearer old-token"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&registry)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/cloud/environment/{ENVIRONMENT_ID}/validate"
        )))
        .and(header("authorization", "Bearer replacement-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "valid": true,
        })))
        .expect(1)
        .mount(&registry)
        .await;
    Mock::given(method("POST"))
        .and(path("/refresh"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "replacement-token",
            "refresh_token": "replacement-refresh-token",
        })))
        .expect(match replacement {
            CredentialReplacement::OAuthRefresh => 1,
            CredentialReplacement::AuthFileReload => 0,
        })
        .mount(&registry)
        .await;

    let mut child = tokio::process::Command::new(codex_utils_cargo_bin::cargo_bin("codex")?)
        .current_dir(home.path())
        .env("CODEX_HOME", home.path())
        .env(
            "CODEX_APP_SERVER_MANAGED_CONFIG_PATH",
            home.path().join("managed_config.toml"),
        )
        .env_remove(OPENAI_FEDERATION_RULE_ID_ENV_VAR)
        .env_remove(OPENAI_IDENTITY_TOKEN_FILE_ENV_VAR)
        .env_remove("CODEX_API_KEY")
        .env_remove("OPENAI_API_KEY")
        .env_remove("CODEX_ACCESS_TOKEN")
        .env(
            "CODEX_REFRESH_TOKEN_URL_OVERRIDE",
            format!("{}/refresh", registry.uri()),
        )
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .args([
            "exec-server",
            "--remote",
            &registry.uri(),
            "--environment-id",
            ENVIRONMENT_ID,
            "--exit-on-stdin-close",
        ])
        .stdin(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let stdin = child.stdin.take();
    let environment_websocket = tokio::select! {
        status = child.wait() => {
            anyhow::bail!("executor exited before connecting: {}", status?);
        }
        result = accept_parent_lifetime_websocket(&listener, TEST_TIMEOUT) => result?,
    };

    // A normal request still uses the cached original token. Its explicit 401
    // must reload this replacement without asking the OAuth authority to refresh.
    if matches!(replacement, CredentialReplacement::AuthFileReload) {
        write_chatgpt_auth(
            home.path(),
            ChatGptAuthFixture::new("replacement-token")
                .account_id("account")
                .chatgpt_account_id("account")
                .chatgpt_user_id("user"),
            AuthCredentialsStoreMode::File,
        )?;
    }

    let executor_public_key = registered_parent_lifetime_executor_public_key(&registry).await?;
    let harness_args = NoiseRendezvousConnectArgs {
        bundle: NoiseRendezvousConnectBundle {
            websocket_url: format!("{rendezvous_url}/relay?role=harness"),
            environment_id: ENVIRONMENT_ID.to_string(),
            executor_registration_id: EXECUTOR_REGISTRATION_ID.to_string(),
            executor_public_key,
            harness_key_authorization: HARNESS_AUTHORIZATION.to_string(),
        },
        harness_identity: NoiseChannelIdentity::generate()?,
        client_name: "validation-refresh-test".to_string(),
        connect_timeout: TEST_TIMEOUT,
        initialize_timeout: TEST_TIMEOUT,
        resume_session_id: None,
        http_client_factory: HttpClientFactory::new(OutboundProxyPolicy::ReqwestDefault),
    };
    let client_task =
        tokio::spawn(async move { ExecServerClient::connect_noise_rendezvous(harness_args).await });
    let harness_websocket = accept_parent_lifetime_websocket(&listener, TEST_TIMEOUT)
        .await
        .context("harness did not connect to the existing relay")?;
    let relay_task = tokio::spawn(proxy_parent_lifetime_relay(
        environment_websocket,
        harness_websocket,
    ));
    let client = tokio::time::timeout(TEST_TIMEOUT, client_task)
        .await
        .context("Noise initialization did not recover from the validation 401")???;
    tokio::time::timeout(TEST_TIMEOUT, client.environment_info())
        .await
        .context("environment_info failed after validation recovery")??;

    let requests = registry
        .received_requests()
        .await
        .context("failed to read registry requests")?;
    let registration_count = requests
        .iter()
        .filter(|request| request.url.path().ends_with("/register"))
        .count();
    let validations = requests
        .iter()
        .filter(|request| request.url.path().ends_with("/validate"))
        .collect::<Vec<_>>();
    assert_eq!(registration_count, 1);
    assert_eq!(validations.len(), 2);
    assert_eq!(
        validations[0].headers.get("authorization"),
        Some(&http::HeaderValue::from_static("Bearer old-token"))
    );
    assert_eq!(
        validations[1].headers.get("authorization"),
        Some(&http::HeaderValue::from_static("Bearer replacement-token"))
    );
    assert_eq!(validations[0].body, validations[1].body);
    let validation: serde_json::Value = serde_json::from_slice(&validations[1].body)?;
    assert_eq!(
        validation["executor_registration_id"],
        serde_json::json!(EXECUTOR_REGISTRATION_ID)
    );
    assert_eq!(
        validation["harness_key_authorization"],
        serde_json::json!(HARNESS_AUTHORIZATION)
    );
    registry.verify().await;

    drop(client);
    drop(stdin);
    let status = tokio::time::timeout(TEST_TIMEOUT, child.wait())
        .await
        .context("executor did not exit after stdin closed")??;
    relay_task.abort();
    let _ = relay_task.await;
    anyhow::ensure!(status.success(), "executor exited with {status}");
    Ok(())
}
