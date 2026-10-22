//! Sends registry requests with current credentials and at most one retry after a 401.
//! Transport failures and other HTTP errors are never replayed here.

use codex_http_client::HttpResponse;
use codex_http_client::Request;
use http::StatusCode;

use super::EnvironmentRegistryClient;
use super::current_trace_context_headers;
use crate::ExecServerError;

impl EnvironmentRegistryClient {
    pub(super) async fn send_authenticated(
        &self,
        request: Request,
    ) -> Result<HttpResponse, ExecServerError> {
        let request = request
            .into_prepared()
            .map_err(ExecServerError::EnvironmentRegistryConfig)?;
        let mut retried = false;
        loop {
            let authenticated = self
                .auth_provider
                .apply_auth(request.clone())
                .await
                .map_err(super::direct::direct_auth_error)?;
            let prepared = authenticated
                .prepare_body_for_send()
                .map_err(ExecServerError::EnvironmentRegistryConfig)?;
            let rejected_headers = prepared.headers.clone();
            let mut outgoing = self
                .http
                .request(authenticated.method, authenticated.url)
                .headers(prepared.headers)
                .headers(current_trace_context_headers())
                .body(prepared.body.unwrap_or_default());
            if let Some(timeout) = authenticated.timeout {
                outgoing = outgoing.timeout(timeout);
            }
            let response = outgoing.send().await?;
            if !retried
                && response.status() == StatusCode::UNAUTHORIZED
                && self
                    .auth_provider
                    .refresh_after_unauthorized(rejected_headers)
                    .await
            {
                retried = true;
                continue;
            }
            return Ok(response);
        }
    }
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod tests;
