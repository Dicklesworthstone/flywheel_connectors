//! Best-effort MCP Streamable HTTP session termination.
//!
//! Stop accepting logical work before sending the server's DELETE. A failed,
//! unsupported or timed-out DELETE must never resurrect local session authority
//! or prevent the FCP subprocess from shutting down.

use std::time::Duration;
use super::McpClient;

const TERMINATION_TIMEOUT: Duration = Duration::from_secs(2);

impl McpClient {
    /// Revoke this client's negotiated session locally and attempt to release
    /// the upstream server's session. Stateless MCP servers have nothing to
    /// terminate. A server may reject DELETE with 405; shutdown remains local
    /// and deterministic in all cases.
    ///
    /// This is best effort. Never propagate arbitrary upstream error bodies
    /// during credential rotation or shutdown.
    pub async fn terminate_session(&self) {
        // Drop cached authority *before* any await for network I/O. Do not hold
        // the mutex while waiting for an upstream server that might hang.
        let old = self.session.lock().await.take();
        let Some(session) = old else { return };
        let Some(id) = session.id.as_ref() else { return };
        let request = self.add_auth(self.client.delete(self.rpc_endpoint()))
            .header("Mcp-Session-Id", id)
            .header("MCP-Protocol-Version", super::PROTOCOL_VERSION)
            .header("Accept", "application/json, text/event-stream");
        // The DELETE may not be supported. The local process always revokes
        // authority, and does not retry a potentially state-changing DELETE.
        let _ = fcp_async_core::time::timeout(TERMINATION_TIMEOUT, request.send()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::McpAuth;
    use serde_json::{Value, json};
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    async fn initialized(server: &MockServer, session: Option<&str>) -> McpClient {
        let mut reply = ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0", "id": 0, "result": {
                "protocolVersion": super::super::PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "terminate-test", "version": "1"}
            }
        }));
        if let Some(id) = session {
            reply = reply.insert_header("Mcp-Session-Id", id);
        }
        Mock::given(method("POST")).and(path("/mcp"))
            .and(body_partial_json(json!({"method": "initialize"})))
            .respond_with(reply).mount(server).await;
        Mock::given(method("POST")).and(path("/mcp"))
            .and(body_partial_json(json!({"method": "notifications/initialized"})))
            .respond_with(ResponseTemplate::new(202)).mount(server).await;
        let client = McpClient::new(McpAuth {api_key: Some("private-key".into())}, &server.uri()).unwrap();
        client.initialize().await.unwrap();
        client
    }

    #[fcp_async_core::runtime::test]
    async fn stateful_shutdown_deletes_exact_session_once_with_auth() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE")).and(path("/mcp"))
            .and(header("Mcp-Session-Id", "opaque-session"))
            .and(header("MCP-Protocol-Version", super::super::PROTOCOL_VERSION))
            .and(header("Authorization", "Bearer private-key"))
            .respond_with(ResponseTemplate::new(200)).expect(1).mount(&server).await;
        let client = initialized(&server, Some("opaque-session")).await;
        client.shutdown();
        client.terminate_session().await;
        assert!(client.session.lock().await.is_none());
        client.terminate_session().await;
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.iter().filter(|request| request.method.as_str() == "DELETE").count(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn stateless_shutdown_never_sends_delete() {
        let server = MockServer::start().await;
        let client = initialized(&server, None).await;
        client.shutdown();
        client.terminate_session().await;
        assert!(client.session.lock().await.is_none());
        assert!(server.received_requests().await.unwrap().iter().all(|r| r.method.as_str() != "DELETE"));
    }

    #[fcp_async_core::runtime::test]
    async fn rejected_termination_cannot_resurrect_local_authority() {
        for status in [405, 500] {
            let server = MockServer::start().await;
            Mock::given(method("DELETE")).and(path("/mcp"))
                .respond_with(ResponseTemplate::new(status).set_body_string("sensitive-upstream"))
                .expect(1).mount(&server).await;
            let client = initialized(&server, Some("retire")).await;
            client.shutdown();
            client.terminate_session().await;
            assert!(client.session.lock().await.is_none());
        }
    }

    #[fcp_async_core::runtime::test]
    async fn timed_out_delete_is_bounded_and_local_authority_remains_revoked() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE")).and(path("/mcp"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(&server).await;
        let client = initialized(&server, Some("slow")).await;
        client.shutdown();
        let start = std::time::Instant::now();
        client.terminate_session().await;
        assert!(start.elapsed() < Duration::from_secs(4));
        assert!(client.session.lock().await.is_none());
    }
}
