//! Best-effort MCP Streamable HTTP session termination.
//!
//! Local admission closes synchronously, before the returned cleanup future is
//! polled. Remote DELETE is optional cleanup, not evidence that external effects
//! were rolled back or that the server cancelled every outstanding operation.

use std::future::Future;
use std::time::{Duration, Instant};

use super::McpClient;

const TERMINATION_TIMEOUT: Duration = Duration::from_secs(2);

impl McpClient {
    /// Permanently stop this client and attempt to release its upstream session.
    ///
    /// Calling this method closes admission and cancels the client's existing
    /// request contexts immediately, even if the returned future is never
    /// polled or is dropped. Await it to attempt best-effort remote cleanup.
    /// Create a new client to reconnect after termination.
    ///
    /// A single two-second budget, measured from this call, covers waiting for
    /// the session mutex and sending DELETE. No mutex is held during network
    /// I/O. Concurrent/repeated calls cannot delete the same cached session
    /// twice. Stateless servers have nothing to delete; HTTP 405 and other
    /// failures cannot reopen the client or block shutdown indefinitely.
    ///
    /// If cleanup is cancelled or cannot acquire the mutex before its deadline,
    /// cached session metadata may remain until a later cleanup attempt or Drop.
    /// The cancelled runtime still denies its use. No detached cleanup is spawned,
    /// no remote error body is exposed, and DELETE is never retried automatically.
    pub fn terminate_session(&self) -> impl Future<Output = ()> + '_ {
        self.terminate_session_with_timeout(TERMINATION_TIMEOUT)
    }

    fn terminate_session_with_timeout(&self, budget: Duration) -> impl Future<Output = ()> + '_ {
        // Do not move this into the async block: shutdown must not depend on
        // whether a caller polls (or even retains) the cleanup future.
        self.shutdown();
        let started = Instant::now();
        async move {
            let remaining = budget.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return;
            }
            let cleanup = async {
                let old = self.session.lock().await.take();
                // A ready lock acquisition can finish after the budget without
                // giving the timer another poll. Do not start late network work.
                if started.elapsed() >= budget {
                    return;
                }
                let Some(session) = old else { return };
                let Some(id) = session.id.as_ref() else { return };
                let request = self.add_auth(self.client.delete(self.rpc_endpoint()))
                    .header("Mcp-Session-Id", id)
                    .header("MCP-Protocol-Version", super::PROTOCOL_VERSION)
                    .header("Accept", "application/json, text/event-stream");
                // Do not use a request context from the now-cancelled runtime.
                // This owned cleanup has its own bounded grace period, never
                // an unbounded task or an automatic replay of a DELETE.
                let _ = request.send().await;
            };
            let _ = fcp_async_core::time::timeout(remaining, cleanup).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;
    use std::task::Poll;

    use super::*;
    use crate::client::McpAuth;
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
        let start = Instant::now();
        client.terminate_session().await;
        assert!(start.elapsed() < Duration::from_secs(4));
        assert!(client.session.lock().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn unpolled_termination_closes_admission_without_sending_network_work() {
        let server = MockServer::start().await;
        let client = initialized(&server, Some("unpolled")).await;
        let cleanup = client.terminate_session();
        assert!(client.runtime.is_shutting_down());
        drop(cleanup);
        assert!(client.initialize().await.is_err());
        assert!(client.tools_list().await.is_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn termination_is_a_permanent_close_without_a_separate_shutdown_call() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(204)).expect(1).mount(&server).await;
        let client = initialized(&server, Some("closed")).await;
        client.terminate_session().await;
        assert!(client.runtime.is_shutting_down());
        assert!(client.initialize().await.is_err());
        assert!(client.rpc_call("ping", json!({})).await.is_err());
        assert!(client.session.lock().await.is_none());
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[fcp_async_core::runtime::test]
    async fn held_session_mutex_is_inside_the_cleanup_deadline() {
        let server = MockServer::start().await;
        let client = initialized(&server, Some("contended")).await;
        let guard = client.session.lock().await;
        fcp_async_core::time::timeout(
            Duration::from_secs(1),
            client.terminate_session_with_timeout(Duration::from_millis(10)),
        ).await.expect("cleanup must not wait indefinitely for its session mutex");
        assert!(client.runtime.is_shutting_down());
        assert!(guard.is_some(), "the lock owner still owns the old metadata");
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
        drop(guard);
        assert!(client.initialize().await.is_err());
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(204)).expect(1).mount(&server).await;
        client.terminate_session().await;
        assert!(client.session.lock().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn delayed_first_poll_does_not_reset_the_cleanup_budget() {
        let server = MockServer::start().await;
        let client = initialized(&server, Some("delayed")).await;
        let cleanup = client.terminate_session_with_timeout(Duration::from_millis(10));
        fcp_async_core::time::sleep(Duration::from_millis(30)).await;
        cleanup.await;
        assert!(client.runtime.is_shutting_down());
        assert!(client.initialize().await.is_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn concurrent_termination_consumes_one_session_without_duplicate_delete() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(204).set_delay(Duration::from_millis(20)))
            .expect(1).mount(&server).await;
        let client = initialized(&server, Some("shared")).await;
        let mut cleanups: Vec<_> = (0..8)
            .map(|_| Some(Box::pin(client.terminate_session())))
            .collect();
        poll_fn(|cx| {
            for cleanup in &mut cleanups {
                if cleanup.as_mut().is_some_and(|future| future.as_mut().poll(cx).is_ready()) {
                    *cleanup = None;
                }
            }
            if cleanups.iter().all(Option::is_none) { Poll::Ready(()) } else { Poll::Pending }
        }).await;
        assert!(client.session.lock().await.is_none());
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[fcp_async_core::runtime::test]
    async fn cancelling_cleanup_cannot_reopen_admission_or_spawn_a_delete() {
        let server = MockServer::start().await;
        let client = initialized(&server, Some("cancelled-cleanup")).await;
        let guard = client.session.lock().await;
        let mut cleanup = Box::pin(client.terminate_session());
        poll_fn(|cx| {
            assert!(cleanup.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        }).await;
        drop(cleanup);
        drop(guard);
        assert!(client.runtime.is_shutting_down());
        assert!(client.tools_list().await.is_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn closing_one_client_does_not_cancel_a_replacement_client() {
        let server = MockServer::start().await;
        let old = initialized(&server, Some("generation")).await;
        let replacement = McpClient::new(McpAuth { api_key: None }, &server.uri()).unwrap();
        drop(old.terminate_session());
        assert!(old.runtime.is_shutting_down());
        assert!(!replacement.runtime.is_shutting_down());
        replacement.initialize().await.unwrap();
        assert!(!replacement.runtime.is_shutting_down());
        assert_eq!(server.received_requests().await.unwrap().len(), 4);
    }
}
