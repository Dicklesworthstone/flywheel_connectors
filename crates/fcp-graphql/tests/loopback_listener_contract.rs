//! Pins the loopback primitive that `tests/client.rs`'s subscription servers
//! are built on (br-4h5ph).
//!
//! Two subscription tests in this crate fail reproducibly, and the obvious
//! suspect was the harness shape: they are the only loopback servers in the
//! workspace built on an async `fcp_async_core::net::TcpListener` inside a
//! `task::spawn`, where every loopback test that PASSES (`fcp-streaming`'s
//! `e2e_sse_reconnect_storm`, and its websocket tests, which alias
//! `StdTcpListener` explicitly) uses a blocking `std::net::TcpListener` on a
//! real thread.
//!
//! This test exists because that hypothesis is WRONG, and it is worth keeping
//! wrong-ness pinned so the next investigation does not re-derive it: an async
//! listener inside a spawned task accepts a second connection after the first
//! closes, exactly as the reconnect test requires. Whatever breaks those two
//! tests is above the TCP layer, not in this primitive.

use std::time::Duration;

use fcp_async_core::net::{TcpListener, TcpStream};
use fcp_async_core::{task, time};

#[fcp_async_core::runtime::test]
async fn async_listener_accepts_a_second_connection_after_the_first_closes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();

    let server = task::spawn(async move {
        let mut accepted = 0usize;
        for _ in 0..2 {
            let (stream, _) = listener.accept().await.expect("accept");
            accepted += 1;
            drop(stream); // close, then loop back to accept()
        }
        accepted
    });

    // First connection, then close it.
    let first = TcpStream::connect(addr.clone())
        .await
        .expect("first connect");
    drop(first);

    // Give the server a moment to loop back to accept(), exactly as the
    // subscription client's 20ms reconnect delay would.
    time::sleep(Duration::from_millis(50)).await;

    let second = TcpStream::connect(addr.clone()).await;
    assert!(
        second.is_ok(),
        "second connect to the SAME still-listening async listener failed: {:?}",
        second.err()
    );
    drop(second);

    let accepted = server.await.expect("server task");
    assert_eq!(accepted, 2, "server should have accepted both connections");
}
