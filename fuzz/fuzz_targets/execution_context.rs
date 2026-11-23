#![no_main]

//! State-machine fuzz target for `fcp_async_core::ExecutionContext`
//! cancellation + scope propagation.
//!
//! `ExecutionContext` is the cancellation + deadline + scope primitive
//! propagated through async work. Clones share one cancellation scope; child()
//! derives a new scope whose cancellation cannot affect parents or siblings.
//!
//! A regression that broke cancellation propagation would let a
//! cancelled request continue spawning work in its descendants — a
//! compute-exhaustion class of bug.
//!
//! Properties asserted (time-independent):
//!
//!   1. **Initial state**: is_cancelled() == false on a fresh context.
//!   2. **Cancel marks cancelled**: after cancel(), is_cancelled() == true.
//!   3. **Child inheritance**: parent.cancel() → child.is_cancelled()
//!      == true (where child = parent.child()).
//!   4. **Cancellation flows down only**: child.cancel() does NOT
//!      cancel the parent.
//!   5. **Idempotent cancel**: cancel(); cancel(); is_cancelled() == true.
//!   6. **Scope preservation**: child().scope() == parent.scope().
//!   7. **with_deadline doesn't cancel**: a fresh deadline-bearing
//!      context is_cancelled() == false.
//!   8. **request_scoped vs background**: request_scoped has
//!      Some(deadline), background has None.
//!
//!   Once-gated anchors verifying canonical state transitions.

use arbitrary::{Arbitrary, Unstructured};
use fcp_async_core::{ContextScope, ExecutionContext};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;
use std::time::Duration;

static EXEC_CTX_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    /// Whether to start in request-scoped mode (true) or background (false).
    is_request: bool,
    timeout_ms: u32,
    /// Number of children to spawn before potential cancellation.
    child_depth: u8,
    /// Whether to cancel the parent.
    cancel_parent: bool,
}

const MAX_CHILD_DEPTH: usize = 4;

fuzz_target!(|data: &[u8]| {
    EXEC_CTX_ANCHOR.call_once(assert_execution_context_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let timeout = Duration::from_millis(u64::from(input.timeout_ms.max(1)));
    let parent = if input.is_request {
        ExecutionContext::request_scoped(timeout)
    } else {
        ExecutionContext::background()
    };

    // ── PROPERTY 1: initial state ────────────────────────────────────
    assert!(
        !parent.is_cancelled(),
        "fresh context should not be cancelled"
    );

    // ── PROPERTY 7+8: scope/deadline shape ───────────────────────────
    if input.is_request {
        assert_eq!(parent.scope(), ContextScope::Request);
        assert!(
            parent.deadline().is_some(),
            "request_scoped MUST have a deadline"
        );
    } else {
        assert_eq!(parent.scope(), ContextScope::Background);
        assert!(
            parent.deadline().is_none(),
            "background MUST NOT have a deadline by default"
        );
    }

    // Build a chain of children.
    let depth = (input.child_depth as usize) % (MAX_CHILD_DEPTH + 1);
    let mut chain = vec![parent.clone()];
    for _ in 0..depth {
        let next = chain.last().unwrap().child();
        chain.push(next);
    }

    // ── PROPERTY 6: scope preservation through child ─────────────────
    for c in &chain {
        assert_eq!(c.scope(), parent.scope(), "child() did not preserve scope");
    }

    if input.cancel_parent {
        // ── PROPERTY 2: cancel marks cancelled ────────────────────────
        parent.cancel();
        assert!(
            parent.is_cancelled(),
            "after cancel() parent.is_cancelled() should be true"
        );

        // ── PROPERTY 5: idempotent cancel ─────────────────────────────
        parent.cancel();
        assert!(
            parent.is_cancelled(),
            "double-cancel should still report cancelled"
        );

        // ── PROPERTY 3: child inheritance ─────────────────────────────
        for (i, c) in chain.iter().enumerate() {
            assert!(
                c.is_cancelled(),
                "chain[{i}] not cancelled after parent cancel — propagation broken"
            );
        }
    } else if depth > 0 {
        let cancelled_index = (input.timeout_ms as usize % depth) + 1;
        chain[cancelled_index].cancel();
        for (index, context) in chain.iter().enumerate() {
            assert_eq!(
                context.is_cancelled(),
                index >= cancelled_index,
                "cancellation must affect exactly the selected subtree"
            );
        }
        assert!(
            !parent.child().is_cancelled(),
            "a cancelled descendant must not poison future work"
        );
    }
});

/// Once-gated anchors verifying canonical state transitions.
fn assert_execution_context_anchored() {
    // Initial state.
    let parent = ExecutionContext::background();
    assert!(!parent.is_cancelled(), "ANCHOR: fresh context cancelled");

    // Cancel parent then check child.
    let child = parent.child();
    assert!(!child.is_cancelled(), "ANCHOR: fresh child cancelled");
    parent.cancel();
    assert!(parent.is_cancelled(), "ANCHOR: parent.cancel() didn't take");
    assert!(
        child.is_cancelled(),
        "ANCHOR REGRESSION: child not cancelled after parent.cancel()"
    );

    // Property 4: cancellation flows down only; clones still share a scope.
    let parent2 = ExecutionContext::background();
    let child2 = parent2.child();
    let sibling = parent2.child();
    let shared_child = child2.clone();
    shared_child.cancel();
    assert!(child2.is_cancelled(), "ANCHOR: clone cancellation didn't take");
    assert!(
        !parent2.is_cancelled(),
        "ANCHOR: child cancellation must not revoke its parent"
    );
    assert!(
        !sibling.is_cancelled(),
        "ANCHOR: child cancellation must not revoke its sibling"
    );
    assert!(
        !parent2.child().is_cancelled(),
        "ANCHOR: child cancellation must not poison future work"
    );

    // Property 7: request_scoped has deadline.
    let req = ExecutionContext::request_scoped(Duration::from_secs(10));
    assert_eq!(req.scope(), ContextScope::Request);
    assert!(
        req.deadline().is_some(),
        "ANCHOR REGRESSION: request_scoped missing deadline"
    );

    let bg = ExecutionContext::background();
    assert_eq!(bg.scope(), ContextScope::Background);
    assert!(
        bg.deadline().is_none(),
        "ANCHOR REGRESSION: background has unexpected deadline"
    );

    // with_deadline doesn't trigger cancellation.
    let bg_with_dl = bg.with_deadline(Duration::from_secs(5));
    assert!(
        !bg_with_dl.is_cancelled(),
        "ANCHOR: with_deadline triggered cancellation"
    );
    assert!(
        bg_with_dl.deadline().is_some(),
        "ANCHOR: with_deadline didn't set deadline"
    );
}
