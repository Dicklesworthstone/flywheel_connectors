//! Pagination helpers for GraphQL APIs.

use std::future::Future;

use thiserror::Error;

use crate::error::GraphqlClientError;

/// Cursor-based page info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorPageInfo {
    /// Whether there is another page.
    pub has_next_page: bool,
    /// Cursor for the next page.
    pub end_cursor: Option<String>,
    /// Optional total count.
    pub total_count: Option<u64>,
}

/// Cursor-based page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorPage<T> {
    /// Items in the page.
    pub items: Vec<T>,
    /// Pagination info.
    pub page_info: CursorPageInfo,
}

/// Offset-based page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffsetPage<T> {
    /// Items in the page.
    pub items: Vec<T>,
    /// Offset of the next page.
    pub next_offset: Option<u64>,
    /// Optional total count.
    pub total_count: Option<u64>,
}

/// Page limit configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageLimit {
    /// Maximum number of items to fetch.
    pub max_items: usize,
}

impl PageLimit {
    /// Create a new limit.
    #[must_use]
    pub const fn new(max_items: usize) -> Self {
        Self { max_items }
    }
}

/// Pagination error type.
#[derive(Debug, Error)]
pub enum PaginationError {
    /// Underlying client error.
    #[error("pagination fetch failed: {0}")]
    Client(#[from] GraphqlClientError),

    /// Pagination limit exceeded.
    #[error("pagination limit exceeded: {0}")]
    LimitExceeded(String),

    /// The server kept claiming more pages without ever advancing.
    #[error("pagination stalled: {0}")]
    Stalled(String),
}

/// Hard ceiling on pages fetched by a single pagination call.
///
/// The item limit alone cannot bound the loop. A server answering
/// `hasNextPage: true` with an EMPTY `items` array never advances `out.len()`,
/// so `remaining` never shrinks and the loop spins forever issuing requests;
/// with `limit: None` even non-empty pages are unbounded and end in OOM. This
/// is the backstop for the case the cursor/offset advancement check below
/// cannot see — a server that dutifully returns a *new* cursor every time but
/// never actually terminates.
const MAX_PAGES: usize = 10_000;

/// Paginate a cursor-based API.
pub async fn paginate_cursor<T, F, Fut>(
    mut cursor: Option<String>,
    limit: Option<PageLimit>,
    mut fetch_page: F,
) -> Result<Vec<T>, PaginationError>
where
    F: FnMut(Option<String>) -> Fut,
    Fut: Future<Output = Result<CursorPage<T>, GraphqlClientError>>,
{
    let mut out = Vec::new();
    let max_items = limit.map(|limit| limit.max_items);
    let mut pages = 0usize;
    loop {
        if let Some(max_items) = max_items {
            if out.len() >= max_items {
                return Err(PaginationError::LimitExceeded(
                    "page limit reached".to_string(),
                ));
            }
        }

        pages = pages.saturating_add(1);
        if pages > MAX_PAGES {
            return Err(PaginationError::Stalled(format!(
                "exceeded {MAX_PAGES} pages without reaching the end of the connection"
            )));
        }

        let page = fetch_page(cursor.clone()).await?;
        let remaining = max_items.map(|max_items| max_items.saturating_sub(out.len()));
        if let Some(remaining) = remaining {
            if remaining == 0 {
                return Err(PaginationError::LimitExceeded(
                    "page limit reached".to_string(),
                ));
            }
            if page.items.len() > remaining {
                out.extend(page.items.into_iter().take(remaining));
                return Err(PaginationError::LimitExceeded(
                    "page limit reached".to_string(),
                ));
            }
        }
        out.extend(page.items);

        if !page.page_info.has_next_page {
            break;
        }
        let next_cursor = page.page_info.end_cursor;
        if next_cursor.is_none() {
            break;
        }
        // A server that hands back the SAME cursor it was just given is not
        // advancing: the next request would be byte-identical to this one, so
        // the loop can only spin. Refuse rather than hang.
        if next_cursor == cursor {
            return Err(PaginationError::Stalled(
                "server returned the same end_cursor it was given".to_string(),
            ));
        }
        cursor = next_cursor;
    }

    Ok(out)
}

/// Paginate an offset-based API.
#[allow(clippy::missing_errors_doc)]
pub async fn paginate_offset<T, F, Fut>(
    mut offset: u64,
    limit: Option<PageLimit>,
    mut fetch_page: F,
) -> Result<Vec<T>, PaginationError>
where
    F: FnMut(u64) -> Fut,
    Fut: Future<Output = Result<OffsetPage<T>, GraphqlClientError>>,
{
    let mut out = Vec::new();
    let max_items = limit.map(|limit| limit.max_items);
    let mut pages = 0usize;
    loop {
        if let Some(max_items) = max_items {
            if out.len() >= max_items {
                return Err(PaginationError::LimitExceeded(
                    "page limit reached".to_string(),
                ));
            }
        }

        pages = pages.saturating_add(1);
        if pages > MAX_PAGES {
            return Err(PaginationError::Stalled(format!(
                "exceeded {MAX_PAGES} pages without reaching the end of the collection"
            )));
        }

        let page = fetch_page(offset).await?;
        let remaining = max_items.map(|max_items| max_items.saturating_sub(out.len()));
        if let Some(remaining) = remaining {
            if remaining == 0 {
                return Err(PaginationError::LimitExceeded(
                    "page limit reached".to_string(),
                ));
            }
            if page.items.len() > remaining {
                out.extend(page.items.into_iter().take(remaining));
                return Err(PaginationError::LimitExceeded(
                    "page limit reached".to_string(),
                ));
            }
        }
        out.extend(page.items);

        match page.next_offset {
            // The offset must strictly increase. A repeated (or rewound)
            // offset means the next request is one already made, so the loop
            // can only spin.
            Some(next) if next <= offset => {
                return Err(PaginationError::Stalled(format!(
                    "server returned next_offset {next} which does not advance past {offset}"
                )));
            }
            Some(next) => offset = next,
            None => break,
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- PageLimit ----

    #[test]
    fn page_limit_new() {
        let limit = PageLimit::new(100);
        assert_eq!(limit.max_items, 100);
    }

    #[test]
    fn page_limit_eq() {
        assert_eq!(PageLimit::new(10), PageLimit::new(10));
        assert_ne!(PageLimit::new(10), PageLimit::new(20));
    }

    // ---- CursorPageInfo ----

    #[test]
    fn cursor_page_info_clone_eq() {
        let info = CursorPageInfo {
            has_next_page: true,
            end_cursor: Some("abc".into()),
            total_count: Some(42),
        };
        let cloned = info.clone();
        assert_eq!(info, cloned);
    }

    // ---- CursorPage ----

    #[test]
    fn cursor_page_clone_eq() {
        let page = CursorPage {
            items: vec![1, 2, 3],
            page_info: CursorPageInfo {
                has_next_page: false,
                end_cursor: None,
                total_count: Some(3),
            },
        };
        let cloned = page.clone();
        assert_eq!(page, cloned);
    }

    // ---- OffsetPage ----

    #[test]
    fn offset_page_clone_eq() {
        let page = OffsetPage {
            items: vec!["a", "b"],
            next_offset: Some(10),
            total_count: None,
        };
        let cloned = page.clone();
        assert_eq!(page, cloned);
    }

    // ---- PaginationError ----

    #[test]
    fn pagination_error_display_limit() {
        let err = PaginationError::LimitExceeded("too many".into());
        assert!(err.to_string().contains("too many"));
    }

    #[test]
    fn pagination_error_from_client_error() {
        let client_err = GraphqlClientError::Json("bad".into());
        let err: PaginationError = client_err.into();
        assert!(err.to_string().contains("pagination fetch"));
    }

    #[test]
    fn page_limit_copy_clone() {
        let limit = PageLimit::new(50);
        let copied = limit;
        let also_copied = limit;
        assert_eq!(copied, also_copied);
    }

    #[test]
    fn page_limit_debug() {
        let limit = PageLimit::new(42);
        let debug = format!("{limit:?}");
        assert!(debug.contains("42"));
    }

    #[test]
    fn cursor_page_info_no_next_page() {
        let info = CursorPageInfo {
            has_next_page: false,
            end_cursor: None,
            total_count: None,
        };
        assert!(!info.has_next_page);
        assert!(info.end_cursor.is_none());
        assert!(info.total_count.is_none());
    }

    #[test]
    fn cursor_page_info_inequality() {
        let a = CursorPageInfo {
            has_next_page: true,
            end_cursor: Some("a".into()),
            total_count: None,
        };
        let b = CursorPageInfo {
            has_next_page: false,
            end_cursor: None,
            total_count: None,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn cursor_page_empty_items() {
        let page: CursorPage<i32> = CursorPage {
            items: vec![],
            page_info: CursorPageInfo {
                has_next_page: false,
                end_cursor: None,
                total_count: Some(0),
            },
        };
        assert!(page.items.is_empty());
        assert_eq!(page.page_info.total_count, Some(0));
    }

    #[test]
    fn offset_page_no_next() {
        let page: OffsetPage<&str> = OffsetPage {
            items: vec!["x"],
            next_offset: None,
            total_count: Some(1),
        };
        assert!(page.next_offset.is_none());
    }

    #[test]
    fn offset_page_inequality() {
        let a: OffsetPage<i32> = OffsetPage {
            items: vec![1],
            next_offset: Some(10),
            total_count: None,
        };
        let b: OffsetPage<i32> = OffsetPage {
            items: vec![2],
            next_offset: Some(10),
            total_count: None,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn pagination_error_debug() {
        let err = PaginationError::LimitExceeded("test".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("LimitExceeded"));
    }

    #[test]
    fn pagination_error_implements_error() {
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&PaginationError::LimitExceeded("x".into()));
    }

    #[fcp_async_core::runtime::test]
    async fn paginate_cursor_single_page() {
        let items = paginate_cursor(None, None, |_cursor| async {
            Ok(CursorPage {
                items: vec![1, 2, 3],
                page_info: CursorPageInfo {
                    has_next_page: false,
                    end_cursor: None,
                    total_count: Some(3),
                },
            })
        })
        .await
        .unwrap();
        assert_eq!(items, vec![1, 2, 3]);
    }

    #[fcp_async_core::runtime::test]
    async fn paginate_cursor_multi_page() {
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let cc = call_count.clone();

        let items = paginate_cursor(None, None, move |cursor| {
            let cc = cc.clone();
            async move {
                let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if n == 0 {
                    Ok(CursorPage {
                        items: vec![1, 2],
                        page_info: CursorPageInfo {
                            has_next_page: true,
                            end_cursor: Some("c1".into()),
                            total_count: None,
                        },
                    })
                } else {
                    assert_eq!(cursor, Some("c1".to_string()));
                    Ok(CursorPage {
                        items: vec![3],
                        page_info: CursorPageInfo {
                            has_next_page: false,
                            end_cursor: None,
                            total_count: None,
                        },
                    })
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(items, vec![1, 2, 3]);
    }

    #[fcp_async_core::runtime::test]
    async fn paginate_cursor_with_limit() {
        let result: Result<Vec<i32>, _> =
            paginate_cursor(None, Some(PageLimit::new(2)), |_cursor| async {
                Ok(CursorPage {
                    items: vec![1, 2, 3, 4, 5],
                    page_info: CursorPageInfo {
                        has_next_page: true,
                        end_cursor: Some("c".into()),
                        total_count: None,
                    },
                })
            })
            .await;
        assert!(matches!(result, Err(PaginationError::LimitExceeded(_))));
    }

    #[fcp_async_core::runtime::test]
    async fn paginate_offset_single_page() {
        let items = paginate_offset(0, None, |_offset| async {
            Ok(OffsetPage {
                items: vec!["a", "b"],
                next_offset: None,
                total_count: Some(2),
            })
        })
        .await
        .unwrap();
        assert_eq!(items, vec!["a", "b"]);
    }

    #[fcp_async_core::runtime::test]
    async fn paginate_offset_multi_page() {
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let cc = call_count.clone();

        let items = paginate_offset(0, None, move |offset| {
            let cc = cc.clone();
            async move {
                let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if n == 0 {
                    assert_eq!(offset, 0);
                    Ok(OffsetPage {
                        items: vec![10, 20],
                        next_offset: Some(2),
                        total_count: None,
                    })
                } else {
                    assert_eq!(offset, 2);
                    Ok(OffsetPage {
                        items: vec![30],
                        next_offset: None,
                        total_count: None,
                    })
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(items, vec![10, 20, 30]);
    }

    // ── Additional async pagination tests ──

    #[fcp_async_core::runtime::test]
    async fn paginate_offset_with_limit() {
        let result: Result<Vec<i32>, _> =
            paginate_offset(0, Some(PageLimit::new(2)), |_offset| async {
                Ok(OffsetPage {
                    items: vec![1, 2, 3, 4, 5],
                    next_offset: Some(5),
                    total_count: None,
                })
            })
            .await;
        assert!(matches!(result, Err(PaginationError::LimitExceeded(_))));
    }

    /// A server that keeps claiming `hasNextPage: true` while handing back the
    /// SAME cursor never advances, and `out.len()` never grows — so the item
    /// limit provides no protection and the loop spins forever issuing
    /// requests. Must terminate with a typed error instead.
    #[fcp_async_core::runtime::test]
    async fn paginate_cursor_refuses_a_non_advancing_cursor() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = std::sync::Arc::clone(&calls);
        let result: Result<Vec<i32>, _> = paginate_cursor(None, None, move |_cursor| {
            let seen = std::sync::Arc::clone(&seen);
            async move {
                seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(CursorPage {
                    items: Vec::new(),
                    page_info: CursorPageInfo {
                        has_next_page: true,
                        end_cursor: Some("stuck".to_string()),
                        total_count: None,
                    },
                })
            }
        })
        .await;

        assert!(
            matches!(result, Err(PaginationError::Stalled(_))),
            "expected Stalled, got {result:?}"
        );
        // First call gets `None`, second is handed "stuck" back — the repeat is
        // detected there, so this terminates immediately rather than at MAX_PAGES.
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    /// Same shape on the offset API: an offset that does not strictly increase
    /// means the next request is one already made.
    #[fcp_async_core::runtime::test]
    async fn paginate_offset_refuses_a_non_advancing_offset() {
        let result: Result<Vec<i32>, _> = paginate_offset(0, None, |_offset| async {
            Ok(OffsetPage {
                items: vec![1],
                next_offset: Some(0),
                total_count: None,
            })
        })
        .await;
        assert!(
            matches!(result, Err(PaginationError::Stalled(_))),
            "expected Stalled, got {result:?}"
        );
    }

    /// Even a server that returns a genuinely NEW cursor every time must not be
    /// able to run the loop unboundedly — the advancement check cannot see that
    /// case, so the page ceiling is the backstop.
    #[fcp_async_core::runtime::test]
    async fn paginate_cursor_stops_at_the_page_ceiling() {
        let page = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&page);
        let result: Result<Vec<i32>, _> = paginate_cursor(None, None, move |_cursor| {
            let counter = std::sync::Arc::clone(&counter);
            async move {
                let n = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(CursorPage {
                    items: Vec::new(),
                    page_info: CursorPageInfo {
                        has_next_page: true,
                        end_cursor: Some(format!("cursor-{n}")),
                        total_count: None,
                    },
                })
            }
        })
        .await;

        assert!(
            matches!(result, Err(PaginationError::Stalled(_))),
            "expected Stalled, got {result:?}"
        );
        assert_eq!(page.load(std::sync::atomic::Ordering::Relaxed), MAX_PAGES);
    }

    #[fcp_async_core::runtime::test]
    async fn paginate_cursor_empty_single_page() {
        let items: Vec<i32> = paginate_cursor(None, None, |_cursor| async {
            Ok(CursorPage {
                items: vec![],
                page_info: CursorPageInfo {
                    has_next_page: false,
                    end_cursor: None,
                    total_count: Some(0),
                },
            })
        })
        .await
        .unwrap();
        assert!(items.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn paginate_offset_empty_single_page() {
        let items: Vec<i32> = paginate_offset(0, None, |_offset| async {
            Ok(OffsetPage {
                items: vec![],
                next_offset: None,
                total_count: Some(0),
            })
        })
        .await
        .unwrap();
        assert!(items.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn paginate_cursor_stops_when_end_cursor_is_none() {
        // has_next_page = true but end_cursor = None → should stop
        let items = paginate_cursor(None, None, |_cursor| async {
            Ok(CursorPage {
                items: vec![1, 2],
                page_info: CursorPageInfo {
                    has_next_page: true,
                    end_cursor: None,
                    total_count: None,
                },
            })
        })
        .await
        .unwrap();
        assert_eq!(items, vec![1, 2]);
    }

    #[fcp_async_core::runtime::test]
    async fn paginate_cursor_with_initial_cursor() {
        let items = paginate_cursor(Some("start".into()), None, |cursor| async move {
            assert_eq!(cursor, Some("start".to_string()));
            Ok(CursorPage {
                items: vec![10, 20],
                page_info: CursorPageInfo {
                    has_next_page: false,
                    end_cursor: None,
                    total_count: None,
                },
            })
        })
        .await
        .unwrap();
        assert_eq!(items, vec![10, 20]);
    }

    #[fcp_async_core::runtime::test]
    async fn paginate_offset_with_initial_offset() {
        let items = paginate_offset(100, None, |offset| async move {
            assert_eq!(offset, 100);
            Ok(OffsetPage {
                items: vec![101, 102],
                next_offset: None,
                total_count: None,
            })
        })
        .await
        .unwrap();
        assert_eq!(items, vec![101, 102]);
    }

    #[fcp_async_core::runtime::test]
    async fn paginate_cursor_limit_exact_fit() {
        // Page returns exactly max_items — should succeed without error
        let items = paginate_cursor(None, Some(PageLimit::new(3)), |_cursor| async {
            Ok(CursorPage {
                items: vec![1, 2, 3],
                page_info: CursorPageInfo {
                    has_next_page: false,
                    end_cursor: None,
                    total_count: None,
                },
            })
        })
        .await
        .unwrap();
        assert_eq!(items, vec![1, 2, 3]);
    }

    #[fcp_async_core::runtime::test]
    async fn paginate_offset_limit_exact_fit() {
        let items = paginate_offset(0, Some(PageLimit::new(2)), |_offset| async {
            Ok(OffsetPage {
                items: vec![1, 2],
                next_offset: None,
                total_count: None,
            })
        })
        .await
        .unwrap();
        assert_eq!(items, vec![1, 2]);
    }

    // ---- PageLimit additional tests ----

    #[test]
    fn page_limit_zero() {
        let limit = PageLimit::new(0);
        assert_eq!(limit.max_items, 0);
    }

    #[test]
    fn page_limit_large_value() {
        let limit = PageLimit::new(usize::MAX);
        assert_eq!(limit.max_items, usize::MAX);
    }

    // ---- CursorPageInfo additional tests ----

    #[test]
    fn cursor_page_info_debug() {
        let info = CursorPageInfo {
            has_next_page: true,
            end_cursor: Some("cursor_abc".into()),
            total_count: Some(100),
        };
        let dbg = format!("{info:?}");
        assert!(dbg.contains("CursorPageInfo"));
        assert!(dbg.contains("cursor_abc"));
    }

    #[test]
    fn cursor_page_info_with_all_none() {
        let info = CursorPageInfo {
            has_next_page: false,
            end_cursor: None,
            total_count: None,
        };
        let cloned = info.clone();
        assert_eq!(info, cloned);
        assert!(!info.has_next_page);
    }

    // ---- CursorPage additional tests ----

    #[test]
    fn cursor_page_debug() {
        let page = CursorPage {
            items: vec![1, 2, 3],
            page_info: CursorPageInfo {
                has_next_page: false,
                end_cursor: None,
                total_count: None,
            },
        };
        let dbg = format!("{page:?}");
        assert!(dbg.contains("CursorPage"));
    }

    #[test]
    fn cursor_page_with_string_items() {
        let page = CursorPage {
            items: vec!["alpha".to_string(), "beta".to_string()],
            page_info: CursorPageInfo {
                has_next_page: true,
                end_cursor: Some("cursor2".into()),
                total_count: Some(10),
            },
        };
        let cloned = page.clone();
        assert_eq!(page.items.len(), cloned.items.len());
        assert_eq!(page, cloned);
    }

    // ---- OffsetPage additional tests ----

    #[test]
    fn offset_page_debug() {
        let page: OffsetPage<i32> = OffsetPage {
            items: vec![10, 20],
            next_offset: Some(2),
            total_count: Some(100),
        };
        let dbg = format!("{page:?}");
        assert!(dbg.contains("OffsetPage"));
    }

    #[test]
    fn offset_page_empty() {
        let page: OffsetPage<String> = OffsetPage {
            items: vec![],
            next_offset: None,
            total_count: Some(0),
        };
        assert!(page.items.is_empty());
        assert_eq!(page.total_count, Some(0));
    }

    #[test]
    fn offset_page_clone() {
        let page = OffsetPage {
            items: vec![1, 2, 3],
            next_offset: Some(3),
            total_count: Some(10),
        };
        let cloned = page.clone();
        assert_eq!(page, cloned);
        assert_eq!(page.items.len(), 3);
    }

    // ---- PaginationError additional tests ----

    #[test]
    fn pagination_error_display_client() {
        let client_err = GraphqlClientError::Protocol {
            message: "broken".into(),
        };
        let err: PaginationError = client_err.into();
        let msg = err.to_string();
        assert!(msg.contains("pagination fetch"));
    }

    #[test]
    fn pagination_error_from_json_error() {
        let client_err = GraphqlClientError::Json("bad json".into());
        let err: PaginationError = client_err.into();
        assert!(err.to_string().contains("pagination fetch"));
    }

    // ---- PageLimit edge cases ----

    #[test]
    fn page_limit_one() {
        let limit = PageLimit::new(1);
        assert_eq!(limit.max_items, 1);
    }

    // ---- CursorPageInfo edge cases ----

    #[test]
    fn cursor_page_info_with_empty_cursor() {
        let info = CursorPageInfo {
            has_next_page: true,
            end_cursor: Some(String::new()),
            total_count: None,
        };
        assert_eq!(info.end_cursor.as_deref(), Some(""));
    }

    #[test]
    fn cursor_page_info_large_total_count() {
        let info = CursorPageInfo {
            has_next_page: false,
            end_cursor: None,
            total_count: Some(u64::MAX),
        };
        assert_eq!(info.total_count, Some(u64::MAX));
    }

    #[test]
    fn cursor_page_info_zero_total_count() {
        let info = CursorPageInfo {
            has_next_page: false,
            end_cursor: None,
            total_count: Some(0),
        };
        assert_eq!(info.total_count, Some(0));
    }

    // ---- OffsetPage edge cases ----

    #[test]
    fn offset_page_large_next_offset() {
        let page: OffsetPage<i32> = OffsetPage {
            items: vec![1],
            next_offset: Some(u64::MAX),
            total_count: None,
        };
        assert_eq!(page.next_offset, Some(u64::MAX));
    }

    #[test]
    fn offset_page_zero_next_offset() {
        let page: OffsetPage<i32> = OffsetPage {
            items: vec![],
            next_offset: Some(0),
            total_count: None,
        };
        assert_eq!(page.next_offset, Some(0));
    }

    // ---- PaginationError additional tests ----

    #[test]
    fn pagination_error_limit_exceeded_display() {
        let err = PaginationError::LimitExceeded("max 100 items".into());
        let msg = err.to_string();
        assert!(msg.contains("pagination limit exceeded"));
        assert!(msg.contains("max 100 items"));
    }

    #[test]
    fn pagination_error_from_http_error() {
        let client_err = GraphqlClientError::Http(crate::error::HttpErrorInfo {
            message: "timeout".into(),
            status_code: None,
            is_timeout: true,
            is_connect: false,
            is_request: false,
        });
        let err: PaginationError = client_err.into();
        assert!(err.to_string().contains("pagination fetch"));
    }

    #[test]
    fn pagination_error_from_protocol_error() {
        let client_err = GraphqlClientError::Protocol {
            message: "broken".into(),
        };
        let err: PaginationError = client_err.into();
        assert!(err.to_string().contains("pagination fetch"));
    }

    #[test]
    fn pagination_error_debug_client_variant() {
        let client_err = GraphqlClientError::Json("parse error".into());
        let err: PaginationError = client_err.into();
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Client"));
    }

    // ---- CursorPage with different item types ----

    #[test]
    fn cursor_page_with_float_items() {
        let page = CursorPage {
            items: vec![1.5_f64, 2.5, 3.5],
            page_info: CursorPageInfo {
                has_next_page: false,
                end_cursor: None,
                total_count: None,
            },
        };
        assert_eq!(page.items.len(), 3);
    }

    #[test]
    fn cursor_page_with_bool_items() {
        let page = CursorPage {
            items: vec![true, false, true],
            page_info: CursorPageInfo {
                has_next_page: false,
                end_cursor: None,
                total_count: Some(3),
            },
        };
        assert_eq!(page.items.len(), 3);
    }

    // ---- OffsetPage with different item types ----

    #[test]
    fn offset_page_with_tuple_items() {
        let page = OffsetPage {
            items: vec![(1, "a"), (2, "b")],
            next_offset: None,
            total_count: None,
        };
        assert_eq!(page.items[0].0, 1);
        assert_eq!(page.items[1].1, "b");
    }

    // ---- CursorPageInfo: clone and use original ----

    #[test]
    fn cursor_page_info_clone_and_use_original() {
        let info = CursorPageInfo {
            has_next_page: true,
            end_cursor: Some("cursor_xyz".into()),
            total_count: Some(500),
        };
        let cloned = info.clone();
        assert_eq!(cloned.end_cursor.as_deref(), Some("cursor_xyz"));
        assert!(info.has_next_page);
        assert_eq!(info.total_count, Some(500));
    }

    // ---- CursorPage: many items ----

    #[test]
    fn cursor_page_large_item_count() {
        let items: Vec<i32> = (0..1000).collect();
        let page = CursorPage {
            items,
            page_info: CursorPageInfo {
                has_next_page: true,
                end_cursor: Some("c1000".into()),
                total_count: Some(5000),
            },
        };
        assert_eq!(page.items.len(), 1000);
        assert_eq!(page.page_info.total_count, Some(5000));
    }

    // ---- OffsetPage: clone and use original ----

    #[test]
    fn offset_page_clone_and_use_original() {
        let page = OffsetPage {
            items: vec!["alpha", "beta", "gamma"],
            next_offset: Some(3),
            total_count: Some(10),
        };
        let cloned = page.clone();
        assert_eq!(cloned.items.len(), 3);
        assert_eq!(page.next_offset, Some(3));
        assert_eq!(page.total_count, Some(10));
    }

    // ---- OffsetPage: large item count ----

    #[test]
    fn offset_page_large_item_count() {
        let items: Vec<u64> = (0..500).collect();
        let page = OffsetPage {
            items,
            next_offset: Some(500),
            total_count: Some(2000),
        };
        assert_eq!(page.items.len(), 500);
    }

    // ---- PaginationError: Display and Debug for both variants ----

    #[test]
    fn pagination_error_client_variant_display() {
        let client_err = GraphqlClientError::Http(crate::error::HttpErrorInfo {
            message: "conn refused".into(),
            status_code: None,
            is_timeout: false,
            is_connect: true,
            is_request: false,
        });
        let err: PaginationError = client_err.into();
        let msg = err.to_string();
        assert!(msg.contains("pagination fetch failed"));
    }

    #[test]
    fn pagination_error_limit_exceeded_debug() {
        let err = PaginationError::LimitExceeded("overflow".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("LimitExceeded"));
        assert!(dbg.contains("overflow"));
    }

    // ---- PageLimit: debug format details ----

    #[test]
    fn page_limit_debug_shows_field() {
        let limit = PageLimit::new(250);
        let dbg = format!("{limit:?}");
        assert!(dbg.contains("max_items"));
        assert!(dbg.contains("250"));
    }

    // ---- CursorPageInfo: unicode cursor ----

    #[test]
    fn cursor_page_info_unicode_cursor() {
        let info = CursorPageInfo {
            has_next_page: true,
            end_cursor: Some("Zeiger-nach-rechts".into()),
            total_count: None,
        };
        assert_eq!(info.end_cursor.as_deref(), Some("Zeiger-nach-rechts"));
    }

    // ---- OffsetPage: total_count with max value ----

    #[test]
    fn offset_page_max_total_count() {
        let page: OffsetPage<u8> = OffsetPage {
            items: vec![],
            next_offset: None,
            total_count: Some(u64::MAX),
        };
        assert_eq!(page.total_count, Some(u64::MAX));
    }

    // ---- CursorPage: equality with different items ----

    #[test]
    fn cursor_page_inequality_by_items() {
        let a = CursorPage {
            items: vec![1, 2],
            page_info: CursorPageInfo {
                has_next_page: false,
                end_cursor: None,
                total_count: None,
            },
        };
        let b = CursorPage {
            items: vec![3, 4],
            page_info: CursorPageInfo {
                has_next_page: false,
                end_cursor: None,
                total_count: None,
            },
        };
        assert_ne!(a, b);
    }

    // ---- OffsetPage: equality with different next_offset ----

    #[test]
    fn offset_page_inequality_by_next_offset() {
        let a: OffsetPage<i32> = OffsetPage {
            items: vec![1],
            next_offset: Some(10),
            total_count: None,
        };
        let b: OffsetPage<i32> = OffsetPage {
            items: vec![1],
            next_offset: Some(20),
            total_count: None,
        };
        assert_ne!(a, b);
    }
}
