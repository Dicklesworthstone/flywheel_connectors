//! Bounded, cancellation-safe discovery of authenticated mesh peers.
//!
//! One refresh runs per router, with at most 16 peer requests in flight and
//! a total deadline that includes waiting for the refresh lock. Completed
//! results are cached immediately so cancelling a caller loses neither
//! verified inventories nor the ability of another caller to resume discovery.
//! A persistent attempt cursor prevents an unreachable prefix of the directory
//! from monopolizing every refresh budget and starving later peers.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;
use std::time::Duration;

use fcp_async_core::sync::Mutex as AsyncMutex;
use fcp_mesh::invoke_route::{
    DEFAULT_MESH_ADVERTISEMENT_MAX_AGE_MS, MeshPeer, MeshPeerAdvertisement, MeshPeerDirectory,
};
use futures_util::{StreamExt, stream};

use super::{Instant, unix_now_ms};

const MAX_CONCURRENT_FETCHES: usize = 16;
const REFRESH_TIMEOUT: Duration = Duration::from_secs(5);
const SUCCESS_CACHE_TTL: Duration = Duration::from_secs(10);
const FAILURE_CACHE_TTL: Duration = Duration::from_secs(1);

#[derive(Debug)]
struct CachedAdvertisement {
    // Bind positive AND negative entries to the exact authorized identity and
    // endpoint. A node id alone is not a cache key across membership reloads.
    peer: MeshPeer,
    checked_at: Instant,
    // A negative cache entry suppresses repeated probes of a failing peer.
    // It never supplies an inventory or counts as evidence of availability.
    advertisement: Option<MeshPeerAdvertisement>,
}

impl CachedAdvertisement {
    fn is_reusable(&self, peer: &MeshPeer, now_ms: u64) -> bool {
        if &self.peer != peer {
            return false;
        }
        match &self.advertisement {
            Some(advertisement) => {
                self.checked_at.elapsed() < SUCCESS_CACHE_TTL
                    && advertisement.issued_at_ms.abs_diff(now_ms)
                        <= DEFAULT_MESH_ADVERTISEMENT_MAX_AGE_MS
            }
            None => self.checked_at.elapsed() < FAILURE_CACHE_TTL,
        }
    }
}

#[derive(Debug, Default)]
struct AdvertisementCache {
    generation: u64,
    // Advance when a fetch starts, including fetches later cancelled. The
    // cursor is reduced modulo the current snapshot's peer count.
    next_peer_index: usize,
    entries: HashMap<String, CachedAdvertisement>,
}

impl AdvertisementCache {
    fn stale_peers(&self, directory: &MeshPeerDirectory, now_ms: u64) -> Vec<(usize, MeshPeer)> {
        let mut peers: Vec<_> = directory.peers().enumerate().collect();
        if peers.is_empty() {
            return Vec::new();
        }
        let start = self.next_peer_index % peers.len();
        peers.rotate_left(start);
        peers
            .into_iter()
            .filter(|(_, peer)| {
                !self
                    .entries
                    .get(peer.node_id.as_str())
                    .is_some_and(|entry| entry.is_reusable(peer, now_ms))
            })
            .map(|(index, peer)| (index, peer.clone()))
            .collect()
    }
}

#[derive(Debug)]
pub(super) struct PeerDiscovery {
    cache: Mutex<AdvertisementCache>,
    refresh: AsyncMutex<()>,
}

impl PeerDiscovery {
    pub(super) fn new() -> Self {
        Self {
            cache: Mutex::new(AdvertisementCache::default()),
            refresh: AsyncMutex::new(()),
        }
    }

    /// Fetch missing inventories through `fetch`, then authenticate them
    /// against this immutable membership snapshot. Transport success alone is
    /// never sufficient to populate the cache.
    pub(super) async fn collect<F, Fut>(
        &self,
        directory: &MeshPeerDirectory,
        fetch: F,
    ) -> Vec<MeshPeerAdvertisement>
    where
        F: Fn(MeshPeer) -> Fut,
        Fut: Future<Output = Result<MeshPeerAdvertisement, String>>,
    {
        let refresh = async {
            // Recheck after acquiring the async lock: another caller may
            // have refreshed everything while this caller was waiting.
            let _refresh_guard = self.refresh.lock().await;
            let (generation, stale_peers) = {
                let mut cache = self
                    .cache
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                // Repeated additions/removals must not grow an unbounded cache.
                // Also remove old negative entries when a peer's endpoint/key
                // changes, so recovery does not wait for the old failure TTL.
                cache.entries.retain(|_, entry| {
                    directory.peer(&entry.peer.node_id) == Some(&entry.peer)
                });
                (cache.generation, cache.stale_peers(directory, unix_now_ms()))
            };
            let mut pending = stream::iter(stale_peers)
                .map(|(index, peer)| {
                    self.record_attempt(generation, index, directory.len());
                    let result = fetch(peer.clone());
                    async move { (peer, result.await) }
                })
                .buffer_unordered(MAX_CONCURRENT_FETCHES);
            while let Some((peer, result)) = pending.next().await {
                let result = result.and_then(|advertisement| {
                    advertisement
                        .verify(
                            &peer.node_id,
                            directory,
                            unix_now_ms(),
                            DEFAULT_MESH_ADVERTISEMENT_MAX_AGE_MS,
                        )
                        .map_err(|error| error.to_string())?;
                    Ok(advertisement)
                });
                let mut cache = self
                    .cache
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if cache.generation != generation {
                    // Invalidation must also fence a fetch that started before
                    // the cache was cleared, not just erase existing entries.
                    break;
                }
                let advertisement = match result {
                    Ok(advertisement) => Some(advertisement),
                    Err(detail) => {
                        tracing::warn!(
                            event = "mesh_advertisement_unavailable",
                            peer = peer.node_id.as_str(),
                            detail = %detail,
                            "skipping mesh peer advertisement"
                        );
                        None
                    }
                };
                cache.entries.insert(
                    peer.node_id.as_str().to_owned(),
                    CachedAdvertisement {
                        peer,
                        checked_at: Instant::now(),
                        advertisement,
                    },
                );
            }
        };
        if fcp_async_core::time::timeout(REFRESH_TIMEOUT, refresh)
            .await
            .is_err()
        {
            tracing::warn!(
                event = "mesh_discovery_deadline",
                peer_count = directory.len(),
                "mesh discovery deadline reached; returning only fresh verified inventories"
            );
        }
        // Re-evaluate signed age after the refresh. A still-live local TTL
        // must never extend the authority of an expired signed advertisement.
        self.snapshot(directory, unix_now_ms())
    }

    fn record_attempt(&self, generation: u64, index: usize, peer_count: usize) {
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache.generation == generation {
            cache.next_peer_index = if index + 1 < peer_count { index + 1 } else { 0 };
        }
    }

    fn snapshot(&self, directory: &MeshPeerDirectory, now_ms: u64) -> Vec<MeshPeerAdvertisement> {
        let cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Directory order is stable even when fetches complete out of order.
        directory
            .peers()
            .filter_map(|peer| {
                cache.entries.get(peer.node_id.as_str())
                    .filter(|entry| entry.is_reusable(peer, now_ms))
                    .and_then(|entry| entry.advertisement.clone())
            })
            .collect()
    }

    pub(super) fn invalidate(&self) {
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.generation = cache.generation.wrapping_add(1);
        cache.next_peer_index = 0;
        cache.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use fcp_core::TailscaleNodeId;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_mesh::invoke_route::MeshPeerConfig;
    use futures_util::future::{join_all, pending};

    use super::*;

    fn directory(count: usize, key: &Ed25519SigningKey) -> MeshPeerDirectory {
        let configs: Vec<_> = (0..count)
            .map(|index| MeshPeerConfig {
                node_id: format!("peer-{index:03}"),
                endpoint: format!("http://127.0.0.1:{}", 20_000 + index),
                public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            })
            .collect();
        MeshPeerDirectory::from_configs(TailscaleNodeId::new("local"), &configs).unwrap()
    }

    fn advertisement(peer: &MeshPeer, key: &Ed25519SigningKey) -> MeshPeerAdvertisement {
        MeshPeerAdvertisement::sign(key, peer.node_id.clone(), unix_now_ms(), Vec::new())
    }

    #[fcp_async_core::runtime::test]
    async fn concurrent_cold_lookups_share_one_refresh() {
        let key = Ed25519SigningKey::generate();
        let directory = directory(1, &key);
        let discovery = PeerDiscovery::new();
        let calls = AtomicUsize::new(0);
        let results = join_all((0..16).map(|_| {
            discovery.collect(&directory, |peer| {
                calls.fetch_add(1, Ordering::SeqCst);
                let ad = advertisement(&peer, &key);
                async move {
                    fcp_async_core::time::sleep(Duration::from_millis(1)).await;
                    Ok(ad)
                }
            })
        }))
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(results.iter().all(|result| result.len() == 1));
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_bounds_concurrency_and_preserves_directory_order() {
        let key = Ed25519SigningKey::generate();
        let directory = directory(MAX_CONCURRENT_FETCHES * 2 + 1, &key);
        let discovery = PeerDiscovery::new();
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let calls = AtomicUsize::new(0);
        let result = discovery
            .collect(&directory, |peer| {
                let ad = advertisement(&peer, &key);
                let active = &active;
                let peak = &peak;
                let calls = &calls;
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(count, Ordering::SeqCst);
                    fcp_async_core::time::sleep(Duration::from_millis(1)).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok(ad)
                }
            })
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), directory.len());
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert!(peak.load(Ordering::SeqCst) > 1);
        assert!(peak.load(Ordering::SeqCst) <= MAX_CONCURRENT_FETCHES);
        let actual: Vec<_> = result.iter().map(|ad| ad.node_id.as_str()).collect();
        let expected: Vec<_> = directory.peers().map(|peer| peer.node_id.as_str()).collect();
        assert_eq!(actual, expected);
    }

    #[fcp_async_core::runtime::test]
    async fn negative_cache_suppresses_repeated_failures_and_allows_recovery() {
        let key = Ed25519SigningKey::generate();
        let directory = directory(1, &key);
        let discovery = PeerDiscovery::new();
        let calls = AtomicUsize::new(0);
        for _ in 0..2 {
            let result = discovery
                .collect(&directory, |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async { Err("peer unreachable".to_owned()) }
                })
                .await;
            assert!(result.is_empty());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        {
            let mut cache = discovery.cache.lock().unwrap();
            for entry in cache.entries.values_mut() {
                entry.checked_at = Instant::now() - FAILURE_CACHE_TTL - Duration::from_millis(1);
            }
        }
        let result = discovery
            .collect(&directory, |peer| {
                calls.fetch_add(1, Ordering::SeqCst);
                let ad = advertisement(&peer, &key);
                async move { Ok(ad) }
            })
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(result.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn unauthenticated_and_wrong_node_inventories_never_enter_positive_cache() {
        let key = Ed25519SigningKey::generate();
        let wrong_key = Ed25519SigningKey::generate();
        let directory = directory(1, &key);
        let discovery = PeerDiscovery::new();
        let invalid = discovery
            .collect(&directory, |peer| {
                let ad = advertisement(&peer, &wrong_key);
                async move { Ok(ad) }
            })
            .await;
        assert!(invalid.is_empty());
        assert!(discovery.cache.lock().unwrap().entries["peer-000"].advertisement.is_none());
        discovery.invalidate();
        let wrong_node = discovery
            .collect(&directory, |_| {
                let ad = MeshPeerAdvertisement::sign(
                    &key,
                    TailscaleNodeId::new("another-peer"),
                    unix_now_ms(),
                    Vec::new(),
                );
                async move { Ok(ad) }
            })
            .await;
        assert!(wrong_node.is_empty());
    }

    #[test]
    fn local_cache_ttl_cannot_extend_signed_advertisement_lifetime() {
        let key = Ed25519SigningKey::generate();
        let directory = directory(1, &key);
        let peer = directory.peers().next().unwrap();
        let ad = advertisement(peer, &key);
        let issued_at_ms = ad.issued_at_ms;
        let discovery = PeerDiscovery::new();
        discovery.cache.lock().unwrap().entries.insert(
            peer.node_id.as_str().to_owned(),
            CachedAdvertisement {
                peer: peer.clone(),
                checked_at: Instant::now(),
                advertisement: Some(ad),
            },
        );
        assert_eq!(discovery.snapshot(&directory, issued_at_ms).len(), 1);
        assert!(
            discovery
                .snapshot(&directory, issued_at_ms + DEFAULT_MESH_ADVERTISEMENT_MAX_AGE_MS + 1)
                .is_empty()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn invalidation_fences_in_flight_refresh_results() {
        let key = Ed25519SigningKey::generate();
        let directory = directory(1, &key);
        let discovery = PeerDiscovery::new();
        let result = discovery
            .collect(&directory, |peer| {
                let ad = advertisement(&peer, &key);
                discovery.invalidate();
                async move { Ok(ad) }
            })
            .await;
        assert!(result.is_empty(), "pre-invalidation fetch must not repopulate the cache");
        assert!(discovery.cache.lock().unwrap().entries.is_empty());
        let recovered = discovery
            .collect(&directory, |peer| {
                let ad = advertisement(&peer, &key);
                async move { Ok(ad) }
            })
            .await;
        assert_eq!(recovered.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn cancellation_releases_refresh_lock_and_preserves_completed_peers() {
        let key = Ed25519SigningKey::generate();
        let directory = directory(2, &key);
        let discovery = PeerDiscovery::new();
        let mut first = Box::pin(discovery.collect(&directory, |peer| {
            let ad = advertisement(&peer, &key);
            async move {
                if peer.node_id.as_str() == "peer-001" {
                    pending::<()>().await;
                }
                Ok(ad)
            }
        }));
        assert!(futures_util::poll!(first.as_mut()).is_pending());
        assert_eq!(discovery.snapshot(&directory, unix_now_ms()).len(), 1);
        drop(first);
        let fetched = AtomicUsize::new(0);
        let recovered = discovery
            .collect(&directory, |peer| {
                fetched.fetch_add(1, Ordering::SeqCst);
                assert_eq!(peer.node_id.as_str(), "peer-001");
                let ad = advertisement(&peer, &key);
                async move { Ok(ad) }
            })
            .await;
        assert_eq!(recovered.len(), 2);
        assert_eq!(fetched.load(Ordering::SeqCst), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn cancelled_refreshes_rotate_past_unreachable_peer_prefixes() {
        let key = Ed25519SigningKey::generate();
        let directory = directory(MAX_CONCURRENT_FETCHES * 2 + 1, &key);
        let discovery = PeerDiscovery::new();
        let attempted = Mutex::new(Vec::new());
        for _ in 0..3 {
            let mut refresh = Box::pin(discovery.collect(&directory, |peer| {
                attempted.lock().unwrap().push(peer.node_id.as_str().to_owned());
                pending::<Result<MeshPeerAdvertisement, String>>()
            }));
            assert!(futures_util::poll!(refresh.as_mut()).is_pending());
            drop(refresh);
        }
        let attempted = attempted.into_inner().unwrap();
        assert_eq!(attempted.len(), MAX_CONCURRENT_FETCHES * 3);
        let distinct: std::collections::BTreeSet<_> = attempted.into_iter().collect();
        assert_eq!(distinct.len(), directory.len(), "a dead prefix must not starve later peers");
        assert!(discovery.snapshot(&directory, unix_now_ms()).is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn total_deadline_preserves_completed_inventory_and_releases_refresh() {
        let key = Ed25519SigningKey::generate();
        let directory = directory(2, &key);
        let discovery = PeerDiscovery::new();
        let refresh = discovery.collect(&directory, |peer| {
            let ad = advertisement(&peer, &key);
            async move {
                if peer.node_id.as_str() == "peer-001" {
                    pending::<()>().await;
                }
                Ok(ad)
            }
        });
        let result = fcp_async_core::time::timeout(
            REFRESH_TIMEOUT + Duration::from_secs(2),
            refresh,
        )
        .await
        .expect("discovery must enforce its own total deadline");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].node_id.as_str(), "peer-000");
        let recovered = discovery
            .collect(&directory, |peer| {
                assert_eq!(peer.node_id.as_str(), "peer-001");
                let ad = advertisement(&peer, &key);
                async move { Ok(ad) }
            })
            .await;
        assert_eq!(recovered.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn key_rotation_never_reuses_an_old_positive_cache_entry() {
        let old_key = Ed25519SigningKey::generate();
        let new_key = Ed25519SigningKey::generate();
        let old_directory = directory(1, &old_key);
        let new_directory = directory(1, &new_key);
        let discovery = PeerDiscovery::new();
        let old = discovery.collect(&old_directory, |peer| {
            let ad = advertisement(&peer, &old_key);
            async move { Ok(ad) }
        }).await;
        assert_eq!(old.len(), 1);
        assert!(discovery.snapshot(&new_directory, unix_now_ms()).is_empty());
        let calls = AtomicUsize::new(0);
        let current = discovery.collect(&new_directory, |peer| {
            calls.fetch_add(1, Ordering::SeqCst);
            let ad = advertisement(&peer, &new_key);
            async move { Ok(ad) }
        }).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(current.len(), 1);
        assert_ne!(current[0].signature, old[0].signature);
        current[0].verify(
            &TailscaleNodeId::new("peer-000"), &new_directory,
            unix_now_ms(), DEFAULT_MESH_ADVERTISEMENT_MAX_AGE_MS,
        ).unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn endpoint_change_invalidates_positive_and_negative_entries() {
        let key = Ed25519SigningKey::generate();
        let old_directory = directory(1, &key);
        let new_directory = MeshPeerDirectory::from_configs(
            TailscaleNodeId::new("local"),
            &[MeshPeerConfig {
                node_id: "peer-000".to_owned(),
                endpoint: "http://127.0.0.1:29999".to_owned(),
                public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            }],
        ).unwrap();
        for initially_available in [false, true] {
            let discovery = PeerDiscovery::new();
            discovery.collect(&old_directory, |peer| {
                let ad = advertisement(&peer, &key);
                async move {
                    if initially_available { Ok(ad) } else { Err("unreachable".to_owned()) }
                }
            }).await;
            assert!(discovery.snapshot(&new_directory, unix_now_ms()).is_empty());
            let calls = AtomicUsize::new(0);
            let current = discovery.collect(&new_directory, |peer| {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(peer.endpoint, "http://127.0.0.1:29999");
                let ad = advertisement(&peer, &key);
                async move { Ok(ad) }
            }).await;
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(current.len(), 1);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn removed_peer_entries_are_pruned_instead_of_accumulating() {
        let key = Ed25519SigningKey::generate();
        let initial = directory(4, &key);
        let reduced = directory(1, &key);
        let discovery = PeerDiscovery::new();
        discovery.collect(&initial, |peer| {
            let ad = advertisement(&peer, &key);
            async move { Ok(ad) }
        }).await;
        let calls = AtomicUsize::new(0);
        let result = discovery.collect(&reduced, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err("unchanged peer should not be fetched".to_owned()) }
        }).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].node_id.as_str(), "peer-000");
        assert_eq!(discovery.cache.lock().unwrap().entries.len(), 1);
    }
}
