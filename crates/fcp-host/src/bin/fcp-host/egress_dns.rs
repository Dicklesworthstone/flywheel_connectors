//! Run host egress DNS on the runtime's blocking resolver. A timed-out caller
//! releases its wait immediately, while the resolver retains its admission
//! until the actual OS lookup returns.

use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use asupersync::sync::OwnedSemaphorePermit;
use fcp_async_core::sync::Semaphore;
use fcp_host::{HostError, HostResult};
use fcp_manifest::NetworkConstraints;

const MAX_ACTIVE_LOOKUPS: usize = 32;

struct AdmittedLookup<A> {
    address: A,
    max_ips: u16,
    deadline: Instant,
    _permit: OwnedSemaphorePermit,
}

impl<A: ToSocketAddrs> ToSocketAddrs for AdmittedLookup<A> {
    type Iter = std::iter::Take<A::Iter>;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        // Time spent waiting for the blocking pool consumes the DNS deadline.
        if Instant::now() >= self.deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        // Retain the first over-limit answer so the normal policy rejects the
        // entire result. Truncating at max_ips could admit an invalid answer.
        Ok(self
            .address
            .to_socket_addrs()?
            .take(usize::from(self.max_ips) + 1))
    }
}

pub(super) async fn resolve(
    host: &str,
    port: u16,
    constraints: &NetworkConstraints,
    protocol: &str,
) -> HostResult<Vec<IpAddr>> {
    if let Ok(ip) = host.parse() {
        return Ok(vec![ip]);
    }
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    let slots = SLOTS.get_or_init(|| Arc::new(Semaphore::new(MAX_ACTIVE_LOOKUPS)));
    let timeout = Duration::from_millis(u64::from(constraints.connect_timeout_ms));
    let deadline = Instant::now() + timeout;
    let lookup = AdmittedLookup {
        address: (host.to_owned(), port),
        max_ips: constraints.dns_max_ips,
        deadline,
        _permit: Arc::clone(slots).try_acquire_owned().map_err(|_| {
            HostError::Unavailable("host-egress DNS resolver capacity exhausted".to_owned())
        })?,
    };
    let result = fcp_async_core::time::timeout(
        deadline.saturating_duration_since(Instant::now()),
        asupersync::net::lookup_all(lookup),
    )
    .await;
    match result {
        Ok(result) if Instant::now() < deadline => result
            .map(|addresses| addresses.into_iter().map(|addr| addr.ip()).collect())
            .map_err(|error| {
                HostError::PreflightFailed(format!(
                    "host-egress {protocol} DNS resolution for `{host}` failed: {error}"
                ))
            }),
        _ => Err(HostError::PreflightFailed(format!(
            "host-egress {protocol} DNS resolution for `{host}` timed out after {}ms",
            constraints.connect_timeout_ms
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn retains_an_overflow_answer_for_policy_rejection() {
        let addresses = [SocketAddr::from(([127, 0, 0, 1], 443)); 4];
        let lookup = AdmittedLookup {
            address: &addresses[..],
            max_ips: 2,
            deadline: Instant::now() + Duration::from_secs(10),
            _permit: Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
        };
        assert_eq!(lookup.to_socket_addrs().unwrap().count(), 3);
    }

    #[test]
    fn expired_lookup_skips_the_os_resolver() {
        struct UnexpectedLookup;
        impl ToSocketAddrs for UnexpectedLookup {
            type Iter = std::iter::Empty<SocketAddr>;

            fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
                panic!("expired work must never start DNS");
            }
        }
        let lookup = AdmittedLookup {
            address: UnexpectedLookup,
            max_ips: 2,
            deadline: Instant::now(),
            _permit: Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
        };
        assert_eq!(
            lookup.to_socket_addrs().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[fcp_async_core::runtime::test]
    async fn abandoned_lookup_holds_capacity_until_the_resolver_exits() {
        use fcp_async_core::channel::oneshot;
        use futures_util::future::{Either, select};
        use std::pin::pin;
        use std::sync::{Mutex, mpsc};

        struct WaitingAddress {
            entered: Mutex<Option<oneshot::Sender<()>>>,
            release: mpsc::Receiver<()>,
        }
        impl ToSocketAddrs for WaitingAddress {
            type Iter = std::iter::Once<SocketAddr>;

            fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
                self.entered
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(())
                    .unwrap();
                self.release.recv_timeout(Duration::from_secs(5)).unwrap();
                Ok(std::iter::once(SocketAddr::from(([127, 0, 0, 1], 443))))
            }
        }
        let slots = Arc::new(Semaphore::new(1));
        let (entered, started) = oneshot::channel();
        let (release, released) = mpsc::channel();
        let lookup = AdmittedLookup {
            address: WaitingAddress {
                entered: Mutex::new(Some(entered)),
                release: released,
            },
            max_ips: 1,
            deadline: Instant::now() + Duration::from_secs(5),
            _permit: Arc::clone(&slots).try_acquire_owned().unwrap(),
        };
        {
            let resolver = pin!(asupersync::net::lookup_all(lookup));
            assert!(matches!(
                select(started, resolver).await,
                Either::Left((Ok(()), _))
            ));
        }
        assert!(Arc::clone(&slots).try_acquire_owned().is_err());
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while slots.available_permits() == 0 {
            assert!(
                Instant::now() < deadline,
                "resolver never released capacity"
            );
            fcp_async_core::time::sleep(Duration::from_millis(5)).await;
        }
    }
}
