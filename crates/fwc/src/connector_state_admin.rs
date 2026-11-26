//! Owner-authenticated reads of the selected connector's state and writer lease.
use std::path::Path;

use anyhow::{Result, ensure};
use serde_json::Value;

use super::{HostAdminClient, mesh_inventory_credential};

pub(super) fn discovery_client(endpoint: &str) -> Result<HostAdminClient> {
    // Discover aliases on the same direct transport, without a default bearer.
    Ok(HostAdminClient::new_with_transport(endpoint, None, true)?
        .with_response_limit(8 * 1024 * 1024))
}

#[derive(Clone, Copy)]
pub(super) enum ReadKind {
    State,
    Lease,
}

pub(super) fn read(
    client: &HostAdminClient,
    kind: ReadKind,
    connector: &str,
    zone: Option<&str>,
    credential_file: Option<&Path>,
) -> Result<Value> {
    let token = mesh_inventory_credential(credential_file).map_err(|_| {
        anyhow::anyhow!("supply a valid owner bearer via --admin-token-file or FCP_HOST_ADMIN_BEARER_TOKEN")
    })?;
    let suffix = match kind {
        ReadKind::State => "state/explain",
        ReadKind::Lease => "lease/status",
    };
    let mut path = format!("/rpc/admin/connectors/{connector}/{suffix}");
    if let Some(zone) = zone {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("zone", zone)
            .finish();
        path.push('?');
        path.push_str(&query);
    }
    let request = client.client.get(format!("{}{path}", client.base_url))
        .bearer_auth(token.as_str())
        .header("x-fcp-zone", "z:owner");
    let payload = client.clone().with_response_limit(1024 * 1024)
        .read_json(request, "GET", &path)?;
    validate_read(&payload, kind, connector, zone)?;
    Ok(payload)
}

fn validate_read(payload: &Value, kind: ReadKind, connector: &str, zone: Option<&str>) -> Result<()> {
    ensure!(
        payload["status"] == "ok" && payload["schema_version"] == "1.0.0"
            && payload["connector_id"].as_str() == Some(connector),
        "host returned an incompatible state or lease response for the selected connector"
    );
    match kind {
        ReadKind::State => {
            let requested = payload.pointer("/zone/requested");
            ensure!(
                requested == Some(&zone.map_or(Value::Null, |zone| Value::String(zone.to_owned()))),
                "host state evidence does not match the requested zone"
            );
            let state = &payload["canonical_state"];
            match (payload["source"].as_str(), state["root_present"].as_bool()) {
                (Some("host-canonical-state"), Some(true)) => ensure!(
                    state["connector_id"].as_str() == Some(connector)
                        && zone.is_none_or(|zone| state["zone_id"].as_str() == Some(zone)),
                    "canonical state evidence belongs to a different connector or zone"
                ),
                (Some("host-cache-markers"), Some(false)) => {}
                _ => anyhow::bail!("host state source and canonical root evidence disagree"),
            }
        }
        ReadKind::Lease => ensure!(
            matches!(payload["source"].as_str(), Some("host-hrw-routing" | "host-unconfigured-hrw-routing"))
                && zone.is_some() && payload["zone_id"].as_str() == zone,
            "host lease evidence does not match the requested zone or evidence source"
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn state_evidence_distinguishes_bound_roots_from_cache_markers() {
        let mut state = json!({"status":"ok","schema_version":"1.0.0","connector_id":"x","zone":{"requested":"z:work"},
            "source":"host-canonical-state","canonical_state":{"connector_id":"x","root_present":true,"zone_id":"z:work"}});
        assert!(validate_read(&state, ReadKind::State, "x", Some("z:work")).is_ok());
        for (path, value) in [
            ("/connector_id", json!("other")), ("/status", json!("error")),
            ("/schema_version", json!("2")), ("/zone/requested", Value::Null),
            ("/canonical_state/connector_id", json!("other")), ("/canonical_state/zone_id", json!("z:owner")),
            ("/source", json!("host-cache-markers")), ("/canonical_state/root_present", json!(false)),
        ] {
            let mut invalid = state.clone();
            *invalid.pointer_mut(path).unwrap() = value;
            assert!(validate_read(&invalid, ReadKind::State, "x", Some("z:work")).is_err(), "{path}");
        }
        state["source"] = json!("host-cache-markers");
        state["canonical_state"] = json!({"root_present":false});
        state["zone"]["requested"] = Value::Null;
        assert!(validate_read(&state, ReadKind::State, "x", None).is_ok());
        assert!(validate_read(&state, ReadKind::Lease, "x", Some("z:work")).is_err());
    }

    #[test]
    fn lease_status_authenticates_owner_and_scopes_the_observation_to_work_zone() {
        let response = json!({"status":"ok","schema_version":"1.0.0","source":"host-unconfigured-hrw-routing",
            "connector_id":"fcp.test","zone_id":"z:work"});
        assert!(validate_read(&response, ReadKind::Lease, "fcp.test", Some("z:owner")).is_err());
        assert!(validate_read(&response, ReadKind::Lease, "other", Some("z:work")).is_err());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let client = discovery_client(&endpoint).unwrap();
        let mut token = tempfile::NamedTempFile::new().unwrap();
        writeln!(token, "owner-test-secret").unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let reader = BufReader::new(socket.try_clone().unwrap());
            let head: Vec<_> = reader.lines().map_while(std::io::Result::ok).take_while(|line| !line.is_empty()).collect();
            let body = response.to_string();
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            head
        });
        read(&client, ReadKind::Lease, "fcp.test", Some("z:work"), Some(token.path())).unwrap();
        let head = server.join().unwrap();
        assert!(head[0].starts_with("GET /rpc/admin/connectors/fcp.test/lease/status?zone=z%3Awork "));
        assert!(head.iter().any(|line| line.eq_ignore_ascii_case("authorization: Bearer owner-test-secret")));
        assert!(head.iter().any(|line| line.eq_ignore_ascii_case("x-fcp-zone: z:owner")));
    }
}
