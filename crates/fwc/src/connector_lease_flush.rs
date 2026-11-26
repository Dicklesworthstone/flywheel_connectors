//! Observe committed state before yielding a singleton writer's lease.
use std::path::PathBuf;

use anyhow::{Result, ensure};
use clap::Args;
use fcp_core::{InstanceId, ObjectId, ZoneId};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{
    CliExitCode, CommandAvailability, CommandEnvelope, DispatchOutcome, HostAdminClient,
    KnowledgeState, connector_resolution_dispatch, connector_state_admin, inject_truth_source_metadata,
    mesh_inventory_credential, missing_host_dispatch, resolve_host_config,
};

#[derive(Args, Debug, Serialize)]
pub(super) struct FlushArgs {
    /// Connector id, alias, or family name on the selected host.
    #[arg(long)]
    connector: String,
    /// Exact zone of the canonical state to observe.
    #[arg(long)]
    zone: ZoneId,
    /// Read the owner bearer from this file (defaults to FCP_HOST_ADMIN_BEARER_TOKEN).
    #[arg(long, value_name = "PATH")]
    #[serde(skip_serializing)]
    admin_token_file: Option<PathBuf>,
}

#[derive(Deserialize)]
struct Observation {
    status: String,
    subcommand: String,
    schema_version: String,
    source: String,
    connector_id: String,
    zone_id: String,
    purpose: String,
    flush: Flush,
}

#[derive(Deserialize, Serialize)]
struct Flush {
    connector_id: String,
    zone_id: String,
    instance_id: Option<String>,
    status_source: String,
    object_writer_excluded_during_read: bool,
    root_present: bool,
    root_object_id: Option<String>,
    head_object_id: Option<String>,
    last_canonical_seq: Option<u64>,
    lease_seq: Option<u64>,
    lease_object_id: Option<String>,
}

impl Observation {
    fn confirm(self, connector: &str, zone: &ZoneId) -> Result<Flush> {
        let flush = self.flush;
        ensure!(
            self.status == "ok" && self.subcommand == "connector lease flush-before-yield"
                && self.schema_version == "1.0.0" && self.source == "host-canonical-state-flush"
                && self.purpose == "connector_state_write"
                && self.connector_id == connector && flush.connector_id == connector
                && self.zone_id == zone.as_str() && flush.zone_id == zone.as_str()
                && flush.status_source == "fcp-store" && flush.object_writer_excluded_during_read,
            "host did not confirm a writer-excluded observation of the requested connector and zone"
        );
        let head_present = flush.head_object_id.is_some();
        ensure!(
            flush.root_present == flush.root_object_id.is_some()
                && (!head_present || flush.root_present)
                && head_present == flush.last_canonical_seq.is_some()
                && head_present == flush.lease_seq.is_some()
                && head_present == flush.lease_object_id.is_some()
                && [&flush.root_object_id, &flush.head_object_id, &flush.lease_object_id]
                    .into_iter().flatten().all(|id| id.parse::<ObjectId>().is_ok())
                && flush.instance_id.as_deref().is_none_or(|id| id.parse::<InstanceId>().is_ok()),
            "canonical root, head, or lease evidence is incomplete or invalid"
        );
        Ok(flush)
    }
}

fn observe(client: &HostAdminClient, connector: &str, zone: &ZoneId, token: &str) -> Result<Flush> {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("zone", zone.as_str())
        .append_pair("require_writer_idle", "true")
        .finish();
    let path = format!("/rpc/admin/connectors/{connector}/lease/flush-before-yield?{query}");
    let request = client.client.post(format!("{}{path}", client.base_url))
        .bearer_auth(token)
        .header("x-fcp-zone", "z:owner")
        .json(&json!({}));
    // This POST collects a local observation. Send it once, and require the
    // explicit result bit so an older host cannot downgrade the verification.
    let response: Observation = client.clone().with_response_limit(64 * 1024)
        .read_json(request, "POST", &path)?;
    response.confirm(connector, zone)
}

pub(super) fn dispatch(args: &FlushArgs, explicit_host: Option<&str>) -> Result<DispatchOutcome> {
    let Some(host) = resolve_host_config(explicit_host)? else {
        return Ok(missing_host_dispatch(
            "connector lease flush-before-yield", json!({"connector":args.connector,"zone":args.zone}),
            vec!["Select the host that owns the durable object store with --host.".to_owned()],
        ));
    };
    let client = connector_state_admin::discovery_client(&host.endpoint)?;
    let (catalog, _) = client.catalog(None)?;
    let record = match catalog.resolve_connector(&args.connector) {
        Ok(record) => record,
        Err(error) => return Ok(connector_resolution_dispatch("connector lease flush-before-yield", &args.connector, &error)),
    };
    let id = record.summary.id.as_str();
    let token = mesh_inventory_credential(args.admin_token_file.as_deref()).map_err(|_| {
        anyhow::anyhow!("supply a valid owner bearer via --admin-token-file or FCP_HOST_ADMIN_BEARER_TOKEN")
    })?;
    let (mut payload, exit_code) = match observe(&client, id, &args.zone, &token) {
        Ok(flush) => (json!({
            "status":"ok", "source":"host-canonical-state-flush", "flush":flush,
            "message":"The host excluded the object writer while verifying this state. Keep the writer fenced through handoff."
        }), CliExitCode::Success),
        Err(error) => (json!({
            "status":"error", "outcome":"unconfirmed", "error":{"type":"writer-observation-unconfirmed","message":error.to_string()},
            "next_actions":["Inspect the selected host, writer ownership and canonical store before proceeding with handoff."]
        }), CliExitCode::Transport),
    };
    payload["command"] = json!("connector");
    payload["subcommand"] = json!("lease flush-before-yield");
    payload["connector_id"] = json!(id);
    payload["zone_id"] = json!(args.zone);
    if matches!(exit_code, CliExitCode::Success) {
        CommandEnvelope::new(CommandAvailability::LiveRuntime, "connector").inject_into(&mut payload);
        inject_truth_source_metadata(&mut payload, KnowledgeState::HostBacked);
    } else {
        CommandEnvelope::new(CommandAvailability::Unavailable, "connector").inject_into(&mut payload);
    }
    Ok(DispatchOutcome { payload, exit_code })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn receipt() -> Value {
        json!({"status":"ok","subcommand":"connector lease flush-before-yield","schema_version":"1.0.0",
            "source":"host-canonical-state-flush","connector_id":"fcp.test","zone_id":"z:work","purpose":"connector_state_write",
            "flush":{"connector_id":"fcp.test","zone_id":"z:work","status_source":"fcp-store","object_writer_excluded_during_read":true,
                "root_present":true,"root_object_id":"12".repeat(32),"head_object_id":"34".repeat(32),
                "last_canonical_seq":5,"lease_seq":2,"lease_object_id":"56".repeat(32)}})
    }

    fn confirm(value: Value) -> Result<Flush> {
        serde_json::from_value::<Observation>(value)?.confirm("fcp.test", &"z:work".parse().unwrap())
    }

    #[test]
    fn accepts_populated_root_empty_root_and_absent_state() {
        let mut value = receipt();
        assert_eq!(confirm(value.clone()).unwrap().last_canonical_seq, Some(5));
        for key in ["head_object_id","last_canonical_seq","lease_seq","lease_object_id"] {
            value["flush"][key] = Value::Null;
        }
        assert!(confirm(value.clone()).unwrap().root_present);
        value["flush"]["root_present"] = json!(false);
        value["flush"]["root_object_id"] = Value::Null;
        assert!(!confirm(value).unwrap().root_present);
    }

    #[test]
    fn refuses_downgraded_cross_scope_and_inconsistent_observations() {
        for (path, new) in [
            ("/flush/object_writer_excluded_during_read", json!(false)), ("/purpose", json!("other")),
            ("/connector_id", json!("other")), ("/flush/connector_id", json!("other")),
            ("/zone_id", json!("z:owner")), ("/flush/zone_id", json!("z:owner")),
            ("/flush/root_present", json!(false)), ("/flush/root_object_id", json!("not-an-object")),
            ("/flush/lease_seq", Value::Null), ("/flush/last_canonical_seq", Value::Null),
            ("/flush/head_object_id", Value::Null), ("/flush/lease_object_id", Value::Null),
        ] {
            let mut value = receipt();
            *value.pointer_mut(path).unwrap() = new;
            assert!(confirm(value).is_err(), "{path}");
        }
        let mut legacy = receipt();
        legacy["flush"].as_object_mut().unwrap().remove("object_writer_excluded_during_read");
        assert!(confirm(legacy).is_err());
    }
}
