//! Same-zone, explicitly declared input references for live HTTP batches.
//!
//! Only accepted scheduler results enter this cache. References substitute JSON
//! values, never strings, authority fields, or recursively evaluated templates.

use std::collections::{BTreeSet, HashMap};
use std::io::{self, Write};
use std::sync::Mutex;

use fcp_core::{Provenance, ProvenanceStep, TaintLevel};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Serialize, Serializer};
use serde_json::Value;

use super::{
    BatchOperationError, HostError, HostResult, HttpBatchInvokeRequest, HttpBatchOperation,
    OperationResult, OperationResultStatus,
};

const REFERENCE_KEY: &str = "$fcp_batch_ref";
const LITERAL_KEY: &str = "$fcp_batch_literal";
const MAX_DEPTH: usize = 64;
const MAX_TEMPLATE_NODES: usize = 65_536;
const MAX_REFERENCES: usize = 128;
const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_FLOW_BYTES: usize = 16 * 1024 * 1024;
const MAX_PROVENANCE_BYTES: usize = 64 * 1024;
const MAX_PROVENANCE_STEPS: usize = 128;

struct Node {
    references: BTreeSet<String>,
    substitutes: bool,
}

struct Retained {
    output: Value,
    provenance: Provenance,
}

#[derive(Default)]
struct State {
    pending: HashMap<String, Provenance>,
    outputs: HashMap<String, Retained>,
    // Cumulative admission, including pending provenance. No refund can reopen
    // a stopped batch or permit repeated expansion to bypass the total budget.
    cache_bytes: usize,
    input_bytes: usize,
}

pub(super) struct Dataflow<'a> {
    members: HashMap<&'a str, &'a HttpBatchOperation>,
    nodes: HashMap<&'a str, Node>,
    sources: BTreeSet<String>,
    state: Mutex<State>,
}

fn invalid() -> HostError {
    HostError::InvalidFilter(
        "invalid batch input reference: require an explicit same-zone dependency, canonical JSON pointer, bounded template and same-zone provenance".into(),
    )
}

fn binding_error(code: &str) -> BatchOperationError {
    BatchOperationError {
        code: code.into(),
        message: "batch input binding failed before invoking this member; no automatic retry is authorized".into(),
        retry_after_ms: None,
    }
}

impl<'a> Dataflow<'a> {
    /// The ordinary executor must validate the graph before compiling templates.
    pub(super) fn compile(request: &'a HttpBatchInvokeRequest) -> HostResult<Self> {
        let members: HashMap<_, _> = request.operations.iter()
            .map(|operation| (operation.id.as_str(), operation)).collect();
        let mut nodes = HashMap::new();
        let mut sources = BTreeSet::new();
        for operation in &request.operations {
            let mut node = Node { references: BTreeSet::new(), substitutes: false };
            let mut visited = 0;
            let mut references = 0;
            scan(&operation.request.input, 0, &mut visited, &mut references, &mut node)?;
            if node.substitutes {
                measure(&operation.request.input, MAX_INPUT_BYTES).map_err(|_| invalid())?;
            }
            for source_id in &node.references {
                let source = members.get(source_id.as_str()).ok_or_else(invalid)?;
                if source.id == operation.id
                    || !operation.depends_on.contains(source_id)
                    || source.request.zone_id != operation.request.zone_id
                {
                    return Err(invalid());
                }
                validate_provenance(source)?;
                validate_provenance(operation)?;
                sources.insert(source_id.clone());
            }
            nodes.insert(operation.id.as_str(), node);
        }
        Ok(Self { members, nodes, sources, state: Mutex::new(State::default()) })
    }

    /// Resolve before constructing the ordinary invocation future. Only input
    /// and provenance change; submitted capability, approval, lease, request ID
    /// and idempotency identity are passed unchanged to ordinary enforcement.
    pub(super) fn resolve(
        &self,
        operation: &HttpBatchOperation,
    ) -> Result<HttpBatchOperation, BatchOperationError> {
        let node = self.nodes.get(operation.id.as_str())
            .ok_or_else(|| binding_error("BATCH_INPUT_BINDING_FAILED"))?;
        if !node.substitutes && !self.sources.contains(&operation.id) {
            return Ok(operation.clone());
        }
        let mut state = self.state.lock()
            .map_err(|_| binding_error("BATCH_INPUT_BINDING_FAILED"))?;
        let input = if node.substitutes {
            // Bound the expanded shape before allocating its encoded buffer or
            // parsed tree. Individually shallow/small sources can otherwise be
            // repeated or nested by a template into an oversized value graph.
            let mut visited = 0;
            validate_bound_shape(&operation.request.input, &state.outputs, 0, &mut visited)?;
            let mut buffer = LimitedBuffer::new(
                MAX_INPUT_BYTES.min(MAX_FLOW_BYTES.saturating_sub(state.input_bytes)),
            );
            let value = BoundValue { value: &operation.request.input, outputs: &state.outputs };
            if serde_json::to_writer(&mut buffer, &value).is_err() {
                return Err(binding_error(if buffer.exceeded {
                    "BATCH_INPUT_LIMIT"
                } else {
                    "BATCH_INPUT_REFERENCE_MISSING"
                }));
            }
            let input: Value = serde_json::from_slice(&buffer.bytes)
                .map_err(|_| binding_error("BATCH_INPUT_BINDING_FAILED"))?;
            state.input_bytes += buffer.bytes.len();
            Some(input)
        } else {
            None
        };
        let mut resolved = operation.clone();
        if let Some(input) = input {
            resolved.request.input = input;
        }
        if !node.references.is_empty() {
            let mut provenance = Provenance::highly_tainted(operation.request.zone_id.clone());
            if let Some(original) = &operation.request.provenance {
                append_chain(&mut provenance, original)?;
            }
            for source in &node.references {
                let retained = state.outputs.get(source)
                    .ok_or_else(|| binding_error("BATCH_INPUT_REFERENCE_MISSING"))?;
                append_chain(&mut provenance, &retained.provenance)?;
            }
            provenance.chain.sort_by_key(|step| step.timestamp_ms);
            // No prior elevation of a literal template attests new provider data.
            provenance.elevated = false;
            provenance.elevation_token = None;
            resolved.request.provenance = Some(provenance);
        }
        if self.sources.contains(&operation.id) {
            let mut provenance = resolved.request.provenance.clone()
                .unwrap_or_else(|| Provenance::new(operation.request.zone_id.clone()));
            provenance.taint = TaintLevel::HighlyTainted;
            provenance.elevated = false;
            provenance.elevation_token = None;
            if provenance.chain.len() >= MAX_PROVENANCE_STEPS {
                return Err(binding_error("BATCH_INPUT_PROVENANCE_LIMIT"));
            }
            let timestamp_ms = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0)
                .max(provenance.chain.iter().map(|step| step.timestamp_ms).max().unwrap_or(0));
            provenance.chain.push(ProvenanceStep {
                timestamp_ms,
                zone: operation.request.zone_id.clone(),
                actor: operation.request.connector_id.to_string(),
                action: operation.request.operation.to_string(),
                resource: format!("batch-result:{}", operation.request.id.0),
            });
            let bytes = measure(&provenance, MAX_PROVENANCE_BYTES.min(
                MAX_FLOW_BYTES.saturating_sub(state.cache_bytes),
            )).map_err(|_| binding_error("BATCH_INPUT_PROVENANCE_LIMIT"))?;
            if state.pending.contains_key(&operation.id) || state.outputs.contains_key(&operation.id) {
                return Err(binding_error("BATCH_INPUT_BINDING_FAILED"));
            }
            state.cache_bytes += bytes;
            state.pending.insert(operation.id.clone(), provenance);
        }
        Ok(resolved)
    }

    /// Called only after the shared executor has applied its retention quota.
    /// A failure here halts admission without relabeling a successful effect.
    pub(super) fn observe(&self, result: &OperationResult) -> Result<(), BatchOperationError> {
        if !self.sources.contains(&result.id) {
            return Ok(());
        }
        let mut state = self.state.lock()
            .map_err(|_| binding_error("BATCH_DATAFLOW_CACHE_FAILED"))?;
        if result.status != OperationResultStatus::Success || result.error.is_some() {
            state.pending.remove(&result.id);
            return Ok(());
        }
        if !self.members.contains_key(result.id.as_str()) || state.outputs.contains_key(&result.id) {
            return Err(binding_error("BATCH_DATAFLOW_CACHE_FAILED"));
        }
        let output = result.output.as_ref()
            .ok_or_else(|| binding_error("BATCH_DATAFLOW_CACHE_FAILED"))?;
        let mut visited = 0;
        validate_data_shape(output, 0, &mut visited)
            .map_err(|()| binding_error("BATCH_DATAFLOW_CACHE_LIMIT"))?;
        let bytes = measure(output, MAX_FLOW_BYTES.saturating_sub(state.cache_bytes))
            .map_err(|_| binding_error("BATCH_DATAFLOW_CACHE_LIMIT"))?;
        let provenance = state.pending.remove(&result.id)
            .ok_or_else(|| binding_error("BATCH_DATAFLOW_CACHE_FAILED"))?;
        state.cache_bytes += bytes;
        state.outputs.insert(result.id.clone(), Retained { output: output.clone(), provenance });
        Ok(())
    }
}

fn validate_bound_shape(
    value: &Value,
    outputs: &HashMap<String, Retained>,
    depth: usize,
    visited: &mut usize,
) -> Result<(), BatchOperationError> {
    if let Some((operation, pointer)) = reference(value)
        .map_err(|()| binding_error("BATCH_INPUT_BINDING_FAILED"))?
    {
        let selected = outputs.get(operation)
            .and_then(|result| result.output.pointer(pointer))
            .ok_or_else(|| binding_error("BATCH_INPUT_REFERENCE_MISSING"))?;
        // Selected provider data is opaque, not another reference template.
        return validate_data_shape(selected, depth, visited)
            .map_err(|()| binding_error("BATCH_INPUT_LIMIT"));
    }
    if let Value::Object(object) = value
        && object.len() == 1
        && object.contains_key(LITERAL_KEY)
    {
        return validate_data_shape(&object[LITERAL_KEY], depth, visited)
            .map_err(|()| binding_error("BATCH_INPUT_LIMIT"));
    }
    *visited += 1;
    if depth > MAX_DEPTH || *visited > MAX_TEMPLATE_NODES {
        return Err(binding_error("BATCH_INPUT_LIMIT"));
    }
    match value {
        Value::Object(object) => {
            for child in object.values() {
                validate_bound_shape(child, outputs, depth + 1, visited)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                validate_bound_shape(child, outputs, depth + 1, visited)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_provenance(operation: &HttpBatchOperation) -> HostResult<()> {
    if let Some(provenance) = &operation.request.provenance {
        if provenance.origin_zone != operation.request.zone_id
            || provenance.chain.len() >= MAX_PROVENANCE_STEPS
            || provenance.chain.iter().any(|step| step.zone != operation.request.zone_id)
            || measure(provenance, MAX_PROVENANCE_BYTES).is_err()
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn append_chain(target: &mut Provenance, source: &Provenance) -> Result<(), BatchOperationError> {
    for step in &source.chain {
        if !target.chain.contains(step) {
            if target.chain.len() >= MAX_PROVENANCE_STEPS {
                return Err(binding_error("BATCH_INPUT_PROVENANCE_LIMIT"));
            }
            target.chain.push(step.clone());
        }
    }
    // Charge metadata before the resolved request can leave this adapter.
    measure(target, MAX_PROVENANCE_BYTES)
        .map_err(|_| binding_error("BATCH_INPUT_PROVENANCE_LIMIT"))?;
    Ok(())
}

fn reference(value: &Value) -> Result<Option<(&str, &str)>, ()> {
    let Some(object) = value.as_object() else { return Ok(None) };
    let Some(reference) = object.get(REFERENCE_KEY) else { return Ok(None) };
    if object.len() != 1 { return Err(()) }
    let reference = reference.as_object().ok_or(())?;
    if reference.len() != 2 { return Err(()) }
    let operation = reference.get("operation").and_then(Value::as_str).ok_or(())?;
    let pointer = reference.get("pointer").and_then(Value::as_str).ok_or(())?;
    if operation.is_empty() || operation.len() > 128 || !valid_pointer(pointer) { return Err(()) }
    Ok(Some((operation, pointer)))
}

fn valid_pointer(pointer: &str) -> bool {
    if pointer.len() > 1024 || (!pointer.is_empty() && !pointer.starts_with('/')) {
        return false;
    }
    let mut bytes = pointer.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
            return false;
        }
    }
    true
}

fn scan(value: &Value, depth: usize, visited: &mut usize, refs: &mut usize, node: &mut Node) -> HostResult<()> {
    *visited += 1;
    if depth > MAX_DEPTH || *visited > MAX_TEMPLATE_NODES { return Err(invalid()) }
    if let Some((source, _)) = reference(value).map_err(|()| invalid())? {
        *refs += 1;
        if *refs > MAX_REFERENCES { return Err(invalid()) }
        node.references.insert(source.to_owned());
        node.substitutes = true;
        return Ok(());
    }
    match value {
        Value::Object(object) if object.contains_key(LITERAL_KEY) => {
            if object.len() != 1 { return Err(invalid()) }
            // Literal escaping suppresses marker interpretation, not resource
            // limits. Inspect shape without interpreting nested marker keys.
            validate_data_shape(&object[LITERAL_KEY], depth + 1, visited)
                .map_err(|()| invalid())?;
            node.substitutes = true;
        }
        Value::Object(object) => {
            for child in object.values() { scan(child, depth + 1, visited, refs, node)?; }
        }
        Value::Array(array) => {
            for child in array { scan(child, depth + 1, visited, refs, node)?; }
        }
        _ => {}
    }
    Ok(())
}

fn validate_data_shape(value: &Value, depth: usize, visited: &mut usize) -> Result<(), ()> {
    *visited += 1;
    if depth > MAX_DEPTH || *visited > MAX_TEMPLATE_NODES {
        return Err(());
    }
    match value {
        Value::Object(object) => {
            for child in object.values() {
                validate_data_shape(child, depth + 1, visited)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                validate_data_shape(child, depth + 1, visited)?;
            }
        }
        _ => {}
    }
    Ok(())
}

struct BoundValue<'a> {
    value: &'a Value,
    outputs: &'a HashMap<String, Retained>,
}

impl Serialize for BoundValue<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;
        if let Some((operation, pointer)) = reference(self.value)
            .map_err(|()| S::Error::custom("invalid batch reference"))?
        {
            let selected = self.outputs.get(operation).and_then(|result| result.output.pointer(pointer))
                .ok_or_else(|| S::Error::custom("unavailable batch reference"))?;
            // Do not evaluate marker-shaped provider data as another template.
            return selected.serialize(serializer);
        }
        match self.value {
            Value::Object(object) if object.len() == 1 && object.contains_key(LITERAL_KEY) => {
                object[LITERAL_KEY].serialize(serializer)
            }
            Value::Object(object) => {
                let mut map = serializer.serialize_map(Some(object.len()))?;
                for (key, value) in object {
                    map.serialize_entry(key, &Self { value, outputs: self.outputs })?;
                }
                map.end()
            }
            Value::Array(array) => {
                let mut sequence = serializer.serialize_seq(Some(array.len()))?;
                for value in array {
                    sequence.serialize_element(&Self { value, outputs: self.outputs })?;
                }
                sequence.end()
            }
            value => value.serialize(serializer),
        }
    }
}

struct LimitedBuffer {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl LimitedBuffer {
    fn new(limit: usize) -> Self { Self { bytes: Vec::new(), limit, exceeded: false } }
}

impl Write for LimitedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::other("batch input byte limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

fn measure(value: &impl Serialize, limit: usize) -> Result<usize, ()> {
    struct Counter { bytes: usize, limit: usize }
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.bytes) {
                return Err(io::Error::other("batch dataflow byte limit"));
            }
            self.bytes += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
    let mut counter = Counter { bytes: 0, limit };
    serde_json::to_writer(&mut counter, value).map_err(|_| ())?;
    Ok(counter.bytes)
}