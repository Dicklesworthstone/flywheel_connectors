//! Native AWS response envelopes, separate from normalized FCP output types.
//!
//! S3, EC2 and STS return XML. Lambda lists use PascalCase JSON; invocation
//! metadata comes from HTTP status and headers, never from the function payload.
//! Wire contracts:
//! https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html
//! https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html
//! https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_StartInstances.html
//! https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
//! https://docs.aws.amazon.com/lambda/latest/api/API_ListFunctions.html
//! https://docs.aws.amazon.com/lambda/latest/api/API_Invoke.html

use quick_xml::{Reader, events::Event};
use serde::{Deserialize, de::DeserializeOwned};

use crate::types::{
    CallerIdentity, Ec2Instance, Ec2StateChange, Ec2Tag, LambdaFunction, LambdaInvokeResponse,
    S3Bucket, S3Object,
};

const MAX_METADATA_BYTES: usize = 10 * 1024 * 1024;
const MAX_XML_DEPTH: usize = 64;

/// Redaction-safe decoding failure. Never retains the provider's body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderDecodeError {
    pub(crate) service: &'static str,
    pub(crate) detail: &'static str,
}

impl std::fmt::Display for ProviderDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid AWS response: {}", self.detail)
    }
}

impl std::error::Error for ProviderDecodeError {}

type ProviderResult<T> = Result<T, ProviderDecodeError>;

/// One provider page. Continuation markers are opaque; the transport must
/// encode them as query parameters and preserve its overall request budget.
#[derive(Debug)]
pub(crate) struct ProviderPage<T> {
    pub(crate) items: Vec<T>,
    pub(crate) next_token: Option<String>,
}

const fn invalid_response(service: &'static str, detail: &'static str) -> ProviderDecodeError {
    ProviderDecodeError { service, detail }
}

fn check_body_size(body: &[u8], service: &'static str) -> ProviderResult<()> {
    if body.len() > MAX_METADATA_BYTES {
        return Err(invalid_response(
            service,
            "metadata exceeds the response limit",
        ));
    }
    Ok(())
}

/// Serde's XML mapping does not bind a struct to its root element. Validate
/// the complete document first, rejecting DTDs, extra roots and deep nesting.
fn parse_xml<T: DeserializeOwned>(
    body: &[u8],
    service: &'static str,
    expected_root: &[u8],
) -> ProviderResult<T> {
    check_body_size(body, service)?;
    let mut reader = Reader::from_reader(body);
    reader.config_mut().enable_all_checks(true);
    reader.config_mut().expand_empty_elements = true;
    let mut depth = 0_usize;
    let mut seen_root = false;
    loop {
        match reader
            .read_event()
            .map_err(|_| invalid_response(service, "malformed XML document"))?
        {
            Event::Start(element) => {
                if depth == 0 {
                    if seen_root || element.local_name().as_ref() != expected_root {
                        return Err(invalid_response(
                            service,
                            "unexpected XML response envelope",
                        ));
                    }
                    seen_root = true;
                }
                depth += 1;
                if depth > MAX_XML_DEPTH {
                    return Err(invalid_response(
                        service,
                        "XML nesting exceeds the response limit",
                    ));
                }
            }
            Event::End(_) => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| invalid_response(service, "unbalanced XML document"))?;
            }
            Event::Text(text) if depth == 0 => {
                if text.as_ref().iter().any(|byte| !byte.is_ascii_whitespace()) {
                    return Err(invalid_response(
                        service,
                        "content outside the XML envelope",
                    ));
                }
            }
            Event::DocType(_) => {
                return Err(invalid_response(
                    service,
                    "XML document types are not supported",
                ));
            }
            Event::CData(_) | Event::GeneralRef(_) if depth == 0 => {
                return Err(invalid_response(
                    service,
                    "content outside the XML envelope",
                ));
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if !seen_root || depth != 0 {
        return Err(invalid_response(
            service,
            "incomplete XML response envelope",
        ));
    }
    quick_xml::de::from_reader(body)
        .map_err(|_| invalid_response(service, "XML response fields do not match the operation"))
}

fn continuation(token: Option<String>) -> Option<String> {
    token.filter(|value| !value.is_empty())
}

#[derive(Deserialize)]
struct S3BucketsResponse {
    #[serde(rename = "Buckets")]
    buckets: S3Buckets,
    #[serde(rename = "ContinuationToken")]
    continuation_token: Option<String>,
}

#[derive(Deserialize)]
struct S3Buckets {
    #[serde(rename = "Bucket", default)]
    buckets: Vec<S3BucketXml>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct S3BucketXml {
    name: String,
    creation_date: Option<String>,
}

pub(crate) fn parse_s3_buckets(body: &[u8]) -> ProviderResult<ProviderPage<S3Bucket>> {
    let response: S3BucketsResponse = parse_xml(body, "s3", b"ListAllMyBucketsResult")?;
    let mut items = Vec::with_capacity(response.buckets.buckets.len());
    for bucket in response.buckets.buckets {
        if bucket.name.is_empty() {
            return Err(invalid_response("s3", "bucket is missing its name"));
        }
        items.push(S3Bucket {
            name: bucket.name,
            creation_date: bucket.creation_date,
        });
    }
    Ok(ProviderPage {
        items,
        next_token: continuation(response.continuation_token),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct S3ObjectsResponse {
    #[serde(rename = "Contents", default)]
    contents: Vec<S3ObjectXml>,
    is_truncated: bool,
    next_continuation_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct S3ObjectXml {
    key: String,
    size: Option<u64>,
    last_modified: Option<String>,
    #[serde(rename = "ETag")]
    etag: Option<String>,
    storage_class: Option<String>,
}

pub(crate) fn parse_s3_objects(body: &[u8]) -> ProviderResult<ProviderPage<S3Object>> {
    let response: S3ObjectsResponse = parse_xml(body, "s3", b"ListBucketResult")?;
    let next_token = continuation(response.next_continuation_token);
    if response.is_truncated != next_token.is_some() {
        return Err(invalid_response(
            "s3",
            "inconsistent object-list continuation",
        ));
    }
    let mut items = Vec::with_capacity(response.contents.len());
    for object in response.contents {
        if object.key.is_empty() {
            return Err(invalid_response("s3", "object is missing its key"));
        }
        items.push(S3Object {
            key: object.key,
            size: object.size,
            last_modified: object.last_modified,
            etag: object.etag,
            storage_class: object.storage_class,
        });
    }
    Ok(ProviderPage { items, next_token })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ec2DescribeResponse {
    reservation_set: Ec2Reservations,
    next_token: Option<String>,
}

#[derive(Deserialize)]
struct Ec2Reservations {
    #[serde(rename = "item", default)]
    reservations: Vec<Ec2Reservation>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ec2Reservation {
    instances_set: Ec2Instances,
}

#[derive(Deserialize)]
struct Ec2Instances {
    #[serde(rename = "item", default)]
    instances: Vec<Ec2InstanceXml>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ec2InstanceXml {
    instance_id: String,
    instance_type: Option<String>,
    instance_state: Option<Ec2StateXml>,
    ip_address: Option<String>,
    private_ip_address: Option<String>,
    launch_time: Option<String>,
    tag_set: Option<Ec2Tags>,
}

#[derive(Deserialize)]
struct Ec2StateXml {
    name: String,
}

#[derive(Deserialize)]
struct Ec2Tags {
    #[serde(rename = "item", default)]
    tags: Vec<Ec2Tag>,
}

pub(crate) fn parse_ec2_instances(body: &[u8]) -> ProviderResult<ProviderPage<Ec2Instance>> {
    let response: Ec2DescribeResponse = parse_xml(body, "ec2", b"DescribeInstancesResponse")?;
    let mut items = Vec::new();
    for reservation in response.reservation_set.reservations {
        for instance in reservation.instances_set.instances {
            if instance.instance_id.is_empty() {
                return Err(invalid_response("ec2", "instance is missing its identity"));
            }
            items.push(Ec2Instance {
                instance_id: instance.instance_id,
                instance_type: instance.instance_type,
                state: instance.instance_state.map(|state| state.name),
                public_ip: instance.ip_address,
                private_ip: instance.private_ip_address,
                launch_time: instance.launch_time,
                tags: instance.tag_set.map(|tags| tags.tags),
            });
        }
    }
    Ok(ProviderPage {
        items,
        next_token: continuation(response.next_token),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ec2ChangeResponse {
    instances_set: Ec2Changes,
}

#[derive(Deserialize)]
struct Ec2Changes {
    #[serde(rename = "item", default)]
    changes: Vec<Ec2ChangeXml>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ec2ChangeXml {
    instance_id: String,
    previous_state: Ec2StateXml,
    current_state: Ec2StateXml,
}

pub(crate) fn parse_ec2_state_change(
    body: &[u8],
    action: &str,
    expected_instance_id: &str,
) -> ProviderResult<Ec2StateChange> {
    let root: &[u8] = match action {
        "StartInstances" => b"StartInstancesResponse",
        "StopInstances" => b"StopInstancesResponse",
        "TerminateInstances" => b"TerminateInstancesResponse",
        _ => return Err(invalid_response("ec2", "unsupported instance state action")),
    };
    let response: Ec2ChangeResponse = parse_xml(body, "ec2", root)?;
    let mut changes = response.instances_set.changes.into_iter();
    let change = changes
        .next()
        .ok_or_else(|| invalid_response("ec2", "missing instance state change"))?;
    if changes.next().is_some() || change.instance_id != expected_instance_id {
        return Err(invalid_response(
            "ec2",
            "state change does not bind the requested instance",
        ));
    }
    if change.previous_state.name.is_empty() || change.current_state.name.is_empty() {
        return Err(invalid_response(
            "ec2",
            "instance state change is incomplete",
        ));
    }
    Ok(Ec2StateChange {
        instance_id: change.instance_id,
        previous_state: change.previous_state.name,
        current_state: change.current_state.name,
    })
}

#[derive(Deserialize)]
struct StsIdentityResponse {
    #[serde(rename = "GetCallerIdentityResult")]
    result: StsIdentity,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct StsIdentity {
    account: String,
    arn: String,
    user_id: String,
}

pub(crate) fn parse_caller_identity(body: &[u8]) -> ProviderResult<CallerIdentity> {
    let response: StsIdentityResponse = parse_xml(body, "sts", b"GetCallerIdentityResponse")?;
    if response.result.account.is_empty()
        || response.result.arn.is_empty()
        || response.result.user_id.is_empty()
    {
        return Err(invalid_response("sts", "caller identity is incomplete"));
    }
    Ok(CallerIdentity {
        account: response.result.account,
        arn: response.result.arn,
        user_id: response.result.user_id,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct LambdaFunctionsResponse {
    functions: Vec<LambdaFunctionJson>,
    next_marker: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct LambdaFunctionJson {
    function_name: String,
    function_arn: Option<String>,
    runtime: Option<String>,
    handler: Option<String>,
    memory_size: Option<u32>,
    timeout: Option<u32>,
    last_modified: Option<String>,
    state: Option<String>,
}

pub(crate) fn parse_lambda_functions(body: &[u8]) -> ProviderResult<ProviderPage<LambdaFunction>> {
    check_body_size(body, "lambda")?;
    let response: LambdaFunctionsResponse = serde_json::from_slice(body)
        .map_err(|_| invalid_response("lambda", "invalid ListFunctions response envelope"))?;
    let mut items = Vec::with_capacity(response.functions.len());
    for function in response.functions {
        if function.function_name.is_empty() {
            return Err(invalid_response("lambda", "function is missing its name"));
        }
        items.push(LambdaFunction {
            function_name: function.function_name,
            function_arn: function.function_arn,
            runtime: function.runtime,
            handler: function.handler,
            memory_size: function.memory_size,
            timeout: function.timeout,
            last_modified: function.last_modified,
            state: function.state,
        });
    }
    Ok(ProviderPage {
        items,
        next_token: continuation(response.next_marker),
    })
}

pub(crate) fn parse_lambda_invoke(
    status: u16,
    function_error: Option<String>,
    executed_version: Option<String>,
    body: &[u8],
) -> ProviderResult<LambdaInvokeResponse> {
    check_body_size(body, "lambda")?;
    // The function payload may itself contain status_code or payload fields.
    // Only HTTP metadata defines the outer result; never unwrap user content.
    let payload = if body.is_empty() && matches!(status, 202 | 204) {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(body)
            .map_err(|_| invalid_response("lambda", "invalid invocation JSON payload"))?
    };
    Ok(LambdaInvokeResponse {
        status_code: status,
        function_error,
        payload,
        executed_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_buckets_decode_native_namespace_and_continuation() {
        let page = parse_s3_buckets(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner><ID>owner</ID></Owner>
  <Buckets>
    <Bucket><Name>alpha</Name><CreationDate>2026-01-01T00:00:00Z</CreationDate></Bucket>
    <Bucket><Name>beta</Name></Bucket>
  </Buckets>
  <ContinuationToken>a+/=&amp;next</ContinuationToken>
</ListAllMyBucketsResult>"#,
        )
        .unwrap();
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].name, "alpha");
        assert_eq!(
            page.items[0].creation_date.as_deref(),
            Some("2026-01-01T00:00:00Z")
        );
        assert_eq!(page.items[1].name, "beta");
        assert!(page.items[1].creation_date.is_none());
        assert_eq!(page.next_token.as_deref(), Some("a+/=&next"));
    }

    #[test]
    fn empty_native_list_envelopes_are_valid() {
        assert!(
            parse_s3_buckets(b"<ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>")
                .unwrap()
                .items
                .is_empty()
        );
        assert!(
            parse_ec2_instances(
                b"<DescribeInstancesResponse><reservationSet/></DescribeInstancesResponse>"
            )
            .unwrap()
            .items
            .is_empty()
        );
        let functions = parse_lambda_functions(br#"{"Functions":[]}"#).unwrap();
        assert!(functions.items.is_empty());
        assert!(functions.next_token.is_none());
    }

    #[test]
    fn s3_objects_decode_native_metadata_and_pagination() {
        let page = parse_s3_objects(
            br#"<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<IsTruncated>true</IsTruncated><NextContinuationToken>next+/=</NextContinuationToken>
<Contents><Key>path/a&amp;b</Key><Size>42</Size><ETag>&quot;etag&quot;</ETag>
<LastModified>2026-01-01</LastModified><StorageClass>STANDARD</StorageClass></Contents>
</ListBucketResult>"#,
        )
        .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].key, "path/a&b");
        assert_eq!(page.items[0].size, Some(42));
        assert_eq!(page.items[0].etag.as_deref(), Some("\"etag\""));
        assert_eq!(page.next_token.as_deref(), Some("next+/="));
        assert!(
            parse_s3_objects(
                b"<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>"
            )
            .unwrap()
            .items
            .is_empty()
        );
    }

    #[test]
    fn s3_objects_refuse_missing_keys_and_lost_continuations() {
        for body in [
            "<ListBucketResult/>",
            "<ListBucketResult><Contents><Key>present</Key></Contents></ListBucketResult>",
            "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Size>42</Size></Contents></ListBucketResult>",
            "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key/></Contents></ListBucketResult>",
            "<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>",
            "<ListBucketResult><IsTruncated>false</IsTruncated><NextContinuationToken>next</NextContinuationToken></ListBucketResult>",
            "<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken/></ListBucketResult>",
        ] {
            assert!(parse_s3_objects(body.as_bytes()).is_err());
        }
    }

    #[test]
    fn ec2_flattens_reservations_without_losing_instance_metadata() {
        let page = parse_ec2_instances(
            br#"<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <requestId>request</requestId>
  <reservationSet>
    <item><reservationId>r-one</reservationId><instancesSet><item>
      <instanceId>i-one</instanceId><instanceType>t3.micro</instanceType>
      <instanceState><code>16</code><name>running</name></instanceState>
      <ipAddress>192.0.2.1</ipAddress><privateIpAddress>10.0.0.1</privateIpAddress>
      <launchTime>2026-01-02T00:00:00Z</launchTime>
      <tagSet><item><key>Name</key><value>build &amp; test</value></item></tagSet>
    </item></instancesSet></item>
    <item><instancesSet><item><instanceId>i-two</instanceId></item></instancesSet></item>
  </reservationSet>
  <nextToken>opaque+/=</nextToken>
</DescribeInstancesResponse>"#,
        )
        .unwrap();
        assert_eq!(page.items.len(), 2);
        let instance = &page.items[0];
        assert_eq!(instance.instance_id, "i-one");
        assert_eq!(instance.instance_type.as_deref(), Some("t3.micro"));
        assert_eq!(instance.state.as_deref(), Some("running"));
        assert_eq!(instance.public_ip.as_deref(), Some("192.0.2.1"));
        assert_eq!(instance.private_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(instance.tags.as_ref().unwrap()[0].value, "build & test");
        assert_eq!(page.items[1].instance_id, "i-two");
        assert!(page.items[1].state.is_none());
        assert_eq!(page.next_token.as_deref(), Some("opaque+/="));
    }

    fn change_response(action: &str, instance_id: &str) -> String {
        format!(
            "<{action}Response><instancesSet><item><instanceId>{instance_id}</instanceId>\
             <currentState><code>0</code><name>pending</name></currentState>\
             <previousState><code>80</code><name>stopped</name></previousState>\
             </item></instancesSet></{action}Response>"
        )
    }

    #[test]
    fn ec2_mutation_response_binds_action_and_instance() {
        for action in ["StartInstances", "StopInstances", "TerminateInstances"] {
            let response = change_response(action, "i-one");
            let change = parse_ec2_state_change(response.as_bytes(), action, "i-one").unwrap();
            assert_eq!(change.instance_id, "i-one");
            assert_eq!(change.previous_state, "stopped");
            assert_eq!(change.current_state, "pending");
            assert!(parse_ec2_state_change(response.as_bytes(), action, "i-other").is_err());
        }
        assert!(
            parse_ec2_state_change(
                change_response("StopInstances", "i-one").as_bytes(),
                "StartInstances",
                "i-one",
            )
            .is_err()
        );
        assert!(
            parse_ec2_state_change(
                b"<StartInstancesResponse><instancesSet/></StartInstancesResponse>",
                "StartInstances",
                "i-one",
            )
            .is_err()
        );
    }

    #[test]
    fn ec2_duplicate_state_changes_are_not_silently_accepted() {
        let response = br#"<StartInstancesResponse><instancesSet>
<item><instanceId>i-one</instanceId><previousState><name>stopped</name></previousState><currentState><name>pending</name></currentState></item>
<item><instanceId>i-one</instanceId><previousState><name>stopped</name></previousState><currentState><name>pending</name></currentState></item>
</instancesSet></StartInstancesResponse>"#;
        assert!(parse_ec2_state_change(response, "StartInstances", "i-one").is_err());
    }

    #[test]
    fn sts_decodes_wrapped_native_identity() {
        let identity = parse_caller_identity(
            br#"<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
<GetCallerIdentityResult><Account>123456789012</Account>
<Arn>arn:aws:sts::123456789012:assumed-role/test/session</Arn><UserId>ROLE:session</UserId>
</GetCallerIdentityResult><ResponseMetadata><RequestId>request</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>"#,
        )
        .unwrap();
        assert_eq!(identity.account, "123456789012");
        assert_eq!(identity.user_id, "ROLE:session");
        assert!(identity.arn.ends_with("/session"));
    }

    #[test]
    fn lambda_list_decodes_native_fields_and_marker() {
        let page = parse_lambda_functions(
            br#"{"Functions":[{"FunctionName":"sync","FunctionArn":"arn:example",
"Runtime":"provided.al2023","Handler":"bootstrap","MemorySize":256,
"Timeout":30,"LastModified":"2026-01-01","PackageType":"Zip"}],"NextMarker":"next+/="}"#,
        )
        .unwrap();
        assert_eq!(page.items.len(), 1);
        let function = &page.items[0];
        assert_eq!(function.function_name, "sync");
        assert_eq!(function.memory_size, Some(256));
        assert_eq!(function.runtime.as_deref(), Some("provided.al2023"));
        assert!(function.state.is_none());
        assert_eq!(page.next_token.as_deref(), Some("next+/="));
    }

    #[test]
    fn lambda_http_metadata_cannot_be_forged_by_function_payload() {
        let body = br#"{"status_code":503,"function_error":null,"payload":{"ok":true},"executed_version":"forged"}"#;
        let response = parse_lambda_invoke(
            200,
            Some("Unhandled".to_owned()),
            Some("42".to_owned()),
            body,
        )
        .unwrap();
        assert_eq!(response.status_code, 200);
        assert_eq!(response.function_error.as_deref(), Some("Unhandled"));
        assert_eq!(response.executed_version.as_deref(), Some("42"));
        assert_eq!(
            response.payload,
            serde_json::from_slice::<serde_json::Value>(body).unwrap()
        );
    }

    #[test]
    fn lambda_invocation_supports_json_values_and_empty_async_responses() {
        for body in [b"null".as_slice(), b"[1,2]", b"42", br#""text""#] {
            assert!(parse_lambda_invoke(200, None, None, body).is_ok());
        }
        for status in [202, 204] {
            assert!(
                parse_lambda_invoke(status, None, None, b"")
                    .unwrap()
                    .payload
                    .is_null()
            );
        }
        assert!(parse_lambda_invoke(200, None, None, b"").is_err());
        assert!(parse_lambda_invoke(200, None, None, b"<html>bad gateway</html>").is_err());
    }

    #[test]
    fn native_decoders_reject_fixture_shapes_and_missing_fields() {
        assert!(parse_s3_buckets(br#"[{"name":"fixture"}]"#).is_err());
        assert!(parse_ec2_instances(br#"[{"instance_id":"fixture"}]"#).is_err());
        assert!(
            parse_caller_identity(br#"{"account":"fixture","arn":"fixture","user_id":"fixture"}"#)
                .is_err()
        );
        assert!(parse_lambda_functions(br#"[{"function_name":"fixture"}]"#).is_err());
        assert!(parse_lambda_functions(br#"{"Functions":[{}]}"#).is_err());
        assert!(parse_lambda_functions(br#"{"Functions":[{"FunctionName":""}]}"#).is_err());
        assert!(parse_caller_identity(
            b"<GetCallerIdentityResponse><GetCallerIdentityResult><Account>a</Account></GetCallerIdentityResult></GetCallerIdentityResponse>"
        ).is_err());
    }

    #[test]
    fn xml_requires_one_complete_expected_root_without_dtd() {
        for body in [
            "<Error><Code>AccessDenied</Code><Buckets/></Error>",
            "<ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult><extra/>",
            "<ListAllMyBucketsResult><Buckets/>",
            "<!DOCTYPE ListAllMyBucketsResult [<!ENTITY x SYSTEM 'file:///secret'>]><ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>",
            "<ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>trailing",
            "<ListAllMyBucketsResult><!-- a -- b --><Buckets/></ListAllMyBucketsResult>",
        ] {
            assert!(parse_s3_buckets(body.as_bytes()).is_err());
        }
    }

    #[test]
    fn decode_errors_are_bounded_and_do_not_echo_provider_content() {
        let sensitive = "do-not-log-this-provider-value";
        let body = format!(
            "<GetCallerIdentityResponse><GetCallerIdentityResult><Account>{sensitive}</Account>\
             <Arn>arn</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>"
        );
        let error = parse_caller_identity(body.as_bytes()).unwrap_err();
        assert!(!error.to_string().contains(sensitive));
        let too_deep = format!(
            "<ListAllMyBucketsResult><Buckets/>{}{}</ListAllMyBucketsResult>",
            "<nested>".repeat(MAX_XML_DEPTH),
            "</nested>".repeat(MAX_XML_DEPTH),
        );
        assert!(parse_s3_buckets(too_deep.as_bytes()).is_err());
        assert!(parse_lambda_functions(&vec![b' '; MAX_METADATA_BYTES + 1]).is_err());
    }
}
