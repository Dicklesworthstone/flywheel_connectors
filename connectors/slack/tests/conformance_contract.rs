use fcp_prelude::FcpError;
use fcp_slack::{connector::SlackConnector, error::SlackError};
use fcp_testkit::{OperationContract, assert_operation_contracts};

#[fcp_async_core::runtime::test]
async fn slack_schema_operation_and_error_contracts_are_advertised() {
    let connector = SlackConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("slack introspection should serialize");

    assert_operation_contracts(
        &introspection,
        &[
            OperationContract {
                id: "slack.post_message",
                capability: "slack.write",
                required_input_fields: &["channel", "text"],
                output_fields: &["message"],
            },
            OperationContract {
                id: "slack.list_channels",
                capability: "slack.read",
                required_input_fields: &[],
                output_fields: &["channels"],
            },
            OperationContract {
                id: "slack.upload_file",
                capability: "slack.files.write",
                required_input_fields: &["channels"],
                output_fields: &["file", "content_length", "content_sha256", "receipt"],
            },
            OperationContract {
                id: "slack.download_file",
                capability: "slack.files.read",
                required_input_fields: &["file_id"],
                output_fields: &["file", "content_base64", "content_length", "content_sha256"],
            },
        ],
    );

    assert!(matches!(
        SlackError::Unauthorized.to_fcp_error(),
        FcpError::Unauthorized { .. }
    ));
    assert!(matches!(
        SlackError::RateLimited {
            retry_after_secs: 2,
        }
        .to_fcp_error(),
        FcpError::RateLimited {
            retry_after_ms: 2_000,
            ..
        }
    ));
    assert!(matches!(
        SlackError::Api {
            error: "missing_scope".into(),
            code: None,
            ok: false,
        }
        .to_fcp_error(),
        FcpError::CapabilityDenied { .. }
    ));
}
