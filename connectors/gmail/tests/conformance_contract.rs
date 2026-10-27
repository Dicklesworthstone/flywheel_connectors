use fcp_gmail::{connector::GmailConnector, error::GmailError};
use fcp_prelude::FcpError;
use fcp_testkit::{OperationContract, assert_operation_contracts};

#[fcp_async_core::runtime::test]
async fn gmail_schema_operation_and_error_contracts_are_advertised() {
    let connector = GmailConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("gmail introspection should serialize");

    assert_operation_contracts(
        &introspection,
        &[
            OperationContract {
                id: "gmail.get_message",
                capability: "gmail.read",
                required_input_fields: &["message_id"],
                output_fields: &["message"],
            },
            OperationContract {
                id: "gmail.get_attachment",
                capability: "gmail.read",
                required_input_fields: &["message_id", "attachment_id"],
                output_fields: &["attachment"],
            },
            OperationContract {
                id: "gmail.sync_history",
                capability: "gmail.history.read",
                required_input_fields: &["lease_seq"],
                output_fields: &["history", "latest_history_id", "effective_start_history_id"],
            },
            OperationContract {
                id: "gmail.send_draft",
                capability: "gmail.send",
                required_input_fields: &["draft_id"],
                output_fields: &["message"],
            },
        ],
    );

    assert!(matches!(
        GmailError::Unauthorized.to_fcp_error(),
        FcpError::Unauthorized { .. }
    ));
    assert!(matches!(
        GmailError::RateLimited {
            retry_after_secs: 3,
        }
        .to_fcp_error(),
        FcpError::RateLimited {
            retry_after_ms: 3_000,
            ..
        }
    ));
    assert!(matches!(
        GmailError::MessageNotFound {
            message_id: "m1".into(),
        }
        .to_fcp_error(),
        FcpError::ResourceNotFound {
            ref resource,
            ..
        } if resource == "message:m1"
    ));
}
