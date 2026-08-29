use serde::{Deserialize, Serialize};

// ── Auth ──

/// `PayPal` `OAuth2` `client_credentials` authentication.
#[derive(Clone, Deserialize)]
pub struct PayPalAuth {
    pub client_id: String,
    pub client_secret: String,
}

impl PayPalAuth {
    #[must_use]
    pub fn is_secretless(&self) -> bool {
        self.client_id.trim().is_empty() || self.client_secret.trim().is_empty()
    }
}

impl std::fmt::Debug for PayPalAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PayPalAuth")
            .field("client_id", &"[REDACTED]")
            .field("client_secret", &"[REDACTED]")
            .finish()
    }
}

// ── OAuth token response ──

#[derive(Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub scope: Option<String>,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

impl std::fmt::Display for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TokenResponse(token_type={}, expires_in={:?})",
            self.token_type, self.expires_in
        )
    }
}

// ── Orders ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PayPalOrder {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub intent: Option<String>,
    #[serde(default)]
    pub purchase_units: Vec<PurchaseUnit>,
    #[serde(default)]
    pub create_time: Option<String>,
    #[serde(default)]
    pub update_time: Option<String>,
    #[serde(default)]
    pub links: Vec<HateoasLink>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PurchaseUnit {
    #[serde(default)]
    pub reference_id: Option<String>,
    #[serde(default)]
    pub amount: Option<Amount>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub payments: Option<PaymentCollection>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Amount {
    pub currency_code: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PaymentCollection {
    #[serde(default)]
    pub captures: Vec<Capture>,
    #[serde(default)]
    pub refunds: Vec<Refund>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HateoasLink {
    pub href: String,
    pub rel: String,
    #[serde(default)]
    pub method: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateOrder {
    pub intent: String,
    pub purchase_units: Vec<CreatePurchaseUnit>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreatePurchaseUnit {
    pub amount: Amount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_id: Option<String>,
}

// ── Payments / Captures ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Capture {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub amount: Option<Amount>,
    #[serde(default)]
    pub create_time: Option<String>,
    #[serde(default)]
    pub update_time: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Refund {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub amount: Option<Amount>,
    #[serde(default)]
    pub create_time: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RefundRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<Amount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note_to_payer: Option<String>,
}

// ── Payments search response ──

#[derive(Debug, Clone, Deserialize)]
pub struct TransactionSearchResponse {
    #[serde(default)]
    pub transaction_details: Vec<TransactionDetail>,
    #[serde(default)]
    pub total_items: Option<u32>,
    #[serde(default)]
    pub total_pages: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransactionDetail {
    #[serde(default)]
    pub transaction_info: Option<TransactionInfo>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransactionInfo {
    #[serde(default)]
    pub transaction_id: Option<String>,
    #[serde(default)]
    pub transaction_status: Option<String>,
    #[serde(default)]
    pub transaction_amount: Option<TransactionAmount>,
    #[serde(default)]
    pub transaction_updated_date: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransactionAmount {
    #[serde(default)]
    pub currency_code: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
}

// ── Invoices ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Invoice {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub detail: Option<InvoiceDetail>,
    #[serde(default)]
    pub primary_recipients: Vec<Recipient>,
    #[serde(default)]
    pub items: Vec<InvoiceItem>,
    #[serde(default)]
    pub amount: Option<InvoiceAmount>,
    #[serde(default)]
    pub links: Vec<HateoasLink>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InvoiceDetail {
    #[serde(default)]
    pub invoice_number: Option<String>,
    #[serde(default)]
    pub invoice_date: Option<String>,
    #[serde(default)]
    pub currency_code: Option<String>,
    #[serde(default)]
    pub memo: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Recipient {
    #[serde(default)]
    pub billing_info: Option<BillingInfo>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BillingInfo {
    #[serde(default)]
    pub email_address: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InvoiceItem {
    pub name: String,
    #[serde(default)]
    pub quantity: Option<String>,
    #[serde(default)]
    pub unit_amount: Option<Amount>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InvoiceAmount {
    #[serde(default)]
    pub currency_code: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateInvoice {
    pub detail: CreateInvoiceDetail,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub primary_recipients: Vec<CreateRecipient>,
    pub items: Vec<CreateInvoiceItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateInvoiceDetail {
    pub currency_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invoice_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateRecipient {
    pub billing_info: CreateBillingInfo,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateBillingInfo {
    pub email_address: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateInvoiceItem {
    pub name: String,
    pub quantity: String,
    pub unit_amount: Amount,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct InvoiceSendResponse {
    pub sent: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InvoicesListResponse {
    #[serde(default)]
    pub items: Vec<Invoice>,
    #[serde(default)]
    pub total_items: Option<u32>,
    #[serde(default)]
    pub total_pages: Option<u32>,
}

// ── Error envelope ──

#[derive(Debug, Clone, Deserialize)]
pub struct PayPalErrorResponse {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub debug_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts() {
        let auth = PayPalAuth {
            client_id: "AeB2cXyZ".into(),
            client_secret: "secret123".into(),
        };
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("AeB2cXyZ"));
        assert!(!debug.contains("secret123"));
    }

    #[test]
    fn auth_secretless_empty_id() {
        let auth = PayPalAuth {
            client_id: String::new(),
            client_secret: "secret".into(),
        };
        assert!(auth.is_secretless());
    }

    #[test]
    fn auth_secretless_empty_secret() {
        let auth = PayPalAuth {
            client_id: "id".into(),
            client_secret: " ".into(),
        };
        assert!(auth.is_secretless());
    }

    #[test]
    fn auth_not_secretless() {
        let auth = PayPalAuth {
            client_id: "id".into(),
            client_secret: "secret".into(),
        };
        assert!(!auth.is_secretless());
    }

    #[test]
    fn deserialize_order() {
        let json = serde_json::json!({
            "id": "5O190127TN364715T",
            "status": "CREATED",
            "intent": "CAPTURE",
            "purchase_units": [{
                "amount": {
                    "currency_code": "USD",
                    "value": "100.00"
                }
            }],
            "links": [{
                "href": "https://api.paypal.com/v2/checkout/orders/5O",
                "rel": "self",
                "method": "GET"
            }]
        });
        let order: PayPalOrder = serde_json::from_value(json).unwrap();
        assert_eq!(order.id, "5O190127TN364715T");
        assert_eq!(order.status, "CREATED");
        assert_eq!(order.purchase_units.len(), 1);
        assert_eq!(order.links.len(), 1);
    }

    #[test]
    fn deserialize_capture() {
        let json = serde_json::json!({
            "id": "2GG279541U",
            "status": "COMPLETED",
            "amount": {
                "currency_code": "USD",
                "value": "50.00"
            }
        });
        let capture: Capture = serde_json::from_value(json).unwrap();
        assert_eq!(capture.status, "COMPLETED");
    }

    #[test]
    fn deserialize_refund() {
        let json = serde_json::json!({
            "id": "1JU",
            "status": "COMPLETED",
            "amount": {
                "currency_code": "USD",
                "value": "10.00"
            }
        });
        let refund: Refund = serde_json::from_value(json).unwrap();
        assert_eq!(refund.status, "COMPLETED");
    }

    #[test]
    fn deserialize_invoice() {
        let json = serde_json::json!({
            "id": "INV2-Z56S-5LLA",
            "status": "DRAFT",
            "detail": {
                "invoice_number": "0001",
                "currency_code": "USD"
            },
            "items": [{
                "name": "Widget",
                "quantity": "1",
                "unit_amount": {
                    "currency_code": "USD",
                    "value": "25.00"
                }
            }]
        });
        let invoice: Invoice = serde_json::from_value(json).unwrap();
        assert_eq!(invoice.id, "INV2-Z56S-5LLA");
        assert_eq!(invoice.status, "DRAFT");
    }

    #[test]
    fn serialize_create_order() {
        let order = CreateOrder {
            intent: "CAPTURE".into(),
            purchase_units: vec![CreatePurchaseUnit {
                amount: Amount {
                    currency_code: "USD".into(),
                    value: "100.00".into(),
                },
                description: Some("Test purchase".into()),
                reference_id: None,
            }],
        };
        let json = serde_json::to_value(&order).unwrap();
        assert_eq!(json["intent"], "CAPTURE");
        assert_eq!(json["purchase_units"][0]["amount"]["value"], "100.00");
    }

    #[test]
    fn serialize_create_invoice() {
        let invoice = CreateInvoice {
            detail: CreateInvoiceDetail {
                currency_code: "USD".into(),
                invoice_number: Some("INV-001".into()),
                memo: None,
            },
            primary_recipients: vec![CreateRecipient {
                billing_info: CreateBillingInfo {
                    email_address: "buyer@example.com".into(),
                },
            }],
            items: vec![CreateInvoiceItem {
                name: "Service".into(),
                quantity: "1".into(),
                unit_amount: Amount {
                    currency_code: "USD".into(),
                    value: "150.00".into(),
                },
            }],
        };
        let json = serde_json::to_value(&invoice).unwrap();
        assert_eq!(json["detail"]["currency_code"], "USD");
        assert_eq!(json["items"][0]["name"], "Service");
    }

    #[test]
    fn serialize_refund_request() {
        let refund = RefundRequest {
            amount: Some(Amount {
                currency_code: "USD".into(),
                value: "25.00".into(),
            }),
            note_to_payer: Some("Refund for damaged item".into()),
        };
        let json = serde_json::to_value(&refund).unwrap();
        assert_eq!(json["amount"]["value"], "25.00");
    }

    #[test]
    fn deserialize_token_response() {
        let json = serde_json::json!({
            "access_token": "A21AAF...",
            "token_type": "Bearer",
            "expires_in": 32400,
            "scope": "https://uri.paypal.com/services/invoicing"
        });
        let tok: TokenResponse = serde_json::from_value(json).unwrap();
        assert_eq!(tok.token_type, "Bearer");
        assert_eq!(tok.expires_in, Some(32400));
    }

    #[test]
    fn deserialize_invoices_list() {
        let json = serde_json::json!({
            "items": [{
                "id": "INV2-1",
                "status": "SENT",
                "items": []
            }],
            "total_items": 1
        });
        let resp: InvoicesListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.items.len(), 1);
    }
}
