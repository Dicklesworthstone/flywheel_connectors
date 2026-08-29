use fcp_prelude::CredentialId;
use serde::{Deserialize, Serialize};

// ── Auth ──

/// Shopify authentication for the Admin API.
#[derive(Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ShopifyAuth {
    AccessToken { access_token: String },
    CredentialId { credential_id: CredentialId },
}

impl ShopifyAuth {
    #[must_use]
    pub const fn redacted_label(&self) -> &'static str {
        match self {
            Self::AccessToken { .. } => "access_token",
            Self::CredentialId { .. } => "credential_id",
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId { .. })
    }
}

impl std::fmt::Debug for ShopifyAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccessToken { .. } => f
                .debug_struct("AccessToken")
                .field("access_token", &"[REDACTED]")
                .finish(),
            Self::CredentialId { credential_id } => f
                .debug_struct("CredentialId")
                .field("credential_id", credential_id)
                .finish(),
        }
    }
}

// ── Products ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Product {
    pub id: u64,
    pub title: String,
    #[serde(default)]
    pub body_html: Option<String>,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub product_type: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub tags: Option<String>,
    #[serde(default)]
    pub variants: Vec<Variant>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Variant {
    pub id: Option<u64>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub price: Option<String>,
    #[serde(default)]
    pub sku: Option<String>,
    #[serde(default)]
    pub inventory_quantity: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateProduct {
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_html: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub variants: Vec<CreateVariant>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateVariant {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sku: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateProduct {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_html: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,
}

// ── Orders ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Order {
    pub id: u64,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub total_price: Option<String>,
    #[serde(default)]
    pub currency: Option<String>,
    #[serde(default)]
    pub financial_status: Option<String>,
    #[serde(default)]
    pub fulfillment_status: Option<String>,
    #[serde(default)]
    pub line_items: Vec<LineItem>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LineItem {
    #[serde(default)]
    pub id: Option<u64>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub quantity: Option<i64>,
    #[serde(default)]
    pub price: Option<String>,
    #[serde(default)]
    pub variant_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateOrder {
    pub line_items: Vec<CreateLineItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub financial_status: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateLineItem {
    pub variant_id: u64,
    pub quantity: i64,
}

// ── Customers ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Customer {
    pub id: u64,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub orders_count: Option<u64>,
    #[serde(default)]
    pub total_spent: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

// ── Inventory ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InventoryLevel {
    #[serde(default)]
    pub inventory_item_id: Option<u64>,
    #[serde(default)]
    pub location_id: Option<u64>,
    #[serde(default)]
    pub available: Option<i64>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

// ── Response wrappers ──

#[derive(Debug, Clone, Deserialize)]
pub struct ProductsResponse {
    pub products: Vec<Product>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProductResponse {
    pub product: Product,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OrdersResponse {
    pub orders: Vec<Order>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OrderResponse {
    pub order: Order,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CustomersResponse {
    pub customers: Vec<Customer>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CustomerResponse {
    pub customer: Customer,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InventoryLevelsResponse {
    pub inventory_levels: Vec<InventoryLevel>,
}

// ── Shop info for health check ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Shop {
    pub id: u64,
    pub name: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub plan_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ShopResponse {
    pub shop: Shop,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = ShopifyAuth::AccessToken {
            access_token: "shpat_secret123".into(),
        };
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("shpat_secret123"));
    }

    #[test]
    fn auth_debug_shows_credential_id() {
        let auth = ShopifyAuth::CredentialId {
            credential_id: CredentialId::parse("12345678-1234-5678-1234-567812345678").unwrap(),
        };
        let debug = format!("{auth:?}");
        assert!(debug.contains("CredentialId"));
        assert!(debug.contains("12345678-1234-5678-1234-567812345678"));
    }

    #[test]
    fn auth_secretless_credential_id() {
        let auth = ShopifyAuth::CredentialId {
            credential_id: CredentialId::parse("12345678-1234-5678-1234-567812345678").unwrap(),
        };
        assert!(auth.is_secretless());
    }

    #[test]
    fn auth_secretless_access_token_disabled() {
        let auth = ShopifyAuth::AccessToken {
            access_token: "shpat_token".into(),
        };
        assert!(!auth.is_secretless());
    }

    #[test]
    fn deserialize_product() {
        let json = serde_json::json!({
            "id": 123_456,
            "title": "Test Product",
            "vendor": "TestVendor",
            "status": "active",
            "variants": [{
                "id": 789,
                "title": "Default",
                "price": "29.99",
                "sku": "TEST-001"
            }]
        });
        let product: Product = serde_json::from_value(json).unwrap();
        assert_eq!(product.id, 123_456);
        assert_eq!(product.title, "Test Product");
        assert_eq!(product.variants.len(), 1);
        assert_eq!(product.variants[0].price.as_deref(), Some("29.99"));
    }

    #[test]
    fn deserialize_order() {
        let json = serde_json::json!({
            "id": 9999,
            "name": "#1001",
            "total_price": "49.99",
            "currency": "USD",
            "financial_status": "paid",
            "line_items": [{
                "id": 111,
                "title": "Widget",
                "quantity": 2,
                "price": "24.99"
            }]
        });
        let order: Order = serde_json::from_value(json).unwrap();
        assert_eq!(order.id, 9999);
        assert_eq!(order.name.as_deref(), Some("#1001"));
        assert_eq!(order.line_items.len(), 1);
    }

    #[test]
    fn deserialize_customer() {
        let json = serde_json::json!({
            "id": 555,
            "first_name": "Jane",
            "last_name": "Doe",
            "email": "jane@example.com",
            "orders_count": 5,
            "total_spent": "199.95"
        });
        let customer: Customer = serde_json::from_value(json).unwrap();
        assert_eq!(customer.id, 555);
        assert_eq!(customer.email.as_deref(), Some("jane@example.com"));
    }

    #[test]
    fn deserialize_inventory_level() {
        let json = serde_json::json!({
            "inventory_item_id": 808,
            "location_id": 303,
            "available": 42
        });
        let level: InventoryLevel = serde_json::from_value(json).unwrap();
        assert_eq!(level.available, Some(42));
    }

    #[test]
    fn deserialize_shop() {
        let json = serde_json::json!({
            "id": 1,
            "name": "My Store",
            "email": "admin@store.com",
            "domain": "mystore.myshopify.com",
            "plan_name": "basic"
        });
        let shop: Shop = serde_json::from_value(json).unwrap();
        assert_eq!(shop.name, "My Store");
    }

    #[test]
    fn serialize_create_product() {
        let product = CreateProduct {
            title: "New Product".into(),
            body_html: Some("<p>Desc</p>".into()),
            vendor: None,
            product_type: None,
            status: Some("draft".into()),
            tags: None,
            variants: vec![CreateVariant {
                title: Some("Default".into()),
                price: Some("19.99".into()),
                sku: None,
            }],
        };
        let json = serde_json::to_value(&product).unwrap();
        assert_eq!(json["title"], "New Product");
        assert!(json.get("vendor").is_none());
        assert_eq!(json["variants"][0]["price"], "19.99");
    }

    #[test]
    fn serialize_create_order() {
        let order = CreateOrder {
            line_items: vec![CreateLineItem {
                variant_id: 123,
                quantity: 2,
            }],
            email: Some("test@example.com".into()),
            financial_status: None,
        };
        let json = serde_json::to_value(&order).unwrap();
        assert_eq!(json["line_items"][0]["variant_id"], 123);
    }

    #[test]
    fn deserialize_products_response() {
        let json = serde_json::json!({
            "products": [{
                "id": 1,
                "title": "Widget",
                "variants": []
            }]
        });
        let resp: ProductsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.products.len(), 1);
    }

    #[test]
    fn deserialize_shop_response() {
        let json = serde_json::json!({
            "shop": {
                "id": 1,
                "name": "Test"
            }
        });
        let resp: ShopResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.shop.name, "Test");
    }
}
