use fcp_core::{ProvisioningRecipe, ProvisioningStep, ProvisioningStepType, RecipeId, StepId};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn assert_recipe_eq(left: &ProvisioningRecipe, right: &ProvisioningRecipe) -> TestResult {
    assert_eq!(left.id, right.id);
    assert_eq!(left.version, right.version);
    assert_eq!(left.description, right.description);
    assert_eq!(serde_json::to_value(left)?, serde_json::to_value(right)?);
    Ok(())
}

fn sample_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("github.oauth"),
        "2026.04",
        "Connect GitHub OAuth app",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("collect_client_id"),
        ProvisioningStepType::PromptUser {
            message: "Enter the GitHub OAuth client ID".to_string(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_client_secret"),
            ProvisioningStepType::StoreSecret {
                key: "github_client_secret".to_string(),
                value_from: StepId::new("collect_client_secret"),
                scope: "connector:fcp.github".to_string(),
            },
        )
        .depends_on(StepId::new("collect_client_id"))
        .with_approval(),
    )
}

#[test]
fn provisioning_recipe_display_format_is_pinned() {
    let empty = ProvisioningRecipe::new(RecipeId::new("empty.setup"), "1", "No steps");
    assert_eq!(empty.to_string(), "empty.setup@1: No steps (0 steps)");

    let one_step = ProvisioningRecipe::new(RecipeId::new("one.setup"), "1", "One step").with_step(
        ProvisioningStep::new(
            StepId::new("prompt"),
            ProvisioningStepType::PromptUser {
                message: "Value?".to_string(),
            },
        ),
    );
    assert_eq!(one_step.to_string(), "one.setup@1: One step (1 step)");

    let multi_step = sample_recipe();
    assert_eq!(
        multi_step.to_string(),
        "github.oauth@2026.04: Connect GitHub OAuth app (2 steps)"
    );
}

#[test]
fn provisioning_recipe_json_roundtrip_shape_is_pinned() -> TestResult {
    let recipe = sample_recipe();
    let value = serde_json::to_value(&recipe)?;

    assert_eq!(
        value,
        serde_json::json!({
            "id": "github.oauth",
            "version": "2026.04",
            "description": "Connect GitHub OAuth app",
            "steps": [
                {
                    "id": "collect_client_id",
                    "type": "prompt_user",
                    "message": "Enter the GitHub OAuth client ID",
                    "requires_approval": false
                },
                {
                    "id": "store_client_secret",
                    "type": "store_secret",
                    "key": "github_client_secret",
                    "value_from": "collect_client_secret",
                    "scope": "connector:fcp.github",
                    "depends_on": ["collect_client_id"],
                    "requires_approval": true
                }
            ]
        })
    );

    let decoded: ProvisioningRecipe = serde_json::from_value(value)?;
    assert_recipe_eq(&recipe, &decoded)?;

    Ok(())
}

#[test]
fn provisioning_recipe_cbor_roundtrip_preserves_recipe() -> TestResult {
    let recipe = sample_recipe();
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&recipe, &mut encoded)?;

    assert_ne!(encoded, [] as [u8; 0]);

    let decoded = ciborium::de::from_reader::<ProvisioningRecipe, _>(encoded.as_slice())?;
    assert_recipe_eq(&recipe, &decoded)?;
    assert_eq!(decoded.to_string(), recipe.to_string());

    Ok(())
}
