use crate::{
    error::VercelResult,
    types::{CreateDeploymentRequest, DeleteStatus, Deployment, DeploymentListResponse},
};

use super::{VercelClient, sanitize_path_segment};

impl VercelClient {
    /// List deployments, optionally scoped to a project.
    ///
    /// # Errors
    ///
    /// Returns [`VercelError`](crate::error::VercelError) on transport failure
    /// or a non-2xx response.
    pub async fn list_deployments(
        &self,
        project_id: Option<&str>,
        limit: Option<u32>,
    ) -> VercelResult<DeploymentListResponse> {
        let mut query = Vec::new();
        if let Some(project_id) = project_id {
            query.push(("projectId", project_id.to_string()));
        }
        if let Some(limit) = limit {
            query.push(("limit", limit.to_string()));
        }
        self.get("/v6/deployments", query).await
    }

    /// Fetch a deployment by id or URL.
    ///
    /// # Errors
    ///
    /// Returns [`VercelError`](crate::error::VercelError) on invalid input,
    /// transport failure, or a non-2xx response.
    pub async fn get_deployment(&self, deployment_id_or_url: &str) -> VercelResult<Deployment> {
        let safe = sanitize_path_segment(deployment_id_or_url, "deployment_id_or_url")?;
        self.get(&format!("/v13/deployments/{safe}"), Vec::new())
            .await
    }

    /// Create a deployment.
    ///
    /// # Errors
    ///
    /// Returns [`VercelError`](crate::error::VercelError) on transport failure
    /// or a non-2xx response.
    pub async fn create_deployment(
        &self,
        request: &CreateDeploymentRequest,
    ) -> VercelResult<Deployment> {
        self.post("/v13/deployments", Vec::new(), request).await
    }

    /// Delete a deployment.
    ///
    /// # Errors
    ///
    /// Returns [`VercelError`](crate::error::VercelError) on invalid input,
    /// transport failure, or a non-2xx response.
    pub async fn delete_deployment(&self, deployment_id: &str) -> VercelResult<DeleteStatus> {
        let safe = sanitize_path_segment(deployment_id, "deployment_id")?;
        self.delete(&format!("/v13/deployments/{safe}"), Vec::new())
            .await
    }
}
