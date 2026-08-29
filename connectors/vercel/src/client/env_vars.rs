use crate::{
    error::VercelResult,
    types::{CreateEnvVarRequest, DeleteStatus, EnvVarListResponse, ProjectEnvVar},
};

use super::{VercelClient, sanitize_path_segment};

impl VercelClient {
    /// List environment variables for a project.
    ///
    /// # Errors
    ///
    /// Returns [`VercelError`](crate::error::VercelError) on invalid input,
    /// transport failure, or a non-2xx response.
    pub async fn list_env_vars(
        &self,
        project_id_or_name: &str,
    ) -> VercelResult<EnvVarListResponse> {
        let project = sanitize_path_segment(project_id_or_name, "project_id_or_name")?;
        self.get(&format!("/v9/projects/{project}/env"), Vec::new())
            .await
    }

    /// Create environment variables for a project.
    ///
    /// # Errors
    ///
    /// Returns [`VercelError`](crate::error::VercelError) on invalid input,
    /// transport failure, or a non-2xx response.
    pub async fn create_env_vars(
        &self,
        project_id_or_name: &str,
        requests: &[CreateEnvVarRequest],
    ) -> VercelResult<Vec<ProjectEnvVar>> {
        let project = sanitize_path_segment(project_id_or_name, "project_id_or_name")?;
        self.post(
            &format!("/v10/projects/{project}/env"),
            Vec::new(),
            requests,
        )
        .await
    }

    /// Delete an environment variable.
    ///
    /// # Errors
    ///
    /// Returns [`VercelError`](crate::error::VercelError) on invalid input,
    /// transport failure, or a non-2xx response.
    pub async fn delete_env_var(
        &self,
        project_id_or_name: &str,
        env_var_id: &str,
    ) -> VercelResult<DeleteStatus> {
        let project = sanitize_path_segment(project_id_or_name, "project_id_or_name")?;
        let env_id = sanitize_path_segment(env_var_id, "environment_variable_id")?;
        self.delete(&format!("/v9/projects/{project}/env/{env_id}"), Vec::new())
            .await
    }
}
