use crate::{
    error::VercelResult,
    types::{AddDomainRequest, DeleteStatus, DomainListResponse, ProjectDomain},
};

use super::{VercelClient, sanitize_path_segment};

impl VercelClient {
    /// List domains attached to a project.
    ///
    /// # Errors
    ///
    /// Returns [`VercelError`](crate::error::VercelError) on invalid input,
    /// transport failure, or a non-2xx response.
    pub async fn list_domains(&self, project_id_or_name: &str) -> VercelResult<DomainListResponse> {
        let project = sanitize_path_segment(project_id_or_name, "project_id_or_name")?;
        self.get(&format!("/v9/projects/{project}/domains"), Vec::new())
            .await
    }

    /// Add a domain to a project.
    ///
    /// # Errors
    ///
    /// Returns [`VercelError`](crate::error::VercelError) on invalid input,
    /// transport failure, or a non-2xx response.
    pub async fn add_domain(
        &self,
        project_id_or_name: &str,
        request: &AddDomainRequest,
    ) -> VercelResult<ProjectDomain> {
        let project = sanitize_path_segment(project_id_or_name, "project_id_or_name")?;
        self.post(
            &format!("/v10/projects/{project}/domains"),
            Vec::new(),
            request,
        )
        .await
    }

    /// Remove a domain from a project.
    ///
    /// # Errors
    ///
    /// Returns [`VercelError`](crate::error::VercelError) on invalid input,
    /// transport failure, or a non-2xx response.
    pub async fn remove_domain(
        &self,
        project_id_or_name: &str,
        domain_name: &str,
    ) -> VercelResult<DeleteStatus> {
        let project = sanitize_path_segment(project_id_or_name, "project_id_or_name")?;
        let domain = sanitize_path_segment(domain_name, "domain_name")?;
        self.delete(
            &format!("/v10/projects/{project}/domains/{domain}"),
            Vec::new(),
        )
        .await
    }
}
