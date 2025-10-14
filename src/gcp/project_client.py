"""
GCP Project Client for IAM operations.

Handles project-level IAM policy retrieval and project metadata.
"""

import logging
from typing import List, Dict, Optional, Any
from google.auth.credentials import Credentials
from google.cloud import resourcemanager
from google.iam.v1 import iam_policy_pb2
from google.api_core.exceptions import (
    GoogleAPIError, 
    NotFound, 
    PermissionDenied,
    Forbidden
)

from ..models.iam_models import ResourceIAMPolicy, ResourceType

logger = logging.getLogger(__name__)


class ProjectClient:
    """Client for GCP Project IAM operations."""
    
    def __init__(self, credentials: Credentials):
        """
        Initialize project client.
        
        Args:
            credentials: Authenticated GCP credentials
        """
        self.credentials = credentials
        self._resource_manager = None
    
    @property
    def resource_manager(self) -> resourcemanager.ProjectsClient:
        """Get or create resource manager client."""
        if self._resource_manager is None:
            self._resource_manager = resourcemanager.ProjectsClient(
                credentials=self.credentials
            )
        return self._resource_manager
    
    def list_projects(self, filter_expression: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all accessible projects.
        
        Args:
            filter_expression: Optional filter for projects (e.g., "lifecycleState:ACTIVE")
            
        Returns:
            List[Dict[str, Any]]: List of project metadata
        """
        try:
            logger.info("Fetching list of accessible projects...")
            
            # Use search_projects which doesn't require parent parameter
            # This returns all projects the user has access to
            request = resourcemanager.SearchProjectsRequest()
            if filter_expression:
                request.query = filter_expression
            
            projects = []
            for project in self.resource_manager.search_projects(request=request):
                # Use camelCase keys to match expected format in the UI
                project_dict = {
                    'projectId': project.project_id,
                    'project_id': project.project_id,  # Keep both for compatibility
                    'name': project.name,
                    'displayName': getattr(project, 'display_name', project.name),
                    'display_name': getattr(project, 'display_name', project.name),  # Keep both
                    'lifecycleState': getattr(project.state, 'name', 'UNKNOWN') if hasattr(project, 'state') else 'ACTIVE',
                    'lifecycle_state': getattr(project.state, 'name', 'UNKNOWN') if hasattr(project, 'state') else 'ACTIVE',  # Keep both
                    'projectNumber': getattr(project, 'project_number', ''),
                    'project_number': getattr(project, 'project_number', ''),  # Keep both
                    'createTime': getattr(project, 'create_time', None),
                    'create_time': getattr(project, 'create_time', None),  # Keep both
                    'parent': {}
                }
                
                # Add parent information if available
                if hasattr(project, 'parent') and project.parent:
                    project_dict['parent'] = {
                        'type': getattr(project.parent, 'type', ''),
                        'id': getattr(project.parent, 'id', '')
                    }
                
                # Add labels if available
                if hasattr(project, 'labels') and project.labels:
                    project_dict['labels'] = dict(project.labels)
                
                projects.append(project_dict)
            
            logger.info(f"Found {len(projects)} accessible projects")
            return projects
            
        except (PermissionDenied, Forbidden) as e:
            logger.error(f"Insufficient permissions to list projects: {e}")
            return []
        except GoogleAPIError as e:
            logger.error(f"Google API error listing projects: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error listing projects: {e}")
            raise
    
    def get_project_metadata(self, project_id: str) -> Optional[Dict[str, Any]]:
        """
        Get metadata for a specific project.
        
        Args:
            project_id: The project ID
            
        Returns:
            Optional[Dict[str, Any]]: Project metadata or None if not found
        """
        try:
            logger.debug(f"Fetching metadata for project: {project_id}")
            
            request = resourcemanager.GetProjectRequest(name=f"projects/{project_id}")
            project = self.resource_manager.get_project(request=request)
            
            project_dict = {
                'project_id': project.project_id,
                'name': project.name,
                'display_name': getattr(project, 'display_name', project.name),
                'lifecycle_state': project.lifecycle_state.name if project.lifecycle_state else 'UNKNOWN',
                'project_number': project.project_number,
                'create_time': project.create_time,
                'parent': {}
            }
            
            # Add parent information if available
            if project.parent:
                project_dict['parent'] = {
                    'type': project.parent.type,
                    'id': project.parent.id
                }
            
            # Add labels if available
            if hasattr(project, 'labels') and project.labels:
                project_dict['labels'] = dict(project.labels)
            
            return project_dict
            
        except NotFound:
            logger.warning(f"Project not found: {project_id}")
            return None
        except (PermissionDenied, Forbidden) as e:
            logger.error(f"Insufficient permissions to access project {project_id}: {e}")
            return None
        except GoogleAPIError as e:
            logger.error(f"Google API error getting project metadata: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error getting project metadata: {e}")
            raise
    
    def get_iam_policy(self, project_id: str) -> Optional[ResourceIAMPolicy]:
        """
        Get IAM policy for a specific project.
        
        Alias for get_project_iam_policy for backward compatibility.
        
        Args:
            project_id: The project ID
            
        Returns:
            Optional[ResourceIAMPolicy]: IAM policy or None if not accessible
        """
        return self.get_project_iam_policy(project_id)
    
    def get_project_iam_policy(self, project_id: str) -> Optional[ResourceIAMPolicy]:
        """
        Get IAM policy for a specific project.
        
        Args:
            project_id: The project ID
            
        Returns:
            Optional[ResourceIAMPolicy]: IAM policy or None if not accessible
        """
        try:
            logger.debug(f"Fetching IAM policy for project: {project_id}")
            
            request = iam_policy_pb2.GetIamPolicyRequest(
                resource=f"projects/{project_id}"
            )
            
            policy = self.resource_manager.get_iam_policy(request=request)
            
            # Convert to our internal format
            policy_dict = {
                'bindings': []
            }
            
            for binding in policy.bindings:
                binding_dict = {
                    'role': binding.role,
                    'members': list(binding.members)
                }
                
                # Add condition if present
                if binding.condition:
                    binding_dict['condition'] = {
                        'expression': binding.condition.expression,
                        'title': binding.condition.title,
                        'description': binding.condition.description
                    }
                
                policy_dict['bindings'].append(binding_dict)
            
            # Add etag and version if available
            if hasattr(policy, 'etag'):
                policy_dict['etag'] = policy.etag
            if hasattr(policy, 'version'):
                policy_dict['version'] = policy.version
            
            return ResourceIAMPolicy.from_api_response(
                policy_dict, 
                project_id, 
                ResourceType.PROJECT
            )
            
        except NotFound:
            logger.warning(f"Project not found: {project_id}")
            return None
        except (PermissionDenied, Forbidden) as e:
            logger.warning(f"Insufficient permissions to access IAM policy for project {project_id}: {e}")
            return None
        except GoogleAPIError as e:
            logger.error(f"Google API error getting project IAM policy: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error getting project IAM policy: {e}")
            raise
    
    def get_multiple_project_iam_policies(self, project_ids: List[str]) -> Dict[str, ResourceIAMPolicy]:
        """
        Get IAM policies for multiple projects.
        
        Args:
            project_ids: List of project IDs
            
        Returns:
            Dict[str, ResourceIAMPolicy]: Mapping of project_id to IAM policy
        """
        policies = {}
        
        logger.info(f"Fetching IAM policies for {len(project_ids)} projects...")
        
        for i, project_id in enumerate(project_ids, 1):
            logger.debug(f"Processing project {i}/{len(project_ids)}: {project_id}")
            
            policy = self.get_project_iam_policy(project_id)
            if policy:
                policies[project_id] = policy
            else:
                logger.warning(f"Could not retrieve IAM policy for project: {project_id}")
        
        logger.info(f"Successfully retrieved {len(policies)} project IAM policies")
        return policies
    
    def get_project_ancestors(self, project_id: str) -> List[Dict[str, Any]]:
        """
        Get the ancestor hierarchy for a project.
        
        Args:
            project_id: The project ID
            
        Returns:
            List[Dict[str, Any]]: List of ancestors (folders, organization)
        """
        try:
            logger.debug(f"Fetching ancestors for project: {project_id}")
            
            request = resourcemanager.GetAncestryRequest(
                name=f"projects/{project_id}"
            )
            
            ancestry = self.resource_manager.get_ancestry(request=request)
            
            ancestors = []
            for ancestor in ancestry.ancestor:
                ancestor_dict = {
                    'resource_id': ancestor.resource_id.id,
                    'resource_type': ancestor.resource_id.type
                }
                ancestors.append(ancestor_dict)
            
            return ancestors
            
        except NotFound:
            logger.warning(f"Project not found: {project_id}")
            return []
        except (PermissionDenied, Forbidden) as e:
            logger.warning(f"Insufficient permissions to get ancestry for project {project_id}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error getting project ancestry: {e}")
            return []
    
    def check_project_accessibility(self, project_ids: List[str]) -> Dict[str, bool]:
        """
        Check which projects are accessible to the current credentials.
        
        Args:
            project_ids: List of project IDs to check
            
        Returns:
            Dict[str, bool]: Mapping of project_id to accessibility status
        """
        accessibility = {}
        
        logger.info(f"Checking accessibility for {len(project_ids)} projects...")
        
        for project_id in project_ids:
            try:
                metadata = self.get_project_metadata(project_id)
                accessibility[project_id] = metadata is not None
            except Exception as e:
                logger.debug(f"Project {project_id} not accessible: {e}")
                accessibility[project_id] = False
        
        accessible_count = sum(accessibility.values())
        logger.info(f"{accessible_count}/{len(project_ids)} projects are accessible")
        
        return accessibility