"""
GCP Organization Client for IAM operations.

Handles organization and folder-level IAM policy retrieval and metadata.
"""

import logging
from typing import List, Dict, Optional, Any
from google.auth.credentials import Credentials
from google.cloud import resourcemanager_v1
from google.api_core.exceptions import (
    GoogleAPIError,
    NotFound,
    PermissionDenied,
    Forbidden
)

from ..models.iam_models import ResourceIAMPolicy, ResourceType
from .cloudfast_analyzer import CloudFastAnalyzer, CloudFastAnalysis, CloudFastPattern

logger = logging.getLogger(__name__)


class OrganizationClient:
    """Client for GCP Organization IAM operations."""
    
    def __init__(self, credentials: Credentials):
        """
        Initialize organization client.
        
        Args:
            credentials: Authenticated GCP credentials
        """
        self.credentials = credentials
        self._organizations_client = None
        self._folders_client = None
        self.cloudfast_analyzer = CloudFastAnalyzer()
    
    @property
    def organizations_client(self) -> resourcemanager_v1.OrganizationsClient:
        """Get or create organizations client."""
        if self._organizations_client is None:
            self._organizations_client = resourcemanager_v1.OrganizationsClient(
                credentials=self.credentials
            )
        return self._organizations_client
    
    @property
    def folders_client(self) -> resourcemanager_v1.FoldersClient:
        """Get or create folders client."""
        if self._folders_client is None:
            self._folders_client = resourcemanager_v1.FoldersClient(
                credentials=self.credentials
            )
        return self._folders_client
    
    def list_organizations(self) -> List[Dict[str, Any]]:
        """
        List all accessible organizations.
        
        Returns:
            List[Dict[str, Any]]: List of organization metadata
        """
        try:
            logger.info("Fetching list of accessible organizations...")
            
            organizations = []
            request = resourcemanager_v1.SearchOrganizationsRequest()
            
            for org in self.organizations_client.search_organizations(request=request):
                org_dict = {
                    'name': org.name,
                    'organization_id': org.name.split('/')[-1] if org.name else '',
                    'display_name': org.display_name,
                    'lifecycle_state': org.lifecycle_state.name if org.lifecycle_state else 'UNKNOWN',
                    'creation_time': org.creation_time,
                    'owner': {
                        'directory_customer_id': getattr(org.owner, 'directory_customer_id', '') if org.owner else ''
                    }
                }
                organizations.append(org_dict)
            
            logger.info(f"Found {len(organizations)} accessible organizations")
            return organizations
            
        except (PermissionDenied, Forbidden) as e:
            logger.error(f"Insufficient permissions to list organizations: {e}")
            return []
        except GoogleAPIError as e:
            logger.error(f"Google API error listing organizations: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error listing organizations: {e}")
            raise
    
    def get_organization(self, organization_id: str) -> Optional[Dict[str, Any]]:
        """
        Get metadata for a specific organization.
        
        Args:
            organization_id: The organization ID
            
        Returns:
            Optional[Dict[str, Any]]: Organization metadata or None if not found
        """
        try:
            logger.debug(f"Fetching metadata for organization: {organization_id}")
            
            request = resourcemanager_v1.GetOrganizationRequest(
                name=f"organizations/{organization_id}"
            )
            org = self.organizations_client.get_organization(request=request)
            
            org_dict = {
                'name': org.name,
                'organization_id': organization_id,
                'display_name': org.display_name,
                'lifecycle_state': org.lifecycle_state.name if org.lifecycle_state else 'UNKNOWN',
                'creation_time': org.creation_time,
                'owner': {
                    'directory_customer_id': getattr(org.owner, 'directory_customer_id', '') if org.owner else ''
                }
            }
            
            return org_dict
            
        except NotFound:
            logger.warning(f"Organization not found: {organization_id}")
            return None
        except (PermissionDenied, Forbidden) as e:
            logger.error(f"Insufficient permissions to access organization {organization_id}: {e}")
            return None
        except GoogleAPIError as e:
            logger.error(f"Google API error getting organization metadata: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error getting organization metadata: {e}")
            raise
    
    def get_organization_iam_policy(self, organization_id: str) -> Optional[ResourceIAMPolicy]:
        """
        Get IAM policy for a specific organization.
        
        Args:
            organization_id: The organization ID
            
        Returns:
            Optional[ResourceIAMPolicy]: IAM policy or None if not accessible
        """
        try:
            logger.debug(f"Fetching IAM policy for organization: {organization_id}")
            
            request = resourcemanager_v1.GetIamPolicyRequest(
                resource=f"organizations/{organization_id}"
            )
            
            policy = self.organizations_client.get_iam_policy(request=request)
            
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
                organization_id,
                ResourceType.ORGANIZATION
            )
            
        except NotFound:
            logger.warning(f"Organization not found: {organization_id}")
            return None
        except (PermissionDenied, Forbidden) as e:
            logger.warning(f"Insufficient permissions to access IAM policy for organization {organization_id}: {e}")
            return None
        except GoogleAPIError as e:
            logger.error(f"Google API error getting organization IAM policy: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error getting organization IAM policy: {e}")
            raise
    
    def list_folders(self, parent: str) -> List[Dict[str, Any]]:
        """
        List folders under a parent resource.
        
        Args:
            parent: Parent resource (e.g., 'organizations/123' or 'folders/456')
            
        Returns:
            List[Dict[str, Any]]: List of folder metadata
        """
        try:
            logger.debug(f"Fetching folders for parent: {parent}")
            
            folders = []
            request = resourcemanager_v1.ListFoldersRequest(parent=parent)
            
            for folder in self.folders_client.list_folders(request=request):
                folder_dict = {
                    'name': folder.name,
                    'folder_id': folder.name.split('/')[-1] if folder.name else '',
                    'display_name': folder.display_name,
                    'lifecycle_state': folder.lifecycle_state.name if folder.lifecycle_state else 'UNKNOWN',
                    'parent': folder.parent,
                    'create_time': folder.create_time,
                    'update_time': folder.update_time
                }
                folders.append(folder_dict)
            
            logger.debug(f"Found {len(folders)} folders under {parent}")
            return folders
            
        except (PermissionDenied, Forbidden) as e:
            logger.warning(f"Insufficient permissions to list folders under {parent}: {e}")
            return []
        except GoogleAPIError as e:
            logger.error(f"Google API error listing folders: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error listing folders: {e}")
            raise
    
    def get_folder(self, folder_id: str) -> Optional[Dict[str, Any]]:
        """
        Get metadata for a specific folder.
        
        Args:
            folder_id: The folder ID
            
        Returns:
            Optional[Dict[str, Any]]: Folder metadata or None if not found
        """
        try:
            logger.debug(f"Fetching metadata for folder: {folder_id}")
            
            request = resourcemanager_v1.GetFolderRequest(
                name=f"folders/{folder_id}"
            )
            folder = self.folders_client.get_folder(request=request)
            
            folder_dict = {
                'name': folder.name,
                'folder_id': folder_id,
                'display_name': folder.display_name,
                'lifecycle_state': folder.lifecycle_state.name if folder.lifecycle_state else 'UNKNOWN',
                'parent': folder.parent,
                'create_time': folder.create_time,
                'update_time': folder.update_time
            }
            
            return folder_dict
            
        except NotFound:
            logger.warning(f"Folder not found: {folder_id}")
            return None
        except (PermissionDenied, Forbidden) as e:
            logger.error(f"Insufficient permissions to access folder {folder_id}: {e}")
            return None
        except GoogleAPIError as e:
            logger.error(f"Google API error getting folder metadata: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error getting folder metadata: {e}")
            raise
    
    def get_folder_iam_policy(self, folder_id: str) -> Optional[ResourceIAMPolicy]:
        """
        Get IAM policy for a specific folder.
        
        Args:
            folder_id: The folder ID
            
        Returns:
            Optional[ResourceIAMPolicy]: IAM policy or None if not accessible
        """
        try:
            logger.debug(f"Fetching IAM policy for folder: {folder_id}")
            
            request = resourcemanager_v1.GetIamPolicyRequest(
                resource=f"folders/{folder_id}"
            )
            
            policy = self.folders_client.get_iam_policy(request=request)
            
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
                folder_id,
                ResourceType.FOLDER
            )
            
        except NotFound:
            logger.warning(f"Folder not found: {folder_id}")
            return None
        except (PermissionDenied, Forbidden) as e:
            logger.warning(f"Insufficient permissions to access IAM policy for folder {folder_id}: {e}")
            return None
        except GoogleAPIError as e:
            logger.error(f"Google API error getting folder IAM policy: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error getting folder IAM policy: {e}")
            raise
    
    def get_organization_hierarchy(self, organization_id: str) -> Dict[str, Any]:
        """
        Get the complete folder hierarchy for an organization.
        
        Args:
            organization_id: The organization ID
            
        Returns:
            Dict[str, Any]: Organization hierarchy with nested folders
        """
        try:
            logger.info(f"Building organization hierarchy for: {organization_id}")
            
            # Get organization info
            org_info = self.get_organization(organization_id)
            if not org_info:
                return {}
            
            # Build hierarchy recursively
            def build_folder_tree(parent_resource: str) -> List[Dict[str, Any]]:
                folders = self.list_folders(parent_resource)
                folder_tree = []
                
                for folder in folders:
                    folder_with_children = folder.copy()
                    folder_resource = f"folders/{folder['folder_id']}"
                    folder_with_children['children'] = build_folder_tree(folder_resource)
                    folder_tree.append(folder_with_children)
                
                return folder_tree
            
            hierarchy = {
                'organization': org_info,
                'folders': build_folder_tree(f"organizations/{organization_id}")
            }
            
            return hierarchy
            
        except Exception as e:
            logger.error(f"Error building organization hierarchy: {e}")
            return {}
    
    def check_organization_access(self, organization_ids: List[str]) -> Dict[str, bool]:
        """
        Check which organizations are accessible to the current credentials.
        
        Args:
            organization_ids: List of organization IDs to check
            
        Returns:
            Dict[str, bool]: Mapping of organization_id to accessibility status
        """
        accessibility = {}
        
        logger.info(f"Checking accessibility for {len(organization_ids)} organizations...")
        
        for org_id in organization_ids:
            try:
                org_info = self.get_organization(org_id)
                accessibility[org_id] = org_info is not None
            except Exception as e:
                logger.debug(f"Organization {org_id} not accessible: {e}")
                accessibility[org_id] = False
        
        accessible_count = sum(accessibility.values())
        logger.info(f"{accessible_count}/{len(organization_ids)} organizations are accessible")
        
        return accessibility
    
    def get_all_accessible_resources(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get all accessible organizations, folders, and their metadata.
        
        Returns:
            Dict[str, List[Dict[str, Any]]]: Mapping of resource types to their lists
        """
        try:
            logger.info("Fetching all accessible organizational resources...")
            
            resources = {
                'organizations': [],
                'folders': []
            }
            
            # Get all accessible organizations
            organizations = self.list_organizations()
            resources['organizations'] = organizations
            
            # For each organization, get all folders
            for org in organizations:
                org_id = org['organization_id']
                org_folders = self.list_folders(f"organizations/{org_id}")
                
                # Add organization context to folders
                for folder in org_folders:
                    folder['organization_id'] = org_id
                    folder['organization_name'] = org['display_name']
                
                resources['folders'].extend(org_folders)
                
                # Recursively get sub-folders
                def get_subfolders(parent_folders: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
                    all_subfolders = []
                    for folder in parent_folders:
                        folder_resource = f"folders/{folder['folder_id']}"
                        subfolders = self.list_folders(folder_resource)
                        
                        # Add context to subfolders
                        for subfolder in subfolders:
                            subfolder['organization_id'] = org_id
                            subfolder['organization_name'] = org['display_name']
                            subfolder['parent_folder_id'] = folder['folder_id']
                        
                        all_subfolders.extend(subfolders)
                        if subfolders:
                            all_subfolders.extend(get_subfolders(subfolders))
                    
                    return all_subfolders
                
                if org_folders:
                    resources['folders'].extend(get_subfolders(org_folders))
            
            logger.info(f"Found {len(resources['organizations'])} organizations and {len(resources['folders'])} folders")
            return resources
            
        except Exception as e:
            logger.error(f"Error fetching organizational resources: {e}")
            return {'organizations': [], 'folders': []}
    
    def analyze_cloudfast_patterns(self, organization_id: str) -> CloudFastAnalysis:
        """
        Analyze organization for CloudFast and Cloud Foundation Fabric patterns.
        
        Args:
            organization_id: The organization ID to analyze
            
        Returns:
            CloudFastAnalysis: Detailed analysis of CloudFast patterns
        """
        try:
            logger.info(f"Analyzing CloudFast patterns for organization: {organization_id}")
            
            # Get organization hierarchy
            hierarchy = self.get_organization_hierarchy(organization_id)
            
            if not hierarchy:
                logger.warning(f"No hierarchy data available for organization: {organization_id}")
                return self.cloudfast_analyzer._create_empty_analysis()
            
            # Perform CloudFast analysis
            analysis = self.cloudfast_analyzer.analyze_organization(hierarchy)
            
            logger.info(f"CloudFast analysis complete - Pattern: {analysis.pattern_type.value}, "
                       f"Confidence: {analysis.confidence_score:.2f}, Squads: {len(analysis.squads)}")
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing CloudFast patterns: {e}")
            return self.cloudfast_analyzer._create_empty_analysis()
    
    def get_enhanced_hierarchy(self, organization_id: str) -> Dict[str, Any]:
        """
        Get organization hierarchy enhanced with CloudFast analysis.
        
        Args:
            organization_id: The organization ID
            
        Returns:
            Dict[str, Any]: Enhanced hierarchy with CloudFast insights
        """
        try:
            logger.info(f"Building enhanced hierarchy with CloudFast analysis for: {organization_id}")
            
            # Get base hierarchy
            hierarchy = self.get_organization_hierarchy(organization_id)
            
            if not hierarchy:
                return {}
            
            # Add CloudFast analysis
            cloudfast_analysis = self.cloudfast_analyzer.analyze_organization(hierarchy)
            
            # Create enhanced hierarchy
            enhanced_hierarchy = {
                **hierarchy,
                'cloudfast_analysis': {
                    'pattern_type': cloudfast_analysis.pattern_type.value,
                    'confidence_score': cloudfast_analysis.confidence_score,
                    'squads': [{
                        'name': squad.name,
                        'folder_id': squad.folder_id,
                        'environments': [{
                            'name': env.name,
                            'type': env.environment_type,
                            'folder_id': env.folder_id
                        } for env in squad.environments],
                        'total_projects': squad.total_projects
                    } for squad in cloudfast_analysis.squads],
                    'environments': cloudfast_analysis.environments,
                    'recommendations': cloudfast_analysis.recommendations,
                    'iam_inheritance': cloudfast_analysis.iam_inheritance_analysis
                }
            }
            
            return enhanced_hierarchy
            
        except Exception as e:
            logger.error(f"Error building enhanced hierarchy: {e}")
            return self.get_organization_hierarchy(organization_id)
    
    def get_squad_recommendations(self, organization_id: str) -> Dict[str, Any]:
        """
        Get CloudFast-specific recommendations for squad-based IAM optimization.
        
        Args:
            organization_id: The organization ID
            
        Returns:
            Dict[str, Any]: Squad-specific recommendations
        """
        try:
            analysis = self.analyze_cloudfast_patterns(organization_id)
            
            recommendations = {
                'pattern_detected': analysis.pattern_type.value,
                'confidence': analysis.confidence_score,
                'squad_count': len(analysis.squads),
                'environment_count': len(analysis.environments),
                'recommendations': analysis.recommendations,
                'squad_details': [],
                'optimization_opportunities': []
            }
            
            # Add detailed squad information
            for squad in analysis.squads:
                squad_detail = {
                    'name': squad.name,
                    'environments': len(squad.environments),
                    'environment_types': list(set(env.environment_type for env in squad.environments)),
                    'folder_id': squad.folder_id,
                    'optimization_priority': self._calculate_squad_priority(squad)
                }
                recommendations['squad_details'].append(squad_detail)
            
            # Generate optimization opportunities
            if analysis.pattern_type == CloudFastPattern.SQUAD_BASED:
                recommendations['optimization_opportunities'].extend([
                    f"Implement group-based access control for {len(analysis.squads)} squads",
                    "Standardize IAM policies across squad environments",
                    "Consider cross-squad role consolidation opportunities"
                ])
            elif analysis.pattern_type == CloudFastPattern.ENVIRONMENT_FIRST:
                recommendations['optimization_opportunities'].extend([
                    "Restructure to squad-based organization for better team autonomy",
                    "Implement environment-specific access controls",
                    "Consider migrating to CloudFast squad-based model"
                ])
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Error generating squad recommendations: {e}")
            return {
                'pattern_detected': 'unknown',
                'confidence': 0.0,
                'squad_count': 0,
                'recommendations': ['Error analyzing organization structure'],
                'optimization_opportunities': []
            }
    
    def _calculate_squad_priority(self, squad: SquadInfo) -> str:
        """
        Calculate optimization priority for a squad.
        
        Args:
            squad: Squad information
            
        Returns:
            str: Priority level (high, medium, low)
        """
        env_count = len(squad.environments)
        has_prod = any(env.environment_type == 'production' for env in squad.environments)
        
        if env_count >= 3 and has_prod:
            return 'high'
        elif env_count >= 2:
            return 'medium'
        else:
            return 'low'
