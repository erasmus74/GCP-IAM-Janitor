"""
GCP IAM Client for role and permission operations.

Handles IAM roles, permissions, and policy analysis operations.
"""

import logging
from typing import List, Dict, Set, Optional, Any, Tuple
from google.auth.credentials import Credentials
from google.cloud import iam_v1
from google.api_core.exceptions import (
    GoogleAPIError,
    NotFound,
    PermissionDenied,
    Forbidden
)

from ..models.iam_models import (
    Role, 
    RoleType, 
    Permission, 
    PolicyAnalysis, 
    Binding,
    Identity,
    PermissionRiskLevel
)

logger = logging.getLogger(__name__)


class IAMClient:
    """Client for GCP IAM operations."""
    
    def __init__(self, credentials: Credentials):
        """
        Initialize IAM client.
        
        Args:
            credentials: Authenticated GCP credentials
        """
        self.credentials = credentials
        self._iam_service = None
    
    @property
    def iam_service(self) -> iam_v1.IAMClient:
        """Get or create IAM service client."""
        if self._iam_service is None:
            self._iam_service = iam_v1.IAMClient(credentials=self.credentials)
        return self._iam_service
    
    def list_roles(self, parent: Optional[str] = None, show_deleted: bool = False) -> List[Role]:
        """
        List available IAM roles.
        
        Args:
            parent: Parent resource (e.g., 'projects/my-project' for custom roles)
            show_deleted: Whether to include deleted roles
            
        Returns:
            List[Role]: List of available roles
        """
        try:
            roles = []
            
            # List predefined roles if no parent specified
            if parent is None:
                logger.info("Fetching predefined IAM roles...")
                
                request = iam_v1.ListRolesRequest(
                    show_deleted=show_deleted,
                    view=iam_v1.RoleView.FULL
                )
                
                for role in self.iam_service.list_roles(request=request):
                    role_obj = Role.from_api_response({
                        'name': role.name,
                        'title': role.title,
                        'description': role.description,
                        'includedPermissions': list(role.included_permissions),
                        'stage': role.stage.name if role.stage else 'GA'
                    })
                    roles.append(role_obj)
                    
            else:
                # List custom roles for the specified parent
                logger.info(f"Fetching custom roles for parent: {parent}")
                
                request = iam_v1.ListRolesRequest(
                    parent=parent,
                    show_deleted=show_deleted,
                    view=iam_v1.RoleView.FULL
                )
                
                for role in self.iam_service.list_roles(request=request):
                    role_obj = Role.from_api_response({
                        'name': role.name,
                        'title': role.title,
                        'description': role.description,
                        'includedPermissions': list(role.included_permissions),
                        'stage': role.stage.name if role.stage else 'GA'
                    })
                    roles.append(role_obj)
            
            logger.info(f"Retrieved {len(roles)} roles")
            return roles
            
        except (PermissionDenied, Forbidden) as e:
            logger.error(f"Insufficient permissions to list roles: {e}")
            return []
        except GoogleAPIError as e:
            logger.error(f"Google API error listing roles: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error listing roles: {e}")
            raise
    
    def get_role(self, role_name: str) -> Optional[Role]:
        """
        Get detailed information about a specific role.
        
        Args:
            role_name: The role name (e.g., 'roles/editor')
            
        Returns:
            Optional[Role]: Role object or None if not found
        """
        try:
            logger.debug(f"Fetching role details: {role_name}")
            
            request = iam_v1.GetRoleRequest(name=role_name)
            role = self.iam_service.get_role(request=request)
            
            role_obj = Role.from_api_response({
                'name': role.name,
                'title': role.title,
                'description': role.description,
                'includedPermissions': list(role.included_permissions),
                'stage': role.stage.name if role.stage else 'GA'
            })
            
            return role_obj
            
        except NotFound:
            logger.warning(f"Role not found: {role_name}")
            return None
        except (PermissionDenied, Forbidden) as e:
            logger.error(f"Insufficient permissions to get role {role_name}: {e}")
            return None
        except GoogleAPIError as e:
            logger.error(f"Google API error getting role: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error getting role: {e}")
            raise
    
    def get_role_permissions(self, role_name: str) -> Set[str]:
        """
        Get permissions for a specific role.
        
        Args:
            role_name: The role name
            
        Returns:
            Set[str]: Set of permission names
        """
        role = self.get_role(role_name)
        if role:
            return role.permissions
        return set()
    
    def analyze_bindings(self, bindings: List[Binding]) -> Dict[str, Any]:
        """
        Analyze IAM policy bindings for insights.
        
        Args:
            bindings: List of IAM policy bindings
            
        Returns:
            Dict[str, Any]: Analysis results
        """
        analysis = {
            'total_bindings': len(bindings),
            'unique_roles': set(),
            'unique_identities': set(),
            'identity_types': {},
            'role_usage': {},
            'conditional_bindings': 0,
            'basic_roles_usage': 0,
            'service_accounts': set(),
            'external_users': set(),
            'groups': set(),
            'high_privilege_bindings': []
        }
        
        # Define high-privilege roles
        high_privilege_roles = {
            'roles/owner',
            'roles/editor',
            'roles/iam.securityAdmin',
            'roles/resourcemanager.organizationAdmin',
            'roles/billing.admin'
        }
        
        for binding in bindings:
            analysis['unique_roles'].add(binding.role)
            
            # Count conditional bindings
            if binding.condition:
                analysis['conditional_bindings'] += 1
            
            # Count basic roles
            if binding.role in ['roles/owner', 'roles/editor', 'roles/viewer']:
                analysis['basic_roles_usage'] += 1
            
            # Track role usage
            analysis['role_usage'][binding.role] = analysis['role_usage'].get(binding.role, 0) + len(binding.members)
            
            # Analyze members
            for member in binding.members:
                analysis['unique_identities'].add(member)
                
                identity = Identity.from_member_string(member)
                
                # Count by identity type
                identity_type = identity.identity_type.value
                analysis['identity_types'][identity_type] = analysis['identity_types'].get(identity_type, 0) + 1
                
                # Categorize identities
                if identity.identity_type.value == 'serviceAccount':
                    analysis['service_accounts'].add(member)
                elif identity.identity_type.value == 'user':
                    # Check for external users (non-Google Workspace domains)
                    if '@gmail.com' in identity.email or '@googlemail.com' in identity.email:
                        analysis['external_users'].add(member)
                elif identity.identity_type.value == 'group':
                    analysis['groups'].add(member)
                
                # Check for high-privilege bindings
                if binding.role in high_privilege_roles:
                    analysis['high_privilege_bindings'].append({
                        'role': binding.role,
                        'member': member,
                        'identity_type': identity_type
                    })
        
        # Convert sets to counts for serialization
        analysis['unique_roles_count'] = len(analysis['unique_roles'])
        analysis['unique_identities_count'] = len(analysis['unique_identities'])
        analysis['service_accounts_count'] = len(analysis['service_accounts'])
        analysis['external_users_count'] = len(analysis['external_users'])
        analysis['groups_count'] = len(analysis['groups'])
        
        # Convert sets to lists for JSON serialization
        analysis['unique_roles'] = list(analysis['unique_roles'])
        analysis['unique_identities'] = list(analysis['unique_identities'])
        analysis['service_accounts'] = list(analysis['service_accounts'])
        analysis['external_users'] = list(analysis['external_users'])
        analysis['groups'] = list(analysis['groups'])
        
        return analysis
    
    def get_permissions_by_service(self, permissions: Set[str]) -> Dict[str, List[str]]:
        """
        Group permissions by GCP service.
        
        Args:
            permissions: Set of permission names
            
        Returns:
            Dict[str, List[str]]: Mapping of service to permissions
        """
        services = {}
        
        for permission in permissions:
            if '.' in permission:
                service = permission.split('.')[0]
                if service not in services:
                    services[service] = []
                services[service].append(permission)
            else:
                # Handle permissions without dots
                if 'other' not in services:
                    services['other'] = []
                services['other'].append(permission)
        
        # Sort permissions within each service
        for service in services:
            services[service].sort()
        
        return services
    
    def analyze_permission_risk(self, permission: str) -> PermissionRiskLevel:
        """
        Analyze the risk level of a permission.
        
        Args:
            permission: Permission name
            
        Returns:
            PermissionRiskLevel: Risk level assessment
        """
        # Define high-risk permission patterns
        critical_patterns = [
            'iam.',
            'setIamPolicy',
            'delete',
            'admin',
            'owner'
        ]
        
        high_patterns = [
            'create',
            'update',
            'write',
            'edit',
            'modify'
        ]
        
        medium_patterns = [
            'get',
            'list',
            'read',
            'view'
        ]
        
        permission_lower = permission.lower()
        
        # Check for critical patterns
        for pattern in critical_patterns:
            if pattern in permission_lower:
                return PermissionRiskLevel.CRITICAL
        
        # Check for high patterns
        for pattern in high_patterns:
            if pattern in permission_lower:
                return PermissionRiskLevel.HIGH
        
        # Check for medium patterns
        for pattern in medium_patterns:
            if pattern in permission_lower:
                return PermissionRiskLevel.MEDIUM
        
        return PermissionRiskLevel.LOW
    
    def find_overprivileged_identities(self, bindings: List[Binding], threshold: int = 5) -> List[str]:
        """
        Find identities that may be overprivileged.
        
        Args:
            bindings: List of IAM policy bindings
            threshold: Minimum number of roles to consider overprivileged
            
        Returns:
            List[str]: List of potentially overprivileged identity emails
        """
        identity_roles = {}
        
        for binding in bindings:
            for member in binding.members:
                if member not in identity_roles:
                    identity_roles[member] = set()
                identity_roles[member].add(binding.role)
        
        overprivileged = []
        for identity, roles in identity_roles.items():
            if len(roles) >= threshold:
                overprivileged.append(identity)
        
        return overprivileged
    
    def generate_policy_analysis(self, bindings: List[Binding], roles_info: Dict[str, Role]) -> PolicyAnalysis:
        """
        Generate comprehensive policy analysis.
        
        Args:
            bindings: List of IAM policy bindings
            roles_info: Mapping of role names to Role objects
            
        Returns:
            PolicyAnalysis: Comprehensive analysis results
        """
        analysis = PolicyAnalysis()
        
        # Basic counts
        analysis.total_bindings = len(bindings)
        
        # Collect all identities and roles
        all_identities = set()
        all_roles = set()
        
        for binding in bindings:
            all_roles.add(binding.role)
            all_identities.update(binding.members)
        
        analysis.total_roles = len(all_roles)
        analysis.total_identities = len(all_identities)
        
        # Analyze identities by type
        for identity_str in all_identities:
            identity = Identity.from_member_string(identity_str)
            analysis.add_identity(identity)
        
        # Analyze roles by type
        for role_name in all_roles:
            if role_name in roles_info:
                role = roles_info[role_name]
                analysis.add_role(role)
                analysis.total_permissions += len(role.permissions)
        
        # Find overprivileged identities
        analysis.overprivileged_identities = self.find_overprivileged_identities(bindings)
        
        # Generate recommendations
        if analysis.basic_roles_count > 0:
            analysis.recommendations.append(
                f"Consider replacing {analysis.basic_roles_count} basic roles with more specific predefined roles"
            )
        
        if len(analysis.overprivileged_identities) > 0:
            analysis.recommendations.append(
                f"Review {len(analysis.overprivileged_identities)} potentially overprivileged identities"
            )
        
        if analysis.unused_roles:
            analysis.recommendations.append(
                f"Consider removing {len(analysis.unused_roles)} unused custom roles"
            )
        
        return analysis
    
    @property
    def basic_roles_count(self) -> int:
        """Helper property for basic roles count in analysis."""
        return getattr(self, '_basic_roles_count', 0)