"""
Data models for GCP IAM entities.

Defines dataclasses and enums for representing IAM identities, roles,
permissions, bindings, and analysis results.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Set, Optional, Union, Any
from datetime import datetime
import json


class IdentityType(Enum):
    """Types of IAM identities."""
    USER = "user"
    SERVICE_ACCOUNT = "serviceAccount"
    GROUP = "group"
    DOMAIN = "domain"
    DELETED = "deleted"
    UNKNOWN = "unknown"


class RoleType(Enum):
    """Types of IAM roles."""
    BASIC = "basic"
    PREDEFINED = "predefined"
    CUSTOM = "custom"


class ResourceType(Enum):
    """Types of GCP resources."""
    ORGANIZATION = "organization"
    FOLDER = "folder"
    PROJECT = "project"
    UNKNOWN = "unknown"


class PermissionRiskLevel(Enum):
    """Risk levels for permissions."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Identity:
    """Represents an IAM identity (user, service account, group, etc.)."""
    
    email: str
    identity_type: IdentityType
    display_name: Optional[str] = None
    deleted: bool = False
    domain: Optional[str] = None
    
    # Aggregated data
    total_roles: int = 0
    projects_with_access: Set[str] = field(default_factory=set)
    roles_assigned: Set[str] = field(default_factory=set)
    effective_permissions: Set[str] = field(default_factory=set)
    
    def __post_init__(self):
        """Post-initialization processing."""
        if isinstance(self.projects_with_access, list):
            self.projects_with_access = set(self.projects_with_access)
        if isinstance(self.roles_assigned, list):
            self.roles_assigned = set(self.roles_assigned)
        if isinstance(self.effective_permissions, list):
            self.effective_permissions = set(self.effective_permissions)
    
    @classmethod
    def from_member_string(cls, member: str) -> 'Identity':
        """
        Create Identity from IAM member string.
        
        Args:
            member: IAM member string like 'user:email@domain.com'
            
        Returns:
            Identity: Parsed identity object
        """
        if ':' not in member:
            return cls(
                email=member,
                identity_type=IdentityType.UNKNOWN
            )
        
        identity_type_str, email = member.split(':', 1)
        
        # Map string to enum
        identity_type_map = {
            'user': IdentityType.USER,
            'serviceAccount': IdentityType.SERVICE_ACCOUNT,
            'group': IdentityType.GROUP,
            'domain': IdentityType.DOMAIN,
            'deleted': IdentityType.DELETED
        }
        
        identity_type = identity_type_map.get(identity_type_str, IdentityType.UNKNOWN)
        
        # Extract domain for user accounts
        domain = None
        if identity_type == IdentityType.USER and '@' in email:
            domain = email.split('@')[1]
        
        # Check if it's a deleted account
        deleted = identity_type == IdentityType.DELETED
        
        return cls(
            email=email,
            identity_type=identity_type,
            domain=domain,
            deleted=deleted
        )
    
    def to_member_string(self) -> str:
        """Convert identity back to IAM member string."""
        return f"{self.identity_type.value}:{self.email}"
    
    def add_role_assignment(self, role_name: str, project_id: str, permissions: Set[str]):
        """Add a role assignment to this identity."""
        self.roles_assigned.add(role_name)
        self.projects_with_access.add(project_id)
        self.effective_permissions.update(permissions)
        self.total_roles = len(self.roles_assigned)


@dataclass
class Permission:
    """Represents an IAM permission."""
    
    name: str
    service: str
    resource: str
    action: str
    risk_level: PermissionRiskLevel = PermissionRiskLevel.LOW
    description: Optional[str] = None
    
    def __post_init__(self):
        """Parse permission name into components."""
        if '.' in self.name:
            parts = self.name.split('.')
            if len(parts) >= 3:
                self.service = parts[0]
                self.resource = parts[1]
                self.action = '.'.join(parts[2:])


@dataclass
class Role:
    """Represents an IAM role."""
    
    name: str
    title: str
    role_type: RoleType
    description: Optional[str] = None
    permissions: Set[str] = field(default_factory=set)
    stage: Optional[str] = None  # GA, BETA, ALPHA, DEPRECATED
    
    # Usage statistics
    usage_count: int = 0
    assigned_to_identities: Set[str] = field(default_factory=set)
    used_in_projects: Set[str] = field(default_factory=set)
    
    def __post_init__(self):
        """Post-initialization processing."""
        if isinstance(self.permissions, list):
            self.permissions = set(self.permissions)
        if isinstance(self.assigned_to_identities, list):
            self.assigned_to_identities = set(self.assigned_to_identities)
        if isinstance(self.used_in_projects, list):
            self.used_in_projects = set(self.used_in_projects)
        
        # Determine role type from name
        if self.role_type == RoleType.CUSTOM and self.name.startswith('roles/'):
            if self.name in ['roles/owner', 'roles/editor', 'roles/viewer']:
                self.role_type = RoleType.BASIC
            else:
                self.role_type = RoleType.PREDEFINED
    
    @classmethod
    def from_api_response(cls, role_data: Dict[str, Any]) -> 'Role':
        """Create Role from GCP API response."""
        name = role_data.get('name', '')
        title = role_data.get('title', '')
        description = role_data.get('description', '')
        stage = role_data.get('stage', '')
        
        # Determine role type
        if name.startswith('projects/'):
            role_type = RoleType.CUSTOM
        elif name in ['roles/owner', 'roles/editor', 'roles/viewer']:
            role_type = RoleType.BASIC
        else:
            role_type = RoleType.PREDEFINED
        
        # Extract permissions
        permissions = set()
        if 'includedPermissions' in role_data:
            permissions = set(role_data['includedPermissions'])
        
        return cls(
            name=name,
            title=title,
            role_type=role_type,
            description=description,
            permissions=permissions,
            stage=stage
        )
    
    def add_usage(self, identity_email: str, project_id: str):
        """Add usage statistics for this role."""
        self.assigned_to_identities.add(identity_email)
        self.used_in_projects.add(project_id)
        self.usage_count = len(self.assigned_to_identities)


@dataclass
class Binding:
    """Represents an IAM policy binding."""
    
    role: str
    members: Set[str] = field(default_factory=set)
    condition: Optional[Dict[str, Any]] = None
    
    # Context information
    resource_name: str = ""
    resource_type: ResourceType = ResourceType.UNKNOWN
    
    def __post_init__(self):
        """Post-initialization processing."""
        if isinstance(self.members, list):
            self.members = set(self.members)
    
    @classmethod
    def from_api_response(cls, binding_data: Dict[str, Any], resource_name: str = "", resource_type: ResourceType = ResourceType.UNKNOWN) -> 'Binding':
        """Create Binding from GCP API response."""
        role = binding_data.get('role', '')
        members = set(binding_data.get('members', []))
        condition = binding_data.get('condition')
        
        return cls(
            role=role,
            members=members,
            condition=condition,
            resource_name=resource_name,
            resource_type=resource_type
        )
    
    def get_identities(self) -> List[Identity]:
        """Get Identity objects for all members in this binding."""
        return [Identity.from_member_string(member) for member in self.members]


@dataclass
class PolicyAnalysis:
    """Results of IAM policy analysis."""
    
    total_identities: int = 0
    total_roles: int = 0
    total_permissions: int = 0
    total_bindings: int = 0
    
    # Breakdowns
    identities_by_type: Dict[IdentityType, int] = field(default_factory=dict)
    roles_by_type: Dict[RoleType, int] = field(default_factory=dict)
    
    # Risk analysis
    overprivileged_identities: List[str] = field(default_factory=list)
    unused_roles: List[str] = field(default_factory=list)
    risky_permissions: List[str] = field(default_factory=list)
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    
    def add_identity(self, identity: Identity):
        """Add identity to analysis."""
        self.total_identities += 1
        self.identities_by_type[identity.identity_type] = \
            self.identities_by_type.get(identity.identity_type, 0) + 1
    
    def add_role(self, role: Role):
        """Add role to analysis."""
        self.total_roles += 1
        self.roles_by_type[role.role_type] = \
            self.roles_by_type.get(role.role_type, 0) + 1
        
        if role.usage_count == 0:
            self.unused_roles.append(role.name)


@dataclass
class OverprivilegedAlert:
    """Alert for potential over-privileging."""
    
    identity_email: str
    severity: PermissionRiskLevel
    title: str
    description: str
    recommended_action: str
    affected_resources: List[str] = field(default_factory=list)
    risky_permissions: List[str] = field(default_factory=list)
    
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class ResourceIAMPolicy:
    """IAM policy for a specific resource."""
    
    resource_name: str
    resource_type: ResourceType
    bindings: List[Binding] = field(default_factory=list)
    etag: Optional[str] = None
    version: int = 1
    
    # Analysis results
    unique_identities: Set[str] = field(default_factory=set)
    unique_roles: Set[str] = field(default_factory=set)
    
    def __post_init__(self):
        """Post-initialization processing."""
        # Calculate unique identities and roles
        for binding in self.bindings:
            self.unique_identities.update(binding.members)
            self.unique_roles.add(binding.role)
    
    @classmethod
    def from_api_response(cls, policy_data: Dict[str, Any], resource_name: str, resource_type: ResourceType) -> 'ResourceIAMPolicy':
        """Create ResourceIAMPolicy from GCP API response."""
        bindings = []
        
        for binding_data in policy_data.get('bindings', []):
            binding = Binding.from_api_response(binding_data, resource_name, resource_type)
            bindings.append(binding)
        
        return cls(
            resource_name=resource_name,
            resource_type=resource_type,
            bindings=bindings,
            etag=policy_data.get('etag'),
            version=policy_data.get('version', 1)
        )
    
    def get_all_identities(self) -> List[Identity]:
        """Get all unique Identity objects from this policy."""
        identities = {}
        
        for binding in self.bindings:
            for member in binding.members:
                if member not in identities:
                    identities[member] = Identity.from_member_string(member)
                
                # Add role information to identity
                identity = identities[member]
                identity.roles_assigned.add(binding.role)
                identity.projects_with_access.add(self.resource_name)
        
        return list(identities.values())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'resource_name': self.resource_name,
            'resource_type': self.resource_type.value,
            'bindings': [
                {
                    'role': binding.role,
                    'members': list(binding.members),
                    'condition': binding.condition
                }
                for binding in self.bindings
            ],
            'etag': self.etag,
            'version': self.version,
            'unique_identities_count': len(self.unique_identities),
            'unique_roles_count': len(self.unique_roles)
        }