"""
Advanced Role Management client for custom role building and role comparison tools.

This module provides comprehensive role management capabilities including:
- Custom role builder with permission selection and validation
- Role comparison and difference analysis
- Role optimization recommendations
- Role usage analysis and impact assessment
- Role template management
"""

import logging
from typing import List, Dict, Set, Optional, Any, Tuple
from datetime import datetime
from google.auth.credentials import Credentials
from google.cloud import iam_admin_v1
from google.api_core.exceptions import GoogleAPIError, NotFound, PermissionDenied
from dataclasses import dataclass, field
import json
import re

from ..models.iam_models import Role, RoleType, Permission, PermissionRiskLevel

logger = logging.getLogger(__name__)


@dataclass
class RoleComparison:
    """Results of comparing two IAM roles."""
    role_a: str
    role_b: str
    common_permissions: Set[str] = field(default_factory=set)
    unique_to_a: Set[str] = field(default_factory=set)
    unique_to_b: Set[str] = field(default_factory=set)
    similarity_score: float = 0.0
    risk_difference: str = "low"
    recommendations: List[str] = field(default_factory=list)


@dataclass
class CustomRoleSpec:
    """Specification for building a custom role."""
    title: str
    description: str
    permissions: Set[str] = field(default_factory=set)
    stage: str = "GA"
    included_roles: List[str] = field(default_factory=list)
    excluded_permissions: Set[str] = field(default_factory=set)


@dataclass
class RoleTemplate:
    """Template for common role patterns."""
    name: str
    title: str
    description: str
    category: str
    permissions: Set[str] = field(default_factory=set)
    required_services: List[str] = field(default_factory=list)
    use_cases: List[str] = field(default_factory=list)


class RoleManagementClient:
    """Advanced client for role management and custom role operations."""
    
    def __init__(self, credentials: Credentials, project_id: Optional[str] = None):
        """
        Initialize Role Management client.
        
        Args:
            credentials: Authenticated GCP credentials
            project_id: GCP project ID for custom role operations
        """
        self.credentials = credentials
        self.project_id = project_id
        self._iam_service = None
        self._predefined_roles_cache = {}
        self._permissions_cache = {}
        self._role_templates = self._initialize_role_templates()
    
    @property
    def iam_service(self) -> iam_admin_v1.IAMClient:
        """Get or create IAM service client."""
        if self._iam_service is None:
            self._iam_service = iam_admin_v1.IAMClient(credentials=self.credentials)
        return self._iam_service
    
    def _initialize_role_templates(self) -> Dict[str, RoleTemplate]:
        """Initialize built-in role templates for common use cases."""
        templates = {
            "developer_readonly": RoleTemplate(
                name="developer_readonly",
                title="Developer Read-Only Access",
                description="Read-only access to development resources",
                category="development",
                permissions={
                    "compute.instances.get",
                    "compute.instances.list",
                    "storage.objects.get",
                    "storage.objects.list",
                    "logging.entries.list",
                    "monitoring.timeSeries.list",
                    "cloudsql.instances.get",
                    "cloudsql.instances.list"
                },
                required_services=["compute", "storage", "logging", "monitoring", "sqladmin"],
                use_cases=["Development team read access", "Troubleshooting", "Monitoring"]
            ),
            
            "devops_deployer": RoleTemplate(
                name="devops_deployer",
                title="DevOps Deployment Access",
                description="Permissions for deployment automation and CI/CD",
                category="devops",
                permissions={
                    "compute.instances.create",
                    "compute.instances.delete",
                    "compute.instances.start",
                    "compute.instances.stop",
                    "storage.objects.create",
                    "storage.objects.delete",
                    "cloudbuild.builds.create",
                    "cloudbuild.builds.get",
                    "container.clusters.get",
                    "container.clusters.update",
                    "run.services.create",
                    "run.services.update"
                },
                required_services=["compute", "storage", "cloudbuild", "container", "run"],
                use_cases=["CI/CD pipelines", "Automated deployments", "Infrastructure as Code"]
            ),
            
            "security_auditor": RoleTemplate(
                name="security_auditor",
                title="Security Audit Access",
                description="Read-only access for security auditing and compliance",
                category="security",
                permissions={
                    "iam.roles.list",
                    "iam.roles.get",
                    "iam.serviceAccounts.list",
                    "iam.serviceAccounts.get",
                    "resourcemanager.projects.getIamPolicy",
                    "logging.entries.list",
                    "securitycenter.findings.list",
                    "securitycenter.assets.list",
                    "cloudasset.assets.searchAllResources",
                    "cloudasset.assets.searchAllIamPolicies"
                },
                required_services=["iam", "resourcemanager", "logging", "securitycenter", "cloudasset"],
                use_cases=["Security auditing", "Compliance reporting", "Risk assessment"]
            ),
            
            "data_scientist": RoleTemplate(
                name="data_scientist",
                title="Data Science Access",
                description="Access for data science and machine learning workflows",
                category="analytics",
                permissions={
                    "bigquery.datasets.get",
                    "bigquery.tables.get",
                    "bigquery.tables.getData",
                    "bigquery.jobs.create",
                    "ml.models.get",
                    "ml.models.predict",
                    "ml.versions.get",
                    "ml.versions.predict",
                    "storage.objects.get",
                    "storage.objects.list",
                    "aiplatform.endpoints.predict",
                    "notebooks.instances.use"
                },
                required_services=["bigquery", "ml", "storage", "aiplatform", "notebooks"],
                use_cases=["Data analysis", "Machine learning", "Model training and inference"]
            )
        }
        
        return templates
    
    def compare_roles(self, role_a: str, role_b: str) -> RoleComparison:
        """
        Compare two roles and analyze their differences.
        
        Args:
            role_a: First role name
            role_b: Second role name
            
        Returns:
            RoleComparison object with detailed comparison results
        """
        comparison = RoleComparison(role_a=role_a, role_b=role_b)
        
        try:
            # Get role details
            role_a_obj = self.get_role_details(role_a)
            role_b_obj = self.get_role_details(role_b)
            
            if not role_a_obj or not role_b_obj:
                logger.error(f"Could not retrieve role details for comparison: {role_a}, {role_b}")
                return comparison
            
            perms_a = role_a_obj.permissions
            perms_b = role_b_obj.permissions
            
            # Calculate set operations
            comparison.common_permissions = perms_a & perms_b
            comparison.unique_to_a = perms_a - perms_b
            comparison.unique_to_b = perms_b - perms_a
            
            # Calculate similarity score (Jaccard similarity)
            union_size = len(perms_a | perms_b)
            if union_size > 0:
                comparison.similarity_score = len(comparison.common_permissions) / union_size
            
            # Assess risk difference
            comparison.risk_difference = self._assess_risk_difference(
                comparison.unique_to_a, comparison.unique_to_b
            )
            
            # Generate recommendations
            comparison.recommendations = self._generate_role_comparison_recommendations(
                comparison, role_a_obj, role_b_obj
            )
            
        except Exception as e:
            logger.error(f"Error comparing roles {role_a} and {role_b}: {e}")
            comparison.recommendations.append(f"Error during comparison: {str(e)}")
        
        return comparison
    
    def get_role_details(self, role_name: str) -> Optional[Role]:
        """Get detailed role information including permissions."""
        try:
            # Check cache first
            if role_name in self._predefined_roles_cache:
                return self._predefined_roles_cache[role_name]
            
            request = iam_v1.GetRoleRequest(name=role_name)
            role_response = self.iam_service.get_role(request=request)
            
            role_obj = Role.from_api_response({
                'name': role_response.name,
                'title': role_response.title,
                'description': role_response.description,
                'includedPermissions': list(role_response.included_permissions),
                'stage': role_response.stage.name if role_response.stage else 'GA'
            })
            
            # Cache the result
            self._predefined_roles_cache[role_name] = role_obj
            
            return role_obj
            
        except NotFound:
            logger.warning(f"Role not found: {role_name}")
            return None
        except Exception as e:
            logger.error(f"Error getting role details for {role_name}: {e}")
            return None
    
    def _assess_risk_difference(self, unique_to_a: Set[str], unique_to_b: Set[str]) -> str:
        """Assess the risk level of differences between two roles."""
        high_risk_permissions = [
            'iam.serviceAccounts.actAs',
            'iam.roles.create',
            'iam.roles.delete',
            'resourcemanager.projects.setIamPolicy',
            'compute.instances.setServiceAccount',
            'storage.objects.delete'
        ]
        
        # Check if any high-risk permissions are in the differences
        all_different_perms = unique_to_a | unique_to_b
        
        high_risk_count = sum(1 for perm in all_different_perms 
                             if any(risk_perm in perm for risk_perm in high_risk_permissions))
        
        total_different = len(all_different_perms)
        
        if high_risk_count > 0 or total_different > 50:
            return "high"
        elif total_different > 20:
            return "medium"
        else:
            return "low"
    
    def _generate_role_comparison_recommendations(
        self, comparison: RoleComparison, role_a: Role, role_b: Role
    ) -> List[str]:
        """Generate recommendations based on role comparison results."""
        recommendations = []
        
        similarity = comparison.similarity_score
        
        if similarity > 0.8:
            recommendations.append(
                f"Roles are very similar ({similarity:.1%} overlap). "
                "Consider consolidating or using one role instead of both."
            )
        elif similarity < 0.2:
            recommendations.append(
                f"Roles have minimal overlap ({similarity:.1%}). "
                "They serve different purposes and should remain separate."
            )
        
        # Analyze unique permissions
        unique_a_count = len(comparison.unique_to_a)
        unique_b_count = len(comparison.unique_to_b)
        
        if unique_a_count > 0:
            recommendations.append(
                f"{role_a.title} has {unique_a_count} unique permissions not in {role_b.title}"
            )
        
        if unique_b_count > 0:
            recommendations.append(
                f"{role_b.title} has {unique_b_count} unique permissions not in {role_a.title}"
            )
        
        # Risk-based recommendations
        if comparison.risk_difference == "high":
            recommendations.append(
                "HIGH RISK: Significant permission differences detected. "
                "Review unique permissions carefully before role substitution."
            )
        elif comparison.risk_difference == "medium":
            recommendations.append(
                "MEDIUM RISK: Notable permission differences. "
                "Test thoroughly if considering role substitution."
            )
        
        return recommendations
    
    def build_custom_role(self, spec: CustomRoleSpec, project_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Build a custom role based on the provided specification.
        
        Args:
            spec: Custom role specification
            project_id: Project ID (uses instance default if not provided)
            
        Returns:
            Dict containing the role creation result and analysis
        """
        if not project_id:
            project_id = self.project_id
        
        if not project_id:
            raise ValueError("Project ID is required for custom role creation")
        
        result = {
            'role_id': '',
            'success': False,
            'validation_errors': [],
            'warnings': [],
            'final_permissions': set(),
            'role_analysis': {},
            'implementation_steps': []
        }
        
        try:
            # Validate the role specification
            validation_result = self._validate_role_spec(spec)
            result['validation_errors'] = validation_result['errors']
            result['warnings'] = validation_result['warnings']
            
            if validation_result['errors']:
                logger.error(f"Role specification validation failed: {validation_result['errors']}")
                return result
            
            # Build the final permission set
            final_permissions = self._build_permission_set(spec)
            result['final_permissions'] = final_permissions
            
            # Generate a role ID
            role_id = self._generate_role_id(spec.title, project_id)
            result['role_id'] = role_id
            
            # Analyze the role
            result['role_analysis'] = self._analyze_custom_role(final_permissions)
            
            # Generate implementation steps
            result['implementation_steps'] = self._generate_implementation_steps(
                role_id, spec, final_permissions, project_id
            )
            
            logger.info(f"Custom role specification built successfully: {role_id}")
            result['success'] = True
            
        except Exception as e:
            logger.error(f"Error building custom role: {e}")
            result['validation_errors'].append(f"Build error: {str(e)}")
        
        return result
    
    def _validate_role_spec(self, spec: CustomRoleSpec) -> Dict[str, List[str]]:
        """Validate a custom role specification."""
        errors = []
        warnings = []
        
        # Validate title
        if not spec.title:
            errors.append("Role title is required")
        elif len(spec.title) > 100:
            errors.append("Role title must be 100 characters or less")
        elif not re.match(r'^[a-zA-Z0-9\s\-_\.]+$', spec.title):
            errors.append("Role title contains invalid characters")
        
        # Validate description
        if not spec.description:
            warnings.append("Role description is recommended")
        elif len(spec.description) > 2000:
            errors.append("Role description must be 2000 characters or less")
        
        # Validate permissions
        if not spec.permissions and not spec.included_roles:
            errors.append("At least one permission or included role is required")
        
        # Validate permission format
        invalid_perms = []
        for perm in spec.permissions:
            if not re.match(r'^[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+', perm):
                invalid_perms.append(perm)
        
        if invalid_perms:
            errors.append(f"Invalid permission format: {', '.join(invalid_perms[:5])}")
        
        # Check for excessive permissions
        if len(spec.permissions) > 500:
            warnings.append("Large number of permissions (>500). Consider using predefined roles instead.")
        
        return {'errors': errors, 'warnings': warnings}
    
    def _build_permission_set(self, spec: CustomRoleSpec) -> Set[str]:
        """Build the final set of permissions for a custom role."""
        final_permissions = set(spec.permissions)
        
        # Add permissions from included roles
        for role_name in spec.included_roles:
            role_obj = self.get_role_details(role_name)
            if role_obj:
                final_permissions.update(role_obj.permissions)
            else:
                logger.warning(f"Could not retrieve permissions for included role: {role_name}")
        
        # Remove excluded permissions
        final_permissions -= spec.excluded_permissions
        
        return final_permissions
    
    def _generate_role_id(self, title: str, project_id: str) -> str:
        """Generate a role ID from the title."""
        # Convert title to a valid role ID
        role_id = re.sub(r'[^a-zA-Z0-9]', '_', title.lower())
        role_id = re.sub(r'_+', '_', role_id)  # Remove multiple underscores
        role_id = role_id.strip('_')  # Remove leading/trailing underscores
        
        # Ensure it starts with a letter
        if role_id and not role_id[0].isalpha():
            role_id = 'custom_' + role_id
        
        # Truncate if too long
        if len(role_id) > 64:
            role_id = role_id[:64]
        
        return role_id
    
    def _analyze_custom_role(self, permissions: Set[str]) -> Dict[str, Any]:
        """Analyze a custom role's permissions and characteristics."""
        analysis = {
            'total_permissions': len(permissions),
            'services_affected': set(),
            'risk_assessment': {
                'overall_risk': 'low',
                'high_risk_permissions': [],
                'risk_factors': []
            },
            'permission_categories': {
                'read': 0,
                'write': 0,
                'admin': 0,
                'delete': 0
            },
            'recommendations': []
        }
        
        # Analyze permissions
        high_risk_patterns = [
            'setIamPolicy', 'actAs', 'delete', 'admin', 'impersonate'
        ]
        
        read_patterns = ['get', 'list', 'view', 'read']
        write_patterns = ['create', 'update', 'write', 'set', 'patch']
        admin_patterns = ['admin', 'manage', 'setIamPolicy']
        delete_patterns = ['delete', 'remove', 'destroy']
        
        for perm in permissions:
            # Extract service
            if '.' in perm:
                service = perm.split('.')[0]
                analysis['services_affected'].add(service)
            
            perm_lower = perm.lower()
            
            # Check risk level
            if any(pattern in perm_lower for pattern in high_risk_patterns):
                analysis['risk_assessment']['high_risk_permissions'].append(perm)
            
            # Categorize permissions
            if any(pattern in perm_lower for pattern in delete_patterns):
                analysis['permission_categories']['delete'] += 1
            elif any(pattern in perm_lower for pattern in admin_patterns):
                analysis['permission_categories']['admin'] += 1
            elif any(pattern in perm_lower for pattern in write_patterns):
                analysis['permission_categories']['write'] += 1
            elif any(pattern in perm_lower for pattern in read_patterns):
                analysis['permission_categories']['read'] += 1
        
        # Assess overall risk
        high_risk_count = len(analysis['risk_assessment']['high_risk_permissions'])
        admin_count = analysis['permission_categories']['admin']
        delete_count = analysis['permission_categories']['delete']
        
        if high_risk_count > 5 or admin_count > 10 or delete_count > 10:
            analysis['risk_assessment']['overall_risk'] = 'high'
            analysis['risk_assessment']['risk_factors'].append('High number of privileged permissions')
        elif high_risk_count > 0 or admin_count > 5 or delete_count > 5:
            analysis['risk_assessment']['overall_risk'] = 'medium'
            analysis['risk_assessment']['risk_factors'].append('Contains privileged permissions')
        
        # Convert sets to lists for JSON serialization
        analysis['services_affected'] = list(analysis['services_affected'])
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_custom_role_recommendations(analysis)
        
        return analysis
    
    def _generate_custom_role_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate recommendations for a custom role."""
        recommendations = []
        
        total_perms = analysis['total_permissions']
        risk_level = analysis['risk_assessment']['overall_risk']
        high_risk_perms = len(analysis['risk_assessment']['high_risk_permissions'])
        
        # Size recommendations
        if total_perms > 100:
            recommendations.append(
                "Consider breaking this role into smaller, more focused roles"
            )
        elif total_perms < 5:
            recommendations.append(
                "Role has very few permissions. Consider using a predefined role instead"
            )
        
        # Risk recommendations
        if risk_level == 'high':
            recommendations.append(
                "HIGH RISK: This role contains many privileged permissions. "
                "Use with caution and implement strong access controls"
            )
        elif risk_level == 'medium':
            recommendations.append(
                "MEDIUM RISK: Review privileged permissions and ensure they are necessary"
            )
        
        # Specific recommendations
        if high_risk_perms > 0:
            recommendations.append(
                f"Review {high_risk_perms} high-risk permissions for necessity"
            )
        
        categories = analysis['permission_categories']
        if categories['delete'] > categories['write']:
            recommendations.append(
                "Role has more delete permissions than write permissions. "
                "Consider if all delete permissions are necessary"
            )
        
        if len(analysis['services_affected']) > 10:
            recommendations.append(
                "Role affects many services. Consider service-specific roles instead"
            )
        
        return recommendations
    
    def _generate_implementation_steps(
        self, role_id: str, spec: CustomRoleSpec, permissions: Set[str], project_id: str
    ) -> List[Dict[str, Any]]:
        """Generate step-by-step implementation instructions."""
        steps = []
        
        # Step 1: Create role definition file
        role_definition = {
            "title": spec.title,
            "description": spec.description,
            "stage": spec.stage,
            "includedPermissions": sorted(list(permissions))
        }
        
        steps.append({
            "step": 1,
            "title": "Create role definition file",
            "command": f"cat > {role_id}.yaml << 'EOF'\n{json.dumps(role_definition, indent=2)}\nEOF",
            "description": "Create a YAML file with the role definition"
        })
        
        # Step 2: Create the custom role
        steps.append({
            "step": 2,
            "title": "Create custom role",
            "command": f"gcloud iam roles create {role_id} --project={project_id} --file={role_id}.yaml",
            "description": "Create the custom role in your GCP project"
        })
        
        # Step 3: Verify role creation
        steps.append({
            "step": 3,
            "title": "Verify role creation",
            "command": f"gcloud iam roles describe {role_id} --project={project_id}",
            "description": "Verify that the role was created successfully"
        })
        
        # Step 4: Test role assignment (optional)
        steps.append({
            "step": 4,
            "title": "Test role assignment (optional)",
            "command": f"gcloud projects add-iam-policy-binding {project_id} "
                      f"--member='user:test-user@example.com' "
                      f"--role='projects/{project_id}/roles/{role_id}'",
            "description": "Test assigning the role to a user (replace with actual email)"
        })
        
        return steps
    
    def get_role_templates(self, category: Optional[str] = None) -> Dict[str, RoleTemplate]:
        """Get available role templates, optionally filtered by category."""
        if category:
            return {
                name: template for name, template in self._role_templates.items()
                if template.category == category
            }
        return self._role_templates.copy()
    
    def create_role_from_template(self, template_name: str, customizations: Optional[Dict[str, Any]] = None) -> CustomRoleSpec:
        """Create a custom role specification from a template."""
        if template_name not in self._role_templates:
            raise ValueError(f"Template '{template_name}' not found")
        
        template = self._role_templates[template_name]
        
        spec = CustomRoleSpec(
            title=template.title,
            description=template.description,
            permissions=template.permissions.copy()
        )
        
        # Apply customizations
        if customizations:
            if 'title' in customizations:
                spec.title = customizations['title']
            if 'description' in customizations:
                spec.description = customizations['description']
            if 'additional_permissions' in customizations:
                spec.permissions.update(customizations['additional_permissions'])
            if 'remove_permissions' in customizations:
                spec.permissions -= set(customizations['remove_permissions'])
        
        return spec
    
    def analyze_role_usage(self, role_name: str, bindings_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze how a role is being used across the organization."""
        usage_analysis = {
            'total_assignments': 0,
            'unique_identities': set(),
            'identity_types': {},
            'projects_used': set(),
            'usage_patterns': [],
            'optimization_opportunities': []
        }
        
        for binding in bindings_data:
            if binding.get('role') == role_name:
                usage_analysis['total_assignments'] += len(binding.get('members', []))
                
                for member in binding.get('members', []):
                    usage_analysis['unique_identities'].add(member)
                    
                    # Analyze identity type
                    if ':' in member:
                        identity_type = member.split(':', 1)[0]
                        usage_analysis['identity_types'][identity_type] = \
                            usage_analysis['identity_types'].get(identity_type, 0) + 1
                
                # Track project usage
                resource_name = binding.get('resource_name', '')
                if 'projects/' in resource_name:
                    project_id = resource_name.split('/')[-1]
                    usage_analysis['projects_used'].add(project_id)
        
        # Convert sets to counts and lists
        usage_analysis['unique_identities_count'] = len(usage_analysis['unique_identities'])
        usage_analysis['projects_used_count'] = len(usage_analysis['projects_used'])
        usage_analysis['unique_identities'] = list(usage_analysis['unique_identities'])
        usage_analysis['projects_used'] = list(usage_analysis['projects_used'])
        
        # Generate optimization opportunities
        if usage_analysis['total_assignments'] == 0:
            usage_analysis['optimization_opportunities'].append(
                "Role is not being used and could be deleted"
            )
        elif usage_analysis['unique_identities_count'] == 1:
            usage_analysis['optimization_opportunities'].append(
                "Role is only used by one identity. Consider if a predefined role would work"
            )
        elif usage_analysis['projects_used_count'] > 10:
            usage_analysis['optimization_opportunities'].append(
                "Role is used across many projects. Consider organization-level assignment"
            )
        
        return usage_analysis
    
    def suggest_role_optimizations(self, roles_usage: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Suggest optimizations based on role usage analysis."""
        optimizations = []
        
        # Find unused roles
        unused_roles = [
            role_name for role_name, usage in roles_usage.items()
            if usage.get('total_assignments', 0) == 0
        ]
        
        if unused_roles:
            optimizations.append({
                'type': 'remove_unused',
                'priority': 'medium',
                'title': 'Remove Unused Roles',
                'description': f'Found {len(unused_roles)} unused custom roles',
                'affected_roles': unused_roles,
                'estimated_benefit': 'Reduced complexity and maintenance overhead'
            })
        
        # Find roles with single user
        single_user_roles = [
            role_name for role_name, usage in roles_usage.items()
            if usage.get('unique_identities_count', 0) == 1
        ]
        
        if single_user_roles:
            optimizations.append({
                'type': 'consolidate_single_user',
                'priority': 'low',
                'title': 'Review Single-User Roles',
                'description': f'Found {len(single_user_roles)} roles used by only one identity',
                'affected_roles': single_user_roles,
                'estimated_benefit': 'Consider using predefined roles instead'
            })
        
        # Find roles used across many projects
        cross_project_roles = [
            role_name for role_name, usage in roles_usage.items()
            if usage.get('projects_used_count', 0) > 5
        ]
        
        if cross_project_roles:
            optimizations.append({
                'type': 'org_level_assignment',
                'priority': 'medium',
                'title': 'Consider Organization-Level Assignment',
                'description': f'Found {len(cross_project_roles)} roles used across many projects',
                'affected_roles': cross_project_roles,
                'estimated_benefit': 'Simplified management through organization-level IAM'
            })
        
        return optimizations