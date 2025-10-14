"""
Permission Deep Dive client for detailed permission analysis and risk scoring.

This module provides comprehensive permission analysis capabilities including:
- Detailed permission risk assessment and scoring
- Permission relationship mapping and dependency analysis
- Security impact analysis and threat modeling
- Permission usage pattern analysis
- Compliance and governance recommendations
"""

import logging
from typing import List, Dict, Set, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass, field
from collections import defaultdict
import re
import json

from ..models.iam_models import Permission, PermissionRiskLevel, Identity, Role

logger = logging.getLogger(__name__)


@dataclass
class PermissionRiskAssessment:
    """Detailed risk assessment for a permission."""
    permission: str
    risk_level: PermissionRiskLevel
    risk_score: int  # 0-100
    risk_factors: List[str] = field(default_factory=list)
    security_implications: List[str] = field(default_factory=list)
    compliance_concerns: List[str] = field(default_factory=list)
    mitigation_strategies: List[str] = field(default_factory=list)
    similar_permissions: List[str] = field(default_factory=list)


@dataclass
class PermissionDependency:
    """Represents a dependency relationship between permissions."""
    permission: str
    depends_on: Set[str] = field(default_factory=set)
    enables: Set[str] = field(default_factory=set)
    conflicts_with: Set[str] = field(default_factory=set)
    commonly_paired_with: Set[str] = field(default_factory=set)


@dataclass
class PermissionUsagePattern:
    """Usage pattern analysis for a permission."""
    permission: str
    usage_frequency: int
    identity_types_using: Dict[str, int] = field(default_factory=dict)
    services_context: List[str] = field(default_factory=list)
    role_contexts: List[str] = field(default_factory=list)
    unusual_usage: List[str] = field(default_factory=list)


@dataclass
class PermissionImpactAnalysis:
    """Security impact analysis for a permission."""
    permission: str
    data_access_level: str  # none, read, write, admin
    resource_scope: str  # single, multiple, global
    privilege_escalation_risk: bool
    lateral_movement_risk: bool
    data_exfiltration_risk: bool
    service_disruption_risk: bool
    blast_radius: str  # limited, moderate, extensive


class PermissionAnalyzer:
    """Advanced client for permission analysis and risk assessment."""
    
    def __init__(self):
        """Initialize Permission Analyzer with built-in knowledge base."""
        self._permission_knowledge_base = self._build_permission_knowledge_base()
        self._risk_patterns = self._initialize_risk_patterns()
        self._compliance_frameworks = self._initialize_compliance_frameworks()
        self._permission_relationships = self._build_permission_relationships()
    
    def _build_permission_knowledge_base(self) -> Dict[str, Dict[str, Any]]:
        """Build comprehensive knowledge base of GCP permissions."""
        knowledge_base = {
            # IAM Permissions - High Risk
            "iam.serviceAccounts.actAs": {
                "risk_level": PermissionRiskLevel.CRITICAL,
                "base_risk_score": 95,
                "description": "Allows impersonation of service accounts",
                "security_implications": [
                    "Complete privilege escalation through service account impersonation",
                    "Potential access to all resources the service account can access",
                    "Bypass of user-based access controls"
                ],
                "compliance_concerns": ["SOX", "PCI-DSS", "HIPAA"],
                "data_access_level": "admin",
                "privilege_escalation_risk": True,
                "blast_radius": "extensive"
            },
            
            "iam.roles.create": {
                "risk_level": PermissionRiskLevel.CRITICAL,
                "base_risk_score": 90,
                "description": "Allows creation of custom IAM roles",
                "security_implications": [
                    "Can create roles with any combination of permissions",
                    "Potential for privilege escalation through custom roles",
                    "Bypass of principle of least privilege"
                ],
                "compliance_concerns": ["SOX", "PCI-DSS"],
                "privilege_escalation_risk": True
            },
            
            "resourcemanager.projects.setIamPolicy": {
                "risk_level": PermissionRiskLevel.CRITICAL,
                "base_risk_score": 95,
                "description": "Allows modification of project-level IAM policies",
                "security_implications": [
                    "Complete control over project access",
                    "Can grant any role to any identity",
                    "Potential for unauthorized access escalation"
                ],
                "compliance_concerns": ["SOX", "PCI-DSS", "HIPAA", "GDPR"],
                "privilege_escalation_risk": True,
                "blast_radius": "extensive"
            },
            
            # Compute Permissions
            "compute.instances.create": {
                "risk_level": PermissionRiskLevel.MEDIUM,
                "base_risk_score": 60,
                "description": "Allows creation of compute instances",
                "security_implications": [
                    "Potential for resource abuse and cost accumulation",
                    "Could be used for cryptocurrency mining",
                    "May create instances with excessive access"
                ],
                "compliance_concerns": ["Cost governance"],
                "data_access_level": "write",
                "service_disruption_risk": True
            },
            
            "compute.instances.delete": {
                "risk_level": PermissionRiskLevel.HIGH,
                "base_risk_score": 75,
                "description": "Allows deletion of compute instances",
                "security_implications": [
                    "Potential for service disruption",
                    "Data loss through instance deletion",
                    "Malicious destruction of infrastructure"
                ],
                "compliance_concerns": ["Business continuity"],
                "service_disruption_risk": True,
                "blast_radius": "moderate"
            },
            
            # Storage Permissions
            "storage.objects.delete": {
                "risk_level": PermissionRiskLevel.HIGH,
                "base_risk_score": 80,
                "description": "Allows deletion of storage objects",
                "security_implications": [
                    "Potential for data loss",
                    "Malicious data destruction",
                    "Compliance violations through data deletion"
                ],
                "compliance_concerns": ["GDPR", "HIPAA", "SOX"],
                "data_access_level": "admin",
                "service_disruption_risk": True
            },
            
            "storage.objects.get": {
                "risk_level": PermissionRiskLevel.MEDIUM,
                "base_risk_score": 45,
                "description": "Allows reading storage objects",
                "security_implications": [
                    "Potential data exfiltration",
                    "Access to sensitive information",
                    "Privacy violations"
                ],
                "compliance_concerns": ["GDPR", "HIPAA"],
                "data_access_level": "read",
                "data_exfiltration_risk": True
            },
            
            # BigQuery Permissions
            "bigquery.datasets.delete": {
                "risk_level": PermissionRiskLevel.HIGH,
                "base_risk_score": 85,
                "description": "Allows deletion of BigQuery datasets",
                "security_implications": [
                    "Massive data loss potential",
                    "Business intelligence disruption",
                    "Compliance violations"
                ],
                "compliance_concerns": ["GDPR", "HIPAA", "SOX"],
                "service_disruption_risk": True,
                "blast_radius": "extensive"
            },
            
            "bigquery.tables.getData": {
                "risk_level": PermissionRiskLevel.MEDIUM,
                "base_risk_score": 50,
                "description": "Allows reading BigQuery table data",
                "security_implications": [
                    "Access to potentially large datasets",
                    "Data exfiltration risk",
                    "Privacy violations"
                ],
                "compliance_concerns": ["GDPR", "HIPAA"],
                "data_access_level": "read",
                "data_exfiltration_risk": True
            }
        }
        
        # Add pattern-based permissions for comprehensive coverage
        self._add_pattern_based_permissions(knowledge_base)
        
        return knowledge_base
    
    def _add_pattern_based_permissions(self, knowledge_base: Dict[str, Dict[str, Any]]):
        """Add pattern-based permission analysis for permissions not in explicit knowledge base."""
        # Define patterns that automatically assign risk levels
        high_risk_patterns = [
            ('delete', PermissionRiskLevel.HIGH, 75),
            ('setIamPolicy', PermissionRiskLevel.CRITICAL, 90),
            ('admin', PermissionRiskLevel.HIGH, 80),
            ('impersonate', PermissionRiskLevel.CRITICAL, 95),
            ('actAs', PermissionRiskLevel.CRITICAL, 95)
        ]
        
        medium_risk_patterns = [
            ('create', PermissionRiskLevel.MEDIUM, 60),
            ('update', PermissionRiskLevel.MEDIUM, 55),
            ('write', PermissionRiskLevel.MEDIUM, 50),
            ('modify', PermissionRiskLevel.MEDIUM, 55)
        ]
        
        low_risk_patterns = [
            ('get', PermissionRiskLevel.LOW, 30),
            ('list', PermissionRiskLevel.LOW, 25),
            ('view', PermissionRiskLevel.LOW, 20),
            ('read', PermissionRiskLevel.LOW, 25)
        ]
        
        # Store patterns for use in dynamic analysis
        knowledge_base['_patterns'] = {
            'high_risk': high_risk_patterns,
            'medium_risk': medium_risk_patterns,
            'low_risk': low_risk_patterns
        }
    
    def _initialize_risk_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize risk assessment patterns."""
        return {
            'privilege_escalation': [
                {'pattern': 'iam\\..*', 'risk_multiplier': 1.5},
                {'pattern': '.*setIamPolicy.*', 'risk_multiplier': 2.0},
                {'pattern': '.*actAs.*', 'risk_multiplier': 2.0},
                {'pattern': '.*impersonate.*', 'risk_multiplier': 2.0}
            ],
            
            'data_access': [
                {'pattern': '.*\\.get$', 'risk_multiplier': 1.0},
                {'pattern': '.*\\.list$', 'risk_multiplier': 1.1},
                {'pattern': '.*\\.getData.*', 'risk_multiplier': 1.3},
                {'pattern': 'storage\\.objects\\..*', 'risk_multiplier': 1.2},
                {'pattern': 'bigquery\\..*\\.getData', 'risk_multiplier': 1.4}
            ],
            
            'destructive_actions': [
                {'pattern': '.*\\.delete$', 'risk_multiplier': 1.8},
                {'pattern': '.*\\.destroy$', 'risk_multiplier': 2.0},
                {'pattern': '.*\\.terminate$', 'risk_multiplier': 1.7}
            ],
            
            'administrative': [
                {'pattern': '.*admin.*', 'risk_multiplier': 1.6},
                {'pattern': '.*manage.*', 'risk_multiplier': 1.4},
                {'pattern': '.*configure.*', 'risk_multiplier': 1.3}
            ]
        }
    
    def _initialize_compliance_frameworks(self) -> Dict[str, Dict[str, Any]]:
        """Initialize compliance framework mappings."""
        return {
            'SOX': {
                'description': 'Sarbanes-Oxley Act',
                'high_risk_permissions': [
                    'iam.serviceAccounts.actAs',
                    'resourcemanager.projects.setIamPolicy',
                    'iam.roles.create',
                    'billing.accounts.update'
                ],
                'requirements': [
                    'Segregation of duties',
                    'Audit trail maintenance',
                    'Access control documentation'
                ]
            },
            
            'PCI-DSS': {
                'description': 'Payment Card Industry Data Security Standard',
                'high_risk_permissions': [
                    'storage.objects.get',
                    'bigquery.tables.getData',
                    'cloudsql.instances.connect',
                    'compute.instances.create'
                ],
                'requirements': [
                    'Restrict access to cardholder data',
                    'Implement strong access control measures',
                    'Regularly monitor and test networks'
                ]
            },
            
            'HIPAA': {
                'description': 'Health Insurance Portability and Accountability Act',
                'high_risk_permissions': [
                    'storage.objects.get',
                    'bigquery.tables.getData',
                    'healthcare.datasets.get',
                    'ml.models.predict'
                ],
                'requirements': [
                    'Minimum necessary access',
                    'Audit logs for PHI access',
                    'Data encryption requirements'
                ]
            },
            
            'GDPR': {
                'description': 'General Data Protection Regulation',
                'high_risk_permissions': [
                    'storage.objects.delete',
                    'bigquery.tables.getData',
                    'storage.objects.get',
                    'ml.models.predict'
                ],
                'requirements': [
                    'Data subject rights',
                    'Data processing records',
                    'Privacy by design'
                ]
            }
        }
    
    def _build_permission_relationships(self) -> Dict[str, PermissionDependency]:
        """Build permission dependency and relationship mappings."""
        relationships = {}
        
        # IAM relationship patterns
        relationships['iam.serviceAccounts.actAs'] = PermissionDependency(
            permission='iam.serviceAccounts.actAs',
            depends_on={'iam.serviceAccounts.get'},
            enables={'*'},  # Can potentially access any resource the SA can access
            conflicts_with=set(),
            commonly_paired_with={'iam.serviceAccounts.get', 'iam.serviceAccounts.list'}
        )
        
        # Storage relationships
        relationships['storage.objects.delete'] = PermissionDependency(
            permission='storage.objects.delete',
            depends_on={'storage.objects.get'},
            enables=set(),
            conflicts_with=set(),
            commonly_paired_with={'storage.objects.create', 'storage.objects.update'}
        )
        
        # Compute relationships
        relationships['compute.instances.delete'] = PermissionDependency(
            permission='compute.instances.delete',
            depends_on={'compute.instances.get'},
            enables=set(),
            conflicts_with=set(),
            commonly_paired_with={'compute.instances.create', 'compute.instances.list'}
        )
        
        return relationships
    
    def analyze_permission_risk(self, permission: str, context: Optional[Dict[str, Any]] = None) -> PermissionRiskAssessment:
        """
        Perform comprehensive risk analysis for a single permission.
        
        Args:
            permission: Permission name to analyze
            context: Additional context (identity type, role, etc.)
            
        Returns:
            PermissionRiskAssessment with detailed analysis
        """
        assessment = PermissionRiskAssessment(
            permission=permission,
            risk_level=PermissionRiskLevel.LOW,
            risk_score=0
        )
        
        try:
            # Get base assessment from knowledge base
            if permission in self._permission_knowledge_base:
                base_info = self._permission_knowledge_base[permission]
                assessment.risk_level = base_info['risk_level']
                assessment.risk_score = base_info['base_risk_score']
                assessment.security_implications = base_info.get('security_implications', [])
                assessment.compliance_concerns = base_info.get('compliance_concerns', [])
            else:
                # Use pattern-based analysis
                assessment = self._analyze_permission_by_patterns(permission)
            
            # Apply contextual risk modifiers
            if context:
                assessment = self._apply_contextual_risk_modifiers(assessment, context)
            
            # Generate risk factors
            assessment.risk_factors = self._identify_risk_factors(permission, assessment.risk_score)
            
            # Generate mitigation strategies
            assessment.mitigation_strategies = self._generate_mitigation_strategies(assessment)
            
            # Find similar permissions
            assessment.similar_permissions = self._find_similar_permissions(permission)
            
        except Exception as e:
            logger.error(f"Error analyzing permission risk for {permission}: {e}")
            assessment.risk_factors.append(f"Analysis error: {str(e)}")
        
        return assessment
    
    def _analyze_permission_by_patterns(self, permission: str) -> PermissionRiskAssessment:
        """Analyze permission using pattern matching when not in knowledge base."""
        assessment = PermissionRiskAssessment(
            permission=permission,
            risk_level=PermissionRiskLevel.LOW,
            risk_score=20  # Default base score
        )
        
        patterns = self._permission_knowledge_base.get('_patterns', {})
        
        # Check high risk patterns first
        for pattern, risk_level, base_score in patterns.get('high_risk', []):
            if re.search(pattern, permission.lower()):
                assessment.risk_level = risk_level
                assessment.risk_score = base_score
                assessment.security_implications.append(f"High-risk pattern detected: {pattern}")
                break
        
        # Check medium risk patterns if not high risk
        if assessment.risk_level == PermissionRiskLevel.LOW:
            for pattern, risk_level, base_score in patterns.get('medium_risk', []):
                if re.search(pattern, permission.lower()):
                    assessment.risk_level = risk_level
                    assessment.risk_score = base_score
                    assessment.security_implications.append(f"Medium-risk pattern detected: {pattern}")
                    break
        
        # Check low risk patterns if still unknown
        if assessment.risk_score == 20:  # Still default
            for pattern, risk_level, base_score in patterns.get('low_risk', []):
                if re.search(pattern, permission.lower()):
                    assessment.risk_level = risk_level
                    assessment.risk_score = base_score
                    break
        
        return assessment
    
    def _apply_contextual_risk_modifiers(self, assessment: PermissionRiskAssessment, context: Dict[str, Any]) -> PermissionRiskAssessment:
        """Apply contextual risk modifiers based on usage context."""
        risk_multiplier = 1.0
        
        # Identity type modifiers
        identity_type = context.get('identity_type')
        if identity_type == 'serviceAccount':
            risk_multiplier *= 1.2  # Service accounts can be automated
            assessment.risk_factors.append("Used by service account (automated risk)")
        elif identity_type == 'user' and context.get('domain', '').endswith('gmail.com'):
            risk_multiplier *= 1.3  # External users
            assessment.risk_factors.append("Used by external user account")
        
        # Role context modifiers
        role_name = context.get('role_name', '')
        if 'admin' in role_name.lower():
            risk_multiplier *= 1.4
            assessment.risk_factors.append("Part of administrative role")
        elif 'owner' in role_name.lower():
            risk_multiplier *= 1.5
            assessment.risk_factors.append("Part of owner role")
        
        # Usage frequency modifiers
        usage_frequency = context.get('usage_frequency', 0)
        if usage_frequency > 100:
            risk_multiplier *= 1.1
            assessment.risk_factors.append("High usage frequency")
        elif usage_frequency == 0:
            risk_multiplier *= 0.9
            assessment.risk_factors.append("Unused permission (lower immediate risk)")
        
        # Apply the multiplier
        assessment.risk_score = int(min(100, assessment.risk_score * risk_multiplier))
        
        # Adjust risk level based on final score
        if assessment.risk_score >= 80:
            assessment.risk_level = PermissionRiskLevel.CRITICAL
        elif assessment.risk_score >= 60:
            assessment.risk_level = PermissionRiskLevel.HIGH
        elif assessment.risk_score >= 40:
            assessment.risk_level = PermissionRiskLevel.MEDIUM
        else:
            assessment.risk_level = PermissionRiskLevel.LOW
        
        return assessment
    
    def _identify_risk_factors(self, permission: str, risk_score: int) -> List[str]:
        """Identify specific risk factors for a permission."""
        risk_factors = []
        
        # Pattern-based risk factors
        if 'delete' in permission.lower():
            risk_factors.append("Destructive action capability")
        if 'admin' in permission.lower():
            risk_factors.append("Administrative privilege")
        if 'iam' in permission.lower():
            risk_factors.append("Identity and access management capability")
        if 'setIamPolicy' in permission:
            risk_factors.append("Can modify access controls")
        if 'actAs' in permission:
            risk_factors.append("Impersonation capability")
        
        # Service-based risk factors
        service = permission.split('.')[0] if '.' in permission else ''
        if service in ['iam', 'resourcemanager']:
            risk_factors.append("Affects security-critical service")
        elif service in ['storage', 'bigquery']:
            risk_factors.append("Accesses data storage service")
        elif service in ['compute', 'container']:
            risk_factors.append("Affects compute infrastructure")
        
        # Score-based risk factors
        if risk_score >= 80:
            risk_factors.append("Critical security impact")
        elif risk_score >= 60:
            risk_factors.append("High security impact")
        
        return risk_factors
    
    def _generate_mitigation_strategies(self, assessment: PermissionRiskAssessment) -> List[str]:
        """Generate mitigation strategies based on risk assessment."""
        strategies = []
        
        # Risk level based strategies
        if assessment.risk_level == PermissionRiskLevel.CRITICAL:
            strategies.extend([
                "Implement strict approval process for this permission",
                "Enable detailed audit logging",
                "Consider time-limited access grants",
                "Implement break-glass access procedures"
            ])
        elif assessment.risk_level == PermissionRiskLevel.HIGH:
            strategies.extend([
                "Require manager approval for assignments",
                "Enable audit logging",
                "Regular access reviews required"
            ])
        elif assessment.risk_level == PermissionRiskLevel.MEDIUM:
            strategies.extend([
                "Regular access reviews recommended",
                "Monitor usage patterns"
            ])
        
        # Permission-specific strategies
        permission = assessment.permission.lower()
        
        if 'delete' in permission:
            strategies.append("Consider requiring two-person authorization")
            strategies.append("Implement soft-delete with recovery period")
        
        if 'iam' in permission:
            strategies.append("Implement segregation of duties")
            strategies.append("Regular privilege access review")
        
        if 'data' in permission or 'storage' in permission:
            strategies.append("Implement data classification and labeling")
            strategies.append("Enable data loss prevention (DLP)")
        
        # Compliance-based strategies
        for framework in assessment.compliance_concerns:
            if framework == 'SOX':
                strategies.append("Maintain detailed audit trails for SOX compliance")
            elif framework == 'PCI-DSS':
                strategies.append("Implement PCI-DSS access control requirements")
            elif framework == 'HIPAA':
                strategies.append("Ensure minimum necessary access principle")
            elif framework == 'GDPR':
                strategies.append("Document lawful basis for data processing")
        
        return list(set(strategies))  # Remove duplicates
    
    def _find_similar_permissions(self, permission: str) -> List[str]:
        """Find permissions similar to the given permission."""
        similar = []
        
        # Extract components
        if '.' in permission:
            service, resource, action = permission.split('.', 2)
            
            # Find permissions in same service with same action
            for perm in self._permission_knowledge_base.keys():
                if perm.startswith('_'):  # Skip meta keys
                    continue
                if '.' in perm:
                    p_service, p_resource, p_action = perm.split('.', 2)
                    if p_service == service and p_action == action and perm != permission:
                        similar.append(perm)
            
            # Find permissions with same resource and action across services
            for perm in self._permission_knowledge_base.keys():
                if perm.startswith('_'):
                    continue
                if '.' in perm and perm != permission:
                    p_parts = perm.split('.', 2)
                    if len(p_parts) == 3 and p_parts[1] == resource and p_parts[2] == action:
                        similar.append(perm)
        
        return similar[:5]  # Limit to top 5 similar permissions
    
    def analyze_permission_set(self, permissions: Set[str], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyze a set of permissions for collective risk and relationships.
        
        Args:
            permissions: Set of permissions to analyze
            context: Additional context information
            
        Returns:
            Dict containing comprehensive analysis of the permission set
        """
        analysis = {
            'total_permissions': len(permissions),
            'risk_distribution': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'average_risk_score': 0,
            'highest_risk_permissions': [],
            'compliance_implications': {},
            'security_concerns': [],
            'permission_relationships': [],
            'optimization_opportunities': [],
            'services_affected': set(),
            'data_access_permissions': [],
            'administrative_permissions': [],
            'destructive_permissions': []
        }
        
        try:
            total_risk_score = 0
            risk_assessments = {}
            
            # Analyze each permission
            for permission in permissions:
                assessment = self.analyze_permission_risk(permission, context)
                risk_assessments[permission] = assessment
                
                # Update risk distribution
                analysis['risk_distribution'][assessment.risk_level.value] += 1
                total_risk_score += assessment.risk_score
                
                # Categorize permissions
                if assessment.risk_level in [PermissionRiskLevel.CRITICAL, PermissionRiskLevel.HIGH]:
                    analysis['highest_risk_permissions'].append({
                        'permission': permission,
                        'risk_level': assessment.risk_level.value,
                        'risk_score': assessment.risk_score,
                        'primary_concern': assessment.security_implications[0] if assessment.security_implications else 'High risk permission'
                    })
                
                # Categorize by type
                perm_lower = permission.lower()
                if 'get' in perm_lower or 'list' in perm_lower or 'read' in perm_lower:
                    analysis['data_access_permissions'].append(permission)
                if 'admin' in perm_lower or 'manage' in perm_lower or 'setIamPolicy' in permission:
                    analysis['administrative_permissions'].append(permission)
                if 'delete' in perm_lower or 'destroy' in perm_lower:
                    analysis['destructive_permissions'].append(permission)
                
                # Track services
                if '.' in permission:
                    service = permission.split('.')[0]
                    analysis['services_affected'].add(service)
                
                # Aggregate compliance concerns
                for concern in assessment.compliance_concerns:
                    if concern not in analysis['compliance_implications']:
                        analysis['compliance_implications'][concern] = 0
                    analysis['compliance_implications'][concern] += 1
            
            # Calculate average risk score
            if permissions:
                analysis['average_risk_score'] = total_risk_score / len(permissions)
            
            # Sort highest risk permissions by score
            analysis['highest_risk_permissions'].sort(key=lambda x: x['risk_score'], reverse=True)
            analysis['highest_risk_permissions'] = analysis['highest_risk_permissions'][:10]
            
            # Analyze permission relationships and dependencies
            analysis['permission_relationships'] = self._analyze_permission_relationships(permissions)
            
            # Generate security concerns
            analysis['security_concerns'] = self._generate_security_concerns(analysis, risk_assessments)
            
            # Generate optimization opportunities
            analysis['optimization_opportunities'] = self._generate_optimization_opportunities(analysis, risk_assessments)
            
            # Convert sets to lists for JSON serialization
            analysis['services_affected'] = list(analysis['services_affected'])
            
        except Exception as e:
            logger.error(f"Error analyzing permission set: {e}")
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_permission_relationships(self, permissions: Set[str]) -> List[Dict[str, Any]]:
        """Analyze relationships and dependencies between permissions."""
        relationships = []
        
        # Check for known dependency relationships
        for permission in permissions:
            if permission in self._permission_relationships:
                dep = self._permission_relationships[permission]
                
                # Check if dependencies are satisfied
                missing_deps = dep.depends_on - permissions
                if missing_deps:
                    relationships.append({
                        'type': 'missing_dependency',
                        'permission': permission,
                        'missing_dependencies': list(missing_deps),
                        'impact': 'Permission may not function as expected without dependencies'
                    })
                
                # Check for commonly paired permissions
                present_pairs = dep.commonly_paired_with & permissions
                missing_pairs = dep.commonly_paired_with - permissions
                if missing_pairs:
                    relationships.append({
                        'type': 'suggested_pairing',
                        'permission': permission,
                        'suggested_permissions': list(missing_pairs),
                        'impact': 'Adding these permissions may improve functionality'
                    })
        
        # Pattern-based relationship analysis
        service_permissions = defaultdict(set)
        for perm in permissions:
            if '.' in perm:
                service = perm.split('.')[0]
                service_permissions[service].add(perm)
        
        # Look for incomplete permission sets within services
        for service, perms in service_permissions.items():
            read_perms = {p for p in perms if any(action in p.lower() for action in ['get', 'list', 'read'])}
            write_perms = {p for p in perms if any(action in p.lower() for action in ['create', 'update', 'write'])}
            delete_perms = {p for p in perms if 'delete' in p.lower()}
            
            if delete_perms and not write_perms:
                relationships.append({
                    'type': 'unusual_pattern',
                    'service': service,
                    'pattern': 'delete without create/update',
                    'impact': 'Unusual to have delete permissions without corresponding write permissions'
                })
            
            if write_perms and not read_perms:
                relationships.append({
                    'type': 'unusual_pattern',
                    'service': service,
                    'pattern': 'write without read',
                    'impact': 'Unusual to have write permissions without corresponding read permissions'
                })
        
        return relationships
    
    def _generate_security_concerns(self, analysis: Dict[str, Any], risk_assessments: Dict[str, PermissionRiskAssessment]) -> List[Dict[str, Any]]:
        """Generate security concerns based on permission analysis."""
        concerns = []
        
        # High risk permission concentration
        critical_count = analysis['risk_distribution']['critical']
        high_count = analysis['risk_distribution']['high']
        
        if critical_count > 5:
            concerns.append({
                'type': 'high_risk_concentration',
                'severity': 'critical',
                'description': f'{critical_count} critical risk permissions detected',
                'recommendation': 'Review necessity of critical permissions and implement strict controls'
            })
        
        if high_count + critical_count > analysis['total_permissions'] * 0.3:
            concerns.append({
                'type': 'excessive_high_risk',
                'severity': 'high',
                'description': 'More than 30% of permissions are high or critical risk',
                'recommendation': 'Consider breaking role into smaller, more focused roles'
            })
        
        # Service concentration concerns
        services_count = len(analysis['services_affected'])
        if services_count > 10:
            concerns.append({
                'type': 'broad_service_access',
                'severity': 'medium',
                'description': f'Permissions span {services_count} different services',
                'recommendation': 'Consider service-specific roles for better segregation'
            })
        
        # Administrative permission concerns
        admin_count = len(analysis['administrative_permissions'])
        if admin_count > 5:
            concerns.append({
                'type': 'excessive_admin_permissions',
                'severity': 'high',
                'description': f'{admin_count} administrative permissions detected',
                'recommendation': 'Administrative permissions should be strictly controlled and audited'
            })
        
        # Destructive permission concerns
        destructive_count = len(analysis['destructive_permissions'])
        if destructive_count > 3:
            concerns.append({
                'type': 'multiple_destructive_permissions',
                'severity': 'high',
                'description': f'{destructive_count} destructive permissions detected',
                'recommendation': 'Implement additional safeguards for destructive operations'
            })
        
        # Compliance concerns
        compliance_frameworks = analysis['compliance_implications']
        if len(compliance_frameworks) > 2:
            concerns.append({
                'type': 'multiple_compliance_impacts',
                'severity': 'medium',
                'description': f'Permissions affect {len(compliance_frameworks)} compliance frameworks',
                'recommendation': 'Ensure compliance requirements are met for all affected frameworks'
            })
        
        return concerns
    
    def _generate_optimization_opportunities(self, analysis: Dict[str, Any], risk_assessments: Dict[str, PermissionRiskAssessment]) -> List[Dict[str, Any]]:
        """Generate optimization opportunities for the permission set."""
        opportunities = []
        
        # Overly broad permissions
        if analysis['average_risk_score'] > 60:
            opportunities.append({
                'type': 'reduce_risk_profile',
                'priority': 'high',
                'description': f'Average risk score is {analysis["average_risk_score"]:.1f}/100',
                'recommendation': 'Review and remove unnecessary high-risk permissions',
                'estimated_impact': 'Significant security improvement'
            })
        
        # Service consolidation opportunities
        services_count = len(analysis['services_affected'])
        if services_count > 15:
            opportunities.append({
                'type': 'service_consolidation',
                'priority': 'medium',
                'description': f'Permissions span {services_count} services',
                'recommendation': 'Consider creating service-specific roles',
                'estimated_impact': 'Improved manageability and security'
            })
        
        # Remove unused-pattern permissions (placeholder for actual usage data)
        read_only_perms = analysis['data_access_permissions']
        if len(read_only_perms) > 20:
            opportunities.append({
                'type': 'consolidate_read_permissions',
                'priority': 'low',
                'description': f'{len(read_only_perms)} read permissions detected',
                'recommendation': 'Consider using predefined viewer roles where appropriate',
                'estimated_impact': 'Simplified permission management'
            })
        
        # Administrative permission segregation
        admin_count = len(analysis['administrative_permissions'])
        if admin_count > 2:
            opportunities.append({
                'type': 'segregate_admin_permissions',
                'priority': 'high',
                'description': f'{admin_count} administrative permissions in single role',
                'recommendation': 'Consider separating administrative functions into dedicated roles',
                'estimated_impact': 'Better segregation of duties'
            })
        
        return opportunities
    
    def generate_permission_report(self, permissions: Set[str], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate a comprehensive permission analysis report."""
        report = {
            'summary': {},
            'detailed_analysis': {},
            'risk_matrix': {},
            'compliance_summary': {},
            'recommendations': {},
            'generated_at': datetime.now().isoformat()
        }
        
        try:
            # Perform comprehensive analysis
            analysis = self.analyze_permission_set(permissions, context)
            
            # Build summary
            report['summary'] = {
                'total_permissions': analysis['total_permissions'],
                'average_risk_score': round(analysis['average_risk_score'], 1),
                'risk_distribution': analysis['risk_distribution'],
                'services_affected': len(analysis['services_affected']),
                'compliance_frameworks_affected': len(analysis['compliance_implications'])
            }
            
            # Build detailed analysis
            report['detailed_analysis'] = {
                'highest_risk_permissions': analysis['highest_risk_permissions'],
                'security_concerns': analysis['security_concerns'],
                'permission_relationships': analysis['permission_relationships'],
                'services_breakdown': {
                    service: [p for p in permissions if p.startswith(service + '.')]
                    for service in analysis['services_affected']
                }
            }
            
            # Build risk matrix
            report['risk_matrix'] = self._build_risk_matrix(permissions, context)
            
            # Build compliance summary
            report['compliance_summary'] = {
                'frameworks_affected': analysis['compliance_implications'],
                'high_risk_compliance_permissions': [
                    perm['permission'] for perm in analysis['highest_risk_permissions']
                    if any(framework in [assess.compliance_concerns for assess in [self.analyze_permission_risk(perm['permission'], context)]][0] 
                          for framework in ['SOX', 'PCI-DSS', 'HIPAA', 'GDPR'])
                ]
            }
            
            # Build recommendations
            report['recommendations'] = {
                'security_improvements': analysis['security_concerns'],
                'optimization_opportunities': analysis['optimization_opportunities'],
                'priority_actions': self._generate_priority_actions(analysis)
            }
            
        except Exception as e:
            logger.error(f"Error generating permission report: {e}")
            report['error'] = str(e)
        
        return report
    
    def _build_risk_matrix(self, permissions: Set[str], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Build a risk matrix for visualization."""
        matrix = {
            'by_service': {},
            'by_risk_level': {level.value: [] for level in PermissionRiskLevel},
            'risk_score_histogram': {'0-20': 0, '21-40': 0, '41-60': 0, '61-80': 0, '81-100': 0}
        }
        
        for permission in permissions:
            assessment = self.analyze_permission_risk(permission, context)
            
            # By service
            if '.' in permission:
                service = permission.split('.')[0]
                if service not in matrix['by_service']:
                    matrix['by_service'][service] = {'permissions': [], 'avg_risk': 0, 'total_risk': 0}
                matrix['by_service'][service]['permissions'].append({
                    'permission': permission,
                    'risk_score': assessment.risk_score,
                    'risk_level': assessment.risk_level.value
                })
                matrix['by_service'][service]['total_risk'] += assessment.risk_score
            
            # By risk level
            matrix['by_risk_level'][assessment.risk_level.value].append(permission)
            
            # Risk score histogram
            score = assessment.risk_score
            if score <= 20:
                matrix['risk_score_histogram']['0-20'] += 1
            elif score <= 40:
                matrix['risk_score_histogram']['21-40'] += 1
            elif score <= 60:
                matrix['risk_score_histogram']['41-60'] += 1
            elif score <= 80:
                matrix['risk_score_histogram']['61-80'] += 1
            else:
                matrix['risk_score_histogram']['81-100'] += 1
        
        # Calculate average risk by service
        for service_data in matrix['by_service'].values():
            if service_data['permissions']:
                service_data['avg_risk'] = service_data['total_risk'] / len(service_data['permissions'])
        
        return matrix
    
    def _generate_priority_actions(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate priority actions based on analysis."""
        actions = []
        
        # Critical permissions review
        critical_count = analysis['risk_distribution']['critical']
        if critical_count > 0:
            actions.append({
                'priority': 1,
                'action': 'Review Critical Permissions',
                'description': f'Immediately review {critical_count} critical-risk permissions',
                'timeline': 'Within 24 hours',
                'impact': 'Critical security improvement'
            })
        
        # High-risk permission assessment
        high_count = analysis['risk_distribution']['high']
        if high_count > 0:
            actions.append({
                'priority': 2,
                'action': 'Assess High-Risk Permissions',
                'description': f'Review {high_count} high-risk permissions for necessity',
                'timeline': 'Within 1 week',
                'impact': 'Significant security improvement'
            })
        
        # Administrative permission segregation
        admin_count = len(analysis['administrative_permissions'])
        if admin_count > 3:
            actions.append({
                'priority': 3,
                'action': 'Segregate Administrative Functions',
                'description': f'Separate {admin_count} admin permissions into dedicated roles',
                'timeline': 'Within 1 month',
                'impact': 'Improved segregation of duties'
            })
        
        return actions