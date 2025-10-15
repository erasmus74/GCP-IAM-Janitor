"""
GCP IAM Compliance Analysis Module

Provides compliance reporting and analysis for major frameworks including:
- HITRUST CSF
- HIPAA Security Rule  
- SOC 2 Type II
- SOC 3
- ISO 27001
- NIST Cybersecurity Framework
- PCI DSS
- FedRAMP

This module analyzes IAM configurations against compliance requirements
and generates detailed reports with findings and recommendations.
"""

import logging
from typing import Dict, List, Set, Tuple, Any, Optional
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from enum import Enum
import json

logger = logging.getLogger(__name__)


class ComplianceStatus(Enum):
    """Compliance status enumeration."""
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT" 
    PARTIAL = "PARTIAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class ComplianceSeverity(Enum):
    """Compliance finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    HITRUST = "HITRUST"
    HIPAA = "HIPAA"
    SOC2 = "SOC2"
    SOC3 = "SOC3"
    ISO27001 = "ISO27001"
    NIST = "NIST"
    PCI_DSS = "PCI_DSS"
    FEDRAMP = "FEDRAMP"


class ComplianceAnalyzer:
    """Main compliance analysis engine."""
    
    def __init__(self):
        self.frameworks = {
            ComplianceFramework.HITRUST: HITRUSTAnalyzer(),
            ComplianceFramework.HIPAA: HIPAAAnalyzer(), 
            ComplianceFramework.SOC2: SOC2Analyzer(),
            ComplianceFramework.SOC3: SOC3Analyzer(),
            ComplianceFramework.ISO27001: ISO27001Analyzer(),
            ComplianceFramework.NIST: NISTAnalyzer(),
            ComplianceFramework.PCI_DSS: PCIDSSAnalyzer(),
            ComplianceFramework.FEDRAMP: FedRAMPAnalyzer()
        }
    
    def analyze_compliance(self, iam_data: Dict[str, Any], frameworks: List[ComplianceFramework] = None) -> Dict[str, Any]:
        """
        Analyze IAM data against specified compliance frameworks.
        
        Args:
            iam_data: IAM analysis data from IAMInsights
            frameworks: List of frameworks to analyze, or None for all
            
        Returns:
            Dict containing compliance analysis results
        """
        if frameworks is None:
            frameworks = list(ComplianceFramework)
        
        results = {
            'analysis_timestamp': datetime.now().isoformat(),
            'frameworks_analyzed': [f.value for f in frameworks],
            'overall_summary': {},
            'framework_results': {},
            'cross_framework_issues': [],
            'recommendations': []
        }
        
        # Analyze each framework
        framework_scores = {}
        all_findings = []
        
        for framework in frameworks:
            if framework in self.frameworks:
                analyzer = self.frameworks[framework]
                framework_result = analyzer.analyze(iam_data)
                results['framework_results'][framework.value] = framework_result
                framework_scores[framework.value] = framework_result['overall_score']
                all_findings.extend(framework_result['findings'])
        
        # Generate overall summary
        results['overall_summary'] = self._generate_overall_summary(framework_scores, all_findings)
        
        # Identify cross-framework issues
        results['cross_framework_issues'] = self._identify_cross_framework_issues(results['framework_results'])
        
        # Generate consolidated recommendations
        results['recommendations'] = self._generate_consolidated_recommendations(all_findings)
        
        return results
    
    def _generate_overall_summary(self, framework_scores: Dict[str, float], all_findings: List[Dict]) -> Dict[str, Any]:
        """Generate overall compliance summary across all frameworks."""
        if not framework_scores:
            return {}
        
        avg_score = sum(framework_scores.values()) / len(framework_scores)
        
        # Count findings by severity
        severity_counts = Counter()
        for finding in all_findings:
            severity_counts[finding['severity']] += 1
        
        # Determine overall status
        if avg_score >= 90:
            overall_status = ComplianceStatus.COMPLIANT.value
        elif avg_score >= 70:
            overall_status = ComplianceStatus.PARTIAL.value
        else:
            overall_status = ComplianceStatus.NON_COMPLIANT.value
        
        return {
            'overall_score': round(avg_score, 2),
            'overall_status': overall_status,
            'frameworks_count': len(framework_scores),
            'total_findings': len(all_findings),
            'critical_findings': severity_counts.get(ComplianceSeverity.CRITICAL.value, 0),
            'high_findings': severity_counts.get(ComplianceSeverity.HIGH.value, 0),
            'medium_findings': severity_counts.get(ComplianceSeverity.MEDIUM.value, 0),
            'low_findings': severity_counts.get(ComplianceSeverity.LOW.value, 0),
            'framework_scores': framework_scores
        }
    
    def _identify_cross_framework_issues(self, framework_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify issues that appear across multiple frameworks."""
        cross_issues = []
        
        # Common issues that appear in multiple frameworks
        common_patterns = [
            'excessive_privileges',
            'external_users',
            'unused_accounts',
            'missing_mfa',
            'shared_accounts',
            'privileged_access_management'
        ]
        
        for pattern in common_patterns:
            affected_frameworks = []
            for framework, result in framework_results.items():
                for finding in result.get('findings', []):
                    if pattern in finding.get('control_id', '').lower() or pattern in finding.get('description', '').lower():
                        affected_frameworks.append(framework)
                        break
            
            if len(affected_frameworks) >= 2:
                cross_issues.append({
                    'issue_type': pattern,
                    'affected_frameworks': affected_frameworks,
                    'impact': 'Multiple compliance frameworks affected',
                    'priority': 'HIGH'
                })
        
        return cross_issues
    
    def _generate_consolidated_recommendations(self, all_findings: List[Dict]) -> List[Dict[str, Any]]:
        """Generate consolidated recommendations across all frameworks."""
        recommendations = []
        
        # Group findings by similar control areas
        control_groups = defaultdict(list)
        for finding in all_findings:
            if finding['status'] != ComplianceStatus.COMPLIANT.value:
                control_area = finding.get('control_area', 'general')
                control_groups[control_area].append(finding)
        
        # Generate recommendations for each control area
        for control_area, findings in control_groups.items():
            if len(findings) >= 2:  # Only create recommendations for areas with multiple issues
                severity_counts = Counter(f['severity'] for f in findings)
                max_severity = max(severity_counts.keys(), key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].index(x))
                
                recommendations.append({
                    'control_area': control_area,
                    'priority': max_severity,
                    'affected_controls': len(findings),
                    'description': f"Address {control_area} issues affecting {len(findings)} controls",
                    'recommendation': self._get_control_area_recommendation(control_area),
                    'frameworks_impacted': len(set(f.get('framework', '') for f in findings))
                })
        
        # Sort by priority and impact
        priority_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        recommendations.sort(key=lambda x: (priority_order.get(x['priority'], 0), x['affected_controls']), reverse=True)
        
        return recommendations[:10]  # Return top 10 recommendations
    
    def _get_control_area_recommendation(self, control_area: str) -> str:
        """Get specific recommendation for a control area."""
        recommendations_map = {
            'access_management': "Implement principle of least privilege and regular access reviews",
            'identity_management': "Strengthen identity verification and account lifecycle management",
            'privileged_access': "Implement privileged access management (PAM) solutions",
            'authentication': "Enforce multi-factor authentication for all privileged accounts",
            'monitoring': "Enhance logging and monitoring of privileged activities",
            'data_protection': "Implement data classification and protection controls",
            'network_security': "Review and strengthen network access controls",
            'general': "Review and remediate identified compliance gaps"
        }
        
        return recommendations_map.get(control_area, recommendations_map['general'])


class BaseComplianceAnalyzer:
    """Base class for framework-specific compliance analyzers."""
    
    def __init__(self, framework_name: str):
        self.framework_name = framework_name
        self.controls = self._load_controls()
    
    def _load_controls(self) -> Dict[str, Any]:
        """Load framework-specific controls. Override in subclasses."""
        return {}
    
    def analyze(self, iam_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze IAM data against framework controls."""
        findings = []
        control_results = {}
        
        for control_id, control in self.controls.items():
            result = self._evaluate_control(control_id, control, iam_data)
            control_results[control_id] = result
            
            if result['status'] != ComplianceStatus.COMPLIANT.value:
                findings.append({
                    'framework': self.framework_name,
                    'control_id': control_id,
                    'control_name': control['name'],
                    'control_area': control.get('area', 'general'),
                    'description': control['description'],
                    'status': result['status'],
                    'severity': result['severity'],
                    'findings': result['findings'],
                    'recommendation': result['recommendation']
                })
        
        # Calculate overall score
        compliant_controls = sum(1 for r in control_results.values() if r['status'] == ComplianceStatus.COMPLIANT.value)
        total_controls = len(control_results)
        overall_score = (compliant_controls / total_controls * 100) if total_controls > 0 else 0
        
        return {
            'framework': self.framework_name,
            'overall_score': round(overall_score, 2),
            'total_controls': total_controls,
            'compliant_controls': compliant_controls,
            'non_compliant_controls': total_controls - compliant_controls,
            'control_results': control_results,
            'findings': findings,
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def _evaluate_control(self, control_id: str, control: Dict[str, Any], iam_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a specific control. Override in subclasses."""
        return {
            'status': ComplianceStatus.NEEDS_REVIEW.value,
            'severity': ComplianceSeverity.MEDIUM.value,
            'findings': ["Control evaluation not implemented"],
            'recommendation': "Manual review required"
        }


class HITRUSTAnalyzer(BaseComplianceAnalyzer):
    """HITRUST CSF compliance analyzer."""
    
    def __init__(self):
        super().__init__("HITRUST")
    
    def _load_controls(self) -> Dict[str, Any]:
        """Load HITRUST CSF controls relevant to IAM."""
        return {
            "01.a": {
                "name": "Access Control Policy",
                "area": "access_management",
                "description": "Organization establishes access control policies",
                "requirement": "Documented access control policies must be established"
            },
            "01.c": {
                "name": "User Access Management",
                "area": "access_management", 
                "description": "Formal user access provisioning process",
                "requirement": "Access must be granted based on business need"
            },
            "01.d": {
                "name": "Privileged Access Rights",
                "area": "privileged_access",
                "description": "Management of privileged access rights",
                "requirement": "Privileged access must be restricted and monitored"
            },
            "01.e": {
                "name": "User Access Reviews",
                "area": "access_management",
                "description": "Regular review of user access rights",
                "requirement": "Access rights must be reviewed regularly"
            },
            "01.f": {
                "name": "Access Rights Removal",
                "area": "access_management",
                "description": "Removal or adjustment of access rights",
                "requirement": "Access must be removed when no longer needed"
            },
            "09.ac": {
                "name": "User Identification and Authentication",
                "area": "authentication",
                "description": "Unique identification for each user",
                "requirement": "Users must be uniquely identified and authenticated"
            }
        }
    
    def _evaluate_control(self, control_id: str, control: Dict[str, Any], iam_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate HITRUST control against IAM data."""
        if control_id == "01.a":
            return self._evaluate_access_control_policy(iam_data)
        elif control_id == "01.c":
            return self._evaluate_user_access_management(iam_data)
        elif control_id == "01.d":
            return self._evaluate_privileged_access(iam_data)
        elif control_id == "01.e":
            return self._evaluate_access_reviews(iam_data)
        elif control_id == "01.f":
            return self._evaluate_access_removal(iam_data)
        elif control_id == "09.ac":
            return self._evaluate_user_identification(iam_data)
        
        return super()._evaluate_control(control_id, control, iam_data)
    
    def _evaluate_access_control_policy(self, iam_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate access control policy implementation."""
        findings = []
        
        # Check for basic role usage (indicates lack of granular policy)
        identities = iam_data.get('identities_analysis', {})
        roles_data = iam_data.get('roles_optimization', {})
        
        basic_role_usage = roles_data.get('basic_roles_usage', [])
        if basic_role_usage:
            findings.append(f"Basic roles (Owner/Editor/Viewer) used by {len(basic_role_usage)} identities")
        
        # Check for external users
        external_users = identities.get('external_users', [])
        if external_users:
            findings.append(f"{len(external_users)} external users detected with access")
        
        if not findings:
            return {
                'status': ComplianceStatus.COMPLIANT.value,
                'severity': ComplianceSeverity.INFO.value,
                'findings': ["Access control policies appear to be properly implemented"],
                'recommendation': "Continue monitoring access control implementation"
            }
        
        severity = ComplianceSeverity.HIGH.value if len(external_users) > 0 else ComplianceSeverity.MEDIUM.value
        
        return {
            'status': ComplianceStatus.NON_COMPLIANT.value,
            'severity': severity,
            'findings': findings,
            'recommendation': "Implement granular access control policies and review external access"
        }
    
    def _evaluate_privileged_access(self, iam_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate privileged access management."""
        findings = []
        
        identities = iam_data.get('identities_analysis', {})
        over_privileged = identities.get('over_privileged', [])
        
        if over_privileged:
            findings.append(f"{len(over_privileged)} identities have excessive privileges")
            
            # Count admin roles
            admin_count = sum(1 for user in over_privileged 
                            if any('admin' in role.lower() or 'owner' in role.lower() 
                                 for role in user.get('high_privilege_roles', [])))
            
            if admin_count > 0:
                findings.append(f"{admin_count} identities have administrative privileges")
        
        if not findings:
            return {
                'status': ComplianceStatus.COMPLIANT.value,
                'severity': ComplianceSeverity.INFO.value,
                'findings': ["Privileged access appears to be properly managed"],
                'recommendation': "Continue monitoring privileged access"
            }
        
        return {
            'status': ComplianceStatus.NON_COMPLIANT.value,
            'severity': ComplianceSeverity.HIGH.value,
            'findings': findings,
            'recommendation': "Implement privileged access management and regular reviews"
        }
    
    def _evaluate_user_access_management(self, iam_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate user access management processes."""
        findings = []
        
        # Check for unused access
        unused_access = iam_data.get('unused_access_analysis', {})
        never_used = unused_access.get('never_used_identities', [])
        inactive_30 = unused_access.get('inactive_30_days', [])
        
        if never_used:
            findings.append(f"{len(never_used)} identities appear to have never been used")
        
        if inactive_30:
            findings.append(f"{len(inactive_30)} identities may be inactive for 30+ days")
        
        # Check grouping opportunities (indicates manual access management)
        grouping = iam_data.get('grouping_opportunities', {})
        role_groups = grouping.get('role_based_groups', [])
        
        high_value_groups = [g for g in role_groups if g.get('consolidation_value', 0) > 10]
        if high_value_groups:
            findings.append(f"{len(high_value_groups)} opportunities for automated access management through groups")
        
        if not findings:
            return {
                'status': ComplianceStatus.COMPLIANT.value,
                'severity': ComplianceSeverity.INFO.value,
                'findings': ["User access management appears adequate"],
                'recommendation': "Continue current access management practices"
            }
        
        return {
            'status': ComplianceStatus.PARTIAL.value,
            'severity': ComplianceSeverity.MEDIUM.value,
            'findings': findings,
            'recommendation': "Implement automated access lifecycle management and regular cleanup"
        }
    
    def _evaluate_access_reviews(self, iam_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate regular access review processes."""
        findings = []
        
        # Evidence of access reviews would be recent access changes
        # Since we don't have temporal data, we check for indicators
        
        identities = iam_data.get('identities_analysis', {})
        total_identities = identities.get('total_identities', 0)
        multi_project_users = identities.get('multi_project_users', [])
        
        if len(multi_project_users) > total_identities * 0.3:  # More than 30% have multi-project access
            findings.append(f"High percentage ({len(multi_project_users)}/{total_identities}) of users have multi-project access - may indicate insufficient access reviews")
        
        # Check for stale service accounts
        unused_access = iam_data.get('unused_access_analysis', {})
        stale_sas = unused_access.get('stale_service_accounts', [])
        
        if stale_sas:
            findings.append(f"{len(stale_sas)} potentially stale service accounts - indicates insufficient access reviews")
        
        return {
            'status': ComplianceStatus.NEEDS_REVIEW.value,
            'severity': ComplianceSeverity.MEDIUM.value,
            'findings': findings or ["Access review processes need manual verification"],
            'recommendation': "Implement regular access reviews (quarterly recommended) and document the process"
        }
    
    def _evaluate_access_removal(self, iam_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate access removal processes."""
        findings = []
        
        unused_access = iam_data.get('unused_access_analysis', {})
        
        # Check for various types of unused access
        never_used = len(unused_access.get('never_used_identities', []))
        inactive_90 = len(unused_access.get('inactive_90_days', []))
        stale_sas = len(unused_access.get('stale_service_accounts', []))
        
        total_unused = never_used + inactive_90 + stale_sas
        
        if total_unused > 0:
            findings.append(f"{total_unused} identities with unused or stale access need removal")
            if never_used > 0:
                findings.append(f"{never_used} identities appear never used")
            if inactive_90 > 0:
                findings.append(f"{inactive_90} identities inactive for 90+ days")
            if stale_sas > 0:
                findings.append(f"{stale_sas} potentially stale service accounts")
        
        if not findings:
            return {
                'status': ComplianceStatus.COMPLIANT.value,
                'severity': ComplianceSeverity.INFO.value,
                'findings': ["Access removal appears to be properly managed"],
                'recommendation': "Continue monitoring and removing unused access"
            }
        
        severity = ComplianceSeverity.HIGH.value if total_unused > 10 else ComplianceSeverity.MEDIUM.value
        
        return {
            'status': ComplianceStatus.NON_COMPLIANT.value,
            'severity': severity,
            'findings': findings,
            'recommendation': "Implement automated access removal processes for unused accounts"
        }
    
    def _evaluate_user_identification(self, iam_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate user identification and authentication."""
        findings = []
        
        identities = iam_data.get('identities_analysis', {})
        external_users = identities.get('external_users', [])
        
        # External users may indicate authentication issues
        if external_users:
            gmail_users = [u for u in external_users if 'gmail.com' in u.get('email', '')]
            if gmail_users:
                findings.append(f"{len(gmail_users)} users using personal Gmail accounts")
        
        # Check for service accounts (should have proper naming)
        by_type = identities.get('by_type', Counter())
        service_accounts = by_type.get('serviceAccount', 0)
        users = by_type.get('user', 0)
        
        if service_accounts > 0:
            findings.append(f"Service account usage: {service_accounts} service accounts vs {users} users")
        
        if not findings:
            return {
                'status': ComplianceStatus.COMPLIANT.value,
                'severity': ComplianceSeverity.INFO.value,
                'findings': ["User identification appears properly implemented"],
                'recommendation': "Continue monitoring user identification practices"
            }
        
        return {
            'status': ComplianceStatus.PARTIAL.value,
            'severity': ComplianceSeverity.MEDIUM.value,
            'findings': findings,
            'recommendation': "Review external user access and ensure proper identity verification"
        }


class HIPAAAnalyzer(BaseComplianceAnalyzer):
    """HIPAA Security Rule compliance analyzer."""
    
    def __init__(self):
        super().__init__("HIPAA")
    
    def _load_controls(self) -> Dict[str, Any]:
        """Load HIPAA Security Rule requirements relevant to IAM."""
        return {
            "164.308.a.1": {
                "name": "Security Officer",
                "area": "access_management",
                "description": "Assign security responsibilities",
                "requirement": "Assign security responsibility to a security officer"
            },
            "164.308.a.3": {
                "name": "Workforce Training and Access Management",
                "area": "access_management", 
                "description": "Authorize access to ePHI systems",
                "requirement": "Implement procedures for authorizing access to ePHI"
            },
            "164.308.a.4": {
                "name": "Information Access Management",
                "area": "access_management",
                "description": "Access authorization and establishment procedures",
                "requirement": "Implement access authorization procedures"
            },
            "164.308.a.5": {
                "name": "Automatic Logoff",
                "area": "authentication",
                "description": "Automatic logoff procedures",
                "requirement": "Implement automatic logoff procedures"
            },
            "164.312.a.1": {
                "name": "Access Control",
                "area": "access_management",
                "description": "Unique user identification and access controls",
                "requirement": "Assign unique user identification and access controls"
            },
            "164.312.a.2": {
                "name": "Automatic Logoff",
                "area": "authentication",
                "description": "Automatic logoff from ePHI systems",
                "requirement": "Implement automatic logoff procedures"
            },
            "164.312.d": {
                "name": "Person or Entity Authentication",
                "area": "authentication",
                "description": "Verify identity before access",
                "requirement": "Verify person or entity identity before access to ePHI"
            }
        }
    
    def _evaluate_control(self, control_id: str, control: Dict[str, Any], iam_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate HIPAA control against IAM data."""
        # HIPAA focuses heavily on access controls and authentication
        # Most controls will require manual verification for full compliance
        
        findings = []
        
        if "access" in control['description'].lower():
            # Access-related controls
            identities = iam_data.get('identities_analysis', {})
            external_users = identities.get('external_users', [])
            over_privileged = identities.get('over_privileged', [])
            
            if external_users:
                findings.append(f"{len(external_users)} external users - verify ePHI access authorization")
            
            if over_privileged:
                findings.append(f"{len(over_privileged)} over-privileged identities - review ePHI access necessity")
            
        elif "authentication" in control['description'].lower():
            # Authentication controls - mostly require manual verification
            findings.append("Authentication controls require manual verification of MFA implementation")
        
        if not findings:
            status = ComplianceStatus.NEEDS_REVIEW.value
            findings = ["Manual review required for HIPAA compliance verification"]
        else:
            status = ComplianceStatus.NON_COMPLIANT.value
        
        return {
            'status': status,
            'severity': ComplianceSeverity.HIGH.value,  # HIPAA violations are always high risk
            'findings': findings,
            'recommendation': "Conduct thorough HIPAA compliance review with legal/compliance team"
        }


class SOC2Analyzer(BaseComplianceAnalyzer):
    """SOC 2 Type II compliance analyzer."""
    
    def __init__(self):
        super().__init__("SOC 2")
    
    def _load_controls(self) -> Dict[str, Any]:
        """Load SOC 2 trust services criteria relevant to IAM."""
        return {
            "CC6.1": {
                "name": "Logical and Physical Access Controls",
                "area": "access_management",
                "description": "Restrict logical and physical access",
                "requirement": "Implement controls to restrict access to system resources"
            },
            "CC6.2": {
                "name": "Access Control Management",
                "area": "access_management",
                "description": "Manage access control systems",
                "requirement": "Design and implement access controls"
            },
            "CC6.3": {
                "name": "Access Removal",
                "area": "access_management", 
                "description": "Remove access when no longer required",
                "requirement": "Remove access promptly when no longer needed"
            },
            "CC6.7": {
                "name": "Data Transmission Controls",
                "area": "data_protection",
                "description": "Protect data during transmission",
                "requirement": "Implement controls for data transmission"
            },
            "CC6.8": {
                "name": "Data Classification",
                "area": "data_protection",
                "description": "Create and maintain data inventory",
                "requirement": "Classify and maintain inventory of data"
            }
        }
    
    def _evaluate_control(self, control_id: str, control: Dict[str, Any], iam_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate SOC 2 control against IAM data."""
        if control_id == "CC6.1":
            return self._evaluate_logical_access_controls(iam_data)
        elif control_id == "CC6.2":
            return self._evaluate_access_control_management(iam_data)
        elif control_id == "CC6.3":
            return self._evaluate_access_removal_soc2(iam_data)
        else:
            # Data protection controls require additional context
            return {
                'status': ComplianceStatus.NEEDS_REVIEW.value,
                'severity': ComplianceSeverity.MEDIUM.value,
                'findings': ["Control requires additional data context for evaluation"],
                'recommendation': "Manual review required for data protection controls"
            }
    
    def _evaluate_logical_access_controls(self, iam_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate logical access controls for SOC 2."""
        findings = []
        
        # Check access control implementation
        roles_data = iam_data.get('roles_optimization', {})
        basic_roles = roles_data.get('basic_roles_usage', [])
        
        if basic_roles:
            findings.append(f"Basic roles used in {len(basic_roles)} cases - lacks principle of least privilege")
        
        # Check for external access
        identities = iam_data.get('identities_analysis', {})
        external_users = identities.get('external_users', [])
        
        if external_users:
            findings.append(f"{len(external_users)} external users - verify access authorization")
        
        # Check privileged access
        over_privileged = identities.get('over_privileged', [])
        if over_privileged:
            findings.append(f"{len(over_privileged)} over-privileged accounts detected")
        
        if not findings:
            return {
                'status': ComplianceStatus.COMPLIANT.value,
                'severity': ComplianceSeverity.INFO.value,
                'findings': ["Logical access controls appear properly implemented"],
                'recommendation': "Continue monitoring access controls"
            }
        
        return {
            'status': ComplianceStatus.NON_COMPLIANT.value,
            'severity': ComplianceSeverity.HIGH.value,
            'findings': findings,
            'recommendation': "Implement granular access controls and principle of least privilege"
        }
    
    def _evaluate_access_control_management(self, iam_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate access control management for SOC 2."""
        findings = []
        
        # Look for evidence of access management processes
        grouping = iam_data.get('grouping_opportunities', {})
        consolidation_impact = grouping.get('consolidation_impact', {})
        
        users_that_can_be_grouped = consolidation_impact.get('total_users_that_can_be_grouped', 0)
        total_identities = iam_data.get('identities_analysis', {}).get('total_identities', 1)
        
        if users_that_can_be_grouped / total_identities > 0.3:  # More than 30% can be grouped
            findings.append("High potential for access management automation through groups")
        
        # Check for unused access (indicates lack of management)
        unused_access = iam_data.get('unused_access_analysis', {})
        inactive_30 = unused_access.get('inactive_30_days', [])
        
        if inactive_30:
            findings.append(f"{len(inactive_30)} accounts inactive for 30+ days - indicates insufficient access management")
        
        if not findings:
            return {
                'status': ComplianceStatus.COMPLIANT.value,
                'severity': ComplianceSeverity.INFO.value,
                'findings': ["Access control management appears adequate"],
                'recommendation': "Continue current access management practices"
            }
        
        return {
            'status': ComplianceStatus.PARTIAL.value,
            'severity': ComplianceSeverity.MEDIUM.value,
            'findings': findings,
            'recommendation': "Implement formal access control management processes"
        }
    
    def _evaluate_access_removal_soc2(self, iam_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate access removal processes for SOC 2."""
        findings = []
        
        unused_access = iam_data.get('unused_access_analysis', {})
        
        # Check for various types of stale access
        never_used = unused_access.get('never_used_identities', [])
        inactive_90 = unused_access.get('inactive_90_days', [])
        stale_sas = unused_access.get('stale_service_accounts', [])
        
        if never_used:
            findings.append(f"{len(never_used)} never-used identities - access not removed")
        
        if inactive_90:
            findings.append(f"{len(inactive_90)} identities inactive for 90+ days")
        
        if stale_sas:
            findings.append(f"{len(stale_sas)} potentially stale service accounts")
        
        total_stale = len(never_used) + len(inactive_90) + len(stale_sas)
        
        if total_stale == 0:
            return {
                'status': ComplianceStatus.COMPLIANT.value,
                'severity': ComplianceSeverity.INFO.value,
                'findings': ["Access removal appears to be properly managed"],
                'recommendation': "Continue monitoring and removing stale access"
            }
        
        severity = ComplianceSeverity.HIGH.value if total_stale > 20 else ComplianceSeverity.MEDIUM.value
        
        return {
            'status': ComplianceStatus.NON_COMPLIANT.value,
            'severity': severity,
            'findings': findings,
            'recommendation': "Implement automated processes for removing unused access"
        }


# Additional analyzer classes for other frameworks would follow similar patterns
class SOC3Analyzer(BaseComplianceAnalyzer):
    """SOC 3 compliance analyzer (simplified version of SOC 2)."""
    
    def __init__(self):
        super().__init__("SOC 3")
    
    def _load_controls(self) -> Dict[str, Any]:
        # SOC 3 has similar but fewer controls than SOC 2
        return {
            "Security": {
                "name": "System Security",
                "area": "access_management",
                "description": "System is protected against unauthorized access",
                "requirement": "Implement access controls and monitoring"
            },
            "Availability": {
                "name": "System Availability", 
                "area": "monitoring",
                "description": "System is available for operation",
                "requirement": "Ensure system availability and recovery"
            }
        }


class ISO27001Analyzer(BaseComplianceAnalyzer):
    """ISO 27001 compliance analyzer."""
    
    def __init__(self):
        super().__init__("ISO 27001")
    
    def _load_controls(self) -> Dict[str, Any]:
        return {
            "A.9.1.1": {
                "name": "Access Control Policy",
                "area": "access_management",
                "description": "Access control policy should be established",
                "requirement": "Establish, document and review access control policy"
            },
            "A.9.2.1": {
                "name": "User Registration and De-registration",
                "area": "identity_management",
                "description": "Formal user registration and de-registration process",
                "requirement": "Implement user lifecycle management"
            },
            "A.9.2.3": {
                "name": "Management of Privileged Access Rights",
                "area": "privileged_access",
                "description": "Allocation and use of privileged access rights",
                "requirement": "Restrict and control privileged access"
            }
        }


class NISTAnalyzer(BaseComplianceAnalyzer):
    """NIST Cybersecurity Framework analyzer."""
    
    def __init__(self):
        super().__init__("NIST")
    
    def _load_controls(self) -> Dict[str, Any]:
        return {
            "PR.AC-1": {
                "name": "Identity and Access Management",
                "area": "identity_management",
                "description": "Identities and credentials are issued, managed, verified, revoked, and audited",
                "requirement": "Implement identity and access management"
            },
            "PR.AC-3": {
                "name": "Remote Access",
                "area": "access_management",
                "description": "Remote access is managed",
                "requirement": "Control remote access"
            },
            "PR.AC-4": {
                "name": "Access Permissions and Authorizations",
                "area": "access_management", 
                "description": "Access permissions and authorizations are managed",
                "requirement": "Implement access authorization"
            }
        }


class PCIDSSAnalyzer(BaseComplianceAnalyzer):
    """PCI DSS compliance analyzer."""
    
    def __init__(self):
        super().__init__("PCI DSS")
    
    def _load_controls(self) -> Dict[str, Any]:
        return {
            "7.1": {
                "name": "Limit Access to Cardholder Data",
                "area": "access_management",
                "description": "Restrict access to cardholder data by business need to know",
                "requirement": "Limit access to cardholder data by business need-to-know"
            },
            "8.1": {
                "name": "User Identification",
                "area": "identity_management",
                "description": "Define and implement policies for proper user identification",
                "requirement": "Assign unique ID to each person with computer access"
            },
            "8.2": {
                "name": "User Authentication",
                "area": "authentication",
                "description": "Implement strong authentication controls",
                "requirement": "Use strong authentication for all system components"
            }
        }


class FedRAMPAnalyzer(BaseComplianceAnalyzer):
    """FedRAMP compliance analyzer."""
    
    def __init__(self):
        super().__init__("FedRAMP")
    
    def _load_controls(self) -> Dict[str, Any]:
        return {
            "AC-2": {
                "name": "Account Management",
                "area": "identity_management",
                "description": "Manages information system accounts",
                "requirement": "Implement account management procedures"
            },
            "AC-3": {
                "name": "Access Enforcement", 
                "area": "access_management",
                "description": "Enforces approved authorizations for logical access",
                "requirement": "Enforce access control policies"
            },
            "AC-6": {
                "name": "Least Privilege",
                "area": "access_management",
                "description": "Employs principle of least privilege",
                "requirement": "Implement principle of least privilege"
            }
        }