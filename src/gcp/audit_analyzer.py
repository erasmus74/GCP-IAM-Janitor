"""
Audit Trail Integration client for historical analysis with Cloud Audit Logs.

This module provides comprehensive audit log analysis capabilities including:
- Historical IAM policy changes tracking
- User activity pattern analysis
- Security incident detection and investigation
- Compliance audit trail generation
- Anomaly detection in access patterns
"""

import logging
from typing import List, Dict, Set, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict, Counter
import json
import re
from google.auth.credentials import Credentials
from google.cloud import logging_v2
from google.cloud.logging_v2 import DESCENDING, ASCENDING
from google.api_core.exceptions import GoogleAPIError, PermissionDenied

from ..models.iam_models import Identity, IdentityType, PermissionRiskLevel

logger = logging.getLogger(__name__)


@dataclass
class AuditLogEntry:
    """Represents a structured audit log entry."""
    timestamp: datetime
    severity: str
    principal_email: str
    service_name: str
    method_name: str
    resource_name: str
    request_metadata: Dict[str, Any] = field(default_factory=dict)
    response: Optional[Dict[str, Any]] = None
    status: Optional[Dict[str, Any]] = None
    audit_log: Optional[Dict[str, Any]] = None


@dataclass
class IAMChangeEvent:
    """Represents an IAM policy change event."""
    timestamp: datetime
    principal_email: str
    resource_name: str
    action: str  # setIamPolicy, createRole, deleteRole, etc.
    changes_summary: str
    before_state: Optional[Dict[str, Any]] = None
    after_state: Optional[Dict[str, Any]] = None
    risk_level: str = "medium"
    compliance_impact: List[str] = field(default_factory=list)


@dataclass
class SecurityIncident:
    """Represents a potential security incident."""
    incident_id: str
    severity: str  # critical, high, medium, low
    incident_type: str
    description: str
    timestamp: datetime
    principal_email: str
    affected_resources: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    related_events: List[str] = field(default_factory=list)


@dataclass
class AccessPattern:
    """Represents user access patterns and anomalies."""
    principal_email: str
    time_period: str
    normal_access_hours: List[int] = field(default_factory=list)
    unusual_access_times: List[datetime] = field(default_factory=list)
    frequent_services: List[str] = field(default_factory=list)
    unusual_services: List[str] = field(default_factory=list)
    ip_addresses: Set[str] = field(default_factory=set)
    suspicious_ip_changes: List[Dict[str, Any]] = field(default_factory=list)
    activity_score: float = 0.0
    anomaly_score: float = 0.0


class AuditAnalyzer:
    """Advanced client for audit log analysis and security monitoring."""
    
    def __init__(self, credentials: Credentials, project_ids: Optional[List[str]] = None):
        """
        Initialize Audit Analyzer.
        
        Args:
            credentials: Authenticated GCP credentials
            project_ids: List of project IDs to monitor (default: all accessible)
        """
        self.credentials = credentials
        self.project_ids = project_ids or []
        self._logging_client = None
        self._iam_methods = self._initialize_iam_methods()
        self._security_patterns = self._initialize_security_patterns()
        self._compliance_events = self._initialize_compliance_events()
    
    @property
    def logging_client(self) -> logging_v2.Client:
        """Get or create Cloud Logging client."""
        if self._logging_client is None:
            self._logging_client = logging_v2.Client(credentials=self.credentials)
        return self._logging_client
    
    def _initialize_iam_methods(self) -> Dict[str, Dict[str, Any]]:
        """Initialize IAM method classifications for analysis."""
        return {
            # High-risk IAM operations
            'google.iam.admin.v1.IAM.SetIamPolicy': {
                'risk_level': 'critical',
                'description': 'IAM policy modification',
                'compliance_impact': ['SOX', 'PCI-DSS', 'HIPAA'],
                'monitoring_priority': 'high'
            },
            'google.iam.admin.v1.IAM.CreateRole': {
                'risk_level': 'high',
                'description': 'Custom role creation',
                'compliance_impact': ['SOX'],
                'monitoring_priority': 'high'
            },
            'google.iam.admin.v1.IAM.DeleteRole': {
                'risk_level': 'high',
                'description': 'Role deletion',
                'compliance_impact': ['SOX'],
                'monitoring_priority': 'high'
            },
            'google.iam.admin.v1.IAM.CreateServiceAccount': {
                'risk_level': 'medium',
                'description': 'Service account creation',
                'compliance_impact': ['SOX'],
                'monitoring_priority': 'medium'
            },
            'google.iam.admin.v1.IAM.DeleteServiceAccount': {
                'risk_level': 'high',
                'description': 'Service account deletion',
                'compliance_impact': ['SOX'],
                'monitoring_priority': 'high'
            },
            
            # Resource manager operations
            'google.cloud.resourcemanager.v3.Projects.SetIamPolicy': {
                'risk_level': 'critical',
                'description': 'Project IAM policy change',
                'compliance_impact': ['SOX', 'PCI-DSS'],
                'monitoring_priority': 'critical'
            },
            'google.cloud.resourcemanager.v3.Organizations.SetIamPolicy': {
                'risk_level': 'critical',
                'description': 'Organization IAM policy change',
                'compliance_impact': ['SOX', 'PCI-DSS'],
                'monitoring_priority': 'critical'
            },
            
            # Authentication events
            'google.auth.oauth2.v1.OAuth2.GetAccessToken': {
                'risk_level': 'low',
                'description': 'OAuth token request',
                'compliance_impact': [],
                'monitoring_priority': 'low'
            }
        }
    
    def _initialize_security_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize security threat patterns for detection."""
        return {
            'privilege_escalation': {
                'indicators': [
                    'rapid succession of IAM changes',
                    'role creation followed by assignment',
                    'unusual service account creation',
                    'owner role assignments'
                ],
                'methods': [
                    'SetIamPolicy',
                    'CreateRole',
                    'CreateServiceAccount'
                ],
                'time_window': timedelta(hours=1),
                'threshold': 3
            },
            
            'lateral_movement': {
                'indicators': [
                    'access from multiple IP addresses',
                    'unusual service access patterns',
                    'cross-project resource access',
                    'service account impersonation'
                ],
                'methods': [
                    'generateAccessToken',
                    'impersonateServiceAccount'
                ],
                'time_window': timedelta(hours=24),
                'threshold': 5
            },
            
            'data_exfiltration': {
                'indicators': [
                    'large data access volumes',
                    'unusual download patterns',
                    'external IP access',
                    'off-hours data access'
                ],
                'methods': [
                    'storage.objects.get',
                    'bigquery.jobs.create',
                    'cloudsql.instances.export'
                ],
                'time_window': timedelta(hours=12),
                'threshold': 10
            },
            
            'account_compromise': {
                'indicators': [
                    'login from unusual locations',
                    'password changes',
                    'failed authentication attempts',
                    'unusual activity patterns'
                ],
                'methods': [
                    'changePassword',
                    'login'
                ],
                'time_window': timedelta(hours=6),
                'threshold': 5
            }
        }
    
    def _initialize_compliance_events(self) -> Dict[str, List[str]]:
        """Initialize events that require compliance tracking."""
        return {
            'SOX': [
                'SetIamPolicy',
                'CreateRole',
                'DeleteRole',
                'CreateServiceAccount',
                'DeleteServiceAccount'
            ],
            'PCI-DSS': [
                'SetIamPolicy',
                'storage.objects.get',
                'bigquery.tables.getData',
                'cloudsql.instances.connect'
            ],
            'HIPAA': [
                'healthcare.datasets.get',
                'storage.objects.get',
                'bigquery.tables.getData',
                'SetIamPolicy'
            ],
            'GDPR': [
                'storage.objects.delete',
                'bigquery.tables.delete',
                'storage.objects.get',
                'ml.models.predict'
            ]
        }
    
    def analyze_historical_iam_changes(
        self, 
        start_time: datetime, 
        end_time: datetime,
        principals: Optional[List[str]] = None,
        resources: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Analyze historical IAM policy changes within a time period.
        
        Args:
            start_time: Start of analysis period
            end_time: End of analysis period
            principals: Optional list of principals to analyze
            resources: Optional list of resources to analyze
            
        Returns:
            Dict containing comprehensive IAM change analysis
        """
        analysis = {
            'time_period': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat(),
                'duration_hours': (end_time - start_time).total_seconds() / 3600
            },
            'total_iam_changes': 0,
            'changes_by_type': {},
            'changes_by_principal': {},
            'changes_by_resource': {},
            'high_risk_changes': [],
            'compliance_events': {},
            'timeline': [],
            'patterns_detected': [],
            'recommendations': []
        }
        
        try:
            # Build filter for IAM-related events
            iam_filter = self._build_iam_filter(start_time, end_time, principals, resources)
            
            # Retrieve audit log entries
            log_entries = self._query_audit_logs(iam_filter)
            
            iam_events = []
            for entry in log_entries:
                if self._is_iam_event(entry):
                    iam_event = self._parse_iam_event(entry)
                    if iam_event:
                        iam_events.append(iam_event)
            
            analysis['total_iam_changes'] = len(iam_events)
            
            # Analyze changes by type
            for event in iam_events:
                event_type = event.action
                analysis['changes_by_type'][event_type] = \
                    analysis['changes_by_type'].get(event_type, 0) + 1
            
            # Analyze changes by principal
            for event in iam_events:
                principal = event.principal_email
                if principal not in analysis['changes_by_principal']:
                    analysis['changes_by_principal'][principal] = []
                analysis['changes_by_principal'][principal].append({
                    'timestamp': event.timestamp.isoformat(),
                    'action': event.action,
                    'resource': event.resource_name,
                    'risk_level': event.risk_level
                })
            
            # Analyze changes by resource
            for event in iam_events:
                resource = event.resource_name
                if resource not in analysis['changes_by_resource']:
                    analysis['changes_by_resource'][resource] = []
                analysis['changes_by_resource'][resource].append({
                    'timestamp': event.timestamp.isoformat(),
                    'principal': event.principal_email,
                    'action': event.action,
                    'risk_level': event.risk_level
                })
            
            # Identify high-risk changes
            analysis['high_risk_changes'] = [
                {
                    'timestamp': event.timestamp.isoformat(),
                    'principal': event.principal_email,
                    'action': event.action,
                    'resource': event.resource_name,
                    'risk_level': event.risk_level,
                    'summary': event.changes_summary,
                    'compliance_impact': event.compliance_impact
                }
                for event in iam_events
                if event.risk_level in ['critical', 'high']
            ]
            
            # Analyze compliance events
            analysis['compliance_events'] = self._analyze_compliance_events(iam_events)
            
            # Build timeline
            analysis['timeline'] = self._build_iam_timeline(iam_events)
            
            # Detect patterns
            analysis['patterns_detected'] = self._detect_iam_patterns(iam_events)
            
            # Generate recommendations
            analysis['recommendations'] = self._generate_iam_recommendations(analysis)
            
        except Exception as e:
            logger.error(f"Error analyzing historical IAM changes: {e}")
            analysis['error'] = str(e)
        
        return analysis
    
    def detect_security_incidents(
        self,
        start_time: datetime,
        end_time: datetime,
        severity_threshold: str = 'medium'
    ) -> List[SecurityIncident]:
        """
        Detect potential security incidents from audit logs.
        
        Args:
            start_time: Start of analysis period
            end_time: End of analysis period
            severity_threshold: Minimum severity to report
            
        Returns:
            List of detected security incidents
        """
        incidents = []
        
        try:
            # Get all relevant audit log entries
            audit_filter = self._build_security_filter(start_time, end_time)
            log_entries = self._query_audit_logs(audit_filter)
            
            # Group events by principal and time windows
            event_groups = self._group_events_for_analysis(log_entries)
            
            # Detect different types of security incidents
            for pattern_type, pattern_config in self._security_patterns.items():
                pattern_incidents = self._detect_pattern_incidents(
                    event_groups, pattern_type, pattern_config
                )
                incidents.extend(pattern_incidents)
            
            # Filter by severity threshold
            severity_order = ['low', 'medium', 'high', 'critical']
            min_severity_index = severity_order.index(severity_threshold)
            
            filtered_incidents = [
                incident for incident in incidents
                if severity_order.index(incident.severity) >= min_severity_index
            ]
            
            # Sort by severity and timestamp
            filtered_incidents.sort(
                key=lambda x: (severity_order.index(x.severity), x.timestamp),
                reverse=True
            )
            
        except Exception as e:
            logger.error(f"Error detecting security incidents: {e}")
            # Return empty list on error
            return []
        
        return filtered_incidents
    
    def analyze_user_access_patterns(
        self,
        principal_email: str,
        days_back: int = 30,
        include_anomalies: bool = True
    ) -> AccessPattern:
        """
        Analyze access patterns for a specific user.
        
        Args:
            principal_email: User email to analyze
            days_back: Number of days to analyze
            include_anomalies: Whether to detect anomalies
            
        Returns:
            AccessPattern with detailed analysis
        """
        end_time = datetime.now()
        start_time = end_time - timedelta(days=days_back)
        
        pattern = AccessPattern(
            principal_email=principal_email,
            time_period=f"{days_back} days"
        )
        
        try:
            # Build filter for user activity
            user_filter = f'''
                protoPayload.authenticationInfo.principalEmail="{principal_email}"
                AND timestamp>="{start_time.isoformat()}Z"
                AND timestamp<="{end_time.isoformat()}Z"
            '''
            
            # Get user's audit log entries
            log_entries = self._query_audit_logs(user_filter)
            
            if not log_entries:
                logger.warning(f"No audit log entries found for user: {principal_email}")
                return pattern
            
            # Analyze access hours
            access_hours = []
            for entry in log_entries:
                hour = entry.timestamp.hour
                access_hours.append(hour)
            
            # Determine normal access hours (most common hours)
            hour_counts = Counter(access_hours)
            total_accesses = len(access_hours)
            
            # Normal hours are those with >5% of total access
            normal_threshold = max(1, total_accesses * 0.05)
            pattern.normal_access_hours = [
                hour for hour, count in hour_counts.items()
                if count >= normal_threshold
            ]
            
            # Unusual access times
            if include_anomalies:
                for entry in log_entries:
                    if entry.timestamp.hour not in pattern.normal_access_hours:
                        # Check if it's truly unusual (off business hours)
                        if entry.timestamp.hour < 6 or entry.timestamp.hour > 22:
                            pattern.unusual_access_times.append(entry.timestamp)
            
            # Analyze service usage patterns
            service_counts = Counter()
            for entry in log_entries:
                if hasattr(entry, 'payload') and entry.payload and hasattr(entry.payload, 'get'):
                    service_name = entry.payload.get('serviceName', 'unknown')
                    service_counts[service_name] += 1
            
            # Most frequent services (top 80% of usage)
            total_service_calls = sum(service_counts.values())
            cumulative_count = 0
            for service, count in service_counts.most_common():
                cumulative_count += count
                pattern.frequent_services.append(service)
                if cumulative_count >= total_service_calls * 0.8:
                    break
            
            # Unusual services (bottom 20% but still used)
            for service, count in service_counts.most_common():
                if service not in pattern.frequent_services and count >= 2:
                    pattern.unusual_services.append(service)
            
            # Analyze IP addresses
            for entry in log_entries:
                if hasattr(entry, 'payload') and entry.payload and hasattr(entry.payload, 'get'):
                    request_metadata = entry.payload.get('requestMetadata', {})
                    caller_ip = request_metadata.get('callerIp', '')
                    if caller_ip:
                        pattern.ip_addresses.add(caller_ip)
            
            # Detect suspicious IP changes
            if include_anomalies and len(pattern.ip_addresses) > 3:
                ip_timeline = []
                for entry in log_entries:
                    if hasattr(entry, 'payload') and entry.payload and hasattr(entry.payload, 'get'):
                        request_metadata = entry.payload.get('requestMetadata', {})
                        caller_ip = request_metadata.get('callerIp', '')
                        if caller_ip:
                            ip_timeline.append({
                                'timestamp': entry.timestamp,
                                'ip': caller_ip
                            })
                
                # Look for rapid IP changes
                ip_timeline.sort(key=lambda x: x['timestamp'])
                for i in range(1, len(ip_timeline)):
                    current = ip_timeline[i]
                    previous = ip_timeline[i-1]
                    
                    time_diff = current['timestamp'] - previous['timestamp']
                    if (time_diff < timedelta(minutes=10) and 
                        current['ip'] != previous['ip']):
                        pattern.suspicious_ip_changes.append({
                            'timestamp': current['timestamp'].isoformat(),
                            'from_ip': previous['ip'],
                            'to_ip': current['ip'],
                            'time_difference_minutes': time_diff.total_seconds() / 60
                        })
            
            # Calculate activity and anomaly scores
            pattern.activity_score = self._calculate_activity_score(log_entries, days_back)
            if include_anomalies:
                pattern.anomaly_score = self._calculate_anomaly_score(pattern)
            
        except Exception as e:
            logger.error(f"Error analyzing access patterns for {principal_email}: {e}")
            pattern.anomaly_score = -1  # Indicate error
        
        return pattern
    
    def generate_compliance_report(
        self,
        framework: str,
        start_time: datetime,
        end_time: datetime,
        include_recommendations: bool = True
    ) -> Dict[str, Any]:
        """
        Generate a compliance audit report for a specific framework.
        
        Args:
            framework: Compliance framework (SOX, PCI-DSS, HIPAA, GDPR)
            start_time: Start of reporting period
            end_time: End of reporting period
            include_recommendations: Whether to include remediation recommendations
            
        Returns:
            Dict containing comprehensive compliance report
        """
        report = {
            'framework': framework,
            'report_period': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat(),
                'duration_days': (end_time - start_time).days
            },
            'compliance_events': [],
            'violations': [],
            'risk_summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'audit_trail': [],
            'statistics': {},
            'recommendations': [] if include_recommendations else None
        }
        
        try:
            if framework not in self._compliance_events:
                raise ValueError(f"Unsupported compliance framework: {framework}")
            
            # Get compliance-relevant events
            framework_methods = self._compliance_events[framework]
            compliance_filter = self._build_compliance_filter(
                start_time, end_time, framework_methods
            )
            
            log_entries = self._query_audit_logs(compliance_filter)
            
            # Process each log entry
            for entry in log_entries:
                event_info = {
                    'timestamp': entry.timestamp.isoformat(),
                    'principal': entry.principal_email,
                    'action': entry.method_name,
                    'resource': entry.resource_name,
                    'source_ip': '',
                    'compliance_relevance': self._assess_compliance_relevance(
                        entry.method_name, framework
                    )
                }
                
                # Extract source IP
                if hasattr(entry, 'payload') and entry.payload:
                    request_metadata = entry.payload.get('requestMetadata', {})
                    event_info['source_ip'] = request_metadata.get('callerIp', 'unknown')
                
                report['compliance_events'].append(event_info)
                
                # Check for violations
                violation = self._check_compliance_violation(entry, framework)
                if violation:
                    report['violations'].append(violation)
                    
                    # Update risk summary
                    risk_level = violation.get('risk_level', 'medium')
                    report['risk_summary'][risk_level] += 1
            
            # Generate statistics
            report['statistics'] = {
                'total_events': len(report['compliance_events']),
                'unique_principals': len(set(
                    event['principal'] for event in report['compliance_events']
                )),
                'total_violations': len(report['violations']),
                'violation_rate': (len(report['violations']) / max(1, len(report['compliance_events']))) * 100,
                'most_active_principals': self._get_most_active_principals(
                    report['compliance_events'], top_n=5
                ),
                'most_common_actions': self._get_most_common_actions(
                    report['compliance_events'], top_n=5
                )
            }
            
            # Build audit trail
            report['audit_trail'] = sorted(
                report['compliance_events'],
                key=lambda x: x['timestamp'],
                reverse=True
            )[:100]  # Limit to most recent 100 events
            
            # Generate recommendations
            if include_recommendations:
                report['recommendations'] = self._generate_compliance_recommendations(
                    report, framework
                )
            
        except Exception as e:
            logger.error(f"Error generating compliance report for {framework}: {e}")
            report['error'] = str(e)
        
        return report
    
    def _build_iam_filter(
        self,
        start_time: datetime,
        end_time: datetime,
        principals: Optional[List[str]] = None,
        resources: Optional[List[str]] = None
    ) -> str:
        """Build filter for IAM-related audit log events."""
        # Base time filter
        filter_parts = [
            f'timestamp>="{start_time.isoformat()}Z"',
            f'timestamp<="{end_time.isoformat()}Z"'
        ]
        
        # Add IAM method filters
        iam_methods = list(self._iam_methods.keys())
        method_filters = ' OR '.join([
            f'protoPayload.methodName="{method}"' for method in iam_methods
        ])
        filter_parts.append(f'({method_filters})')
        
        # Add principal filters if specified
        if principals:
            principal_filters = ' OR '.join([
                f'protoPayload.authenticationInfo.principalEmail="{principal}"'
                for principal in principals
            ])
            filter_parts.append(f'({principal_filters})')
        
        # Add resource filters if specified
        if resources:
            resource_filters = ' OR '.join([
                f'protoPayload.resourceName="{resource}"' for resource in resources
            ])
            filter_parts.append(f'({resource_filters})')
        
        return ' AND '.join(filter_parts)
    
    def _build_security_filter(self, start_time: datetime, end_time: datetime) -> str:
        """Build filter for security-relevant audit log events."""
        return f'''
            timestamp>="{start_time.isoformat()}Z"
            AND timestamp<="{end_time.isoformat()}Z"
            AND (
                protoPayload.methodName:"iam"
                OR protoPayload.methodName:"setIamPolicy"
                OR protoPayload.methodName:"generateAccessToken"
                OR protoPayload.methodName:"impersonateServiceAccount"
                OR severity:"ERROR"
                OR severity:"WARNING"
            )
        '''
    
    def _build_compliance_filter(
        self,
        start_time: datetime,
        end_time: datetime,
        methods: List[str]
    ) -> str:
        """Build filter for compliance-relevant events."""
        method_filters = ' OR '.join([
            f'protoPayload.methodName:"{method}"' for method in methods
        ])
        
        return f'''
            timestamp>="{start_time.isoformat()}Z"
            AND timestamp<="{end_time.isoformat()}Z"
            AND ({method_filters})
        '''
    
    def _query_audit_logs(self, filter_str: str, max_results: int = 1000) -> List[AuditLogEntry]:
        """Query Cloud Audit Logs with the specified filter."""
        try:
            entries = self.logging_client.list_entries(
                filter_=filter_str,
                order_by=DESCENDING,
                max_results=max_results
            )
            
            audit_entries = []
            for entry in entries:
                audit_entry = self._parse_log_entry(entry)
                if audit_entry:
                    audit_entries.append(audit_entry)
            
            return audit_entries
            
        except PermissionDenied as e:
            logger.error(f"Permission denied accessing audit logs: {e}")
            return []
        except Exception as e:
            logger.error(f"Error querying audit logs: {e}")
            return []
    
    def _parse_log_entry(self, entry) -> Optional[AuditLogEntry]:
        """Parse a raw log entry into structured format."""
        try:
            if not hasattr(entry, 'payload') or not entry.payload:
                return None
            
            payload = entry.payload
            
            # Handle case where payload is a string instead of dict
            if isinstance(payload, str):
                logger.warning(f"Payload is string, cannot parse: {payload[:100]}...")
                return None
            
            # Ensure payload has get method (is dict-like)
            if not hasattr(payload, 'get'):
                logger.warning(f"Payload is not dict-like: {type(payload)}")
                return None
            
            return AuditLogEntry(
                timestamp=entry.timestamp,
                severity=entry.severity.name if hasattr(entry.severity, 'name') else str(entry.severity),
                principal_email=payload.get('authenticationInfo', {}).get('principalEmail', 'unknown'),
                service_name=payload.get('serviceName', 'unknown'),
                method_name=payload.get('methodName', 'unknown'),
                resource_name=payload.get('resourceName', 'unknown'),
                request_metadata=payload.get('requestMetadata', {}),
                response=payload.get('response'),
                status=payload.get('status'),
                audit_log=payload
            )
            
        except Exception as e:
            logger.warning(f"Error parsing log entry: {e}")
            return None
    
    def _is_iam_event(self, entry: AuditLogEntry) -> bool:
        """Check if a log entry is an IAM-related event."""
        return (entry.method_name in self._iam_methods or
                'iam' in entry.method_name.lower() or
                'setIamPolicy' in entry.method_name)
    
    def _parse_iam_event(self, entry: AuditLogEntry) -> Optional[IAMChangeEvent]:
        """Parse an audit log entry into an IAM change event."""
        try:
            method_info = self._iam_methods.get(entry.method_name, {})
            
            # Extract changes summary
            changes_summary = self._extract_iam_changes_summary(entry)
            
            return IAMChangeEvent(
                timestamp=entry.timestamp,
                principal_email=entry.principal_email,
                resource_name=entry.resource_name,
                action=entry.method_name,
                changes_summary=changes_summary,
                risk_level=method_info.get('risk_level', 'medium'),
                compliance_impact=method_info.get('compliance_impact', [])
            )
            
        except Exception as e:
            logger.warning(f"Error parsing IAM event: {e}")
            return None
    
    def _extract_iam_changes_summary(self, entry: AuditLogEntry) -> str:
        """Extract a human-readable summary of IAM changes."""
        if not entry.audit_log:
            return "IAM change (details not available)"
        
        method = entry.method_name
        
        if 'setIamPolicy' in method:
            return "IAM policy modified"
        elif 'createRole' in method:
            return "Custom role created"
        elif 'deleteRole' in method:
            return "Role deleted"
        elif 'createServiceAccount' in method:
            return "Service account created"
        elif 'deleteServiceAccount' in method:
            return "Service account deleted"
        else:
            return f"IAM operation: {method}"
    
    def _group_events_for_analysis(self, log_entries: List[AuditLogEntry]) -> Dict[str, List[AuditLogEntry]]:
        """Group events by principal for pattern analysis."""
        groups = defaultdict(list)
        
        for entry in log_entries:
            principal = entry.principal_email
            groups[principal].append(entry)
        
        # Sort events within each group by timestamp
        for principal in groups:
            groups[principal].sort(key=lambda x: x.timestamp)
        
        return dict(groups)
    
    def _detect_pattern_incidents(
        self,
        event_groups: Dict[str, List[AuditLogEntry]],
        pattern_type: str,
        pattern_config: Dict[str, Any]
    ) -> List[SecurityIncident]:
        """Detect incidents matching a specific pattern."""
        incidents = []
        
        for principal, events in event_groups.items():
            # Look for pattern matches within time windows
            time_window = pattern_config['time_window']
            threshold = pattern_config['threshold']
            target_methods = pattern_config.get('methods', [])
            
            # Group events by time windows
            window_start = None
            window_events = []
            
            for event in events:
                if window_start is None:
                    window_start = event.timestamp
                    window_events = [event]
                    continue
                
                if event.timestamp - window_start <= time_window:
                    window_events.append(event)
                else:
                    # Analyze the completed window
                    if self._window_matches_pattern(window_events, pattern_config):
                        incident = self._create_security_incident(
                            pattern_type, principal, window_events, pattern_config
                        )
                        incidents.append(incident)
                    
                    # Start new window
                    window_start = event.timestamp
                    window_events = [event]
            
            # Check the last window
            if self._window_matches_pattern(window_events, pattern_config):
                incident = self._create_security_incident(
                    pattern_type, principal, window_events, pattern_config
                )
                incidents.append(incident)
        
        return incidents
    
    def _window_matches_pattern(
        self,
        events: List[AuditLogEntry],
        pattern_config: Dict[str, Any]
    ) -> bool:
        """Check if events in a time window match a security pattern."""
        if len(events) < pattern_config['threshold']:
            return False
        
        target_methods = pattern_config.get('methods', [])
        if not target_methods:
            return True
        
        # Check if any target methods are present
        event_methods = {event.method_name for event in events}
        return any(
            any(target in method for target in target_methods)
            for method in event_methods
        )
    
    def _create_security_incident(
        self,
        pattern_type: str,
        principal: str,
        events: List[AuditLogEntry],
        pattern_config: Dict[str, Any]
    ) -> SecurityIncident:
        """Create a security incident from detected pattern."""
        incident_id = f"{pattern_type}_{principal}_{events[0].timestamp.strftime('%Y%m%d_%H%M%S')}"
        
        # Determine severity based on pattern type and event count
        event_count = len(events)
        if pattern_type == 'privilege_escalation':
            severity = 'critical' if event_count >= 5 else 'high'
        elif pattern_type == 'account_compromise':
            severity = 'high' if event_count >= 10 else 'medium'
        else:
            severity = 'medium'
        
        # Extract affected resources
        affected_resources = list(set(event.resource_name for event in events))
        
        # Generate description
        description = f"{pattern_type.replace('_', ' ').title()} detected: {event_count} suspicious events in {pattern_config['time_window']}"
        
        return SecurityIncident(
            incident_id=incident_id,
            severity=severity,
            incident_type=pattern_type,
            description=description,
            timestamp=events[0].timestamp,
            principal_email=principal,
            affected_resources=affected_resources,
            indicators=pattern_config.get('indicators', []),
            recommended_actions=self._get_incident_recommendations(pattern_type, severity),
            related_events=[event.method_name for event in events]
        )
    
    def _get_incident_recommendations(self, pattern_type: str, severity: str) -> List[str]:
        """Get recommended actions for a security incident."""
        base_recommendations = {
            'privilege_escalation': [
                "Review and audit recent IAM policy changes",
                "Verify legitimacy of role creations and assignments",
                "Consider revoking suspicious permissions temporarily",
                "Enable additional monitoring for the affected principal"
            ],
            'lateral_movement': [
                "Investigate cross-project access patterns",
                "Review service account usage and impersonation",
                "Check for unauthorized resource access",
                "Consider network-level restrictions"
            ],
            'data_exfiltration': [
                "Review data access logs and volumes",
                "Check for unauthorized downloads or exports",
                "Implement data loss prevention controls",
                "Consider quarantining affected accounts"
            ],
            'account_compromise': [
                "Force password reset for affected account",
                "Review and revoke active sessions",
                "Enable additional authentication factors",
                "Audit recent account activities"
            ]
        }
        
        recommendations = base_recommendations.get(pattern_type, [
            "Investigate the detected activities",
            "Review audit logs for additional context",
            "Consider implementing additional security controls"
        ])
        
        if severity == 'critical':
            recommendations.insert(0, "CRITICAL: Immediate investigation and response required")
        
        return recommendations
    
    def _analyze_compliance_events(self, iam_events: List[IAMChangeEvent]) -> Dict[str, Any]:
        """Analyze IAM events for compliance implications."""
        compliance_analysis = {}
        
        for framework, framework_events in self._compliance_events.items():
            framework_analysis = {
                'total_events': 0,
                'high_risk_events': 0,
                'events_by_principal': {},
                'timeline': []
            }
            
            for event in iam_events:
                if any(framework_event in event.action for framework_event in framework_events):
                    framework_analysis['total_events'] += 1
                    
                    if event.risk_level in ['critical', 'high']:
                        framework_analysis['high_risk_events'] += 1
                    
                    # Track by principal
                    principal = event.principal_email
                    if principal not in framework_analysis['events_by_principal']:
                        framework_analysis['events_by_principal'][principal] = 0
                    framework_analysis['events_by_principal'][principal] += 1
                    
                    # Add to timeline
                    framework_analysis['timeline'].append({
                        'timestamp': event.timestamp.isoformat(),
                        'principal': principal,
                        'action': event.action,
                        'resource': event.resource_name,
                        'risk_level': event.risk_level
                    })
            
            # Sort timeline by timestamp
            framework_analysis['timeline'].sort(key=lambda x: x['timestamp'], reverse=True)
            
            compliance_analysis[framework] = framework_analysis
        
        return compliance_analysis
    
    def _build_iam_timeline(self, iam_events: List[IAMChangeEvent]) -> List[Dict[str, Any]]:
        """Build a chronological timeline of IAM events."""
        timeline = []
        
        for event in iam_events:
            timeline.append({
                'timestamp': event.timestamp.isoformat(),
                'principal': event.principal_email,
                'action': event.action,
                'resource': event.resource_name,
                'risk_level': event.risk_level,
                'summary': event.changes_summary,
                'compliance_frameworks': event.compliance_impact
            })
        
        # Sort by timestamp (most recent first)
        timeline.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return timeline
    
    def _detect_iam_patterns(self, iam_events: List[IAMChangeEvent]) -> List[Dict[str, Any]]:
        """Detect patterns in IAM changes."""
        patterns = []
        
        # Pattern 1: Rapid succession of IAM changes by same principal
        principal_events = defaultdict(list)
        for event in iam_events:
            principal_events[event.principal_email].append(event)
        
        for principal, events in principal_events.items():
            if len(events) >= 5:  # 5 or more changes
                # Check if they occurred within a short time period
                events.sort(key=lambda x: x.timestamp)
                time_span = events[-1].timestamp - events[0].timestamp
                
                if time_span <= timedelta(hours=1):
                    patterns.append({
                        'type': 'rapid_iam_changes',
                        'description': f'Principal {principal} made {len(events)} IAM changes within {time_span}',
                        'principal': principal,
                        'event_count': len(events),
                        'time_span_hours': time_span.total_seconds() / 3600,
                        'risk_level': 'high' if len(events) >= 10 else 'medium'
                    })
        
        # Pattern 2: Off-hours IAM changes
        for event in iam_events:
            hour = event.timestamp.hour
            if hour < 6 or hour > 22:  # Outside business hours
                patterns.append({
                    'type': 'off_hours_iam_change',
                    'description': f'IAM change during off-hours: {event.changes_summary}',
                    'principal': event.principal_email,
                    'timestamp': event.timestamp.isoformat(),
                    'hour': hour,
                    'action': event.action,
                    'risk_level': 'medium'
                })
        
        return patterns
    
    def _generate_iam_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on IAM analysis."""
        recommendations = []
        
        total_changes = analysis['total_iam_changes']
        high_risk_changes = len(analysis['high_risk_changes'])
        
        if total_changes == 0:
            recommendations.append("No IAM changes detected in the analyzed period")
            return recommendations
        
        if high_risk_changes > 0:
            recommendations.append(
                f"Review {high_risk_changes} high-risk IAM changes for necessity and authorization"
            )
        
        if high_risk_changes / total_changes > 0.3:
            recommendations.append(
                "High proportion of risky IAM changes detected. Consider implementing approval workflows"
            )
        
        # Check for top active principals
        principal_counts = {
            principal: len(events) 
            for principal, events in analysis['changes_by_principal'].items()
        }
        
        if principal_counts:
            most_active = max(principal_counts.items(), key=lambda x: x[1])
            if most_active[1] > 10:
                recommendations.append(
                    f"Principal {most_active[0]} made {most_active[1]} IAM changes. "
                    "Consider reviewing their activities for patterns"
                )
        
        # Check patterns
        if analysis.get('patterns_detected'):
            pattern_count = len(analysis['patterns_detected'])
            recommendations.append(
                f"{pattern_count} suspicious patterns detected. "
                "Review pattern details and consider additional monitoring"
            )
        
        return recommendations
    
    def _calculate_activity_score(self, log_entries: List[AuditLogEntry], days_back: int) -> float:
        """Calculate activity score for a user (0-100)."""
        if not log_entries:
            return 0.0
        
        total_entries = len(log_entries)
        daily_average = total_entries / max(1, days_back)
        
        # Normalize to 0-100 scale (assuming 10+ daily activities = high activity)
        activity_score = min(100.0, (daily_average / 10.0) * 100.0)
        
        return round(activity_score, 1)
    
    def _calculate_anomaly_score(self, pattern: AccessPattern) -> float:
        """Calculate anomaly score based on detected patterns."""
        anomaly_score = 0.0
        
        # Unusual access times
        if pattern.unusual_access_times:
            anomaly_score += min(30.0, len(pattern.unusual_access_times) * 2.0)
        
        # Unusual services
        if pattern.unusual_services:
            anomaly_score += min(20.0, len(pattern.unusual_services) * 5.0)
        
        # Multiple IP addresses
        if len(pattern.ip_addresses) > 3:
            anomaly_score += min(25.0, (len(pattern.ip_addresses) - 3) * 5.0)
        
        # Suspicious IP changes
        if pattern.suspicious_ip_changes:
            anomaly_score += min(25.0, len(pattern.suspicious_ip_changes) * 10.0)
        
        return min(100.0, round(anomaly_score, 1))
    
    def _assess_compliance_relevance(self, method_name: str, framework: str) -> str:
        """Assess how relevant a method is for compliance."""
        framework_methods = self._compliance_events.get(framework, [])
        
        if any(method in method_name for method in framework_methods):
            return 'high'
        elif 'iam' in method_name.lower():
            return 'medium'
        else:
            return 'low'
    
    def _check_compliance_violation(self, entry: AuditLogEntry, framework: str) -> Optional[Dict[str, Any]]:
        """Check if an audit log entry represents a compliance violation."""
        # This is a simplified check - in practice, you'd have more sophisticated rules
        violations = []
        
        if framework == 'SOX':
            # SOX requires segregation of duties
            if 'setIamPolicy' in entry.method_name and entry.principal_email.endswith('@gmail.com'):
                violations.append({
                    'type': 'external_user_iam_change',
                    'risk_level': 'high',
                    'description': 'External user made IAM policy changes',
                    'timestamp': entry.timestamp.isoformat(),
                    'principal': entry.principal_email,
                    'action': entry.method_name
                })
        
        return violations[0] if violations else None
    
    def _get_most_active_principals(self, events: List[Dict[str, Any]], top_n: int = 5) -> List[Dict[str, Any]]:
        """Get the most active principals in compliance events."""
        principal_counts = Counter(event['principal'] for event in events)
        
        return [
            {'principal': principal, 'event_count': count}
            for principal, count in principal_counts.most_common(top_n)
        ]
    
    def _get_most_common_actions(self, events: List[Dict[str, Any]], top_n: int = 5) -> List[Dict[str, Any]]:
        """Get the most common actions in compliance events."""
        action_counts = Counter(event['action'] for event in events)
        
        return [
            {'action': action, 'count': count}
            for action, count in action_counts.most_common(top_n)
        ]
    
    def _generate_compliance_recommendations(self, report: Dict[str, Any], framework: str) -> List[str]:
        """Generate compliance-specific recommendations."""
        recommendations = []
        
        total_events = report['statistics']['total_events']
        violation_count = len(report['violations'])
        
        if total_events == 0:
            recommendations.append(f"No {framework} compliance events detected in the reporting period")
            return recommendations
        
        if violation_count > 0:
            recommendations.append(
                f"Address {violation_count} compliance violations identified in the report"
            )
        
        violation_rate = report['statistics']['violation_rate']
        if violation_rate > 5.0:  # More than 5% violation rate
            recommendations.append(
                f"High violation rate ({violation_rate:.1f}%) detected. "
                "Consider implementing preventive controls"
            )
        
        # Framework-specific recommendations
        if framework == 'SOX':
            recommendations.extend([
                "Ensure proper segregation of duties for financial system access",
                "Implement regular access reviews and certifications",
                "Maintain detailed audit trails for all IAM changes"
            ])
        elif framework == 'PCI-DSS':
            recommendations.extend([
                "Restrict access to cardholder data environments",
                "Implement strong authentication for administrative access",
                "Regular monitoring of privileged account activities"
            ])
        elif framework == 'HIPAA':
            recommendations.extend([
                "Ensure minimum necessary access to PHI",
                "Regular audit of healthcare data access patterns",
                "Implement role-based access controls"
            ])
        elif framework == 'GDPR':
            recommendations.extend([
                "Document lawful basis for data processing activities",
                "Implement data subject rights management procedures",
                "Regular privacy impact assessments"
            ])
        
        return recommendations