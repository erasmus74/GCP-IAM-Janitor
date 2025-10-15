"""
Enhanced Identity Analysis client for group membership resolution and user activity tracking.

This module provides advanced identity analysis capabilities including:
- Group membership resolution using Google Cloud Identity API
- User activity tracking through Admin SDK
- Identity risk scoring and analysis
- Group hierarchy mapping
"""

import logging
from typing import List, Dict, Set, Optional, Any, Tuple
from datetime import datetime, timedelta
from google.auth.credentials import Credentials
from google.cloud import logging_v2
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.api_core.exceptions import GoogleAPIError, NotFound, PermissionDenied

from ..models.iam_models import Identity, IdentityType, PermissionRiskLevel

logger = logging.getLogger(__name__)


class IdentityAnalysisClient:
    """Enhanced client for identity analysis and group membership resolution."""
    
    def __init__(self, credentials: Credentials, customer_id: Optional[str] = None):
        """
        Initialize Identity Analysis client.
        
        Args:
            credentials: Authenticated GCP credentials
            customer_id: Google Workspace customer ID (required for group resolution)
        """
        self.credentials = credentials
        self.customer_id = customer_id
        self._cloud_identity_service = None
        self._admin_service = None
        self._logging_client = None
    
    @property
    def cloud_identity_service(self):
        """Get or create Cloud Identity API service client."""
        if self._cloud_identity_service is None:
            try:
                self._cloud_identity_service = build(
                    'cloudidentity',
                    'v1',
                    credentials=self.credentials
                )
            except Exception as e:
                logger.warning(f"Could not initialize Cloud Identity API: {e}")
                self._cloud_identity_service = None
        return self._cloud_identity_service
    
    @property
    def admin_service(self):
        """Get or create Admin SDK service client."""
        if self._admin_service is None:
            try:
                self._admin_service = build(
                    'admin',
                    'directory_v1',
                    credentials=self.credentials
                )
            except Exception as e:
                logger.warning(f"Could not initialize Admin SDK: {e}")
                self._admin_service = None
        return self._admin_service
    
    @property
    def logging_client(self) -> logging_v2.Client:
        """Get or create Cloud Logging client."""
        if self._logging_client is None:
            self._logging_client = logging_v2.Client(credentials=self.credentials)
        return self._logging_client
    
    def resolve_group_memberships(self, user_email: str, enable_api_calls: bool = False) -> Dict[str, Any]:
        """
        Resolve group memberships for a user.
        
        Args:
            user_email: User email address
            enable_api_calls: Whether to make actual API calls (disabled by default due to common permission issues)
            
        Returns:
            Dict containing group membership information
        """
        memberships = {
            'direct_groups': [],
            'nested_groups': [],
            'all_groups': set(),
            'group_hierarchy': {},
            'resolution_errors': []
        }
        
        # Skip API calls by default to avoid HTTP 400 errors
        if not enable_api_calls:
            memberships['resolution_errors'].append("Cloud Identity API calls disabled (use enable_api_calls=True to enable)")
            return memberships
        
        if not self.cloud_identity_service:
            memberships['resolution_errors'].append("Cloud Identity API not available")
            return memberships
        
        try:
            # Search for groups this user is a member of
            # Fix the query format - use proper member query syntax
            query = f"member_key_id == 'user:{user_email}'"
            
            request = self.cloud_identity_service.groups().search(
                query=query,
                view='FULL'
            )
            
            while request:
                response = request.execute()
                
                for group in response.get('groups', []):
                    group_email = group.get('groupKey', {}).get('id', '')
                    group_name = group.get('displayName', group_email)
                    
                    group_info = {
                        'email': group_email,
                        'name': group_name,
                        'description': group.get('description', ''),
                        'labels': group.get('labels', {}),
                        'parent': group.get('parent', ''),
                        'create_time': group.get('createTime', ''),
                        'update_time': group.get('updateTime', '')
                    }
                    
                    memberships['direct_groups'].append(group_info)
                    memberships['all_groups'].add(group_email)
                    
                    # Resolve nested groups
                    nested = self._resolve_nested_groups(group_email)
                    memberships['nested_groups'].extend(nested)
                    memberships['all_groups'].update([g['email'] for g in nested])
                    
                    # Build hierarchy
                    if group_info['parent']:
                        parent_email = group_info['parent'].split('/')[-1]
                        if parent_email not in memberships['group_hierarchy']:
                            memberships['group_hierarchy'][parent_email] = []
                        memberships['group_hierarchy'][parent_email].append(group_email)
                
                request = self.cloud_identity_service.groups().search_next(
                    request, response
                )
                
        except HttpError as e:
            error_msg = f"HTTP error resolving groups for {user_email}: {e}"
            logger.warning(error_msg)
            memberships['resolution_errors'].append(error_msg)
        except Exception as e:
            error_msg = f"Error resolving groups for {user_email}: {e}"
            logger.error(error_msg)
            memberships['resolution_errors'].append(error_msg)
        
        # Convert set to list for serialization
        memberships['all_groups'] = list(memberships['all_groups'])
        
        return memberships
    
    def _resolve_nested_groups(self, group_email: str, visited: Optional[Set[str]] = None) -> List[Dict[str, Any]]:
        """
        Recursively resolve nested group memberships.
        
        Args:
            group_email: Group email to resolve
            visited: Set of already visited groups to prevent cycles
            
        Returns:
            List of nested group information
        """
        if visited is None:
            visited = set()
        
        if group_email in visited:
            return []
        
        visited.add(group_email)
        nested_groups = []
        
        try:
            if not self.cloud_identity_service:
                return nested_groups
            
            # Get group memberships
            group_name = f"groups/{group_email}"
            request = self.cloud_identity_service.groups().memberships().list(
                parent=group_name,
                view='FULL'
            )
            
            response = request.execute()
            
            for membership in response.get('memberships', []):
                member_key = membership.get('memberKey', {})
                if member_key.get('namespace') == 'cloudidentity.googleapis.com/groups.discussion_forum':
                    nested_group_email = member_key.get('id', '')
                    if nested_group_email and nested_group_email not in visited:
                        
                        # Get group details
                        group_details = self._get_group_details(nested_group_email)
                        if group_details:
                            nested_groups.append(group_details)
                            
                            # Recursively resolve deeper nesting
                            deeper_nested = self._resolve_nested_groups(nested_group_email, visited.copy())
                            nested_groups.extend(deeper_nested)
                            
        except Exception as e:
            logger.warning(f"Error resolving nested groups for {group_email}: {e}")
        
        return nested_groups
    
    def _get_group_details(self, group_email: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a group."""
        try:
            if not self.cloud_identity_service:
                return None
                
            group_name = f"groups/{group_email}"
            group = self.cloud_identity_service.groups().get(
                name=group_name,
                view='FULL'
            ).execute()
            
            return {
                'email': group.get('groupKey', {}).get('id', ''),
                'name': group.get('displayName', ''),
                'description': group.get('description', ''),
                'labels': group.get('labels', {}),
                'parent': group.get('parent', ''),
                'member_count': group.get('directMemberCount', 0),
                'create_time': group.get('createTime', ''),
                'update_time': group.get('updateTime', '')
            }
            
        except Exception as e:
            logger.warning(f"Error getting group details for {group_email}: {e}")
            return None
    
    def track_user_activity(self, user_email: str, days_back: int = 30) -> Dict[str, Any]:
        """
        Track user activity through audit logs and admin activities.
        
        Args:
            user_email: User email address
            days_back: Number of days to look back for activity
            
        Returns:
            Dict containing user activity information
        """
        activity = {
            'login_events': [],
            'iam_changes': [],
            'resource_access': [],
            'last_activity': None,
            'activity_score': 0,
            'risk_factors': [],
            'summary': {
                'total_events': 0,
                'login_count': 0,
                'iam_changes_count': 0,
                'resource_access_count': 0,
                'active_days': 0
            }
        }
        
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(days=days_back)
            
            # Query audit logs for user activity
            activity_data = self._query_audit_logs(user_email, start_time, end_time)
            
            # Process login events
            login_events = self._extract_login_events(activity_data)
            activity['login_events'] = login_events
            activity['summary']['login_count'] = len(login_events)
            
            # Process IAM changes
            iam_changes = self._extract_iam_changes(activity_data, user_email)
            activity['iam_changes'] = iam_changes
            activity['summary']['iam_changes_count'] = len(iam_changes)
            
            # Process resource access
            resource_access = self._extract_resource_access(activity_data)
            activity['resource_access'] = resource_access
            activity['summary']['resource_access_count'] = len(resource_access)
            
            # Calculate activity metrics
            if activity_data:
                activity['last_activity'] = max([event.get('timestamp', '') for event in activity_data])
                activity['summary']['total_events'] = len(activity_data)
                
                # Calculate active days
                active_dates = set()
                for event in activity_data:
                    if event.get('timestamp'):
                        date_str = event['timestamp'][:10]  # Extract date part
                        active_dates.add(date_str)
                activity['summary']['active_days'] = len(active_dates)
                
                # Calculate activity score (0-100)
                activity['activity_score'] = self._calculate_activity_score(activity)
                
                # Identify risk factors
                activity['risk_factors'] = self._identify_activity_risks(activity, user_email)
                
        except Exception as e:
            logger.error(f"Error tracking activity for {user_email}: {e}")
            activity['error'] = str(e)
        
        return activity
    
    def _query_audit_logs(self, user_email: str, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Query Cloud Audit Logs for user activity."""
        try:
            filter_str = f'''
            protoPayload.authenticationInfo.principalEmail="{user_email}"
            AND timestamp>="{start_time.isoformat()}Z"
            AND timestamp<="{end_time.isoformat()}Z"
            '''
            
            entries = self.logging_client.list_entries(
                filter_=filter_str,
                order_by=logging_v2.DESCENDING,
                max_results=1000
            )
            
            events = []
            for entry in entries:
                event_data = {
                    'timestamp': entry.timestamp.isoformat(),
                    'severity': entry.severity,
                    'resource': entry.resource.type if entry.resource else 'unknown',
                    'method': '',
                    'service': '',
                    'caller_ip': '',
                    'user_agent': '',
                    'request_metadata': {}
                }
                
                if hasattr(entry, 'payload') and entry.payload and hasattr(entry.payload, 'get'):
                    payload = entry.payload
                    event_data.update({
                        'method': payload.get('methodName', ''),
                        'service': payload.get('serviceName', ''),
                        'caller_ip': payload.get('requestMetadata', {}).get('callerIp', ''),
                        'user_agent': payload.get('requestMetadata', {}).get('userAgent', ''),
                        'request_metadata': payload.get('requestMetadata', {})
                    })
                
                events.append(event_data)
            
            return events
            
        except Exception as e:
            logger.warning(f"Error querying audit logs: {e}")
            return []
    
    def _extract_login_events(self, activity_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract login events from activity data."""
        login_events = []
        
        login_methods = [
            'google.login',
            'google.auth',
            'oauth2.googleapis.com'
        ]
        
        for event in activity_data:
            service = event.get('service', '').lower()
            method = event.get('method', '').lower()
            
            if any(login_method in service or login_method in method for login_method in login_methods):
                login_events.append({
                    'timestamp': event.get('timestamp'),
                    'ip_address': event.get('caller_ip'),
                    'user_agent': event.get('user_agent'),
                    'method': event.get('method'),
                    'success': 'error' not in event.get('severity', '').lower()
                })
        
        return login_events
    
    def _extract_iam_changes(self, activity_data: List[Dict[str, Any]], user_email: str) -> List[Dict[str, Any]]:
        """Extract IAM-related changes made by the user."""
        iam_changes = []
        
        iam_methods = [
            'setIamPolicy',
            'getIamPolicy',
            'testIamPermissions',
            'createRole',
            'updateRole',
            'deleteRole',
            'createServiceAccount',
            'deleteServiceAccount'
        ]
        
        for event in activity_data:
            method = event.get('method', '')
            
            if any(iam_method in method for iam_method in iam_methods):
                iam_changes.append({
                    'timestamp': event.get('timestamp'),
                    'method': method,
                    'service': event.get('service'),
                    'resource': event.get('resource'),
                    'ip_address': event.get('caller_ip'),
                    'risk_level': self._assess_iam_change_risk(method)
                })
        
        return iam_changes
    
    def _extract_resource_access(self, activity_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract resource access patterns."""
        resource_access = []
        
        # Track various resource access patterns
        resource_methods = [
            'get', 'list', 'create', 'update', 'delete',
            'insert', 'patch', 'start', 'stop'
        ]
        
        for event in activity_data:
            method = event.get('method', '').lower()
            service = event.get('service', '')
            
            if any(res_method in method for res_method in resource_methods):
                resource_access.append({
                    'timestamp': event.get('timestamp'),
                    'service': service,
                    'method': method,
                    'resource_type': event.get('resource'),
                    'ip_address': event.get('caller_ip')
                })
        
        return resource_access
    
    def _calculate_activity_score(self, activity: Dict[str, Any]) -> int:
        """Calculate user activity score (0-100)."""
        score = 0
        summary = activity['summary']
        
        # Base score from login frequency (0-30 points)
        login_count = summary.get('login_count', 0)
        score += min(30, login_count * 2)
        
        # Resource access activity (0-40 points)
        access_count = summary.get('resource_access_count', 0)
        score += min(40, access_count // 10)
        
        # Active days consistency (0-20 points)
        active_days = summary.get('active_days', 0)
        score += min(20, active_days)
        
        # IAM changes (0-10 points, but can be negative for excessive changes)
        iam_changes = summary.get('iam_changes_count', 0)
        if iam_changes > 0:
            if iam_changes <= 5:
                score += min(10, iam_changes * 2)
            else:
                score -= (iam_changes - 5) * 2  # Penalty for excessive IAM changes
        
        return max(0, min(100, score))
    
    def _assess_iam_change_risk(self, method: str) -> str:
        """Assess risk level of IAM changes."""
        high_risk_methods = [
            'setIamPolicy',
            'createRole',
            'updateRole',
            'deleteRole',
            'deleteServiceAccount'
        ]
        
        medium_risk_methods = [
            'createServiceAccount',
            'testIamPermissions'
        ]
        
        if any(risk_method in method for risk_method in high_risk_methods):
            return 'high'
        elif any(risk_method in method for risk_method in medium_risk_methods):
            return 'medium'
        else:
            return 'low'
    
    def _identify_activity_risks(self, activity: Dict[str, Any], user_email: str) -> List[Dict[str, Any]]:
        """Identify potential security risks from user activity."""
        risks = []
        
        # Check for excessive IAM changes
        iam_changes_count = activity['summary'].get('iam_changes_count', 0)
        if iam_changes_count > 10:
            risks.append({
                'type': 'excessive_iam_changes',
                'severity': 'high',
                'description': f'User made {iam_changes_count} IAM changes in the tracking period',
                'recommendation': 'Review IAM changes for necessity and appropriateness'
            })
        
        # Check for unusual login patterns
        login_events = activity.get('login_events', [])
        unique_ips = set(event.get('ip_address', '') for event in login_events if event.get('ip_address'))
        if len(unique_ips) > 5:
            risks.append({
                'type': 'multiple_ip_addresses',
                'severity': 'medium',
                'description': f'Login attempts from {len(unique_ips)} different IP addresses',
                'recommendation': 'Verify login locations and consider IP restrictions'
            })
        
        # Check for failed login attempts
        failed_logins = [event for event in login_events if not event.get('success', True)]
        if len(failed_logins) > 3:
            risks.append({
                'type': 'failed_login_attempts',
                'severity': 'medium',
                'description': f'{len(failed_logins)} failed login attempts detected',
                'recommendation': 'Investigate failed login attempts and consider MFA'
            })
        
        # Check for low activity score
        activity_score = activity.get('activity_score', 0)
        if activity_score < 20:
            risks.append({
                'type': 'low_activity',
                'severity': 'low',
                'description': f'Low activity score ({activity_score}/100) may indicate unused account',
                'recommendation': 'Consider deactivating or removing permissions for inactive accounts'
            })
        
        # Check for external email domains
        if '@gmail.com' in user_email or '@googlemail.com' in user_email:
            risks.append({
                'type': 'external_user',
                'severity': 'medium',
                'description': 'External user account detected',
                'recommendation': 'Verify business need for external access and consider time-limited access'
            })
        
        return risks
    
    def batch_analyze_identities(self, identities: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Perform batch analysis of multiple identities.
        
        Args:
            identities: List of identity email addresses
            
        Returns:
            Dict mapping identity emails to their analysis results
        """
        results = {}
        
        for identity_email in identities:
            logger.info(f"Analyzing identity: {identity_email}")
            
            try:
                # Skip service accounts and groups for some analyses
                identity_obj = Identity.from_member_string(identity_email)
                
                analysis_result = {
                    'identity_type': identity_obj.identity_type.value,
                    'domain': identity_obj.domain,
                    'group_memberships': {},
                    'activity_tracking': {},
                    'risk_assessment': {
                        'overall_risk': 'low',
                        'risk_factors': []
                    }
                }
                
                # Only analyze user accounts for group memberships and activity
                if identity_obj.identity_type == IdentityType.USER:
                    # Resolve group memberships (API calls disabled by default)
                    analysis_result['group_memberships'] = self.resolve_group_memberships(identity_email, enable_api_calls=False)
                    
                    # Track user activity (also disabled by default to avoid Cloud Logging API calls)
                    analysis_result['activity_tracking'] = self._get_minimal_activity_data(identity_email)
                    
                    # Assess overall risk
                    analysis_result['risk_assessment'] = self._assess_identity_risk(
                        analysis_result['group_memberships'],
                        analysis_result['activity_tracking'],
                        identity_obj
                    )
                
                results[identity_email] = analysis_result
                
            except Exception as e:
                logger.error(f"Error analyzing identity {identity_email}: {e}")
                results[identity_email] = {
                    'error': str(e),
                    'identity_type': 'unknown'
                }
        
        return results
    
    def _assess_identity_risk(self, group_data: Dict[str, Any], activity_data: Dict[str, Any], identity: Identity) -> Dict[str, Any]:
        """Assess overall risk for an identity."""
        risk_factors = []
        risk_score = 0
        
        # Group membership risks
        if group_data.get('direct_groups'):
            high_privilege_groups = [
                'admin', 'owner', 'security', 'billing'
            ]
            for group in group_data['direct_groups']:
                group_name = group.get('name', '').lower()
                if any(priv_group in group_name for priv_group in high_privilege_groups):
                    risk_factors.append({
                        'type': 'high_privilege_group',
                        'description': f'Member of high-privilege group: {group["name"]}',
                        'severity': 'high'
                    })
                    risk_score += 30
        
        # Activity risks
        activity_risks = activity_data.get('risk_factors', [])
        for risk in activity_risks:
            risk_factors.append(risk)
            if risk.get('severity') == 'high':
                risk_score += 25
            elif risk.get('severity') == 'medium':
                risk_score += 15
            else:
                risk_score += 5
        
        # Identity type risks
        if identity.identity_type == IdentityType.USER and identity.domain:
            external_domains = ['gmail.com', 'googlemail.com', 'hotmail.com', 'yahoo.com']
            if identity.domain in external_domains:
                risk_factors.append({
                    'type': 'external_domain',
                    'description': f'External email domain: {identity.domain}',
                    'severity': 'medium'
                })
                risk_score += 20
        
        # Determine overall risk level
        if risk_score >= 50:
            overall_risk = 'high'
        elif risk_score >= 25:
            overall_risk = 'medium'
        else:
            overall_risk = 'low'
        
        return {
            'overall_risk': overall_risk,
            'risk_score': risk_score,
            'risk_factors': risk_factors,
            'recommendations': self._generate_risk_recommendations(risk_factors, overall_risk)
        }
    
    def _generate_risk_recommendations(self, risk_factors: List[Dict[str, Any]], overall_risk: str) -> List[str]:
        """Generate recommendations based on identified risks."""
        recommendations = []
        
        # Risk type specific recommendations
        risk_types = [factor.get('type') for factor in risk_factors]
        
        if 'high_privilege_group' in risk_types:
            recommendations.append("Review necessity of high-privilege group memberships")
        
        if 'external_domain' in risk_types:
            recommendations.append("Consider time-limited access for external users")
        
        if 'excessive_iam_changes' in risk_types:
            recommendations.append("Implement approval workflow for IAM changes")
        
        if 'multiple_ip_addresses' in risk_types:
            recommendations.append("Consider IP restrictions or conditional access policies")
        
        if 'low_activity' in risk_types:
            recommendations.append("Review account necessity and consider deactivation")
        
        # Overall risk recommendations
        if overall_risk == 'high':
            recommendations.append("HIGH RISK: Immediate review and remediation required")
            recommendations.append("Consider temporary access suspension pending review")
        elif overall_risk == 'medium':
            recommendations.append("MEDIUM RISK: Schedule review within 30 days")
            recommendations.append("Implement additional monitoring for this identity")
        
        return recommendations
    
    def _get_minimal_activity_data(self, identity_email: str) -> Dict[str, Any]:
        """
        Get minimal activity data without making expensive API calls.
        
        Args:
            identity_email: Identity email address
            
        Returns:
            Dict containing minimal activity information
        """
        return {
            'activity_score': 50,  # Default neutral score
            'summary': {
                'login_count': 0,
                'iam_changes_count': 0,
                'resource_access_count': 0
            },
            'login_events': [],
            'risk_factors': [],
            'note': 'Activity tracking disabled - enable Cloud Logging API calls for detailed analysis'
        }
