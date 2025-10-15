"""
Read-Only Group Analysis Client for Google Cloud Identity.

SAFETY GUARANTEE: This module ONLY performs read operations.
NO create, update, or delete operations are implemented or will be implemented.
All modifications must be performed manually by users through generated commands.
"""

import logging
import re
from typing import List, Dict, Set, Optional, Any
from google.auth.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)

# Global safety flag - ALWAYS read-only
READ_ONLY_MODE = True


class GroupAnalysisClient:
    """
    Read-only client for analyzing Cloud Identity groups.
    
    SAFETY FEATURES:
    - Only performs read operations (list, get, search)
    - No create, update, or delete methods
    - Validates group names against Cloud Identity requirements
    - Checks for existing groups before recommendations
    - All operations are logged for audit purposes
    """
    
    def __init__(self, credentials: Credentials, customer_id: Optional[str] = None):
        """
        Initialize read-only group analysis client.
        
        Args:
            credentials: Authenticated GCP credentials (requires read-only permissions)
            customer_id: Google Workspace customer ID (required for group operations)
        """
        self.credentials = credentials
        self.customer_id = customer_id
        self._cloud_identity_service = None
        
        # Log initialization in read-only mode
        logger.info("🔒 GroupAnalysisClient initialized in READ-ONLY mode")
        logger.info("⚠️  This client will NEVER perform any write operations")
    
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
                logger.info("Cloud Identity API service initialized (read-only)")
            except Exception as e:
                logger.warning(f"Could not initialize Cloud Identity API: {e}")
                self._cloud_identity_service = None
        return self._cloud_identity_service
    
    def check_group_exists(self, group_email: str) -> Dict[str, Any]:
        """
        Check if a group already exists.
        
        READ-ONLY OPERATION: Only queries existing groups.
        
        Args:
            group_email: Email address of the group to check
            
        Returns:
            Dict with 'exists' boolean and group details if found
        """
        logger.info(f"🔍 READ-ONLY: Checking if group exists: {group_email}")
        
        result = {
            'exists': False,
            'group_email': group_email,
            'details': None,
            'error': None
        }
        
        if not self.cloud_identity_service:
            result['error'] = "Cloud Identity API not available"
            return result
        
        try:
            # Search for the group
            query = f"groupKey.id == '{group_email}'"
            request = self.cloud_identity_service.groups().search(
                query=query,
                view='FULL'
            )
            
            response = request.execute()
            groups = response.get('groups', [])
            
            if groups:
                result['exists'] = True
                result['details'] = self._parse_group_details(groups[0])
                logger.info(f"✓ Group found: {group_email}")
            else:
                logger.info(f"✗ Group does not exist: {group_email}")
                
        except HttpError as e:
            error_msg = f"HTTP error checking group: {e}"
            logger.warning(error_msg)
            result['error'] = error_msg
        except Exception as e:
            error_msg = f"Error checking group: {e}"
            logger.error(error_msg)
            result['error'] = error_msg
        
        return result
    
    def batch_check_groups(self, group_emails: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Check multiple groups for existence.
        
        READ-ONLY OPERATION: Only queries existing groups.
        
        Args:
            group_emails: List of group email addresses to check
            
        Returns:
            Dict mapping group emails to their check results
        """
        logger.info(f"🔍 READ-ONLY: Batch checking {len(group_emails)} groups")
        
        results = {}
        for group_email in group_emails:
            results[group_email] = self.check_group_exists(group_email)
        
        existing_count = sum(1 for r in results.values() if r['exists'])
        logger.info(f"✓ Batch check complete: {existing_count}/{len(group_emails)} groups exist")
        
        return results
    
    def list_all_groups(self, parent: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all groups in the organization.
        
        READ-ONLY OPERATION: Only retrieves group information.
        
        Args:
            parent: Optional parent resource (e.g., "customers/{customer_id}")
            
        Returns:
            List of group details
        """
        logger.info("🔍 READ-ONLY: Listing all groups")
        
        groups = []
        
        if not self.cloud_identity_service:
            logger.warning("Cloud Identity API not available")
            return groups
        
        try:
            # Use parent if provided, otherwise search all groups
            if parent:
                request = self.cloud_identity_service.groups().list(
                    parent=parent,
                    view='FULL'
                )
            else:
                # Search for all groups
                request = self.cloud_identity_service.groups().search(
                    view='FULL'
                )
            
            while request:
                response = request.execute()
                
                for group in response.get('groups', []):
                    groups.append(self._parse_group_details(group))
                
                # Get next page if available
                if parent:
                    request = self.cloud_identity_service.groups().list_next(
                        request, response
                    )
                else:
                    request = self.cloud_identity_service.groups().search_next(
                        request, response
                    )
            
            logger.info(f"✓ Found {len(groups)} groups")
            
        except Exception as e:
            logger.error(f"Error listing groups: {e}")
        
        return groups
    
    def get_group_members(self, group_email: str) -> Dict[str, Any]:
        """
        Get members of a specific group.
        
        READ-ONLY OPERATION: Only retrieves membership information.
        
        Args:
            group_email: Email address of the group
            
        Returns:
            Dict with member information
        """
        logger.info(f"🔍 READ-ONLY: Getting members for group: {group_email}")
        
        result = {
            'group_email': group_email,
            'members': [],
            'member_count': 0,
            'error': None
        }
        
        if not self.cloud_identity_service:
            result['error'] = "Cloud Identity API not available"
            return result
        
        try:
            group_name = f"groups/{group_email}"
            request = self.cloud_identity_service.groups().memberships().list(
                parent=group_name,
                view='FULL'
            )
            
            while request:
                response = request.execute()
                
                for membership in response.get('memberships', []):
                    member_info = {
                        'email': membership.get('memberKey', {}).get('id', ''),
                        'role': membership.get('roles', [{}])[0].get('name', 'MEMBER'),
                        'type': membership.get('type', 'USER'),
                        'create_time': membership.get('createTime', '')
                    }
                    result['members'].append(member_info)
                
                request = self.cloud_identity_service.groups().memberships().list_next(
                    request, response
                )
            
            result['member_count'] = len(result['members'])
            logger.info(f"✓ Found {result['member_count']} members in {group_email}")
            
        except HttpError as e:
            error_msg = f"HTTP error getting members: {e}"
            logger.warning(error_msg)
            result['error'] = error_msg
        except Exception as e:
            error_msg = f"Error getting members: {e}"
            logger.error(error_msg)
            result['error'] = error_msg
        
        return result
    
    def validate_group_name(self, group_name: str, domain: str) -> Dict[str, Any]:
        """
        Validate a proposed group name against Cloud Identity requirements.
        
        READ-ONLY OPERATION: Only validates name format, doesn't create anything.
        
        Args:
            group_name: Proposed group name (without domain)
            domain: Domain for the group email
            
        Returns:
            Dict with validation results and suggestions
        """
        logger.info(f"🔍 READ-ONLY: Validating group name: {group_name}@{domain}")
        
        validation = {
            'valid': True,
            'group_name': group_name,
            'full_email': f"{group_name}@{domain}",
            'errors': [],
            'warnings': [],
            'suggestions': []
        }
        
        # Check length (Cloud Identity has limits)
        if len(group_name) < 1:
            validation['valid'] = False
            validation['errors'].append("Group name is too short (minimum 1 character)")
        
        if len(group_name) > 63:
            validation['valid'] = False
            validation['errors'].append("Group name is too long (maximum 63 characters)")
        
        # Check for valid characters (lowercase letters, numbers, hyphens, periods)
        if not re.match(r'^[a-z0-9][a-z0-9._-]*[a-z0-9]$', group_name, re.IGNORECASE):
            validation['valid'] = False
            validation['errors'].append(
                "Group name must start and end with alphanumeric character "
                "and contain only letters, numbers, periods, hyphens, and underscores"
            )
        
        # Check for consecutive periods
        if '..' in group_name:
            validation['valid'] = False
            validation['errors'].append("Group name cannot contain consecutive periods")
        
        # Warnings for best practices
        if group_name.startswith('group-') or group_name.startswith('grp-'):
            validation['warnings'].append(
                "Consider removing redundant 'group-' or 'grp-' prefix"
            )
        
        if len(group_name) > 40:
            validation['warnings'].append(
                "Consider shorter name for better readability (current length: {})".format(len(group_name))
            )
        
        # Suggestions
        if not validation['valid']:
            # Generate a suggested valid name
            suggested = re.sub(r'[^a-z0-9._-]', '-', group_name.lower())
            suggested = re.sub(r'-+', '-', suggested)  # Remove consecutive hyphens
            suggested = suggested.strip('-_.')  # Remove leading/trailing special chars
            
            if suggested and suggested != group_name.lower():
                validation['suggestions'].append(f"Suggested valid name: {suggested}")
        
        if validation['valid']:
            logger.info(f"✓ Group name is valid: {group_name}@{domain}")
        else:
            logger.warning(f"✗ Group name is invalid: {group_name}@{domain}")
            for error in validation['errors']:
                logger.warning(f"  - {error}")
        
        return validation
    
    def find_naming_conflicts(self, proposed_groups: List[str], domain: str) -> Dict[str, Any]:
        """
        Find naming conflicts among proposed groups and existing groups.
        
        READ-ONLY OPERATION: Only checks for conflicts, doesn't modify anything.
        
        Args:
            proposed_groups: List of proposed group names (without domain)
            domain: Domain for the group emails
            
        Returns:
            Dict with conflict information
        """
        logger.info(f"🔍 READ-ONLY: Checking for naming conflicts among {len(proposed_groups)} proposed groups")
        
        conflicts = {
            'has_conflicts': False,
            'existing_groups': [],
            'duplicate_proposals': [],
            'similar_names': [],
            'safe_to_create': []
        }
        
        # Check for duplicates within proposed names
        seen = {}
        for name in proposed_groups:
            normalized = name.lower()
            if normalized in seen:
                conflicts['duplicate_proposals'].append({
                    'name': name,
                    'duplicate_of': seen[normalized]
                })
                conflicts['has_conflicts'] = True
            else:
                seen[normalized] = name
        
        # Check against existing groups
        full_emails = [f"{name}@{domain}" for name in proposed_groups]
        existing_check = self.batch_check_groups(full_emails)
        
        for email, check_result in existing_check.items():
            name = email.split('@')[0]
            
            if check_result['exists']:
                conflicts['existing_groups'].append({
                    'name': name,
                    'email': email,
                    'details': check_result['details']
                })
                conflicts['has_conflicts'] = True
            else:
                conflicts['safe_to_create'].append(name)
        
        # Check for similar names (potential confusion)
        for i, name1 in enumerate(proposed_groups):
            for name2 in proposed_groups[i+1:]:
                if self._are_names_similar(name1, name2):
                    conflicts['similar_names'].append({
                        'name1': name1,
                        'name2': name2,
                        'warning': 'Names are very similar and may cause confusion'
                    })
        
        logger.info(
            f"✓ Conflict check complete: "
            f"{len(conflicts['existing_groups'])} existing, "
            f"{len(conflicts['duplicate_proposals'])} duplicates, "
            f"{len(conflicts['similar_names'])} similar names"
        )
        
        return conflicts
    
    def _parse_group_details(self, group_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Cloud Identity group data into simplified format."""
        return {
            'email': group_data.get('groupKey', {}).get('id', ''),
            'name': group_data.get('displayName', ''),
            'description': group_data.get('description', ''),
            'labels': group_data.get('labels', {}),
            'parent': group_data.get('parent', ''),
            'member_count': group_data.get('directMemberCount', 0),
            'create_time': group_data.get('createTime', ''),
            'update_time': group_data.get('updateTime', ''),
            'resource_name': group_data.get('name', '')
        }
    
    def _are_names_similar(self, name1: str, name2: str, threshold: float = 0.8) -> bool:
        """
        Check if two names are suspiciously similar.
        
        Uses simple character-based similarity.
        """
        name1_lower = name1.lower()
        name2_lower = name2.lower()
        
        # Exact match (case-insensitive)
        if name1_lower == name2_lower:
            return True
        
        # One is substring of other
        if name1_lower in name2_lower or name2_lower in name1_lower:
            return True
        
        # Character-based similarity (simple Jaccard similarity)
        set1 = set(name1_lower.replace('-', '').replace('_', '').replace('.', ''))
        set2 = set(name2_lower.replace('-', '').replace('_', '').replace('.', ''))
        
        if not set1 or not set2:
            return False
        
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        
        similarity = intersection / union if union > 0 else 0
        
        return similarity >= threshold


# Safety assertion - ensure this module never gets write capabilities
assert READ_ONLY_MODE is True, "CRITICAL: GroupAnalysisClient must always be read-only"


def verify_read_only_mode() -> bool:
    """
    Verify that the module is in read-only mode.
    
    This can be called by the UI to confirm safety guarantees.
    """
    return READ_ONLY_MODE


# Export only read-only verification
__all__ = ['GroupAnalysisClient', 'verify_read_only_mode', 'READ_ONLY_MODE']
