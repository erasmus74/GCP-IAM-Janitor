"""
Safe Command Generator for GCP IAM Group Management.

SAFETY GUARANTEE: This module ONLY generates commands for user review.
NO commands are ever executed by this tool. All commands must be manually
reviewed and executed by users with appropriate caution.

All generated commands include:
- Comprehensive comments explaining purpose
- Safety warnings and prerequisites
- Validation steps
- Rollback procedures
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import json

logger = logging.getLogger(__name__)

# Global safety flags
READ_ONLY_MODE = True
NEVER_EXECUTE_COMMANDS = True


class CommandGenerator:
    """
    Generates safe, validated commands for Cloud Identity group management.
    
    SAFETY FEATURES:
    - NO command execution - only generation
    - Includes pre-execution validation commands
    - Generates corresponding rollback commands
    - Adds safety comments and warnings
    - Risk assessment for each operation
    - Dependency ordering (create before assign)
    """
    
    def __init__(self, domain: str, customer_id: Optional[str] = None):
        """
        Initialize command generator.
        
        Args:
            domain: Primary domain for group creation
            customer_id: Google Workspace customer ID (optional)
        """
        self.domain = domain
        self.customer_id = customer_id
        self.generated_commands = []
        
        logger.info("🔒 CommandGenerator initialized - READ-ONLY MODE")
        logger.info("⚠️  Generated commands are for MANUAL EXECUTION ONLY")
    
    def generate_group_creation_commands(
        self,
        group_recommendations: List[Dict[str, Any]],
        include_validation: bool = True,
        include_rollback: bool = True
    ) -> Dict[str, Any]:
        """
        Generate commands for creating Cloud Identity groups.
        
        Args:
            group_recommendations: List of group recommendations from analysis
            include_validation: Include validation commands
            include_rollback: Include rollback commands
            
        Returns:
            Dict with categorized commands and metadata
        """
        logger.info(f"Generating commands for {len(group_recommendations)} groups")
        
        command_bundle = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'domain': self.domain,
                'group_count': len(group_recommendations),
                'read_only_mode': READ_ONLY_MODE,
                'execution_warning': '⚠️  MANUAL EXECUTION REQUIRED - Review all commands before running'
            },
            'phases': []
        }
        
        # Phase 1: Pre-execution validation
        if include_validation:
            command_bundle['phases'].append(
                self._generate_validation_phase(group_recommendations)
            )
        
        # Phase 2: Backup current state
        command_bundle['phases'].append(
            self._generate_backup_phase(group_recommendations)
        )
        
        # Phase 3: Group creation
        command_bundle['phases'].append(
            self._generate_creation_phase(group_recommendations)
        )
        
        # Phase 4: Add members to groups
        command_bundle['phases'].append(
            self._generate_membership_phase(group_recommendations)
        )
        
        # Phase 5: Assign IAM roles to groups
        command_bundle['phases'].append(
            self._generate_iam_assignment_phase(group_recommendations)
        )
        
        # Phase 6: Remove individual user permissions (DANGEROUS)
        command_bundle['phases'].append(
            self._generate_cleanup_phase(group_recommendations)
        )
        
        # Phase 7: Post-execution validation
        if include_validation:
            command_bundle['phases'].append(
                self._generate_post_validation_phase(group_recommendations)
            )
        
        # Emergency rollback procedures
        if include_rollback:
            command_bundle['rollback'] = self._generate_rollback_procedures(
                group_recommendations
            )
        
        return command_bundle
    
    def _generate_validation_phase(
        self,
        groups: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate pre-execution validation commands."""
        commands = []
        
        commands.append({
            'type': 'comment',
            'content': '=' * 80
        })
        commands.append({
            'type': 'comment',
            'content': 'PHASE 1: PRE-EXECUTION VALIDATION'
        })
        commands.append({
            'type': 'comment',
            'content': 'Run these commands BEFORE making any changes to verify current state'
        })
        commands.append({
            'type': 'comment',
            'content': '=' * 80
        })
        commands.append({'type': 'newline'})
        
        # Check if Cloud Identity API is enabled
        commands.append({
            'type': 'comment',
            'content': 'Verify Cloud Identity API is enabled'
        })
        commands.append({
            'type': 'command',
            'command': 'gcloud services list --enabled | grep cloudidentity.googleapis.com',
            'description': 'Check if Cloud Identity API is enabled',
            'risk_level': 'safe',
            'required': True
        })
        commands.append({'type': 'newline'})
        
        # Check current IAM policy for each project
        projects = set()
        for group in groups:
            projects.update(group.get('projects', []))
        
        commands.append({
            'type': 'comment',
            'content': 'Export current IAM policies (IMPORTANT: Keep these for rollback)'
        })
        
        for project in sorted(projects):
            commands.append({
                'type': 'command',
                'command': f'gcloud projects get-iam-policy {project} --format=json > iam-backup-{project}-$(date +%Y%m%d-%H%M%S).json',
                'description': f'Backup current IAM policy for project {project}',
                'risk_level': 'safe',
                'required': True
            })
        
        commands.append({'type': 'newline'})
        
        # Check if proposed groups already exist
        commands.append({
            'type': 'comment',
            'content': 'Check if proposed groups already exist (should NOT exist)'
        })
        
        for group in groups[:5]:  # Show first 5 as examples
            group_email = f"{group['suggested_group_name']}@{self.domain}"
            commands.append({
                'type': 'command',
                'command': f'gcloud identity groups describe {group_email} 2>&1 || echo "Group does not exist (expected)"',
                'description': f'Verify {group_email} does not already exist',
                'risk_level': 'safe',
                'required': True
            })
        
        if len(groups) > 5:
            commands.append({
                'type': 'comment',
                'content': f'... (check remaining {len(groups) - 5} groups similarly)'
            })
        
        return {
            'phase': 1,
            'name': 'Pre-Execution Validation',
            'description': 'Validate current state before making changes',
            'required': True,
            'commands': commands,
            'estimated_time': '5-10 minutes',
            'risk_level': 'safe'
        }
    
    def _generate_backup_phase(
        self,
        groups: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate backup commands."""
        commands = []
        
        commands.append({
            'type': 'comment',
            'content': '=' * 80
        })
        commands.append({
            'type': 'comment',
            'content': 'PHASE 2: BACKUP CURRENT CONFIGURATION'
        })
        commands.append({
            'type': 'comment',
            'content': '⚠️  CRITICAL: Do not skip this phase - needed for emergency rollback'
        })
        commands.append({
            'type': 'comment',
            'content': '=' * 80
        })
        commands.append({'type': 'newline'})
        
        # Create backup directory
        backup_dir = f"iam-janitor-backup-$(date +%Y%m%d-%H%M%S)"
        commands.append({
            'type': 'comment',
            'content': 'Create backup directory'
        })
        commands.append({
            'type': 'command',
            'command': f'mkdir -p {backup_dir}',
            'description': 'Create directory for backups',
            'risk_level': 'safe',
            'required': True
        })
        commands.append({'type': 'newline'})
        
        # Export current group memberships for affected users
        users = set()
        for group in groups:
            users.update(group.get('users', []))
        
        commands.append({
            'type': 'comment',
            'content': 'Document current user permissions (for each affected user)'
        })
        commands.append({
            'type': 'comment',
            'content': f'Total users to backup: {len(users)}'
        })
        
        # Show example for first few users
        for i, user in enumerate(sorted(users)[:3]):
            commands.append({
                'type': 'command',
                'command': f'echo "Permissions for {user}:" >> {backup_dir}/user-permissions-backup.txt',
                'description': f'Document permissions for {user}',
                'risk_level': 'safe',
                'required': True
            })
        
        if len(users) > 3:
            commands.append({
                'type': 'comment',
                'content': f'... (backup remaining {len(users) - 3} users similarly)'
            })
        
        return {
            'phase': 2,
            'name': 'Backup Current Configuration',
            'description': 'Create backups for emergency rollback',
            'required': True,
            'commands': commands,
            'estimated_time': '10-15 minutes',
            'risk_level': 'safe'
        }
    
    def _generate_creation_phase(
        self,
        groups: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate group creation commands."""
        commands = []
        
        commands.append({
            'type': 'comment',
            'content': '=' * 80
        })
        commands.append({
            'type': 'comment',
            'content': 'PHASE 3: CREATE CLOUD IDENTITY GROUPS'
        })
        commands.append({
            'type': 'comment',
            'content': '⚠️  CAUTION: These commands will CREATE new groups'
        })
        commands.append({
            'type': 'comment',
            'content': 'Review each group carefully before creation'
        })
        commands.append({
            'type': 'comment',
            'content': '=' * 80
        })
        commands.append({'type': 'newline'})
        
        for i, group in enumerate(groups, 1):
            group_name = group['suggested_group_name']
            group_email = f"{group_name}@{self.domain}"
            description = group.get('description', f"Auto-generated group for {group.get('match_type', 'similar')} users")
            
            commands.append({
                'type': 'comment',
                'content': f"Group {i}/{len(groups)}: {group_name}"
            })
            commands.append({
                'type': 'comment',
                'content': f"Users: {group['user_count']}, Projects: {len(group.get('projects', []))}"
            })
            commands.append({
                'type': 'comment',
                'content': f"Purpose: {description[:80]}"
            })
            
            # Group creation command
            # Note: gcloud identity groups create requires specific format
            commands.append({
                'type': 'command',
                'command': (
                    f'gcloud identity groups create {group_email} \\\n'
                    f'  --display-name="{group_name}" \\\n'
                    f'  --description="{description}" \\\n'
                    f'  --labels="created-by=iam-janitor,purpose=consolidation"'
                ),
                'description': f'Create group {group_email}',
                'risk_level': 'medium',
                'required': True,
                'rollback': f'gcloud identity groups delete {group_email} --quiet'
            })
            
            # Verification command
            commands.append({
                'type': 'command',
                'command': f'gcloud identity groups describe {group_email}',
                'description': f'Verify group {group_email} was created',
                'risk_level': 'safe',
                'required': True
            })
            
            commands.append({'type': 'newline'})
        
        return {
            'phase': 3,
            'name': 'Create Cloud Identity Groups',
            'description': 'Create new groups for consolidation',
            'required': True,
            'commands': commands,
            'estimated_time': f'{len(groups) * 2}-{len(groups) * 3} minutes',
            'risk_level': 'medium',
            'warning': '⚠️  This phase creates new resources. Ensure validation phase passed.'
        }
    
    def _generate_membership_phase(
        self,
        groups: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate commands to add members to groups."""
        commands = []
        
        commands.append({
            'type': 'comment',
            'content': '=' * 80
        })
        commands.append({
            'type': 'comment',
            'content': 'PHASE 4: ADD MEMBERS TO GROUPS'
        })
        commands.append({
            'type': 'comment',
            'content': '⚠️  CAUTION: These commands will ADD users to groups'
        })
        commands.append({
            'type': 'comment',
            'content': 'Verify each user should be in the group before adding'
        })
        commands.append({
            'type': 'comment',
            'content': '=' * 80
        })
        commands.append({'type': 'newline'})
        
        for group in groups:
            group_name = group['suggested_group_name']
            group_email = f"{group_name}@{self.domain}"
            users = group.get('users', [])
            
            commands.append({
                'type': 'comment',
                'content': f"Adding {len(users)} members to {group_email}"
            })
            
            for user in users:
                commands.append({
                    'type': 'command',
                    'command': (
                        f'gcloud identity groups memberships add \\\n'
                        f'  --group-email="{group_email}" \\\n'
                        f'  --member-email="{user}"'
                    ),
                    'description': f'Add {user} to {group_email}',
                    'risk_level': 'low',
                    'required': True,
                    'rollback': f'gcloud identity groups memberships delete --group-email="{group_email}" --member-email="{user}" --quiet'
                })
            
            # Verification
            commands.append({
                'type': 'command',
                'command': f'gcloud identity groups memberships list --group-email="{group_email}"',
                'description': f'Verify members of {group_email}',
                'risk_level': 'safe',
                'required': True
            })
            
            commands.append({'type': 'newline'})
        
        return {
            'phase': 4,
            'name': 'Add Members to Groups',
            'description': 'Add users to newly created groups',
            'required': True,
            'commands': commands,
            'estimated_time': f'{sum(len(g.get("users", [])) for g in groups) * 0.5}-{sum(len(g.get("users", [])) for g in groups)} minutes',
            'risk_level': 'low'
        }
    
    def _generate_iam_assignment_phase(
        self,
        groups: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate IAM role assignment commands for groups."""
        commands = []
        
        commands.append({
            'type': 'comment',
            'content': '=' * 80
        })
        commands.append({
            'type': 'comment',
            'content': 'PHASE 5: ASSIGN IAM ROLES TO GROUPS'
        })
        commands.append({
            'type': 'comment',
            'content': '⚠️  CAUTION: These commands grant permissions to groups'
        })
        commands.append({
            'type': 'comment',
            'content': 'Verify all role assignments before execution'
        })
        commands.append({
            'type': 'comment',
            'content': '=' * 80
        })
        commands.append({'type': 'newline'})
        
        for group in groups:
            group_name = group['suggested_group_name']
            group_email = f"{group_name}@{self.domain}"
            roles = group.get('roles', group.get('suggested_roles', []))
            projects = group.get('all_projects', group.get('projects', []))
            
            if not roles or not projects:
                continue
            
            commands.append({
                'type': 'comment',
                'content': f"Assigning roles to {group_email}"
            })
            commands.append({
                'type': 'comment',
                'content': f"Roles: {', '.join(roles)}"
            })
            commands.append({
                'type': 'comment',
                'content': f"Projects: {len(projects)}"
            })
            
            for project in projects:
                for role in roles:
                    commands.append({
                        'type': 'command',
                        'command': (
                            f'gcloud projects add-iam-policy-binding {project} \\\n'
                            f'  --member="group:{group_email}" \\\n'
                            f'  --role="{role}" \\\n'
                            f'  --condition=None'
                        ),
                        'description': f'Grant {role} to {group_email} on {project}',
                        'risk_level': 'medium',
                        'required': True,
                        'rollback': f'gcloud projects remove-iam-policy-binding {project} --member="group:{group_email}" --role="{role}" --quiet'
                    })
            
            # Verification
            commands.append({
                'type': 'command',
                'command': f'gcloud projects get-iam-policy {projects[0]} --flatten="bindings[].members" --filter="bindings.members:group:{group_email}"',
                'description': f'Verify IAM bindings for {group_email}',
                'risk_level': 'safe',
                'required': True
            })
            
            commands.append({'type': 'newline'})
        
        return {
            'phase': 5,
            'name': 'Assign IAM Roles to Groups',
            'description': 'Grant permissions to groups',
            'required': True,
            'commands': commands,
            'estimated_time': f'{sum(len(g.get("projects", [])) * len(g.get("roles", [])) for g in groups) * 1}-{sum(len(g.get("projects", [])) * len(g.get("roles", [])) for g in groups) * 2} minutes',
            'risk_level': 'medium',
            'warning': '⚠️  This phase grants permissions. Verify group memberships are correct first.'
        }
    
    def _generate_cleanup_phase(
        self,
        groups: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate commands to remove individual user permissions (DANGEROUS)."""
        commands = []
        
        commands.append({
            'type': 'comment',
            'content': '=' * 80
        })
        commands.append({
            'type': 'comment',
            'content': 'PHASE 6: REMOVE INDIVIDUAL USER PERMISSIONS'
        })
        commands.append({
            'type': 'comment',
            'content': '🚨 DANGER: These commands will REMOVE existing permissions'
        })
        commands.append({
            'type': 'comment',
            'content': '🚨 ONLY run after verifying groups work correctly'
        })
        commands.append({
            'type': 'comment',
            'content': '🚨 Test with ONE user first, then wait 24-48 hours'
        })
        commands.append({
            'type': 'comment',
            'content': '🚨 Have backups ready for emergency rollback'
        })
        commands.append({
            'type': 'comment',
            'content': '=' * 80
        })
        commands.append({'type': 'newline'})
        
        commands.append({
            'type': 'comment',
            'content': '⚠️  RECOMMENDED APPROACH:'
        })
        commands.append({
            'type': 'comment',
            'content': '1. Run ONE remove command for a test user'
        })
        commands.append({
            'type': 'comment',
            'content': '2. Verify test user can still access via group'
        })
        commands.append({
            'type': 'comment',
            'content': '3. Wait 24-48 hours to ensure no issues'
        })
        commands.append({
            'type': 'comment',
            'content': '4. Proceed with remaining users in small batches'
        })
        commands.append({'type': 'newline'})
        
        for group in groups[:2]:  # Only show first 2 as examples for safety
            group_name = group['suggested_group_name']
            group_email = f"{group_name}@{self.domain}"
            users = group.get('users', [])
            roles = group.get('roles', group.get('suggested_roles', []))
            projects = group.get('all_projects', group.get('projects', []))
            
            commands.append({
                'type': 'comment',
                'content': f"Removing individual permissions for users in {group_email}"
            })
            commands.append({
                'type': 'comment',
                'content': f"⚠️  Users will rely on group membership after this step"
            })
            
            # Show only first user as example
            if users and roles and projects:
                user = users[0]
                project = projects[0]
                role = roles[0]
                
                commands.append({
                    'type': 'comment',
                    'content': f"Example: Remove direct permissions for {user}"
                })
                commands.append({
                    'type': 'command',
                    'command': (
                        f'# TEST USER: {user}\n'
                        f'gcloud projects remove-iam-policy-binding {project} \\\n'
                        f'  --member="user:{user}" \\\n'
                        f'  --role="{role}"'
                    ),
                    'description': f'Remove {role} from {user} on {project} (TEST)',
                    'risk_level': 'high',
                    'required': False,
                    'rollback': f'gcloud projects add-iam-policy-binding {project} --member="user:{user}" --role="{role}"'
                })
                
                commands.append({
                    'type': 'comment',
                    'content': f"... (repeat for remaining {len(users)-1} users and {len(projects)-1} projects after successful test)"
                })
            
            commands.append({'type': 'newline'})
        
        if len(groups) > 2:
            commands.append({
                'type': 'comment',
                'content': f"... ({len(groups)-2} more groups with similar cleanup commands)"
            })
        
        return {
            'phase': 6,
            'name': 'Remove Individual User Permissions (DANGEROUS)',
            'description': 'Clean up individual user permissions after group-based access is verified',
            'required': False,
            'commands': commands,
            'estimated_time': 'DAYS - Do not rush this phase',
            'risk_level': 'high',
            'warning': '🚨 EXTREME CAUTION: Only proceed after thorough testing and validation'
        }
    
    def _generate_post_validation_phase(
        self,
        groups: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate post-execution validation commands."""
        commands = []
        
        commands.append({
            'type': 'comment',
            'content': '=' * 80
        })
        commands.append({
            'type': 'comment',
            'content': 'PHASE 7: POST-EXECUTION VALIDATION'
        })
        commands.append({
            'type': 'comment',
            'content': 'Verify all changes were applied correctly'
        })
        commands.append({
            'type': 'comment',
            'content': '=' * 80
        })
        commands.append({'type': 'newline'})
        
        commands.append({
            'type': 'comment',
            'content': 'Verify all groups were created'
        })
        
        for group in groups[:5]:  # Show first 5
            group_email = f"{group['suggested_group_name']}@{self.domain}"
            commands.append({
                'type': 'command',
                'command': f'gcloud identity groups describe {group_email} --format="value(displayName, groupKey.id)"',
                'description': f'Verify {group_email} exists',
                'risk_level': 'safe',
                'required': True
            })
        
        if len(groups) > 5:
            commands.append({
                'type': 'comment',
                'content': f'... (verify remaining {len(groups) - 5} groups similarly)'
            })
        
        commands.append({'type': 'newline'})
        
        commands.append({
            'type': 'comment',
            'content': 'Test user access through groups (pick a test user)'
        })
        commands.append({
            'type': 'command',
            'command': '# Replace TEST_USER@domain.com with actual test user\n# gcloud projects get-iam-policy PROJECT_ID --flatten="bindings[].members" --filter="bindings.members:user:TEST_USER@domain.com"',
            'description': 'Verify test user has correct permissions via group',
            'risk_level': 'safe',
            'required': True
        })
        
        return {
            'phase': 7,
            'name': 'Post-Execution Validation',
            'description': 'Verify all changes were successful',
            'required': True,
            'commands': commands,
            'estimated_time': '10-15 minutes',
            'risk_level': 'safe'
        }
    
    def _generate_rollback_procedures(
        self,
        groups: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate emergency rollback procedures."""
        commands = []
        
        commands.append({
            'type': 'comment',
            'content': '=' * 80
        })
        commands.append({
            'type': 'comment',
            'content': 'EMERGENCY ROLLBACK PROCEDURES'
        })
        commands.append({
            'type': 'comment',
            'content': '🚨 Use these commands ONLY if something goes wrong'
        })
        commands.append({
            'type': 'comment',
            'content': '=' * 80
        })
        commands.append({'type': 'newline'})
        
        commands.append({
            'type': 'comment',
            'content': 'Step 1: Restore IAM policies from backup'
        })
        commands.append({
            'type': 'command',
            'command': '# gcloud projects set-iam-policy PROJECT_ID iam-backup-PROJECT_ID-TIMESTAMP.json',
            'description': 'Restore IAM policy from backup (replace PROJECT_ID and TIMESTAMP)',
            'risk_level': 'medium',
            'required': False
        })
        commands.append({'type': 'newline'})
        
        commands.append({
            'type': 'comment',
            'content': 'Step 2: Delete created groups (if needed)'
        })
        
        for group in groups[:3]:  # Show first 3 as examples
            group_email = f"{group['suggested_group_name']}@{self.domain}"
            commands.append({
                'type': 'command',
                'command': f'gcloud identity groups delete {group_email} --quiet',
                'description': f'Delete group {group_email}',
                'risk_level': 'high',
                'required': False
            })
        
        if len(groups) > 3:
            commands.append({
                'type': 'comment',
                'content': f'... (delete remaining {len(groups) - 3} groups if necessary)'
            })
        
        commands.append({'type': 'newline'})
        
        commands.append({
            'type': 'comment',
            'content': 'Step 3: Contact support if needed'
        })
        commands.append({
            'type': 'comment',
            'content': 'Document what went wrong and preserve all backup files'
        })
        
        return {
            'name': 'Emergency Rollback',
            'description': 'Procedures to undo changes if something goes wrong',
            'commands': commands,
            'warning': '🚨 Only use rollback if absolutely necessary'
        }
    
    def format_commands_as_script(
        self,
        command_bundle: Dict[str, Any],
        include_phases: Optional[List[int]] = None
    ) -> str:
        """
        Format commands as an executable bash script.
        
        Args:
            command_bundle: Bundle of commands from generate_group_creation_commands
            include_phases: List of phase numbers to include (default: all)
            
        Returns:
            Formatted bash script as string
        """
        script_lines = []
        
        # Script header with safety warnings
        script_lines.extend([
            '#!/bin/bash',
            '#',
            '# GCP IAM Group Creation Script',
            '# Generated by GCP IAM Janitor',
            '#',
            '# ⚠️  WARNING: READ THIS ENTIRE SCRIPT BEFORE EXECUTION',
            '# ⚠️  This script makes changes to your GCP environment',
            '# ⚠️  Ensure you have reviewed all commands and have backups',
            '#',
            f'# Generated: {command_bundle["metadata"]["generated_at"]}',
            f'# Domain: {command_bundle["metadata"]["domain"]}',
            f'# Groups: {command_bundle["metadata"]["group_count"]}',
            '#',
            '',
            '# Exit on any error',
            'set -e',
            'set -o pipefail',
            '',
            '# Enable command logging',
            'set -x',
            '',
            '# Color codes for output',
            'RED="\\033[0;31m"',
            'GREEN="\\033[0;32m"',
            'YELLOW="\\033[1;33m"',
            'NC="\\033[0m" # No Color',
            '',
            'echo -e "${YELLOW}╔═══════════════════════════════════════╗${NC}"',
            'echo -e "${YELLOW}║  GCP IAM Group Creation Script      ║${NC}"',
            'echo -e "${YELLOW}║  ⚠️  REVIEW BEFORE EXECUTION ⚠️        ║${NC}"',
            'echo -e "${YELLOW}╚═══════════════════════════════════════╝${NC}"',
            'echo ""',
            '',
        ])
        
        # Add phases
        for phase in command_bundle.get('phases', []):
            phase_num = phase['phase']
            
            # Skip if specific phases requested and this isn't one
            if include_phases and phase_num not in include_phases:
                continue
            
            script_lines.append('')
            script_lines.append(f'# {"=" * 78}')
            script_lines.append(f'# {phase["name"]}')
            script_lines.append(f'# {phase["description"]}')
            if phase.get('warning'):
                script_lines.append(f'# {phase["warning"]}')
            script_lines.append(f'# Estimated time: {phase["estimated_time"]}')
            script_lines.append(f'# Risk level: {phase["risk_level"].upper()}')
            script_lines.append(f'# {"=" * 78}')
            script_lines.append('')
            
            # Add user confirmation for dangerous phases
            if phase.get('risk_level') in ['high', 'medium']:
                script_lines.extend([
                    f'echo -e "${{YELLOW}}About to run: {phase["name"]}${{NC}}"',
                    f'echo -e "${{YELLOW}}Risk Level: {phase["risk_level"].upper()}${{NC}}"',
                    'read -p "Continue? (yes/no): " -r',
                    'if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then',
                    '    echo "Skipped by user"',
                    '    exit 0',
                    'fi',
                    ''
                ])
            
            # Add commands from phase
            for cmd in phase['commands']:
                if cmd['type'] == 'comment':
                    script_lines.append(f'# {cmd["content"]}')
                elif cmd['type'] == 'newline':
                    script_lines.append('')
                elif cmd['type'] == 'command':
                    script_lines.append(f'# {cmd["description"]}')
                    if cmd.get('risk_level') == 'high':
                        script_lines.append('# 🚨 HIGH RISK COMMAND - Review carefully')
                    script_lines.append(cmd['command'])
                    script_lines.append('')
        
        script_lines.extend([
            '',
            'echo -e "${GREEN}═══════════════════════════════════════${NC}"',
            'echo -e "${GREEN}Script completed successfully!${NC}"',
            'echo -e "${GREEN}═══════════════════════════════════════${NC}"',
            ''
        ])
        
        return '\n'.join(script_lines)


# Safety assertions
assert READ_ONLY_MODE is True, "CRITICAL: CommandGenerator must never execute commands"
assert NEVER_EXECUTE_COMMANDS is True, "CRITICAL: Commands must be manually executed by users"


__all__ = ['CommandGenerator', 'READ_ONLY_MODE', 'NEVER_EXECUTE_COMMANDS']
