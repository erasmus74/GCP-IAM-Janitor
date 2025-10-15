"""
Advanced analytics and insights for GCP IAM optimization.

Provides intelligent analysis for finding optimization opportunities,
security issues, and actionable recommendations.
"""

import logging
from typing import Dict, List, Set, Tuple, Any, Optional
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import pandas as pd

# CloudFast imports
try:
    from ..gcp.cloudfast_analyzer import CloudFastAnalyzer, CloudFastAnalysis, CloudFastPattern
except ImportError:
    logger.warning("CloudFast analyzer not available - some features may be limited")
    CloudFastAnalyzer = None

logger = logging.getLogger(__name__)


class IAMInsights:
    """Advanced IAM analytics and insights generator."""
    
    def __init__(self):
        self.insights = []
        self.recommendations = []
        self.cloudfast_analyzer = CloudFastAnalyzer() if CloudFastAnalyzer else None
        
    def analyze_project_data(self, projects_data: Dict[str, Dict]) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of IAM data across projects.
        
        Args:
            projects_data: Dict mapping project_id to IAM policy data
            
        Returns:
            Dict containing all analysis results and insights
        """
        logger.info(f"Analyzing IAM data for {len(projects_data)} projects")
        
        # Extract and normalize data
        identities, roles_usage, cross_project_analysis = self._extract_data(projects_data)
        
        analysis = {
            'identities_analysis': self._analyze_identities(identities, cross_project_analysis),
            'roles_optimization': self._analyze_roles_optimization(roles_usage, cross_project_analysis),
            'security_insights': self._analyze_security_issues(identities, cross_project_analysis),
            'grouping_opportunities': self._find_grouping_opportunities(identities, cross_project_analysis),
            'organization_level_opportunities': self._find_org_level_opportunities(cross_project_analysis),
            'duplicate_permissions': self._find_duplicate_permissions(identities, roles_usage),
            'unused_access_analysis': self._analyze_unused_access(identities),
            'recommendations': self._generate_recommendations(identities, roles_usage, cross_project_analysis)
        }
        
        return analysis
    
    def _extract_data(self, projects_data: Dict[str, Dict]) -> Tuple[Dict, Dict, Dict]:
        """Extract and normalize IAM data for analysis."""
        identities = defaultdict(lambda: {
            'projects': set(),
            'roles': set(),
            'identity_type': 'unknown',
            'email': '',
            'domain': '',
            'role_project_mapping': defaultdict(set),
            'first_seen': datetime.now(),
            'last_activity': datetime.now()  # Placeholder - would need audit logs
        })
        
        roles_usage = defaultdict(lambda: {
            'projects': set(),
            'identities': set(),
            'permissions_estimated': 0,
            'is_basic_role': False,
            'is_custom': False
        })
        
        cross_project_analysis = {
            'role_patterns': defaultdict(set),  # role -> set of projects
            'identity_patterns': defaultdict(set),  # identity -> set of projects
            'common_role_combinations': defaultdict(int),
            'project_similarity': defaultdict(set)
        }
        
        for project_id, policy_data in projects_data.items():
            if not policy_data or 'bindings' not in policy_data:
                continue
                
            project_identities = set()
            project_roles = set()
            
            for binding in policy_data['bindings']:
                role = binding['role']
                members = binding.get('members', [])
                
                # Track role usage
                roles_usage[role]['projects'].add(project_id)
                roles_usage[role]['identities'].update(members)
                roles_usage[role]['is_basic_role'] = role in ['roles/owner', 'roles/editor', 'roles/viewer']
                roles_usage[role]['is_custom'] = role.startswith('projects/')
                
                project_roles.add(role)
                
                for member in members:
                    # Parse identity
                    identity_type, email = self._parse_identity(member)
                    domain = self._extract_domain(email, identity_type)
                    
                    # Track identity data
                    identities[member]['projects'].add(project_id)
                    identities[member]['roles'].add(role)
                    identities[member]['identity_type'] = identity_type
                    identities[member]['email'] = email
                    identities[member]['domain'] = domain
                    identities[member]['role_project_mapping'][role].add(project_id)
                    
                    project_identities.add(member)
                    
                    # Cross-project patterns
                    cross_project_analysis['identity_patterns'][member].add(project_id)
                    cross_project_analysis['role_patterns'][role].add(project_id)
            
            # Analyze role combinations within project
            role_combination = tuple(sorted(project_roles))
            if len(role_combination) > 1:
                cross_project_analysis['common_role_combinations'][role_combination] += 1
        
        return dict(identities), dict(roles_usage), cross_project_analysis
    
    def _parse_identity(self, member: str) -> Tuple[str, str]:
        """Parse identity member string into type and email."""
        if ':' in member:
            identity_type, email = member.split(':', 1)
            return identity_type, email
        return 'unknown', member
    
    def _extract_domain(self, email: str, identity_type: str) -> str:
        """Extract domain from email address."""
        if '@' in email and identity_type in ['user', 'serviceAccount']:
            return email.split('@')[1]
        return ''
    
    def _analyze_identities(self, identities: Dict, cross_project: Dict) -> Dict[str, Any]:
        """Analyze identity patterns and issues."""
        analysis = {
            'total_identities': len(identities),
            'by_type': Counter(),
            'by_domain': Counter(),
            'multi_project_users': [],
            'service_account_analysis': {},
            'external_users': [],
            'over_privileged': [],
            'single_project_only': []
        }
        
        for member, data in identities.items():
            identity_type = data['identity_type']
            domain = data['domain']
            project_count = len(data['projects'])
            role_count = len(data['roles'])
            
            analysis['by_type'][identity_type] += 1
            if domain:
                analysis['by_domain'][domain] += 1
            
            # Multi-project analysis
            if project_count > 1:
                analysis['multi_project_users'].append({
                    'identity': member,
                    'email': data['email'],
                    'type': identity_type,
                    'projects': list(data['projects']),
                    'roles': list(data['roles']),
                    'project_count': project_count,
                    'role_count': role_count
                })
            else:
                analysis['single_project_only'].append({
                    'identity': member,
                    'email': data['email'],
                    'type': identity_type,
                    'project': list(data['projects'])[0],
                    'roles': list(data['roles'])
                })
            
            # External users (Gmail, etc.)
            if identity_type == 'user' and domain in ['gmail.com', 'googlemail.com']:
                analysis['external_users'].append({
                    'email': data['email'],
                    'projects': list(data['projects']),
                    'roles': list(data['roles'])
                })
            
            # Over-privileged (many roles or owner/editor)
            high_privilege_roles = {'roles/owner', 'roles/editor', 'roles/iam.securityAdmin'}
            if role_count > 3 or any(role in high_privilege_roles for role in data['roles']):
                analysis['over_privileged'].append({
                    'identity': member,
                    'email': data['email'],
                    'type': identity_type,
                    'role_count': role_count,
                    'high_privilege_roles': [r for r in data['roles'] if r in high_privilege_roles],
                    'projects': list(data['projects'])
                })
        
        # Sort by most impactful
        analysis['multi_project_users'].sort(key=lambda x: x['project_count'], reverse=True)
        analysis['over_privileged'].sort(key=lambda x: x['role_count'], reverse=True)
        
        return analysis
    
    def _analyze_roles_optimization(self, roles_usage: Dict, cross_project: Dict) -> Dict[str, Any]:
        """Analyze role usage patterns for optimization opportunities."""
        analysis = {
            'total_roles': len(roles_usage),
            'basic_roles_usage': [],
            'underutilized_custom_roles': [],
            'cross_project_roles': [],
            'role_consolidation_opportunities': []
        }
        
        for role, data in roles_usage.items():
            project_count = len(data['projects'])
            identity_count = len(data['identities'])
            
            # Basic roles that should be replaced
            if data['is_basic_role'] and identity_count > 0:
                analysis['basic_roles_usage'].append({
                    'role': role,
                    'projects': list(data['projects']),
                    'identities': list(data['identities']),
                    'impact': f"{identity_count} identities across {project_count} projects"
                })
            
            # Custom roles with low usage
            if data['is_custom'] and identity_count < 3:
                analysis['underutilized_custom_roles'].append({
                    'role': role,
                    'projects': list(data['projects']),
                    'identities': list(data['identities']),
                    'usage': f"{identity_count} identities"
                })
            
            # Roles used across multiple projects (org-level candidates)
            if project_count > 2:
                analysis['cross_project_roles'].append({
                    'role': role,
                    'project_count': project_count,
                    'identity_count': identity_count,
                    'projects': list(data['projects']),
                    'org_level_candidate': project_count > len(data['projects']) * 0.5
                })
        
        # Sort by impact
        analysis['basic_roles_usage'].sort(key=lambda x: len(x['identities']), reverse=True)
        analysis['cross_project_roles'].sort(key=lambda x: x['project_count'], reverse=True)
        
        return analysis
    
    def _analyze_security_issues(self, identities: Dict, cross_project: Dict) -> Dict[str, Any]:
        """Identify security concerns and risks."""
        analysis = {
            'high_risk_identities': [],
            'external_access': [],
            'service_account_risks': [],
            'broad_access_patterns': []
        }
        
        dangerous_roles = {
            'roles/owner', 'roles/editor', 'roles/iam.securityAdmin',
            'roles/resourcemanager.organizationAdmin', 'roles/billing.admin'
        }
        
        for member, data in identities.items():
            identity_type = data['identity_type']
            email = data['email']
            roles = data['roles']
            projects = data['projects']
            
            # High-risk access patterns
            dangerous_role_count = len(roles.intersection(dangerous_roles))
            if dangerous_role_count > 0 or len(projects) > 10:
                analysis['high_risk_identities'].append({
                    'identity': email,
                    'type': identity_type,
                    'dangerous_roles': list(roles.intersection(dangerous_roles)),
                    'project_count': len(projects),
                    'total_roles': len(roles),
                    'risk_score': dangerous_role_count * 3 + len(projects)
                })
            
            # External access
            if identity_type == 'user' and data['domain'] not in ['', 'your-domain.com']:  # Replace with your actual domain
                analysis['external_access'].append({
                    'email': email,
                    'domain': data['domain'],
                    'projects': list(projects),
                    'roles': list(roles)
                })
            
            # Service account analysis
            if identity_type == 'serviceAccount':
                # Check if service account has excessive permissions
                if 'roles/owner' in roles or len(roles) > 5:
                    analysis['service_account_risks'].append({
                        'email': email,
                        'roles': list(roles),
                        'projects': list(projects),
                        'risk_reason': 'Excessive permissions'
                    })
        
        # Sort by risk
        analysis['high_risk_identities'].sort(key=lambda x: x['risk_score'], reverse=True)
        
        return analysis
    
    def _find_grouping_opportunities(self, identities: Dict, cross_project: Dict) -> Dict[str, Any]:
        """Find opportunities to group users and consolidate IAM policies."""
        analysis = {
            'role_based_groups': [],
            'project_based_groups': [],
            'domain_based_groups': [],
            'similarity_groups': [],
            'consolidation_impact': {},
            'implementation_roadmap': []
        }
        
        # Convert identities to user-focused format for advanced analysis
        user_data = {}
        for member, data in identities.items():
            if data['identity_type'] == 'user':
                user_data[data['email']] = {
                    'type': 'user',
                    'roles': list(data['roles']),
                    'projects': list(data['projects']),
                    'domain': data['domain']
                }
        
        # 1. Exact role match groups (highest consolidation value)
        role_patterns = {}
        for email, data in user_data.items():
            role_signature = tuple(sorted(data['roles']))
            if role_signature not in role_patterns:
                role_patterns[role_signature] = {
                    'users': [],
                    'common_projects': set(),
                    'all_projects': set()
                }
            role_patterns[role_signature]['users'].append(email)
            role_patterns[role_signature]['all_projects'].update(data['projects'])
            
            if not role_patterns[role_signature]['common_projects']:
                role_patterns[role_signature]['common_projects'] = set(data['projects'])
            else:
                role_patterns[role_signature]['common_projects'] &= set(data['projects'])
        
        # Process exact matches with consolidation metrics
        for roles, pattern_data in role_patterns.items():
            if len(pattern_data['users']) >= 2:  # At least 2 users
                consolidation_value = self._calculate_consolidation_value(
                    pattern_data['users'], list(roles), list(pattern_data['all_projects'])
                )
                
                # Calculate policies saved
                policies_saved = len(pattern_data['users']) * len(pattern_data['all_projects'])
                
                analysis['role_based_groups'].append({
                    'group_id': f"exact_{hash(roles) % 10000}",
                    'users': pattern_data['users'],
                    'user_count': len(pattern_data['users']),
                    'roles': list(roles),
                    'common_projects': list(pattern_data['common_projects']),
                    'all_projects': list(pattern_data['all_projects']),
                    'project_count': len(pattern_data['all_projects']),
                    'suggested_group_name': self._suggest_group_name(roles, pattern_data['users']),
                    'match_type': 'exact',
                    'consolidation_value': consolidation_value,
                    'policies_saved': policies_saved,
                    'priority': 'HIGH' if consolidation_value > 15 else 'MEDIUM',
                    'implementation_complexity': 'LOW'
                })
        
        # 2. Project-based grouping (users with overlapping project access)
        project_groups = self._find_project_based_consolidation(user_data)
        analysis['project_based_groups'] = project_groups
        
        # 3. Similarity-based grouping (fuzzy role matching)
        similarity_groups = self._find_similarity_consolidation(user_data)
        analysis['similarity_groups'] = similarity_groups
        
        # 4. Domain-based consolidation
        domain_groups = self._find_domain_consolidation(user_data)
        analysis['domain_based_groups'] = domain_groups
        
        # 5. Calculate overall consolidation impact
        analysis['consolidation_impact'] = self._calculate_total_consolidation_impact(
            analysis
        )
        
        # 6. Generate implementation roadmap
        analysis['implementation_roadmap'] = self._generate_implementation_roadmap(
            analysis
        )
        
        return analysis
    
    def _calculate_consolidation_value(self, users, roles, projects):
        """Calculate the business value of consolidating users into a group."""
        # Base value: number of individual IAM bindings that would be eliminated
        base_value = len(users) * len(projects)
        
        # Role complexity multiplier
        high_value_roles = ['roles/owner', 'roles/editor', 'roles/viewer', 
                           'roles/compute.admin', 'roles/storage.admin',
                           'roles/bigquery.admin', 'roles/cloudsql.admin']
        role_multiplier = sum(2 if role in high_value_roles else 1 for role in roles)
        
        # Multi-project bonus (org-level consolidation opportunity)
        project_bonus = len(projects) * 0.5 if len(projects) > 3 else 0
        
        return base_value * role_multiplier + project_bonus
    
    def _find_project_based_consolidation(self, user_data):
        """Find consolidation opportunities based on project access patterns."""
        project_groups = []
        
        # Group users by project combinations for maximum consolidation
        project_patterns = {}
        for user, data in user_data.items():
            project_signature = tuple(sorted(data['projects']))
            if len(project_signature) >= 2:  # Multi-project users only
                if project_signature not in project_patterns:
                    project_patterns[project_signature] = []
                project_patterns[project_signature].append(user)
        
        for projects, users in project_patterns.items():
            if len(users) >= 2:  # Multiple users same projects
                # Analyze role overlap for optimal group composition
                all_roles = []
                role_counts = {}
                
                for user in users:
                    for role in user_data[user]['roles']:
                        all_roles.append(role)
                        role_counts[role] = role_counts.get(role, 0) + 1
                
                # Find roles present in majority of users
                threshold = max(2, len(users) * 0.6)  # At least 60% or minimum 2
                common_roles = [role for role, count in role_counts.items() if count >= threshold]
                
                if common_roles:
                    consolidation_value = self._calculate_consolidation_value(
                        users, common_roles, list(projects)
                    )
                    
                    project_groups.append({
                        'group_id': f"project_{hash(projects) % 10000}",
                        'users': users,
                        'user_count': len(users),
                        'projects': list(projects),
                        'project_count': len(projects),
                        'common_roles': common_roles,
                        'role_overlap_percentage': (len(common_roles) / len(set(all_roles))) * 100,
                        'suggested_group_name': self._suggest_project_group_name(projects, common_roles),
                        'match_type': 'project_overlap',
                        'consolidation_value': consolidation_value,
                        'policies_saved': len(users) * len(projects),
                        'priority': 'HIGH' if len(projects) > 3 else 'MEDIUM',
                        'implementation_complexity': 'MEDIUM'
                    })
        
        return sorted(project_groups, key=lambda x: x['consolidation_value'], reverse=True)
    
    def _find_similarity_consolidation(self, user_data):
        """Find users with similar (but not identical) access patterns."""
        similarity_groups = []
        users = list(user_data.keys())
        processed_users = set()
        
        for i in range(len(users)):
            if users[i] in processed_users:
                continue
                
            similar_cluster = [users[i]]
            base_roles = set(user_data[users[i]]['roles'])
            base_projects = set(user_data[users[i]]['projects'])
            
            # Find similar users
            for j in range(i + 1, len(users)):
                if users[j] in processed_users:
                    continue
                    
                compare_roles = set(user_data[users[j]]['roles'])
                compare_projects = set(user_data[users[j]]['projects'])
                
                # Calculate role and project similarity
                role_similarity = len(base_roles & compare_roles) / len(base_roles | compare_roles)
                project_similarity = len(base_projects & compare_projects) / len(base_projects | compare_projects)
                
                # Combined similarity score
                overall_similarity = (role_similarity * 0.7) + (project_similarity * 0.3)
                
                if overall_similarity > 0.6:  # 60% similar
                    similar_cluster.append(users[j])
            
            if len(similar_cluster) >= 2:
                # Calculate optimal roles for this cluster
                all_user_roles = [user_data[u]['roles'] for u in similar_cluster]
                all_user_projects = [user_data[u]['projects'] for u in similar_cluster]
                
                optimal_roles = self._calculate_optimal_role_set(all_user_roles)
                common_projects = set.intersection(*[set(projects) for projects in all_user_projects])
                all_projects = set.union(*[set(projects) for projects in all_user_projects])
                
                consolidation_value = self._calculate_consolidation_value(
                    similar_cluster, optimal_roles, list(all_projects)
                )
                
                similarity_groups.append({
                    'group_id': f"similar_{hash(tuple(sorted(similar_cluster))) % 10000}",
                    'users': similar_cluster,
                    'user_count': len(similar_cluster),
                    'current_roles_overlap': list(set.intersection(*[set(user_data[u]['roles']) for u in similar_cluster])),
                    'suggested_roles': optimal_roles,
                    'common_projects': list(common_projects),
                    'all_projects': list(all_projects),
                    'project_count': len(all_projects),
                    'suggested_group_name': self._suggest_similarity_group_name(similar_cluster, optimal_roles),
                    'match_type': 'similarity',
                    'consolidation_value': consolidation_value,
                    'policies_saved': len(similar_cluster) * len(all_projects),
                    'priority': 'MEDIUM',
                    'implementation_complexity': 'MEDIUM'
                })
                
                # Mark users as processed
                for user in similar_cluster:
                    processed_users.add(user)
        
        return sorted(similarity_groups, key=lambda x: x['consolidation_value'], reverse=True)
    
    def _find_domain_consolidation(self, user_data):
        """Find domain-based consolidation opportunities."""
        domain_groups = []
        domain_users = {}
        
        # Group users by domain
        for user, data in user_data.items():
            domain = data['domain']
            if domain and domain not in ['gmail.com', 'googlemail.com']:  # Skip external
                if domain not in domain_users:
                    domain_users[domain] = []
                domain_users[domain].append(user)
        
        for domain, users in domain_users.items():
            if len(users) >= 2:  # Minimum for domain consolidation
                # Analyze patterns within domain
                all_roles = []
                all_projects = set()
                role_counts = {}
                
                for user in users:
                    for role in user_data[user]['roles']:
                        all_roles.append(role)
                        role_counts[role] = role_counts.get(role, 0) + 1
                    all_projects.update(user_data[user]['projects'])
                
                # Find roles common across domain users
                threshold = max(2, len(users) * 0.4)  # 40% threshold for domains
                common_roles = [role for role, count in role_counts.items() if count >= threshold]
                
                consolidation_value = self._calculate_consolidation_value(
                    users, common_roles, list(all_projects)
                )
                
                # Only include if there's significant consolidation value
                if consolidation_value > 5 or len(users) >= 5:
                    domain_groups.append({
                        'group_id': f"domain_{hash(domain) % 10000}",
                        'domain': domain,
                        'users': users,
                        'user_count': len(users),
                        'common_roles': common_roles,
                        'all_projects': list(all_projects),
                        'project_count': len(all_projects),
                        'suggested_group_name': f"{domain.split('.')[0]}-team@{domain}",
                        'match_type': 'domain_based',
                        'consolidation_value': consolidation_value,
                        'policies_saved': len(users) * len(all_projects),
                        'priority': 'LOW' if len(common_roles) < 2 else 'MEDIUM',
                        'implementation_complexity': 'LOW'
                    })
        
        return sorted(domain_groups, key=lambda x: x['consolidation_value'], reverse=True)
    
    def _calculate_optimal_role_set(self, user_role_lists):
        """Calculate the optimal set of roles for a group."""
        role_counts = {}
        total_users = len(user_role_lists)
        
        for roles in user_role_lists:
            for role in roles:
                role_counts[role] = role_counts.get(role, 0) + 1
        
        # Include roles that appear in at least 60% of users
        threshold = total_users * 0.6
        optimal_roles = [role for role, count in role_counts.items() if count >= threshold]
        
        return optimal_roles
    
    def _suggest_group_name(self, roles, users):
        """Suggest a meaningful group name based on roles and users."""
        # Extract key role types for naming
        role_keywords = []
        for role in roles[:3]:  # Use first 3 roles for naming
            if role.startswith('roles/'):
                role_part = role.split('/')[-1]
                # Clean up role name
                clean_part = role_part.replace('Admin', '').replace('admin', '')
                clean_part = clean_part.replace('User', '').replace('user', '')
                if clean_part and clean_part not in role_keywords:
                    role_keywords.append(clean_part)
        
        # Fallback to domain if users from same domain
        if len(set(u.split('@')[-1] for u in users if '@' in u)) == 1:
            domain = users[0].split('@')[-1] if '@' in users[0] else 'group'
            domain_name = domain.split('.')[0]
            if role_keywords:
                return f"{domain_name}-{'-'.join(role_keywords[:2])}-group"
            return f"{domain_name}-group"
        
        # Use role-based naming
        if role_keywords:
            return f"{'-'.join(role_keywords[:2])}-group"
        
        return f"consolidated-group-{len(users)}-users"
    
    def _suggest_project_group_name(self, projects, roles):
        """Suggest group name based on project access patterns."""
        # Extract common project patterns
        project_keywords = []
        for project in projects[:2]:  # Use first 2 projects
            # Extract meaningful parts from project ID
            parts = project.replace('-', ' ').replace('_', ' ').split()
            for part in parts:
                if part.lower() in ['prod', 'dev', 'staging', 'test', 'web', 'api', 'data', 'ml']:
                    if part.lower() not in [p.lower() for p in project_keywords]:
                        project_keywords.append(part.lower())
        
        # Use role info if available
        role_keywords = []
        for role in roles[:2]:
            if role.startswith('roles/'):
                role_part = role.split('/')[-1].replace('admin', '').replace('Admin', '')
                if role_part and role_part not in role_keywords:
                    role_keywords.append(role_part)
        
        name_parts = project_keywords + role_keywords
        if name_parts:
            return f"{'-'.join(name_parts[:3])}-group"
        
        return f"multi-project-group-{len(projects)}-projects"
    
    def _suggest_similarity_group_name(self, users, roles):
        """Suggest group name for similarity-based groups."""
        # Use domain if users are from same domain
        domains = list(set(u.split('@')[-1] for u in users if '@' in u))
        if len(domains) == 1 and domains[0] not in ['gmail.com', 'googlemail.com']:
            domain_name = domains[0].split('.')[0]
            return f"{domain_name}-similar-access-group"
        
        # Use role-based naming
        role_keywords = []
        for role in roles[:2]:
            if role.startswith('roles/'):
                role_part = role.split('/')[-1].lower()
                if role_part not in role_keywords:
                    role_keywords.append(role_part)
        
        if role_keywords:
            return f"similar-{'-'.join(role_keywords)}-group"
        
        return f"similar-access-group-{len(users)}-users"
    
    def _calculate_total_consolidation_impact(self, analysis):
        """Calculate the overall impact of all consolidation opportunities."""
        impact = {
            'total_policies_that_can_be_eliminated': 0,
            'total_users_that_can_be_grouped': 0,
            'total_groups_to_create': 0,
            'high_impact_opportunities': 0,
            'estimated_management_reduction_percentage': 0,
            'consolidation_by_type': {}
        }
        
        all_groups = (
            analysis['role_based_groups'] +
            analysis['similarity_groups'] +
            analysis['project_based_groups'] +
            analysis['domain_based_groups']
        )
        
        grouped_users = set()
        consolidation_by_type = {'exact': 0, 'similarity': 0, 'project_overlap': 0, 'domain_based': 0}
        
        for group in all_groups:
            if group['consolidation_value'] > 3:  # Only count valuable consolidations
                impact['total_groups_to_create'] += 1
                impact['total_policies_that_can_be_eliminated'] += group.get('policies_saved', 0)
                
                # Track consolidation by type
                match_type = group.get('match_type', 'unknown')
                consolidation_by_type[match_type] = consolidation_by_type.get(match_type, 0) + 1
                
                for user in group['users']:
                    grouped_users.add(user)
                
                if group['priority'] == 'HIGH':
                    impact['high_impact_opportunities'] += 1
        
        impact['total_users_that_can_be_grouped'] = len(grouped_users)
        impact['consolidation_by_type'] = consolidation_by_type
        
        # Estimate management reduction (rough calculation)
        if impact['total_policies_that_can_be_eliminated'] > 0:
            impact['estimated_management_reduction_percentage'] = min(85, 
                (impact['total_policies_that_can_be_eliminated'] / max(1, len(grouped_users))) * 10
            )
        
        return impact
    
    def _generate_implementation_roadmap(self, analysis):
        """Generate a prioritized roadmap for implementing grouping changes."""
        roadmap = []
        
        all_groups = (
            analysis['role_based_groups'] +
            analysis['similarity_groups'] +
            analysis['project_based_groups'] +
            analysis['domain_based_groups']
        )
        
        # Sort by priority and consolidation value
        priority_order = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        sorted_groups = sorted(all_groups, 
                              key=lambda x: (priority_order.get(x['priority'], 0), x['consolidation_value']), 
                              reverse=True)
        
        phase = 1
        groups_in_phase = 0
        current_phase_groups = []
        
        for group in sorted_groups[:15]:  # Top 15 opportunities
            if groups_in_phase >= 5:  # Max 5 groups per phase
                roadmap.append({
                    'phase': phase,
                    'title': f"Phase {phase}: {self._get_phase_title(current_phase_groups)}",
                    'groups': current_phase_groups,
                    'estimated_policies_saved': sum(g.get('policies_saved', 0) for g in current_phase_groups),
                    'implementation_effort': self._estimate_phase_effort(current_phase_groups)
                })
                phase += 1
                groups_in_phase = 0
                current_phase_groups = []
            
            current_phase_groups.append({
                'group_id': group['group_id'],
                'name': group['suggested_group_name'],
                'type': group['match_type'],
                'users': group['users'],
                'user_count': group['user_count'],
                'roles': group.get('roles', group.get('suggested_roles', [])),
                'projects': group.get('all_projects', group.get('projects', [])),
                'priority': group['priority'],
                'policies_saved': group.get('policies_saved', 0),
                'implementation_commands': self._generate_gcloud_commands(group)
            })
            groups_in_phase += 1
        
        # Add remaining groups to final phase
        if current_phase_groups:
            roadmap.append({
                'phase': phase,
                'title': f"Phase {phase}: {self._get_phase_title(current_phase_groups)}",
                'groups': current_phase_groups,
                'estimated_policies_saved': sum(g.get('policies_saved', 0) for g in current_phase_groups),
                'implementation_effort': self._estimate_phase_effort(current_phase_groups)
            })
        
        return roadmap
    
    def _get_phase_title(self, groups):
        """Generate a descriptive title for an implementation phase."""
        if not groups:
            return "Consolidation Phase"
        
        high_priority_count = sum(1 for g in groups if g['priority'] == 'HIGH')
        if high_priority_count > 0:
            return f"High-Impact Consolidation ({high_priority_count} critical groups)"
        
        exact_matches = sum(1 for g in groups if g['type'] == 'exact')
        if exact_matches > 0:
            return f"Exact Match Consolidation ({exact_matches} groups)"
        
        return f"Optimization Phase ({len(groups)} groups)"
    
    def _estimate_phase_effort(self, groups):
        """Estimate implementation effort for a phase."""
        total_effort = 0
        for group in groups:
            # Base effort per group
            effort = 2  # hours
            
            # Additional effort based on complexity
            if group.get('implementation_complexity') == 'HIGH':
                effort *= 2
            elif group.get('implementation_complexity') == 'MEDIUM':
                effort *= 1.5
            
            # Additional effort based on number of users
            effort += group['user_count'] * 0.1
            
            # Additional effort based on number of projects
            effort += len(group['projects']) * 0.2
            
            total_effort += effort
        
        return f"{total_effort:.1f} hours"
    
    def _generate_gcloud_commands(self, group):
        """Generate comprehensive gcloud commands for implementing a group consolidation."""
        commands = []
        group_name = group['suggested_group_name']
        
        # Detect domain from users in the group
        users = group.get('users', [])
        detected_domains = set()
        for user in users:
            if '@' in user:
                user_domain = user.split('@')[1]
                detected_domains.add(user_domain)
        
        # Use the most common domain or fallback to yourdomain.com
        if detected_domains:
            domain = list(detected_domains)[0]  # Use first detected domain
            if len(detected_domains) > 1:
                # Log multiple domains found
                domain_list = ', '.join(detected_domains)
        else:
            domain = "yourdomain.com"
        
        group_email = f"{group_name}@{domain}"
        
        # Header with consolidation summary
        commands.append("#!/bin/bash")
        commands.append(f"# IAM Consolidation Script for: {group_name}")
        commands.append(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        commands.append(f"# Users to consolidate: {len(group['users'])}")
        commands.append(f"# Projects affected: {len(group.get('all_projects', group.get('projects', [])))}")
        commands.append(f"# Estimated policies saved: {group.get('policies_saved', 0)}")
        commands.append(f"# Priority: {group.get('priority', 'MEDIUM')}")
        commands.append(f"# Domain: {domain}")
        if len(detected_domains) > 1:
            commands.append(f"# Note: Multiple domains detected: {', '.join(detected_domains)}")
        commands.append("#")
        commands.append("# PREREQUISITES:")
        commands.append("# 1. Cloud Identity Groups API must be enabled")
        commands.append("# 2. User must have the following IAM roles:")
        commands.append("#    - Group Admin (groups.googleapis.com/admin) for group operations")
        commands.append("#    - Project IAM Admin (roles/resourcemanager.projectIamAdmin) for each project")
        commands.append("#    - Organization Policy Administrator (if org-level changes)")
        commands.append("# 3. gcloud CLI authenticated with appropriate permissions")
        commands.append("#")
        commands.append("# USAGE:")
        commands.append("# 1. Review all commands before execution")
        commands.append("# 2. Test in non-production environment first")
        commands.append("# 3. Have rollback plan ready")
        commands.append("# 4. Execute during maintenance window")
        commands.append("")
        
        # Set variables
        commands.append("# Configuration variables")
        commands.append(f"GROUP_NAME='{group_name}'")
        commands.append(f"GROUP_EMAIL='{group_email}'")
        commands.append(f"DOMAIN='{domain}'")
        commands.append("")
        
        # Pre-flight checks
        commands.append("# Pre-flight checks")
        commands.append("echo '🔍 Pre-flight checks...'")
        commands.append("")
        
        commands.append("# Check if user has required permissions")
        commands.append("echo 'Checking current user authentication...'")
        commands.append("CURRENT_USER=$(gcloud auth list --filter=status:ACTIVE --format='value(account)')")
        commands.append("echo \"Authenticated as: $CURRENT_USER\"")
        commands.append("")
        
        commands.append("# Check if Cloud Identity Groups API is enabled")
        commands.append("echo 'Checking if Cloud Identity Groups API is enabled...'")
        commands.append("if gcloud services list --enabled --filter='name:cloudidentity.googleapis.com' --format='value(name)' --quiet | grep -q cloudidentity; then")
        commands.append("  echo '✅ Cloud Identity Groups API is enabled'")
        commands.append("else")
        commands.append("  echo '⚠️ WARNING: Cloud Identity Groups API is not enabled'")
        commands.append("  echo 'Enable it with: gcloud services enable cloudidentity.googleapis.com'")
        commands.append("  echo 'Do you want to continue anyway? (y/N)'")
        commands.append("  read -r response")
        commands.append("  if [[ \"$response\" != \"y\" && \"$response\" != \"Y\" ]]; then")
        commands.append("    echo 'Exiting...'")
        commands.append("    exit 1")
        commands.append("  fi")
        commands.append("fi")
        commands.append("")
        
        # Check if group already exists
        commands.append("# Check if group already exists")
        commands.append(f"echo 'Checking if group {group_email} exists...'")
        commands.append(f"if gcloud identity groups describe {group_email} --quiet 2>/dev/null; then")
        commands.append(f"  echo 'Group {group_email} already exists'")
        commands.append(f"  GROUP_EXISTS=true")
        commands.append("else")
        commands.append(f"  echo 'Group {group_email} does not exist'")
        commands.append(f"  GROUP_EXISTS=false")
        commands.append("fi")
        commands.append("")
        
        # Create group using gcloud
        commands.append("# STEP 1: Create Google Group")
        commands.append("echo '📧 Creating Google Group...'")
        commands.append("")
        commands.append("if [ \"$GROUP_EXISTS\" = \"false\" ]; then")
        commands.append(f"  echo 'Creating group: {group_email}'")
        commands.append(f"  gcloud identity groups create {group_email} \\")
        commands.append(f"    --display-name='{group_name}' \\")
        commands.append(f"    --description='IAM consolidation group for {group_name}' \\")
        commands.append(f"    --labels=created-by=iam-janitor,purpose=consolidation \\")
        commands.append(f"    --quiet")
        commands.append("  ")
        commands.append("  if [ $? -eq 0 ]; then")
        commands.append(f"    echo '✅ Successfully created group: {group_email}'")
        commands.append("  else")
        commands.append(f"    echo '❌ ERROR: Failed to create group {group_email}'")
        commands.append("    echo 'Please check your permissions and try again'")
        commands.append("    exit 1")
        commands.append("  fi")
        commands.append("else")
        commands.append(f"  echo 'Using existing group: {group_email}'")
        commands.append("fi")
        commands.append("")
        commands.append("# Wait for group creation to propagate")
        commands.append("echo 'Waiting for group creation to propagate...'")
        commands.append("sleep 5")
        commands.append("")
        
        # Add members to group
        commands.append("# STEP 2: Add members to group")
        commands.append("echo '👥 Adding members to group...'")
        commands.append("")
        
        users = group['users']
        commands.append(f"# Members to add ({len(users)} total)")
        commands.append(f"echo 'Adding {len(users)} members to {group_email}...'")
        commands.append("")
        
        # Add each member using gcloud commands
        for i, user in enumerate(users):
            user_email = user if '@' in user else f"{user}@{domain}"
            commands.append(f"# Adding member {i+1}/{len(users)}: {user_email}")
            commands.append(f"echo 'Adding member {i+1}/{len(users)}: {user_email}'")
            
            # Check if member already exists in group
            commands.append(f"if gcloud identity groups memberships list --group-email={group_email} --filter='preferredMemberKey.id:{user_email}' --format='value(name)' --quiet 2>/dev/null | grep -q '.'; then")
            commands.append(f"  echo '  ℹ️ Member {user_email} already in group'")
            commands.append("else")
            commands.append(f"  echo '  Adding {user_email} to group...'")
            commands.append(f"  gcloud identity groups memberships add \\")
            commands.append(f"    --group-email={group_email} \\")
            commands.append(f"    --member-email={user_email} \\")
            commands.append(f"    --roles=MEMBER \\")
            commands.append(f"    --quiet")
            commands.append("  ")
            commands.append("  if [ $? -eq 0 ]; then")
            commands.append(f"    echo '  ✅ Successfully added {user_email}'")
            commands.append("  else")
            commands.append(f"    echo '  ⚠️ WARNING: Failed to add {user_email} (continuing with others)'")
            commands.append("  fi")
            commands.append("fi")
            commands.append("")
        
        # Verify group membership
        commands.append("# Verify group membership")
        commands.append(f"echo 'Verifying group membership for {group_email}...'")
        commands.append(f"MEMBER_COUNT=$(gcloud identity groups memberships list --group-email={group_email} --format='value(name)' --quiet 2>/dev/null | wc -l)")
        commands.append(f"echo \"Group now has $MEMBER_COUNT members\"")
        commands.append("")
        commands.append("echo 'Waiting for group membership to propagate...'")
        commands.append("sleep 15")
        commands.append("")
        
        # Grant roles to group
        roles = group.get('roles', group.get('suggested_roles', []))
        projects = group.get('all_projects', group.get('projects', []))
        
        if roles and projects:
            commands.append("# STEP 3: Grant roles to group")
            commands.append("echo '🔐 Granting roles to group...'")
            commands.append("")
            
            for i, project in enumerate(projects):
                commands.append(f"# Project {i+1}/{len(projects)}: {project}")
                commands.append(f"echo 'Processing project: {project}'")
                
                for j, role in enumerate(roles):
                    commands.append(f"echo '  Granting role {j+1}/{len(roles)}: {role}'")
                    commands.append(f"gcloud projects add-iam-policy-binding {project} --member='group:{group_email}' --role='{role}' --quiet")
                    commands.append("")
                    
                    # Add error checking
                    commands.append("if [ $? -ne 0 ]; then")
                    commands.append(f"  echo 'ERROR: Failed to grant {role} to group in project {project}'")
                    commands.append("  exit 1")
                    commands.append("fi")
                    commands.append("")
            
            # Verification step
            commands.append("# STEP 4: Verify group permissions")
            commands.append("echo '✅ Verifying group permissions...'")
            commands.append("sleep 5  # Wait for IAM changes to propagate")
            commands.append("")
            
            for project in projects[:3]:  # Verify first 3 projects
                commands.append(f"echo 'Verifying permissions in project: {project}'")
                commands.append(f"gcloud projects get-iam-policy {project} --flatten='bindings[].members' --format='table(bindings.role)' --filter='bindings.members:group:{group_email}'")
                commands.append("")
            
            # Remove individual user permissions (with safety checks)
            commands.append("# STEP 5: Remove individual user permissions (DANGER ZONE)")
            commands.append("echo '⚠️  CAUTION: About to remove individual user permissions'")
            commands.append("echo 'Make sure group permissions are working correctly first!'")
            commands.append("echo 'Press Enter to continue or Ctrl+C to abort...'")
            commands.append("read -r")
            commands.append("")
            
            for i, user in enumerate(users):
                user_email = user if '@' in user else f"{user}@{domain}"
                commands.append(f"# Removing permissions for user {i+1}/{len(users)}: {user_email}")
                commands.append(f"echo 'Removing individual permissions for: {user_email}'")
                
                for project in projects:
                    for role in roles:
                        commands.append(f"echo '  Removing {role} from {project}'")
                        commands.append(f"gcloud projects remove-iam-policy-binding {project} --member='user:{user_email}' --role='{role}' --quiet 2>/dev/null || echo '    (Permission not found - OK)'")
                commands.append("")
            
            # Final verification
            commands.append("# STEP 6: Final verification")
            commands.append("echo '🎯 Final verification...'")
            commands.append("")
            
            # Check that users no longer have individual permissions
            commands.append("echo 'Verifying individual permissions have been removed:'")
            for user in users[:3]:  # Check first 3 users
                user_email = user if '@' in user else f"{user}@{domain}"
                commands.append(f"echo 'Checking {user_email}:'")
                for project in projects[:2]:  # Check first 2 projects
                    commands.append(f"gcloud projects get-iam-policy {project} --flatten='bindings[].members' --format='table(bindings.role)' --filter='bindings.members:user:{user_email}' || echo '  No individual permissions (Good!)'")
                commands.append("")
            
            # Summary
            commands.append("# CONSOLIDATION SUMMARY")
            commands.append("echo ''")
            commands.append("echo '✨ ======================================='")
            commands.append("echo '✨ IAM CONSOLIDATION COMPLETED!'")
            commands.append("echo '✨ ======================================='")
            commands.append(f"echo 'Group created: {group_email}'")
            commands.append(f"echo 'Users consolidated: {len(users)}'")
            commands.append(f"echo 'Projects affected: {len(projects)}'")
            commands.append(f"echo 'Roles granted: {len(roles)}'")
            commands.append(f"echo 'IAM bindings eliminated: {group.get("policies_saved", len(users) * len(projects))}'")
            commands.append("echo ''")
            
            # Post-consolidation verification
            commands.append("# POST-CONSOLIDATION VERIFICATION")
            commands.append("echo '🔍 Running final verification...'")
            commands.append("")
            
            # Test group access with sample commands
            if projects and len(projects) > 0:
                sample_project = projects[0]
                commands.append(f"echo 'Testing group access on sample project: {sample_project}'")
                commands.append(f"gcloud projects get-iam-policy {sample_project} --flatten='bindings[].members' --filter='bindings.members:group:{group_email}'")
                commands.append("echo 'If you see roles listed above, the consolidation was successful!'")
                commands.append("")
            
            # Cleanup verification
            commands.append("echo 'Spot-checking that individual permissions were removed:'")
            if users and len(users) > 0:
                sample_user = users[0]
                sample_user_email = sample_user if '@' in sample_user else f"{sample_user}@{domain}"
                if projects and len(projects) > 0:
                    commands.append(f"gcloud projects get-iam-policy {sample_project} --flatten='bindings[].members' --filter='bindings.members:user:{sample_user_email}' || echo 'Good - no individual permissions found'")
            commands.append("")
            
            # Rollback instructions
            commands.append("# ROLLBACK INSTRUCTIONS (if needed)")
            commands.append("echo 'If rollback is needed:'")
            commands.append(f"echo '1. Remove group {group_email} from all projects:'")
            for project in projects[:3]:
                for role in roles[:2]:
                    commands.append(f"echo '   gcloud projects remove-iam-policy-binding {project} --member=group:{group_email} --role={role}'")
            commands.append("echo '2. Re-add individual user permissions as needed'")
            commands.append("echo '3. Delete the Google Group via Admin Console'")
        
        return commands
    
    def _find_org_level_opportunities(self, cross_project: Dict) -> Dict[str, Any]:
        """Find opportunities to move permissions to organization level with detailed identity mappings."""
        analysis = {
            'org_level_candidates': [],
            'folder_level_candidates': [],
            'inheritance_opportunities': [],
            'org_level_groups': [],
            'suggested_org_policies': [],
            'implementation_summary': {
                'total_org_opportunities': 0,
                'estimated_policies_reduced': 0,
                'affected_identities': 0
            }
        }
        
        # Enhanced analysis of roles used across many projects
        role_identity_mapping = {}
        for role, projects in cross_project['role_patterns'].items():
            if len(projects) > 3:  # Used in multiple projects
                # Find identities that have this role across projects
                identities_with_role = set()
                for identity, identity_projects in cross_project['identity_patterns'].items():
                    # This is a simplified check - in real implementation, we'd check specific role-identity-project mappings
                    overlap = len(identity_projects.intersection(projects))
                    if overlap >= 2:  # Identity appears in at least 2 projects with this pattern
                        identities_with_role.add(identity)
                
                role_priority = 'HIGH' if len(projects) > 6 else 'MEDIUM'
                consolidation_value = len(projects) * len(identities_with_role)
                
                candidate = {
                    'role': role,
                    'project_count': len(projects),
                    'projects': list(projects),
                    'identities': list(identities_with_role),
                    'identity_count': len(identities_with_role),
                    'consolidation_value': consolidation_value,
                    'priority': role_priority,
                    'recommendation': 'Move to organization level' if len(projects) > 5 else 'Consider folder-level assignment',
                    'estimated_policies_saved': len(projects) * len(identities_with_role),
                    'implementation_complexity': 'HIGH' if len(identities_with_role) > 10 else 'MEDIUM'
                }
                
                if len(projects) > 5:
                    analysis['org_level_candidates'].append(candidate)
                else:
                    analysis['folder_level_candidates'].append(candidate)
                
                role_identity_mapping[role] = identities_with_role
        
        # Enhanced inheritance opportunities with specific group suggestions
        identity_role_mapping = {}
        for identity, projects in cross_project['identity_patterns'].items():
            if len(projects) > 4:
                # Find roles this identity has across projects
                likely_roles = []
                for role, role_projects in cross_project['role_patterns'].items():
                    overlap = len(projects.intersection(role_projects))
                    if overlap >= 2:
                        likely_roles.append(role)
                
                inheritance_value = len(projects) * len(likely_roles)
                identity_type = 'user' if 'user:' in identity else 'serviceAccount' if 'serviceAccount:' in identity else 'group'
                
                inheritance_opp = {
                    'identity': identity,
                    'identity_type': identity_type,
                    'project_count': len(projects),
                    'projects': list(projects),
                    'roles': likely_roles,
                    'role_count': len(likely_roles),
                    'inheritance_value': inheritance_value,
                    'priority': 'HIGH' if len(projects) > 8 else 'MEDIUM',
                    'recommendation': 'Consider org-level or folder-level role assignment',
                    'suggested_action': f"Create org-level group for {identity_type} with similar access patterns"
                }
                
                analysis['inheritance_opportunities'].append(inheritance_opp)
                identity_role_mapping[identity] = likely_roles
        
        # Generate intelligent org-level group suggestions
        analysis['org_level_groups'] = self._suggest_org_level_groups(
            role_identity_mapping, identity_role_mapping, cross_project
        )
        
        # Generate suggested org-level policies
        analysis['suggested_org_policies'] = self._suggest_org_policies(
            analysis['org_level_candidates'], analysis['inheritance_opportunities']
        )
        
        # Calculate implementation summary
        analysis['implementation_summary'] = {
            'total_org_opportunities': len(analysis['org_level_candidates']) + len(analysis['folder_level_candidates']),
            'estimated_policies_reduced': sum(c.get('estimated_policies_saved', 0) for c in analysis['org_level_candidates']),
            'affected_identities': len(set().union(*[c.get('identities', []) for c in analysis['org_level_candidates']])),
            'high_priority_count': len([c for c in analysis['org_level_candidates'] if c.get('priority') == 'HIGH'])
        }
        
        # Sort by impact and priority
        analysis['org_level_candidates'].sort(key=lambda x: (x.get('consolidation_value', 0), x.get('project_count', 0)), reverse=True)
        analysis['inheritance_opportunities'].sort(key=lambda x: (x.get('inheritance_value', 0), x.get('project_count', 0)), reverse=True)
        analysis['folder_level_candidates'].sort(key=lambda x: x.get('consolidation_value', 0), reverse=True)
        
        return analysis
    
    def _suggest_org_level_groups(self, role_identity_mapping: Dict, identity_role_mapping: Dict, cross_project: Dict) -> List[Dict[str, Any]]:
        """Suggest org-level groups based on cross-project access patterns."""
        org_groups = []
        
        # Group identities with similar org-wide access patterns
        processed_identities = set()
        
        for identity, roles in identity_role_mapping.items():
            if identity in processed_identities:
                continue
            
            # Find other identities with similar role patterns
            similar_identities = [identity]
            identity_roles_set = set(roles)
            
            for other_identity, other_roles in identity_role_mapping.items():
                if other_identity == identity or other_identity in processed_identities:
                    continue
                
                other_roles_set = set(other_roles)
                similarity = len(identity_roles_set & other_roles_set) / len(identity_roles_set | other_roles_set)
                
                if similarity > 0.6:  # 60% role similarity
                    similar_identities.append(other_identity)
            
            if len(similar_identities) >= 2:  # At least 2 identities for a group
                common_roles = list(set.intersection(*[set(identity_role_mapping[id_]) for id_ in similar_identities]))
                all_projects = set()
                
                # Calculate affected projects
                for identity in similar_identities:
                    if identity in cross_project['identity_patterns']:
                        all_projects.update(cross_project['identity_patterns'][identity])
                
                consolidation_value = len(similar_identities) * len(common_roles) * len(all_projects)
                
                org_groups.append({
                    'suggested_group_name': f"org-wide-{len(similar_identities)}-users-group",
                    'identities': similar_identities,
                    'identity_count': len(similar_identities),
                    'common_roles': common_roles,
                    'affected_projects': list(all_projects),
                    'project_count': len(all_projects),
                    'consolidation_value': consolidation_value,
                    'org_level': True,
                    'priority': 'HIGH' if len(all_projects) > 10 else 'MEDIUM',
                    'implementation_type': 'organization_level',
                    'estimated_savings': len(similar_identities) * len(all_projects)
                })
                
                for identity in similar_identities:
                    processed_identities.add(identity)
        
        return sorted(org_groups, key=lambda x: x['consolidation_value'], reverse=True)
    
    def _suggest_org_policies(self, org_candidates: List[Dict], inheritance_opportunities: List[Dict]) -> List[Dict[str, Any]]:
        """Suggest specific organization-level policies."""
        org_policies = []
        
        # High-impact roles that should be moved to org level
        high_impact_roles = [c for c in org_candidates if c.get('priority') == 'HIGH']
        
        for candidate in high_impact_roles:
            role = candidate['role']
            identities = candidate['identities']
            projects = candidate['projects']
            
            # Suggest creating an org-level group for this role
            policy_suggestion = {
                'policy_type': 'organization_role_assignment',
                'role': role,
                'suggested_group': f"org-{role.split('/')[-1].replace('.', '-')}-group",
                'affected_identities': identities,
                'affected_projects': projects,
                'implementation_steps': [
                    f"1. Create Google Group: org-{role.split('/')[-1].replace('.', '-')}-group@yourdomain.com",
                    f"2. Add {len(identities)} identities to the group",
                    f"3. Grant {role} to the group at organization level",
                    f"4. Remove individual project-level assignments for {len(projects)} projects",
                    "5. Test and verify access works correctly"
                ],
                'estimated_reduction': f"{len(projects) * len(identities)} individual IAM bindings",
                'priority': candidate['priority'],
                'complexity': candidate['implementation_complexity']
            }
            
            org_policies.append(policy_suggestion)
        
        # Folder-level suggestions for medium-impact opportunities
        medium_impact_roles = [c for c in org_candidates if c.get('priority') == 'MEDIUM']
        
        for candidate in medium_impact_roles[:5]:  # Limit to top 5 medium impact
            role = candidate['role']
            identities = candidate['identities']
            projects = candidate['projects']
            
            policy_suggestion = {
                'policy_type': 'folder_level_assignment',
                'role': role,
                'suggested_group': f"folder-{role.split('/')[-1].replace('.', '-')}-group",
                'affected_identities': identities,
                'affected_projects': projects,
                'implementation_steps': [
                    "1. Identify appropriate folder structure for projects",
                    f"2. Create Google Group: folder-{role.split('/')[-1].replace('.', '-')}-group@yourdomain.com",
                    f"3. Add {len(identities)} identities to the group",
                    f"4. Grant {role} to the group at folder level",
                    f"5. Remove individual project-level assignments"
                ],
                'estimated_reduction': f"{len(projects) * len(identities)} individual IAM bindings",
                'priority': 'MEDIUM',
                'complexity': 'HIGH'  # Folder-level changes are more complex
            }
            
            org_policies.append(policy_suggestion)
        
        return sorted(org_policies, key=lambda x: {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}[x['priority']], reverse=True)
    
    def _find_duplicate_permissions(self, identities: Dict, roles_usage: Dict) -> Dict[str, Any]:
        """Find duplicate or redundant permission assignments."""
        analysis = {
            'redundant_assignments': [],
            'overlapping_roles': []
        }
        
        # This would require detailed role permission data
        # For now, identify basic patterns
        
        for member, data in identities.items():
            roles = list(data['roles'])
            
            # Check for basic role redundancy
            if 'roles/owner' in roles and ('roles/editor' in roles or 'roles/viewer' in roles):
                analysis['redundant_assignments'].append({
                    'identity': data['email'],
                    'issue': 'Has Owner role with redundant Editor/Viewer roles',
                    'roles': roles,
                    'recommendation': 'Remove Editor/Viewer roles as Owner includes these permissions'
                })
            
            if 'roles/editor' in roles and 'roles/viewer' in roles:
                analysis['redundant_assignments'].append({
                    'identity': data['email'],
                    'issue': 'Has Editor role with redundant Viewer role',
                    'roles': roles,
                    'recommendation': 'Remove Viewer role as Editor includes these permissions'
                })
        
        return analysis
    
    def _analyze_unused_access(self, identities: Dict) -> Dict[str, Any]:
        """Analyze potentially unused access with enhanced inactive identity detection."""
        analysis = {
            'potentially_unused': [],
            'stale_service_accounts': [],
            'inactive_users': [],
            'never_used_identities': [],
            'inactive_30_days': [],
            'inactive_90_days': [],
            'usage_summary': {
                'total_identities': len(identities),
                'potentially_inactive': 0,
                'never_used_count': 0,
                'inactive_30_count': 0,
                'inactive_90_count': 0
            }
        }
        
        current_time = datetime.now()
        thirty_days_ago = current_time - timedelta(days=30)
        ninety_days_ago = current_time - timedelta(days=90)
        
        for member, data in identities.items():
            identity_email = data['email']
            identity_type = data['identity_type']
            last_activity = data.get('last_activity', current_time)
            first_seen = data.get('first_seen', current_time)
            
            # Detect inactive identities based on patterns and heuristics
            # Since we don't have audit logs, we use creation patterns and role assignments
            
            # Service accounts with minimal activity indicators
            if identity_type == 'serviceAccount':
                # Single role, single project service accounts are often unused
                if (len(data['projects']) == 1 and len(data['roles']) == 1):
                    analysis['stale_service_accounts'].append({
                        'identity': identity_email,
                        'projects': list(data['projects']),
                        'roles': list(data['roles']),
                        'reason': 'Single role in single project - likely test or abandoned',
                        'recommendation': 'Verify if still needed, consider removing',
                        'risk_level': 'LOW'
                    })
                
                # Service accounts with viewer-only access might be unused
                if data['roles'] == {'roles/viewer'}:
                    analysis['potentially_unused'].append({
                        'identity': identity_email,
                        'type': 'Service Account',
                        'projects': list(data['projects']),
                        'roles': list(data['roles']),
                        'reason': 'Viewer-only access - possibly unused monitoring account',
                        'recommendation': 'Check if monitoring/logging is actually happening',
                        'risk_level': 'LOW'
                    })
            
            # User accounts with suspicious patterns
            elif identity_type == 'user':
                # External users (Gmail addresses) - higher scrutiny
                if data['domain'] in ['gmail.com', 'googlemail.com']:
                    analysis['inactive_users'].append({
                        'identity': identity_email,
                        'domain': data['domain'],
                        'projects': list(data['projects']),
                        'roles': list(data['roles']),
                        'reason': 'External user - requires regular access review',
                        'recommendation': 'Verify current employment status and need',
                        'risk_level': 'HIGH',
                        'category': 'external_user'
                    })
                
                # Users with only viewer access might be inactive
                if len(data['roles']) == 1 and list(data['roles'])[0] == 'roles/viewer':
                    analysis['potentially_unused'].append({
                        'identity': identity_email,
                        'type': 'User',
                        'projects': list(data['projects']),
                        'roles': list(data['roles']),
                        'reason': 'Viewer-only access - possibly inactive',
                        'recommendation': 'Confirm if user still needs access',
                        'risk_level': 'MEDIUM'
                    })
            
            # Heuristic-based inactive detection (since we don't have real audit logs)
            # We simulate activity detection based on role assignments and patterns
            
            # "Never used" - accounts with minimal roles and single project
            if (len(data['roles']) <= 1 and 
                len(data['projects']) == 1 and 
                identity_type != 'group'):
                analysis['never_used_identities'].append({
                    'identity': identity_email,
                    'type': identity_type,
                    'projects': list(data['projects']),
                    'roles': list(data['roles']),
                    'reason': 'Minimal access pattern suggests never used',
                    'recommendation': 'Remove if confirmed unused',
                    'confidence': 'MEDIUM'
                })
                analysis['usage_summary']['never_used_count'] += 1
            
            # Simulate "30 days inactive" based on role complexity
            # Simple roles in single projects are more likely to be inactive
            elif (len(data['roles']) <= 2 and 
                  len(data['projects']) <= 2 and
                  not any(role in ['roles/owner', 'roles/editor'] for role in data['roles'])):
                analysis['inactive_30_days'].append({
                    'identity': identity_email,
                    'type': identity_type,
                    'projects': list(data['projects']),
                    'roles': list(data['roles']),
                    'reason': 'Limited access pattern - possibly inactive for 30+ days',
                    'recommendation': 'Verify recent activity and current need',
                    'confidence': 'LOW',
                    'suggested_action': 'Monitor for another 30 days before removal'
                })
                analysis['usage_summary']['inactive_30_count'] += 1
            
            # Simulate "90 days inactive" - broader pattern
            elif (len(data['projects']) <= 3 and 
                  identity_type == 'user' and 
                  not any(role in ['roles/owner'] for role in data['roles'])):
                analysis['inactive_90_days'].append({
                    'identity': identity_email,
                    'type': identity_type,
                    'projects': list(data['projects']),
                    'roles': list(data['roles']),
                    'reason': 'Access pattern suggests possible 90+ day inactivity',
                    'recommendation': 'Schedule access review with user',
                    'confidence': 'LOW',
                    'suggested_action': 'Contact user to confirm ongoing need'
                })
                analysis['usage_summary']['inactive_90_count'] += 1
        
        # Update summary
        analysis['usage_summary']['potentially_inactive'] = (
            len(analysis['potentially_unused']) + 
            len(analysis['stale_service_accounts']) + 
            len(analysis['inactive_users'])
        )
        
        # Sort by risk level and impact
        risk_priority = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        
        for category in ['potentially_unused', 'stale_service_accounts', 'inactive_users']:
            analysis[category].sort(
                key=lambda x: (risk_priority.get(x.get('risk_level', 'LOW'), 0), len(x.get('projects', []))), 
                reverse=True
            )
        
        return analysis
    
    def _generate_recommendations(self, identities: Dict, roles_usage: Dict, cross_project: Dict) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations for IAM optimization."""
        recommendations = []
        
        # High-priority security recommendations
        external_users = [i for i in identities.values() 
                         if i['identity_type'] == 'user' and i['domain'] in ['gmail.com', 'googlemail.com']]
        if external_users:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Security',
                'title': f'Review {len(external_users)} external users with Gmail addresses',
                'description': 'External users may pose security risks',
                'action': 'Audit external user access and consider removing or restricting',
                'impact': f'{len(external_users)} identities affected'
            })
        
        # Basic role replacement
        basic_role_users = sum(1 for r in roles_usage.values() 
                              if r['is_basic_role'] and len(r['identities']) > 0)
        if basic_role_users > 0:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Optimization',
                'title': f'Replace {basic_role_users} basic role assignments with specific roles',
                'description': 'Basic roles (Owner/Editor/Viewer) grant broad permissions',
                'action': 'Replace with specific predefined roles following principle of least privilege',
                'impact': f'Improved security posture across multiple projects'
            })
        
        # Grouping opportunities
        multi_project_users = [i for i in identities.values() if len(i['projects']) > 2]
        if len(multi_project_users) > 5:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Management',
                'title': f'Create groups for {len(multi_project_users)} users with multi-project access',
                'description': 'Users with access to multiple projects can be managed more efficiently through groups',
                'action': 'Create Google Groups and assign roles to groups instead of individual users',
                'impact': 'Simplified IAM management and easier access reviews'
            })
        
        # Organization-level opportunities
        org_candidates = [role for role, projects in cross_project['role_patterns'].items() 
                         if len(projects) > 3]
        if org_candidates:
            recommendations.append({
                'priority': 'LOW',
                'category': 'Optimization',
                'title': f'Consider organization-level assignment for {len(org_candidates)} roles',
                'description': 'Some roles are used across many projects and could be inherited',
                'action': 'Move frequently used roles to organization or folder level',
                'impact': 'Reduced management overhead and improved consistency'
            })
        
        return recommendations
    
    def analyze_with_cloudfast(self, projects_data: Dict[str, Dict], 
                              organization_hierarchy: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Enhanced analysis incorporating CloudFast organizational patterns.
        
        Args:
            projects_data: Dict mapping project_id to IAM policy data
            organization_hierarchy: Optional organization hierarchy data
            
        Returns:
            Dict containing enhanced analysis with CloudFast insights
        """
        logger.info("Performing CloudFast-enhanced IAM analysis")
        
        # Perform base analysis
        base_analysis = self.analyze_project_data(projects_data)
        
        # Add CloudFast analysis if available
        cloudfast_insights = {}
        if self.cloudfast_analyzer and organization_hierarchy:
            cloudfast_insights = self._analyze_cloudfast_patterns(organization_hierarchy, projects_data)
        
        # Enhance recommendations with CloudFast context
        enhanced_recommendations = self._enhance_recommendations_with_cloudfast(
            base_analysis['recommendations'], cloudfast_insights
        )
        
        return {
            **base_analysis,
            'cloudfast_analysis': cloudfast_insights,
            'recommendations': enhanced_recommendations,
            'squad_based_insights': self._generate_squad_insights(cloudfast_insights, projects_data)
        }
    
    def _analyze_cloudfast_patterns(self, hierarchy: Dict[str, Any], 
                                   projects_data: Dict[str, Dict]) -> Dict[str, Any]:
        """
        Analyze CloudFast patterns and their IAM implications.
        
        Args:
            hierarchy: Organization hierarchy
            projects_data: Project IAM data
            
        Returns:
            Dict containing CloudFast analysis results
        """
        if not self.cloudfast_analyzer:
            return {}
        
        try:
            # Perform CloudFast analysis
            cloudfast_analysis = self.cloudfast_analyzer.analyze_organization(hierarchy)
            
            # Map projects to squads/environments
            project_squad_mapping = self._map_projects_to_squads(projects_data, cloudfast_analysis)
            
            # Analyze IAM patterns within CloudFast structure
            squad_iam_analysis = self._analyze_squad_iam_patterns(project_squad_mapping, projects_data)
            
            return {
                'pattern_type': cloudfast_analysis.pattern_type.value,
                'confidence_score': cloudfast_analysis.confidence_score,
                'squad_count': len(cloudfast_analysis.squads),
                'environment_types': cloudfast_analysis.environments,
                'squads': [{
                    'name': squad.name,
                    'environments': len(squad.environments),
                    'folder_id': squad.folder_id,
                    'environment_types': [env.environment_type for env in squad.environments]
                } for squad in cloudfast_analysis.squads],
                'project_squad_mapping': project_squad_mapping,
                'squad_iam_analysis': squad_iam_analysis,
                'cloudfast_recommendations': cloudfast_analysis.recommendations
            }
            
        except Exception as e:
            logger.error(f"Error in CloudFast analysis: {e}")
            return {}
    
    def _map_projects_to_squads(self, projects_data: Dict[str, Dict], 
                               cloudfast_analysis) -> Dict[str, Dict[str, str]]:
        """
        Map projects to their squad and environment context.
        
        Args:
            projects_data: Project IAM data
            cloudfast_analysis: CloudFast analysis results
            
        Returns:
            Dict mapping project_id to squad/environment info
        """
        project_mapping = {}
        
        # For now, use heuristics to map projects to squads
        # In a real implementation, this would use the folder hierarchy
        for project_id in projects_data.keys():
            # Extract squad/environment from project naming patterns
            squad_info = self._extract_squad_from_project_name(project_id, cloudfast_analysis)
            project_mapping[project_id] = squad_info
        
        return project_mapping
    
    def _extract_squad_from_project_name(self, project_id: str, cloudfast_analysis) -> Dict[str, str]:
        """
        Extract squad and environment information from project name.
        
        Args:
            project_id: Project identifier
            cloudfast_analysis: CloudFast analysis results
            
        Returns:
            Dict with squad and environment information
        """
        # Common CloudFast project naming patterns:
        # squad-env-purpose, env-squad-purpose, squad-purpose-env
        project_lower = project_id.lower().replace('_', '-')
        parts = project_lower.split('-')
        
        # Look for environment patterns
        env_patterns = ['dev', 'test', 'stage', 'staging', 'prod', 'production', 'sandbox']
        detected_env = None
        for part in parts:
            if any(env in part for env in env_patterns):
                detected_env = part
                break
        
        # Look for squad patterns (assuming first non-env part is squad)
        detected_squad = None
        for part in parts:
            if part != detected_env and len(part) > 2:  # Avoid short words like 'ui', 'api'
                detected_squad = part
                break
        
        return {
            'squad': detected_squad or 'unknown',
            'environment': detected_env or 'unknown',
            'project_id': project_id
        }
    
    def _analyze_squad_iam_patterns(self, project_mapping: Dict[str, Dict], 
                                   projects_data: Dict[str, Dict]) -> Dict[str, Any]:
        """
        Analyze IAM patterns within squad structure.
        
        Args:
            project_mapping: Project to squad mapping
            projects_data: Project IAM data
            
        Returns:
            Dict containing squad-based IAM analysis
        """
        squad_analysis = defaultdict(lambda: {
            'projects': set(),
            'environments': set(),
            'users': set(),
            'roles': set(),
            'cross_env_users': set(),
            'environment_specific_roles': defaultdict(set)
        })
        
        # Analyze each project within squad context
        for project_id, policy_data in projects_data.items():
            if not policy_data or 'bindings' not in policy_data:
                continue
            
            squad_info = project_mapping.get(project_id, {})
            squad = squad_info.get('squad', 'unknown')
            environment = squad_info.get('environment', 'unknown')
            
            squad_data = squad_analysis[squad]
            squad_data['projects'].add(project_id)
            squad_data['environments'].add(environment)
            
            # Track users and roles per squad
            for binding in policy_data['bindings']:
                role = binding['role']
                members = binding.get('members', [])
                
                squad_data['roles'].add(role)
                squad_data['environment_specific_roles'][environment].add(role)
                
                for member in members:
                    if member.startswith('user:'):
                        squad_data['users'].add(member)
                        
                        # Check if user has access to multiple environments in this squad
                        user_envs = set()
                        for other_proj, other_squad_info in project_mapping.items():
                            if other_squad_info.get('squad') == squad:
                                for other_binding in projects_data.get(other_proj, {}).get('bindings', []):
                                    if member in other_binding.get('members', []):
                                        user_envs.add(other_squad_info.get('environment'))
                        
                        if len(user_envs) > 1:
                            squad_data['cross_env_users'].add(member)
        
        # Convert sets to lists for JSON serialization
        result = {}
        for squad, data in squad_analysis.items():
            result[squad] = {
                'projects': list(data['projects']),
                'environments': list(data['environments']),
                'user_count': len(data['users']),
                'role_count': len(data['roles']),
                'cross_environment_users': list(data['cross_env_users']),
                'environment_role_distribution': {
                    env: list(roles) for env, roles in data['environment_specific_roles'].items()
                }
            }
        
        return result
    
    def _enhance_recommendations_with_cloudfast(self, base_recommendations: List[Dict], 
                                               cloudfast_insights: Dict) -> List[Dict]:
        """
        Enhance recommendations with CloudFast-specific insights.
        
        Args:
            base_recommendations: Base IAM recommendations
            cloudfast_insights: CloudFast analysis results
            
        Returns:
            Enhanced recommendations list
        """
        enhanced_recommendations = base_recommendations.copy()
        
        if not cloudfast_insights:
            return enhanced_recommendations
        
        # Add CloudFast-specific recommendations
        pattern_type = cloudfast_insights.get('pattern_type', 'unknown')
        squad_count = cloudfast_insights.get('squad_count', 0)
        
        if pattern_type == 'squad_based' and squad_count > 0:
            enhanced_recommendations.insert(0, {
                'priority': 'HIGH',
                'category': 'CloudFast Optimization',
                'title': f'Optimize IAM for {squad_count} squad-based structure',
                'description': 'CloudFast squad-based organization detected - leverage for IAM optimization',
                'action': 'Implement squad-level Google Groups and environment-specific role inheritance',
                'impact': f'Streamlined IAM management across {squad_count} squads',
                'cloudfast_specific': True
            })
        
        # Add squad-specific recommendations
        squad_iam_analysis = cloudfast_insights.get('squad_iam_analysis', {})
        for squad, analysis in squad_iam_analysis.items():
            if len(analysis.get('cross_environment_users', [])) > 2:
                enhanced_recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'Squad Management',
                    'title': f'Optimize cross-environment access for squad "{squad}"',
                    'description': f'Squad has {len(analysis["cross_environment_users"])} users with multi-environment access',
                    'action': f'Create squad-level groups with environment inheritance for {squad}',
                    'impact': 'Improved squad autonomy and simplified access management',
                    'cloudfast_specific': True,
                    'squad': squad
                })
        
        # Add CloudFast recommendations from analyzer
        for cf_rec in cloudfast_insights.get('cloudfast_recommendations', []):
            enhanced_recommendations.append({
                'priority': 'MEDIUM',
                'category': 'CloudFast Structure',
                'title': cf_rec,
                'description': 'CloudFast pattern analysis recommendation',
                'action': 'Review and implement based on CloudFast best practices',
                'impact': 'Improved organizational structure alignment',
                'cloudfast_specific': True
            })
        
        return enhanced_recommendations
    
    def _generate_squad_insights(self, cloudfast_insights: Dict, 
                                projects_data: Dict[str, Dict]) -> Dict[str, Any]:
        """
        Generate squad-specific insights for CloudFast organizations.
        
        Args:
            cloudfast_insights: CloudFast analysis results
            projects_data: Project IAM data
            
        Returns:
            Dict containing squad-specific insights
        """
        if not cloudfast_insights:
            return {}
        
        squad_insights = {
            'total_squads': cloudfast_insights.get('squad_count', 0),
            'pattern_confidence': cloudfast_insights.get('confidence_score', 0),
            'squad_summaries': [],
            'optimization_opportunities': []
        }
        
        squad_iam_analysis = cloudfast_insights.get('squad_iam_analysis', {})
        
        for squad, analysis in squad_iam_analysis.items():
            squad_summary = {
                'name': squad,
                'project_count': len(analysis.get('projects', [])),
                'environment_count': len(analysis.get('environments', [])),
                'user_count': analysis.get('user_count', 0),
                'role_count': analysis.get('role_count', 0),
                'cross_env_user_count': len(analysis.get('cross_environment_users', [])),
                'optimization_score': self._calculate_squad_optimization_score(analysis)
            }
            squad_insights['squad_summaries'].append(squad_summary)
            
            # Generate optimization opportunities
            if squad_summary['cross_env_user_count'] > 1:
                squad_insights['optimization_opportunities'].append({
                    'squad': squad,
                    'type': 'group_consolidation',
                    'description': f'Create squad-level group for {squad_summary["cross_env_user_count"]} cross-environment users',
                    'impact': 'high'
                })
            
            if squad_summary['role_count'] > 10:
                squad_insights['optimization_opportunities'].append({
                    'squad': squad,
                    'type': 'role_standardization',
                    'description': f'Standardize {squad_summary["role_count"]} roles across squad environments',
                    'impact': 'medium'
                })
        
        return squad_insights
    
    def _calculate_squad_optimization_score(self, squad_analysis: Dict[str, Any]) -> float:
        """
        Calculate optimization score for a squad (0-1, higher is better optimized).
        
        Args:
            squad_analysis: Squad IAM analysis data
            
        Returns:
            Float optimization score
        """
        score = 1.0
        
        # Penalize excessive cross-environment users (suggests need for groups)
        cross_env_users = len(squad_analysis.get('cross_environment_users', []))
        total_users = squad_analysis.get('user_count', 1)
        if cross_env_users / total_users > 0.5:
            score -= 0.3
        
        # Penalize high role count (suggests need for standardization)
        role_count = squad_analysis.get('role_count', 0)
        if role_count > 15:
            score -= 0.2
        elif role_count > 10:
            score -= 0.1
        
        # Reward consistent environment structure
        environments = squad_analysis.get('environments', [])
        if len(environments) >= 3:  # dev, staging, prod
            score += 0.1
        
        return max(0.0, min(1.0, score))
