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

logger = logging.getLogger(__name__)


class IAMInsights:
    """Advanced IAM analytics and insights generator."""
    
    def __init__(self):
        self.insights = []
        self.recommendations = []
        
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
        """Generate gcloud commands for implementing a group."""
        commands = []
        group_name = group['suggested_group_name']
        
        # Create group command (assuming Google Groups)
        commands.append(f"# Create Google Group: {group_name}")
        commands.append(f"# This should be done through Google Admin Console or Groups API")
        commands.append(f"# Group email: {group_name}@yourdomain.com")
        commands.append("")
        
        # Add members to group
        commands.append(f"# Add members to {group_name}")
        for user in group['users']:
            commands.append(f"# Add {user} to group via Admin Console")
        commands.append("")
        
        # Grant roles to group
        roles = group.get('roles', group.get('suggested_roles', []))
        projects = group.get('all_projects', group.get('projects', []))
        
        if roles and projects:
            commands.append(f"# Grant roles to group {group_name}@yourdomain.com")
            for project in projects:
                for role in roles:
                    commands.append(
                        f"gcloud projects add-iam-policy-binding {project} "
                        f"--member='group:{group_name}@yourdomain.com' "
                        f"--role='{role}'"
                    )
            commands.append("")
            
            # Remove individual user permissions
            commands.append(f"# Remove individual user permissions (after group is verified)")
            for user in group['users']:
                for project in projects:
                    for role in roles:
                        commands.append(
                            f"gcloud projects remove-iam-policy-binding {project} "
                            f"--member='user:{user}' "
                            f"--role='{role}'"
                        )
        
        return commands
    
    def _find_org_level_opportunities(self, cross_project: Dict) -> Dict[str, Any]:
        """Find opportunities to move permissions to organization level."""
        analysis = {
            'org_level_candidates': [],
            'folder_level_candidates': [],
            'inheritance_opportunities': []
        }
        
        # Roles used across many projects are candidates for org-level assignment
        for role, projects in cross_project['role_patterns'].items():
            if len(projects) > 3:  # Used in multiple projects
                analysis['org_level_candidates'].append({
                    'role': role,
                    'project_count': len(projects),
                    'projects': list(projects),
                    'recommendation': 'Move to organization level' if len(projects) > 5 else 'Consider folder-level assignment'
                })
        
        # Identities with broad access
        for identity, projects in cross_project['identity_patterns'].items():
            if len(projects) > 4:
                analysis['inheritance_opportunities'].append({
                    'identity': identity,
                    'project_count': len(projects),
                    'projects': list(projects),
                    'recommendation': 'Consider org-level or folder-level role assignment'
                })
        
        analysis['org_level_candidates'].sort(key=lambda x: x['project_count'], reverse=True)
        analysis['inheritance_opportunities'].sort(key=lambda x: x['project_count'], reverse=True)
        
        return analysis
    
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
        """Analyze potentially unused access (placeholder for audit log integration)."""
        analysis = {
            'potentially_unused': [],
            'stale_service_accounts': [],
            'inactive_users': []
        }
        
        # This would require audit log data for real analysis
        # For now, identify patterns that suggest potential unused access
        
        for member, data in identities.items():
            # Service accounts with only one role in one project might be unused
            if (data['identity_type'] == 'serviceAccount' and 
                len(data['projects']) == 1 and 
                len(data['roles']) == 1):
                analysis['potentially_unused'].append({
                    'identity': data['email'],
                    'type': 'Service Account',
                    'projects': list(data['projects']),
                    'roles': list(data['roles']),
                    'reason': 'Single role in single project - verify if still needed'
                })
        
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