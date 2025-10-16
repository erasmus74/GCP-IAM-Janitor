"""
Overview page for GCP IAM Janitor.

Displays high-level statistics, key metrics, and interactive visualizations
for IAM policies across selected projects and organizations.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import timedelta
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
from collections import defaultdict, Counter

from ..auth.credentials import get_session_credentials
from ..gcp.project_client import ProjectClient
from ..gcp.org_client import OrganizationClient
from ..gcp.iam_client import IAMClient
from ..models.iam_models import (
    ResourceIAMPolicy, 
    ResourceType, 
    Identity, 
    IdentityType,
    RoleType
)
from ..utils.cache import (
    ProgressTracker, 
    cached, 
    get_cache_manager,
    generate_recommendations
)

# CloudFast imports
try:
    from ..gcp.cloudfast_analyzer import CloudFastPattern
    from ..analytics.insights import IAMInsights
    CLOUDFAST_AVAILABLE = True
except ImportError:
    logger.warning("CloudFast features not available")
    CLOUDFAST_AVAILABLE = False

logger = logging.getLogger(__name__)


def load_iam_data(filters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Load and aggregate IAM data based on filters with intelligent cache invalidation.

    Args:
        filters: Dictionary containing filter criteria

    Returns:
        Dict[str, Any]: Aggregated IAM data
    """
    credentials, _ = get_session_credentials()
    if not credentials:
        return {}

    # Intelligent cache invalidation based on filter changes
    cache_manager = get_cache_manager()
    cache_invalidated = cache_manager.invalidate_by_filter_change(filters, context="overview")

    # Generate cache key
    cache_key = f"overview_load_iam_data_{cache_manager._generate_cache_key(filters)}"

    # Try to get cached data (only if not invalidated)
    if not cache_invalidated:
        cached_data = cache_manager.get(cache_key)
        if cached_data is not None:
            logger.debug("Cache hit for load_iam_data")
            # Even with cached data, show a quick "Loading from cache" message
            progress_placeholder = st.empty()
            progress_placeholder.success("✅ Loading data from cache...")
            return cached_data
    
    project_client = ProjectClient(credentials)
    org_client = OrganizationClient(credentials)
    iam_client = IAMClient(credentials)
    
    data = {
        'policies': [],
        'identities': {},
        'roles': {},
        'organizations': [],
        'projects': [],
        'statistics': {
            'total_identities': 0,
            'total_roles': 0,
            'total_bindings': 0,
            'total_projects': 0,
            'total_organizations': 0
        }
    }
    
    try:
        # Determine total steps for progress tracking
        total_steps = 0
        if filters.get('selected_projects'):
            total_steps += len(filters['selected_projects'])
        if filters.get('selected_orgs'):
            total_steps += len(filters['selected_orgs'])
        
        if total_steps == 0:
            st.warning("No resources selected. Please select projects or organizations in the sidebar.")
            return data
        
        progress = ProgressTracker(total_steps, "Loading IAM data")
        
        # Load project-level data
        if filters.get('selected_projects'):
            for project_id in filters['selected_projects']:
                progress.step(f"Loading project: {project_id}")
                
                project_metadata = project_client.get_project_metadata(project_id)
                if project_metadata:
                    data['projects'].append(project_metadata)
                
                policy = project_client.get_project_iam_policy(project_id)
                if policy:
                    policy.resource_name = project_id
                    policy.resource_type = ResourceType.PROJECT
                    data['policies'].append(policy)
        
        # Load organization-level data
        if filters.get('selected_orgs'):
            for org_id in filters['selected_orgs']:
                progress.step(f"Loading organization: {org_id}")
                
                org_metadata = org_client.get_organization(org_id)
                if org_metadata:
                    data['organizations'].append(org_metadata)
                
                policy = org_client.get_organization_iam_policy(org_id)
                if policy:
                    policy.resource_name = org_id
                    policy.resource_type = ResourceType.ORGANIZATION
                    data['policies'].append(policy)
        
        # Process and aggregate data
        progress.set_progress(total_steps, "Processing IAM data...")
        
        all_identities = {}
        all_roles = set()
        total_bindings = 0
        
        for policy in data['policies']:
            total_bindings += len(policy.bindings)
            
            for binding in policy.bindings:
                all_roles.add(binding.role)
                
                for member in binding.members:
                    if member not in all_identities:
                        all_identities[member] = Identity.from_member_string(member)
                    
                    identity = all_identities[member]
                    identity.roles_assigned.add(binding.role)
                    identity.projects_with_access.add(policy.resource_name)
        
        # Update statistics
        data['identities'] = all_identities
        data['statistics'].update({
            'total_identities': len(all_identities),
            'total_roles': len(all_roles),
            'total_bindings': total_bindings,
            'total_projects': len(data['projects']),
            'total_organizations': len(data['organizations'])
        })
        
        # Load role details for analysis
        roles_cache_key = "predefined_roles"
        cached_roles = get_cache_manager().get(roles_cache_key)
        
        if cached_roles is None:
            try:
                predefined_roles = iam_client.list_roles()
                roles_dict = {role.name: role for role in predefined_roles}
                get_cache_manager().set(roles_cache_key, roles_dict)
                data['roles'] = roles_dict
            except Exception as e:
                logger.warning(f"Could not load role details: {e}")
                data['roles'] = {}
        else:
            data['roles'] = cached_roles
        
        # Complete the progress and clean up UI elements
        progress.complete("Analysis complete!")
        
        # Cache the result for future use
        cache_manager.set(cache_key, data, timedelta(minutes=30))
        
        return data
        
    except Exception as e:
        logger.error(f"Error loading IAM data: {e}")
        # Clean up any progress UI elements that might be hanging
        try:
            if 'progress' in locals():
                progress.cleanup()
        except:
            pass
        st.error(f"Error loading data: {str(e)}")
        return data


def create_cloudfast_overview(data: Dict[str, Any]) -> None:
    """
    Create CloudFast organizational pattern overview section.
    """
    if not CLOUDFAST_AVAILABLE:
        return
    
    try:
        credentials, _ = get_session_credentials()
        if not credentials:
            return
        
        # Check if we have organization data
        orgs = data.get('organizations', [])
        if not orgs:
            return
        
        org_client = OrganizationClient(credentials)
        
        st.subheader("🌐 CloudFast Organization Analysis")
        
        # Analyze the first organization (or let user select if multiple)
        org_to_analyze = orgs[0]['organization_id'] if orgs else None
        
        if len(orgs) > 1:
            org_options = {org['display_name']: org['organization_id'] for org in orgs}
            selected_org_name = st.selectbox(
                "Select organization for CloudFast analysis:",
                list(org_options.keys())
            )
            org_to_analyze = org_options[selected_org_name]
        
        if org_to_analyze:
            # Get CloudFast analysis
            with st.spinner("Analyzing CloudFast patterns..."):
                cloudfast_analysis = org_client.analyze_cloudfast_patterns(org_to_analyze)
            
            if cloudfast_analysis.confidence_score > 0:
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    pattern_emoji = {
                        'squad_based': '👥',
                        'environment_first': '🌍', 
                        'business_unit': '🏢',
                        'hybrid': '🔀',
                        'unknown': '❓'
                    }
                    st.metric(
                        label="Organization Pattern",
                        value=f"{pattern_emoji.get(cloudfast_analysis.pattern_type.value, '❓')} {cloudfast_analysis.pattern_type.value.replace('_', ' ').title()}",
                        help=f"Confidence: {cloudfast_analysis.confidence_score:.1%}"
                    )
                
                with col2:
                    st.metric(
                        label="Squads Detected",
                        value=len(cloudfast_analysis.squads),
                        help="Number of squad-based organizational units"
                    )
                
                with col3:
                    st.metric(
                        label="Environment Types",
                        value=len(cloudfast_analysis.environments),
                        help=f"Environments: {', '.join(cloudfast_analysis.environments)}"
                    )
                
                with col4:
                    confidence_color = "green" if cloudfast_analysis.confidence_score > 0.7 else "orange" if cloudfast_analysis.confidence_score > 0.4 else "red"
                    st.metric(
                        label="Pattern Confidence",
                        value=f"{cloudfast_analysis.confidence_score:.1%}",
                        delta=None,
                        help="How confident the analysis is about the detected pattern"
                    )
                    st.markdown(f"<style>.metric-container {{border-left: 4px solid {confidence_color};}}</style>", unsafe_allow_html=True)
                
                # CloudFast recommendations
                if cloudfast_analysis.recommendations:
                    st.subheader("💡 CloudFast Recommendations")
                    for rec in cloudfast_analysis.recommendations[:5]:  # Show top 5
                        if rec.startswith('✅'):
                            st.success(rec)
                        elif rec.startswith('⚠️') or rec.startswith('❓'):
                            st.warning(rec)
                        else:
                            st.info(rec)
                
                # Squad details if available
                if cloudfast_analysis.squads:
                    st.subheader("👥 Squad Overview")
                    squad_data = []
                    for squad in cloudfast_analysis.squads:
                        squad_data.append({
                            'Squad': squad.name,
                            'Environments': len(squad.environments),
                            'Environment Types': ', '.join(set(env.environment_type for env in squad.environments)),
                            'Total Projects': squad.total_projects
                        })
                    
                    if squad_data:
                        df = pd.DataFrame(squad_data)
                        st.dataframe(df, use_container_width=True)
            else:
                st.info("No clear CloudFast patterns detected in this organization.")
                
    except Exception as e:
        logger.warning(f"CloudFast analysis failed: {e}")
        # Don't show error to user - just skip the CloudFast section


def create_overview_metrics(data: Dict[str, Any]) -> None:
    """Create overview metric cards."""
    stats = data.get('statistics', {})
    
    st.subheader("📊 Overview Metrics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="Total Identities",
            value=stats.get('total_identities', 0),
            help="Unique users, service accounts, and groups"
        )
    
    with col2:
        st.metric(
            label="Total Roles",
            value=stats.get('total_roles', 0),
            help="Unique roles assigned across all resources"
        )
    
    with col3:
        st.metric(
            label="IAM Bindings",
            value=stats.get('total_bindings', 0),
            help="Total number of role-to-identity bindings"
        )
    
    with col4:
        st.metric(
            label="Resources Analyzed",
            value=stats.get('total_projects', 0) + stats.get('total_organizations', 0),
            help="Projects and organizations analyzed"
        )


def create_identity_analysis_chart(identities: Dict[str, Identity]) -> None:
    """Create identity type analysis chart."""
    if not identities:
        st.info("No identity data available")
        return
    
    # Count identities by type
    identity_counts = Counter()
    for identity in identities.values():
        identity_counts[identity.identity_type.value.title()] += 1
    
    if not identity_counts:
        st.info("No identity data to display")
        return
    
    # Create pie chart
    fig = px.pie(
        values=list(identity_counts.values()),
        names=list(identity_counts.keys()),
        title="Identity Distribution by Type",
        color_discrete_sequence=px.colors.qualitative.Set3
    )
    
    fig.update_traces(textposition='inside', textinfo='percent+label')
    fig.update_layout(showlegend=True, height=400)
    
    st.plotly_chart(fig, use_container_width=True)


def create_roles_per_identity_chart(identities: Dict[str, Identity]) -> None:
    """Create chart showing roles per identity distribution."""
    if not identities:
        return
    
    # Count roles per identity
    roles_per_identity = [len(identity.roles_assigned) for identity in identities.values()]
    
    if not roles_per_identity:
        return
    
    # Create histogram
    fig = px.histogram(
        x=roles_per_identity,
        nbins=20,
        title="Distribution of Roles per Identity",
        labels={'x': 'Number of Roles', 'y': 'Number of Identities'},
        color_discrete_sequence=['#1f77b4']
    )
    
    fig.update_layout(
        showlegend=False,
        height=400,
        xaxis_title="Number of Roles Assigned",
        yaxis_title="Number of Identities"
    )
    
    st.plotly_chart(fig, use_container_width=True)


def create_project_bindings_chart(policies: List[ResourceIAMPolicy]) -> None:
    """Create chart showing IAM bindings per project."""
    if not policies:
        return
    
    # Group policies by project and count bindings
    project_bindings = {}
    for policy in policies:
        if policy.resource_type == ResourceType.PROJECT:
            project_bindings[policy.resource_name] = len(policy.bindings)
    
    if not project_bindings:
        st.info("No project data available for chart")
        return
    
    # Create bar chart
    fig = px.bar(
        x=list(project_bindings.keys()),
        y=list(project_bindings.values()),
        title="IAM Bindings per Project",
        labels={'x': 'Project ID', 'y': 'Number of IAM Bindings'},
        color_discrete_sequence=['#2ca02c']
    )
    
    fig.update_layout(
        showlegend=False,
        height=400,
        xaxis_title="Project ID",
        yaxis_title="Number of IAM Bindings",
        xaxis_tickangle=-45
    )
    
    st.plotly_chart(fig, use_container_width=True)


def create_top_roles_chart(identities: Dict[str, Identity]) -> None:
    """Create chart showing most assigned roles."""
    if not identities:
        return
    
    # Count role assignments
    role_counts = Counter()
    for identity in identities.values():
        for role in identity.roles_assigned:
            role_counts[role] += 1
    
    # Get top 15 roles
    top_roles = dict(role_counts.most_common(15))
    
    if not top_roles:
        return
    
    # Create horizontal bar chart
    fig = px.bar(
        x=list(top_roles.values()),
        y=list(top_roles.keys()),
        orientation='h',
        title="Top 15 Most Assigned Roles",
        labels={'x': 'Number of Assignments', 'y': 'Role Name'},
        color_discrete_sequence=['#ff7f0e']
    )
    
    fig.update_layout(
        showlegend=False,
        height=600,
        xaxis_title="Number of Assignments",
        yaxis_title="Role Name"
    )
    
    st.plotly_chart(fig, use_container_width=True)


def create_security_insights(data: Dict[str, Any]) -> None:
    """Create security insights section."""
    st.subheader("🛡️ Security Insights")
    
    identities = data.get('identities', {})
    roles = data.get('roles', {})
    
    if not identities:
        st.info("No data available for security analysis")
        return
    
    # Analyze overprivileged identities
    overprivileged = []
    external_users = []
    service_accounts = []
    
    for identity in identities.values():
        if len(identity.roles_assigned) > 5:
            overprivileged.append(identity)
        
        if identity.identity_type == IdentityType.USER and identity.domain:
            if 'gmail.com' in identity.domain or 'googlemail.com' in identity.domain:
                external_users.append(identity)
        
        if identity.identity_type == IdentityType.SERVICE_ACCOUNT:
            service_accounts.append(identity)
    
    # Create warning cards
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if overprivileged:
            st.warning(f"⚠️ {len(overprivileged)} potentially overprivileged identities")
            with st.expander("View overprivileged identities"):
                for identity in overprivileged[:10]:  # Show top 10
                    st.write(f"• {identity.email} ({len(identity.roles_assigned)} roles)")
        else:
            st.success("✅ No overprivileged identities detected")
    
    with col2:
        if external_users:
            st.warning(f"⚠️ {len(external_users)} external users (Gmail accounts)")
            with st.expander("View external users"):
                for identity in external_users[:10]:
                    st.write(f"• {identity.email}")
        else:
            st.success("✅ No external users detected")
    
    with col3:
        if service_accounts:
            st.info(f"ℹ️ {len(service_accounts)} service accounts")
            with st.expander("Service account breakdown"):
                sa_projects = Counter()
                for sa in service_accounts:
                    for project in sa.projects_with_access:
                        sa_projects[project] += 1
                
                for project, count in sa_projects.most_common(5):
                    st.write(f"• {project}: {count} service accounts")
        else:
            st.info("No service accounts found")


def create_recommendations_section(data: Dict[str, Any]) -> None:
    """Create recommendations section."""
    st.subheader("💡 Recommendations")
    
    identities_list = list(data.get('identities', {}).values())
    roles_list = list(data.get('roles', {}).values())
    policies = data.get('policies', [])
    
    # Extract bindings for analysis
    all_bindings = []
    for policy in policies:
        all_bindings.extend(policy.bindings)
    
    try:
        recommendations = generate_recommendations(identities_list, roles_list, all_bindings)
        
        if recommendations:
            for i, rec in enumerate(recommendations[:5], 1):  # Show top 5 recommendations
                st.info(f"{i}. {rec}")
        else:
            st.success("🎉 No immediate recommendations - your IAM configuration looks good!")
    
    except Exception as e:
        logger.warning(f"Error generating recommendations: {e}")
        st.warning("Could not generate recommendations at this time")


def render_overview_page(filters: Dict[str, Any]) -> None:
    """
    Render the overview page.
    
    Args:
        filters: Dictionary containing filter criteria from sidebar
    """
    st.title("📊 IAM Overview")
    st.markdown("High-level view of IAM policies across your selected GCP resources")
    
    # Load data
    data = load_iam_data(filters)
    
    if not data or not data.get('policies'):
        st.warning("No IAM data available. Please select resources in the sidebar and ensure you have appropriate permissions.")
        return
    
    # CloudFast analysis (if organization data available)
    create_cloudfast_overview(data)
    
    # Overview metrics
    create_overview_metrics(data)
    
    st.markdown("---")
    
    # Charts section
    col1, col2 = st.columns(2)
    
    with col1:
        create_identity_analysis_chart(data.get('identities', {}))
    
    with col2:
        create_roles_per_identity_chart(data.get('identities', {}))
    
    # Additional charts
    col3, col4 = st.columns(2)
    
    with col3:
        create_project_bindings_chart(data.get('policies', []))
    
    with col4:
        create_top_roles_chart(data.get('identities', {}))
    
    st.markdown("---")
    
    # Security insights
    create_security_insights(data)
    
    st.markdown("---")
    
    # Recommendations
    create_recommendations_section(data)
    
    # Data export section
    st.markdown("---")
    st.subheader("📋 Export Data")
    
    col_export1, col_export2, col_export3 = st.columns(3)
    
    with col_export1:
        if st.button("📊 Export Overview Summary"):
            summary_data = {
                'statistics': data.get('statistics', {}),
                'timestamp': pd.Timestamp.now().isoformat(),
                'filters_applied': filters
            }
            
            st.download_button(
                label="Download Summary JSON",
                data=pd.DataFrame([summary_data]).to_json(orient='records'),
                file_name=f"iam_overview_summary_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    with col_export2:
        if data.get('identities') and st.button("👥 Export Identities"):
            identities_df = pd.DataFrame([
                {
                    'email': identity.email,
                    'type': identity.identity_type.value,
                    'domain': identity.domain,
                    'roles_count': len(identity.roles_assigned),
                    'projects_count': len(identity.projects_with_access),
                    'roles': ', '.join(identity.roles_assigned),
                    'projects': ', '.join(identity.projects_with_access)
                }
                for identity in data['identities'].values()
            ])
            
            csv = identities_df.to_csv(index=False)
            st.download_button(
                label="Download Identities CSV",
                data=csv,
                file_name=f"iam_identities_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    
    with col_export3:
        if st.button("📄 Generate Full Report"):
            st.info("Full report generation coming soon!")
    
    # Debug info (only show in development)
    if st.checkbox("Show Debug Info", value=False):
        st.subheader("🔧 Debug Information")
        st.json({
            'filters_applied': filters,
            'data_keys': list(data.keys()),
            'policies_count': len(data.get('policies', [])),
            'identities_count': len(data.get('identities', {})),
            'cache_stats': get_cache_manager().get_cache_stats()
        })