"""
GCP IAM Janitor - Enhanced Version with Intelligent Insights

A comprehensive web application for inventorying, analyzing, and optimizing 
GCP IAM with intelligent recommendations and actionable insights.
"""

import logging
import streamlit as st
from typing import Dict, Any, List, Optional
from google.cloud import resourcemanager
from google.auth import default
from google.auth.exceptions import DefaultCredentialsError
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Import our analytics module
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from src.analytics.insights import IAMInsights

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def configure_page():
    """Configure Streamlit page settings."""
    st.set_page_config(
        page_title="GCP IAM Janitor - Enhanced",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Custom CSS for better styling
    st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        text-align: center;
        color: #1f77b4;
        margin-bottom: 2rem;
    }
    
    .insight-card {
        background-color: #f0f8ff;
        border-left: 4px solid #1f77b4;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 0.5rem;
    }
    
    .warning-card {
        background-color: #fff3cd;
        border-left: 4px solid #ffc107;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 0.5rem;
    }
    
    .danger-card {
        background-color: #f8d7da;
        border-left: 4px solid #dc3545;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 0.5rem;
    }
    
    .success-card {
        background-color: #d1e7dd;
        border-left: 4px solid #198754;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 0.5rem;
    }
    
    .recommendation {
        background-color: #e8f4f8;
        border: 1px solid #bee5eb;
        border-radius: 0.5rem;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    </style>
    """, unsafe_allow_html=True)


def get_credentials():
    """Get Application Default Credentials."""
    try:
        credentials, project = default()
        return credentials, project
    except DefaultCredentialsError:
        return None, None


def list_projects(credentials):
    """List all accessible projects."""
    if not credentials:
        return []
    
    try:
        client = resourcemanager.ProjectsClient(credentials=credentials)
        projects = []
        
        request = resourcemanager.SearchProjectsRequest()
        for project in client.search_projects(request=request):
            # Get state safely
            state = 'ACTIVE'
            try:
                if hasattr(project, 'state') and project.state:
                    if hasattr(project.state, 'name'):
                        state = project.state.name
                    else:
                        state = str(project.state)
            except Exception:
                state = 'ACTIVE'
            
            # Get display name or fallback to name
            display_name = project.name
            try:
                if hasattr(project, 'display_name') and project.display_name:
                    display_name = project.display_name
            except Exception:
                pass
            
            projects.append({
                'project_id': project.project_id,
                'name': display_name,
                'lifecycle_state': state,
                'project_number': project.name.split('/')[-1] if '/' in project.name else 'N/A'
            })
        
        return projects
    except Exception as e:
        st.error(f"Error listing projects: {e}")
        return []


def get_project_iam_policy(credentials, project_id):
    """Get IAM policy for a project."""
    if not credentials:
        return None
    
    try:
        client = resourcemanager.ProjectsClient(credentials=credentials)
        policy = client.get_iam_policy(resource=f"projects/{project_id}")
        
        # Convert to dict for analysis
        policy_dict = {
            'bindings': []
        }
        
        for binding in policy.bindings:
            policy_dict['bindings'].append({
                'role': binding.role,
                'members': list(binding.members)
            })
        
        return policy_dict
    except Exception as e:
        st.warning(f"Could not get IAM policy for {project_id}: {e}")
        return None


def analyze_iam_data(projects_data):
    """Analyze IAM data from projects."""
    if not projects_data:
        return {}
    
    all_identities = set()
    all_roles = set()
    total_bindings = 0
    identity_types = {'user': 0, 'serviceAccount': 0, 'group': 0, 'other': 0}
    
    for project_id, policy in projects_data.items():
        if not policy or 'bindings' not in policy:
            continue
            
        total_bindings += len(policy['bindings'])
        
        for binding in policy['bindings']:
            all_roles.add(binding['role'])
            
            for member in binding['members']:
                all_identities.add(member)
                
                # Categorize identity type
                if member.startswith('user:'):
                    identity_types['user'] += 1
                elif member.startswith('serviceAccount:'):
                    identity_types['serviceAccount'] += 1
                elif member.startswith('group:'):
                    identity_types['group'] += 1
                else:
                    identity_types['other'] += 1
    
    return {
        'total_identities': len(all_identities),
        'total_roles': len(all_roles),
        'total_bindings': total_bindings,
        'identity_types': identity_types,
        'projects_analyzed': len(projects_data)
    }


def create_insights_dashboard(insights_data):
    """Create the main insights dashboard."""
    if not insights_data:
        st.info("No insights data available")
        return
    
    st.header("🧠 Intelligent Insights")
    
    # Recommendations section
    recommendations = insights_data.get('recommendations', [])
    if recommendations:
        st.subheader("🎯 Priority Recommendations")
        
        # Group by priority
        high_priority = [r for r in recommendations if r.get('priority') == 'HIGH']
        medium_priority = [r for r in recommendations if r.get('priority') == 'MEDIUM']
        low_priority = [r for r in recommendations if r.get('priority') == 'LOW']
        
        for rec in high_priority:
            st.markdown(f"""
            <div class="danger-card">
            <h4>🚨 HIGH PRIORITY: {rec['title']}</h4>
            <p><strong>Category:</strong> {rec['category']}</p>
            <p><strong>Description:</strong> {rec['description']}</p>
            <p><strong>Action:</strong> {rec['action']}</p>
            <p><strong>Impact:</strong> {rec['impact']}</p>
            </div>
            """, unsafe_allow_html=True)
        
        for rec in medium_priority:
            st.markdown(f"""
            <div class="warning-card">
            <h4>⚠️ MEDIUM PRIORITY: {rec['title']}</h4>
            <p><strong>Category:</strong> {rec['category']}</p>
            <p><strong>Description:</strong> {rec['description']}</p>
            <p><strong>Action:</strong> {rec['action']}</p>
            <p><strong>Impact:</strong> {rec['impact']}</p>
            </div>
            """, unsafe_allow_html=True)
        
        for rec in low_priority:
            st.markdown(f"""
            <div class="insight-card">
            <h4>💡 LOW PRIORITY: {rec['title']}</h4>
            <p><strong>Category:</strong> {rec['category']}</p>
            <p><strong>Description:</strong> {rec['description']}</p>
            <p><strong>Action:</strong> {rec['action']}</p>
            <p><strong>Impact:</strong> {rec['impact']}</p>
            </div>
            """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Detailed insights sections
    col1, col2 = st.columns(2)
    
    with col1:
        show_security_insights(insights_data.get('security_insights', {}))
        show_grouping_opportunities(insights_data.get('grouping_opportunities', {}))
    
    with col2:
        show_role_optimization(insights_data.get('roles_optimization', {}))
        show_org_level_opportunities(insights_data.get('organization_level_opportunities', {}))
    
    # Full-width sections
    show_identity_analysis(insights_data.get('identities_analysis', {}))
    show_duplicate_permissions(insights_data.get('duplicate_permissions', {}))


def show_security_insights(security_data):
    """Display security insights."""
    st.subheader("🛡️ Security Analysis")
    
    high_risk = security_data.get('high_risk_identities', [])
    external_access = security_data.get('external_access', [])
    sa_risks = security_data.get('service_account_risks', [])
    
    if high_risk:
        st.warning(f"⚠️ {len(high_risk)} high-risk identities detected")
        with st.expander("View high-risk identities"):
            for identity in high_risk[:5]:  # Show top 5
                st.write(f"**{identity['identity']}** (Risk Score: {identity['risk_score']})")
                st.write(f"- Type: {identity['type']}")
                st.write(f"- Dangerous roles: {', '.join(identity['dangerous_roles'])}")
                st.write(f"- Projects: {identity['project_count']}")
                st.write("---")
    
    if external_access:
        st.error(f"🔓 {len(external_access)} external users detected")
        with st.expander("View external users"):
            for user in external_access[:3]:
                st.write(f"**{user['email']}** ({user['domain']})")
                st.write(f"- Projects: {len(user['projects'])}")
                st.write(f"- Roles: {', '.join(user['roles'])}")
    
    if sa_risks:
        st.warning(f"🤖 {len(sa_risks)} risky service accounts")
        with st.expander("View service account risks"):
            for sa in sa_risks[:3]:
                st.write(f"**{sa['email']}**")
                st.write(f"- Reason: {sa['risk_reason']}")
                st.write(f"- Roles: {', '.join(sa['roles'])}")


def show_grouping_opportunities(grouping_data):
    """Display grouping opportunities."""
    st.subheader("👥 Grouping Opportunities")
    
    role_groups = grouping_data.get('role_based_groups', [])
    domain_groups = grouping_data.get('domain_based_groups', [])
    
    if role_groups:
        st.info(f"💡 {len(role_groups)} role-based grouping opportunities")
        with st.expander("View role-based groups"):
            for group in role_groups[:3]:
                st.write(f"**Suggested Group:** {group['suggested_group_name']}")
                st.write(f"- Users: {group['user_count']}")
                st.write(f"- Common roles: {', '.join(group['roles'])}")
                st.write("---")
    
    if domain_groups:
        st.info(f"🏢 {len(domain_groups)} domain-based grouping opportunities")
        with st.expander("View domain-based groups"):
            for group in domain_groups[:3]:
                st.write(f"**Domain:** {group['domain']}")
                st.write(f"- Users: {group['user_count']}")
                st.write(f"- Suggested group: {group['suggested_group_name']}")


def show_role_optimization(roles_data):
    """Display role optimization insights."""
    st.subheader("🔧 Role Optimization")
    
    basic_roles = roles_data.get('basic_roles_usage', [])
    cross_project = roles_data.get('cross_project_roles', [])
    underutilized = roles_data.get('underutilized_custom_roles', [])
    
    if basic_roles:
        st.warning(f"⚠️ {len(basic_roles)} basic role assignments to optimize")
        with st.expander("View basic role usage"):
            for role in basic_roles[:3]:
                st.write(f"**{role['role']}**")
                st.write(f"- Impact: {role['impact']}")
                st.write(f"- Projects: {', '.join(role['projects'])}")
    
    if cross_project:
        st.info(f"🔄 {len(cross_project)} roles used across multiple projects")
        with st.expander("View cross-project roles"):
            for role in cross_project[:5]:
                st.write(f"**{role['role']}**")
                st.write(f"- Used in {role['project_count']} projects")
                st.write(f"- {role['identity_count']} identities")
                if role['org_level_candidate']:
                    st.write("- 🎯 **Candidate for org-level assignment**")
    
    if underutilized:
        st.info(f"📉 {len(underutilized)} underutilized custom roles")


def show_org_level_opportunities(org_data):
    """Display organization-level opportunities."""
    st.subheader("🏢 Organization-Level Opportunities")
    
    org_candidates = org_data.get('org_level_candidates', [])
    inheritance_opps = org_data.get('inheritance_opportunities', [])
    
    if org_candidates:
        st.info(f"⬆️ {len(org_candidates)} roles suitable for org-level assignment")
        with st.expander("View organization candidates"):
            for candidate in org_candidates[:5]:
                st.write(f"**{candidate['role']}**")
                st.write(f"- Used in {candidate['project_count']} projects")
                st.write(f"- Recommendation: {candidate['recommendation']}")
    
    if inheritance_opps:
        st.info(f"👤 {len(inheritance_opps)} users with broad access patterns")


def show_identity_analysis(identity_data):
    """Display detailed identity analysis."""
    st.subheader("👤 Identity Analysis")
    
    multi_project = identity_data.get('multi_project_users', [])
    over_privileged = identity_data.get('over_privileged', [])
    external_users = identity_data.get('external_users', [])
    
    if multi_project or over_privileged or external_users:
        tab1, tab2, tab3 = st.tabs(["Multi-Project Users", "Over-Privileged", "External Users"])
        
        with tab1:
            if multi_project:
                st.write(f"Found {len(multi_project)} users with access to multiple projects")
                df = pd.DataFrame([{
                    'Email': user['email'],
                    'Type': user['type'],
                    'Projects': user['project_count'],
                    'Roles': user['role_count']
                } for user in multi_project[:10]])
                st.dataframe(df, width='stretch')
        
        with tab2:
            if over_privileged:
                st.write(f"Found {len(over_privileged)} potentially over-privileged identities")
                df = pd.DataFrame([{
                    'Email': user['email'],
                    'Type': user['type'],
                    'Total Roles': user['role_count'],
                    'High-Privilege Roles': ', '.join(user['high_privilege_roles'])
                } for user in over_privileged[:10]])
                st.dataframe(df, width='stretch')
        
        with tab3:
            if external_users:
                st.write(f"Found {len(external_users)} external users")
                df = pd.DataFrame([{
                    'Email': user['email'],
                    'Projects': len(user['projects']),
                    'Roles': ', '.join(user['roles'])
                } for user in external_users[:10]])
                st.dataframe(df, width='stretch')


def show_duplicate_permissions(duplicate_data):
    """Display duplicate permissions analysis."""
    st.subheader("🔄 Duplicate Permissions")
    
    redundant = duplicate_data.get('redundant_assignments', [])
    
    if redundant:
        st.warning(f"⚠️ {len(redundant)} redundant role assignments found")
        
        for item in redundant[:5]:
            st.markdown(f"""
            <div class="warning-card">
            <h4>🔄 {item['identity']}</h4>
            <p><strong>Issue:</strong> {item['issue']}</p>
            <p><strong>Recommendation:</strong> {item['recommendation']}</p>
            <p><strong>Current roles:</strong> {', '.join(item['roles'])}</p>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.success("✅ No obvious duplicate permissions detected")


def main():
    """Main application entry point."""
    configure_page()
    
    st.markdown('<h1 class="main-header">🔐 GCP IAM Janitor - Enhanced</h1>', unsafe_allow_html=True)
    st.markdown("*Advanced IAM analysis with intelligent insights and recommendations*")
    
    # Check authentication
    if 'credentials' not in st.session_state:
        credentials, project = get_credentials()
        st.session_state.credentials = credentials
        st.session_state.project = project
    
    credentials = st.session_state.get('credentials')
    project = st.session_state.get('project')
    
    if not credentials:
        st.error("❌ Authentication required")
        st.markdown("""
        **Please authenticate with Google Cloud:**
        
        ```bash
        gcloud auth application-default login
        ```
        
        Then refresh this page.
        """)
        return
    
    st.success(f"✅ Authenticated! Current project: {project}")
    
    # Sidebar controls
    with st.sidebar:
        st.title("🔐 GCP IAM Janitor")
        st.markdown("*Enhanced Edition*")
        st.markdown("---")
        
        # Intelligent auto-refresh info
        st.info("💡 Data auto-refreshes when selection changes")

        if st.button("🗑️ Clear All Cache"):
            # Clear all cache
            for key in list(st.session_state.keys()):
                if 'cache' in key or 'insights' in key:
                    del st.session_state[key]
            st.success("Cache cleared!")
            st.rerun()

        st.markdown("---")
        
        # Load projects
        if 'projects_cache' not in st.session_state:
            with st.spinner("Loading projects..."):
                st.session_state.projects_cache = list_projects(credentials)
        
        projects = st.session_state.projects_cache
        
        if not projects:
            st.warning("No projects found")
            return
        
        st.subheader("Projects")
        st.write(f"Found {len(projects)} projects")
        
        # Add search filter for projects
        search_term = st.text_input(
            "🔍 Search projects (by ID or name):",
            placeholder="Type to filter projects...",
            help="Enter part of project ID or name to filter the list"
        )
        
        # Filter projects based on search term
        if search_term:
            filtered_projects = [
                p for p in projects 
                if search_term.lower() in p['project_id'].lower() 
                or search_term.lower() in p['name'].lower()
            ]
            st.write(f"Showing {len(filtered_projects)} projects matching '{search_term}'")
        else:
            filtered_projects = projects
        
        # Project selection - show filtered projects
        project_options = [p['project_id'] for p in filtered_projects]
        
        # Bulk selection options
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("✅ Select All Filtered"):
                st.session_state.selected_projects = project_options.copy()
                st.rerun()
        with col2:
            if st.button("⭐ Select First 10"):
                st.session_state.selected_projects = project_options[:10]
                st.rerun()
        with col3:
            if st.button("❌ Clear Selection"):
                st.session_state.selected_projects = []
                st.rerun()
        
        # Default to first 5 projects for performance, but allow selection of any
        if 'selected_projects' not in st.session_state:
            default_selection = project_options[:5] if len(project_options) >= 5 else project_options
        else:
            # Filter session state selection to only include projects that exist in filtered list
            default_selection = [p for p in st.session_state.selected_projects if p in project_options]
        
        selected_projects = st.multiselect(
            f"Select projects to analyze (showing {len(filtered_projects)} projects):",
            project_options,
            default=default_selection,
            format_func=lambda x: next((p['name'] for p in filtered_projects if p['project_id'] == x), x),
            help=f"Choose from {len(filtered_projects)} projects. Use search above to filter. Use buttons above for bulk selection.",
            key="project_selector"
        )
        
        # Update session state with current selection
        st.session_state.selected_projects = selected_projects
        
        # Analysis options
        st.markdown("---")
        st.subheader("Analysis Options")
        
        enable_insights = st.checkbox("🧠 Enable Advanced Insights", value=True)
        show_basic_metrics = st.checkbox("📊 Show Basic Metrics", value=True)
        
    if not selected_projects:
        st.info("Please select projects in the sidebar to analyze.")
        return
    
    # Load IAM data
    cache_key = f"iam_data_{'-'.join(selected_projects)}"
    if cache_key not in st.session_state:
        projects_data = {}
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        for i, project_id in enumerate(selected_projects):
            status_text.text(f"Loading IAM data for {project_id}...")
            policy = get_project_iam_policy(credentials, project_id)
            if policy:
                projects_data[project_id] = policy
            
            progress_bar.progress((i + 1) / len(selected_projects))
        
        st.session_state[cache_key] = projects_data
        status_text.empty()
        progress_bar.empty()
    
    projects_data = st.session_state[cache_key]
    
    if not projects_data:
        st.warning("No IAM data could be loaded from the selected projects.")
        return
    
    # Basic analysis
    basic_analysis = analyze_iam_data(projects_data)
    
    # Show basic metrics if requested
    if show_basic_metrics:
        st.subheader("📊 Overview Metrics")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Identities", basic_analysis.get('total_identities', 0))
        
        with col2:
            st.metric("Total Roles", basic_analysis.get('total_roles', 0))
        
        with col3:
            st.metric("IAM Bindings", basic_analysis.get('total_bindings', 0))
        
        with col4:
            st.metric("Projects Analyzed", basic_analysis.get('projects_analyzed', 0))
        
        st.markdown("---")
    
    # Advanced insights
    if enable_insights:
        insights_cache_key = f"insights_{cache_key}"
        
        if insights_cache_key not in st.session_state:
            with st.spinner("🧠 Generating intelligent insights..."):
                insights_engine = IAMInsights()
                insights_data = insights_engine.analyze_project_data(projects_data)
                st.session_state[insights_cache_key] = insights_data
        
        insights_data = st.session_state[insights_cache_key]
        create_insights_dashboard(insights_data)
    
    # Export functionality
    st.markdown("---")
    st.subheader("📥 Export Analysis")
    
    col_export1, col_export2 = st.columns(2)
    
    with col_export1:
        if st.button("📊 Export Basic Analysis"):
            export_data = {
                'basic_analysis': basic_analysis,
                'timestamp': pd.Timestamp.now().isoformat(),
                'projects': selected_projects
            }
            
            st.download_button(
                label="Download Basic Analysis JSON",
                data=pd.DataFrame([export_data]).to_json(orient='records'),
                file_name=f"basic_iam_analysis_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    with col_export2:
        if enable_insights and 'insights_data' in locals():
            if st.button("🧠 Export Detailed Insights"):
                export_data = {
                    'insights_analysis': insights_data,
                    'basic_analysis': basic_analysis,
                    'timestamp': pd.Timestamp.now().isoformat(),
                    'projects': selected_projects
                }
                
                st.download_button(
                    label="Download Full Insights JSON",
                    data=pd.DataFrame([export_data]).to_json(orient='records'),
                    file_name=f"full_iam_insights_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )


if __name__ == "__main__":
    main()