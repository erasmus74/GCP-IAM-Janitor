"""
Advanced GCP IAM Janitor Dashboard

This is the most comprehensive version featuring:
- Enhanced Identity Analysis with group resolution and activity tracking
- Advanced Role Management with custom role builder and comparison tools
- Permission Deep Dive with detailed risk scoring and analysis
- Audit Trail Integration with historical analysis and incident detection
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import networkx as nx
from pyvis.network import Network
import tempfile
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Page configuration
st.set_page_config(
    page_title="Advanced GCP IAM Janitor",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Import our custom modules
try:
    from src.auth.credentials import get_authenticated_credentials
    from src.gcp.project_client import ProjectClient
    from src.gcp.iam_client import IAMClient
    from src.gcp.identity_client import IdentityAnalysisClient
    from src.gcp.role_management_client import RoleManagementClient
    from src.gcp.permission_analyzer import PermissionAnalyzer
    from src.gcp.audit_analyzer import AuditAnalyzer
    from src.analytics.insights import IAMInsights
    from src.utils.cache import cache_data, get_cached_data, clear_cache
except ImportError as e:
    st.error(f"Import error: {e}")
    st.error("Please ensure all required modules are properly installed.")
    st.stop()


def init_session_state():
    """Initialize session state variables."""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'credentials' not in st.session_state:
        st.session_state.credentials = None
    if 'selected_projects_advanced' not in st.session_state:
        st.session_state.selected_projects_advanced = []
    if 'iam_data_advanced' not in st.session_state:
        st.session_state.iam_data_advanced = None
    if 'analysis_cache' not in st.session_state:
        st.session_state.analysis_cache = {}


def authenticate():
    """Handle authentication."""
    with st.spinner("Authenticating with Google Cloud..."):
        try:
            credentials = get_authenticated_credentials()
            if credentials:
                st.session_state.authenticated = True
                st.session_state.credentials = credentials
                st.success("✅ Successfully authenticated with Google Cloud!")
                return True
            else:
                st.error("❌ Authentication failed. Please check your credentials.")
                return False
        except Exception as e:
            st.error(f"❌ Authentication error: {str(e)}")
            return False


def load_projects_data():
    """Load and cache projects data."""
    if not st.session_state.authenticated:
        return []
    
    cache_key = "projects_data_advanced"
    cached_data = get_cached_data(cache_key)
    
    if cached_data:
        return cached_data
    
    try:
        with st.spinner("Loading projects..."):
            project_client = ProjectClient(st.session_state.credentials)
            projects = project_client.list_projects()
            cache_data(cache_key, projects, ttl=300)  # 5 minutes cache
            return projects
    except Exception as e:
        st.error(f"Error loading projects: {str(e)}")
        return []


def load_iam_data(selected_projects: List[str]):
    """Load IAM data for selected projects."""
    if not selected_projects:
        return None
    
    cache_key = f"iam_data_{hash(str(sorted(selected_projects)))}"
    cached_data = get_cached_data(cache_key)
    
    if cached_data:
        return cached_data
    
    try:
        with st.spinner(f"Loading IAM data for {len(selected_projects)} projects..."):
            project_client = ProjectClient(st.session_state.credentials)
            iam_client = IAMClient(st.session_state.credentials)
            
            progress_bar = st.progress(0)
            all_policies = []
            
            for i, project_id in enumerate(selected_projects):
                try:
                    policy = project_client.get_iam_policy(project_id)
                    if policy:
                        all_policies.append(policy)
                    progress_bar.progress((i + 1) / len(selected_projects))
                except Exception as e:
                    st.warning(f"Could not load IAM policy for project {project_id}: {str(e)}")
                    continue
            
            progress_bar.empty()
            cache_data(cache_key, all_policies, ttl=600)  # 10 minutes cache
            return all_policies
            
    except Exception as e:
        st.error(f"Error loading IAM data: {str(e)}")
        return None


def render_sidebar():
    """Render the sidebar with project selection and navigation."""
    st.sidebar.title("🔒 Advanced IAM Janitor")
    st.sidebar.markdown("---")
    
    # Authentication status
    if st.session_state.authenticated:
        st.sidebar.success("✅ Authenticated")
        if st.sidebar.button("🔄 Refresh Authentication"):
            st.session_state.authenticated = False
            st.rerun()
    else:
        st.sidebar.error("❌ Not authenticated")
        if st.sidebar.button("🔐 Authenticate"):
            if authenticate():
                st.rerun()
    
    if not st.session_state.authenticated:
        st.sidebar.warning("Please authenticate to continue")
        return None
    
    # Load projects
    projects = load_projects_data()
    if not projects:
        st.sidebar.error("No projects available")
        return None
    
    # Project selection
    st.sidebar.markdown("### 🎯 Project Selection")
    
    # Create project options with search functionality
    project_options = [f"{p['name']} ({p['projectId']})" for p in projects]
    
    # Search filter
    search_term = st.sidebar.text_input("🔍 Search projects", placeholder="Type to search...")
    
    if search_term:
        filtered_options = [opt for opt in project_options if search_term.lower() in opt.lower()]
    else:
        filtered_options = project_options
    
    # Multi-select with helper buttons
    selected_project_names = st.sidebar.multiselect(
        "Select projects to analyze:",
        options=filtered_options,
        default=st.session_state.selected_projects_advanced,
        key="project_selector_advanced"
    )
    
    # Helper buttons
    col1, col2, col3 = st.sidebar.columns([1, 1, 1])
    
    with col1:
        if st.button("✅ All"):
            st.session_state.selected_projects_advanced = filtered_options.copy()
            st.rerun()
    
    with col2:
        if st.button("🔟 First 10"):
            st.session_state.selected_projects_advanced = filtered_options[:10].copy()
            st.rerun()
    
    with col3:
        if st.button("❌ Clear"):
            st.session_state.selected_projects_advanced = []
            st.rerun()
    
    # Update session state
    st.session_state.selected_projects_advanced = selected_project_names
    
    # Extract project IDs
    selected_project_ids = []
    for project_name in selected_project_names:
        project_id = project_name.split('(')[-1].rstrip(')')
        selected_project_ids.append(project_id)
    
    # Cache management
    st.sidebar.markdown("---")
    st.sidebar.markdown("### ⚙️ Settings")
    
    if st.sidebar.button("🗑️ Clear Cache"):
        clear_cache()
        st.sidebar.success("Cache cleared!")
    
    # Analysis options
    st.sidebar.markdown("### 📊 Analysis Options")
    
    enable_advanced_features = st.sidebar.checkbox("🚀 Enable Advanced Features", value=True)
    enable_audit_logs = st.sidebar.checkbox("📋 Enable Audit Log Analysis", value=False,
                                          help="Requires Cloud Logging read permissions")
    days_back = st.sidebar.slider("📅 Analysis Period (days)", 1, 90, 30)
    
    return {
        'selected_projects': selected_project_ids,
        'enable_advanced_features': enable_advanced_features,
        'enable_audit_logs': enable_audit_logs,
        'days_back': days_back
    }


def render_overview_tab(iam_data, config):
    """Render the overview tab with key metrics and visualizations."""
    st.header("📊 Advanced IAM Overview")
    
    if not iam_data:
        st.warning("No IAM data available. Please select projects in the sidebar.")
        return
    
    # Calculate basic metrics
    all_identities = set()
    all_roles = set()
    all_bindings = []
    all_permissions = set()
    
    for policy in iam_data:
        for binding in policy.bindings:
            all_bindings.append(binding)
            all_identities.update(binding.members)
            all_roles.add(binding.role)
    
    # Basic metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("🎭 Total Identities", len(all_identities))
    
    with col2:
        st.metric("👑 Unique Roles", len(all_roles))
    
    with col3:
        st.metric("🔗 IAM Bindings", len(all_bindings))
    
    with col4:
        st.metric("📁 Projects Analyzed", len(iam_data))
    
    st.markdown("---")
    
    # Identity type breakdown
    if config['enable_advanced_features']:
        st.subheader("🔍 Advanced Identity Analysis")
        
        # Analyze identity types
        identity_types = {}
        external_users = []
        service_accounts = []
        
        for identity_str in all_identities:
            try:
                from src.models.iam_models import Identity
                identity = Identity.from_member_string(identity_str)
                identity_type = identity.identity_type.value
                
                identity_types[identity_type] = identity_types.get(identity_type, 0) + 1
                
                if identity_type == 'user' and identity.domain:
                    if identity.domain in ['gmail.com', 'googlemail.com']:
                        external_users.append(identity.email)
                elif identity_type == 'serviceAccount':
                    service_accounts.append(identity.email)
                    
            except Exception as e:
                logger.warning(f"Error parsing identity {identity_str}: {e}")
                continue
        
        # Identity distribution chart
        if identity_types:
            col1, col2 = st.columns([2, 1])
            
            with col1:
                fig = px.pie(
                    values=list(identity_types.values()),
                    names=list(identity_types.keys()),
                    title="Identity Type Distribution"
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                st.markdown("#### 🚨 Security Highlights")
                if external_users:
                    st.warning(f"⚠️ {len(external_users)} external users detected")
                    with st.expander("View external users"):
                        for user in external_users[:10]:  # Show first 10
                            st.write(f"• {user}")
                        if len(external_users) > 10:
                            st.write(f"... and {len(external_users) - 10} more")
                
                if service_accounts:
                    st.info(f"🤖 {len(service_accounts)} service accounts")
        
        # Role analysis
        st.subheader("👑 Role Analysis")
        
        try:
            iam_client = IAMClient(st.session_state.credentials)
            role_analysis = iam_client.analyze_bindings(all_bindings)
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Basic Roles Usage", role_analysis.get('basic_roles_usage', 0))
            
            with col2:
                st.metric("High-Privilege Bindings", len(role_analysis.get('high_privilege_bindings', [])))
            
            with col3:
                st.metric("Conditional Bindings", role_analysis.get('conditional_bindings', 0))
            
            # High-privilege bindings table
            if role_analysis.get('high_privilege_bindings'):
                st.markdown("#### 🚨 High-Privilege Role Assignments")
                high_priv_df = pd.DataFrame(role_analysis['high_privilege_bindings'])
                st.dataframe(high_priv_df, use_container_width=True)
                
        except Exception as e:
            st.error(f"Error in role analysis: {str(e)}")
    
    # Basic visualizations
    st.subheader("📈 IAM Binding Distribution")
    
    # Role usage frequency
    role_counts = {}
    for binding in all_bindings:
        role_counts[binding.role] = role_counts.get(binding.role, 0) + len(binding.members)
    
    if role_counts:
        # Top 10 most used roles
        top_roles = sorted(role_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        fig = go.Figure(data=[
            go.Bar(x=[r[1] for r in top_roles], y=[r[0] for r in top_roles], orientation='h')
        ])
        fig.update_layout(
            title="Top 10 Most Assigned Roles",
            xaxis_title="Number of Assignments",
            yaxis_title="Role"
        )
        st.plotly_chart(fig, use_container_width=True)


def render_identity_analysis_tab(iam_data, config):
    """Render the enhanced identity analysis tab."""
    st.header("🔍 Enhanced Identity Analysis")
    
    if not iam_data or not config['enable_advanced_features']:
        st.warning("Advanced features disabled or no data available.")
        return
    
    try:
        # Initialize identity analysis client
        identity_client = IdentityAnalysisClient(st.session_state.credentials)
        
        # Get all unique identities
        all_identities = set()
        for policy in iam_data:
            for binding in policy.bindings:
                all_identities.update(binding.members)
        
        # Filter to just user accounts for detailed analysis
        user_identities = []
        from src.models.iam_models import Identity, IdentityType
        
        for identity_str in all_identities:
            identity = Identity.from_member_string(identity_str)
            if identity.identity_type == IdentityType.USER:
                user_identities.append(identity_str)
        
        st.subheader("👥 User Identity Deep Dive")
        st.write(f"Found {len(user_identities)} user accounts for analysis")
        
        if user_identities:
            # Select user for detailed analysis
            selected_user = st.selectbox(
                "Select a user for detailed analysis:",
                options=user_identities[:20],  # Limit to first 20 for performance
                help="Showing first 20 users for performance"
            )
            
            if selected_user:
                with st.spinner(f"Analyzing {selected_user}..."):
                    # Group membership analysis
                    st.markdown("#### 👥 Group Membership Analysis")
                    
                    try:
                        memberships = identity_client.resolve_group_memberships(selected_user)
                        
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            st.metric("Direct Groups", len(memberships['direct_groups']))
                        
                        with col2:
                            st.metric("Nested Groups", len(memberships['nested_groups']))
                        
                        with col3:
                            st.metric("Total Groups", len(memberships['all_groups']))
                        
                        if memberships['direct_groups']:
                            st.markdown("**Direct Group Memberships:**")
                            for group in memberships['direct_groups']:
                                st.write(f"• {group['name']} ({group['email']})")
                        
                        if memberships['resolution_errors']:
                            st.warning("Group resolution encountered some issues:")
                            for error in memberships['resolution_errors']:
                                st.write(f"• {error}")
                    
                    except Exception as e:
                        st.warning(f"Group membership analysis failed: {str(e)}")
                        st.info("This may be due to missing Cloud Identity API permissions")
                    
                    # User activity tracking
                    st.markdown("#### 📈 Activity Pattern Analysis")
                    
                    try:
                        activity = identity_client.track_user_activity(selected_user, config['days_back'])
                        
                        col1, col2, col3, col4 = st.columns(4)
                        
                        with col1:
                            st.metric("Activity Score", f"{activity['activity_score']}/100")
                        
                        with col2:
                            st.metric("Login Events", activity['summary']['login_count'])
                        
                        with col3:
                            st.metric("IAM Changes", activity['summary']['iam_changes_count'])
                        
                        with col4:
                            st.metric("Resource Access", activity['summary']['resource_access_count'])
                        
                        # Activity timeline
                        if activity['login_events']:
                            st.markdown("**Recent Login Activity:**")
                            login_df = pd.DataFrame(activity['login_events'])
                            if not login_df.empty:
                                st.dataframe(login_df.head(10), use_container_width=True)
                        
                        # Risk factors
                        if activity.get('risk_factors'):
                            st.markdown("**🚨 Risk Factors Detected:**")
                            for risk in activity['risk_factors']:
                                risk_level = risk.get('severity', 'low')
                                if risk_level == 'high':
                                    st.error(f"• {risk['description']}")
                                elif risk_level == 'medium':
                                    st.warning(f"• {risk['description']}")
                                else:
                                    st.info(f"• {risk['description']}")
                    
                    except Exception as e:
                        st.warning(f"Activity tracking failed: {str(e)}")
                        st.info("This may be due to missing Cloud Logging permissions")
        
        # Batch identity risk assessment
        st.subheader("🎯 Batch Risk Assessment")
        
        if st.button("🔍 Analyze All User Identities"):
            with st.spinner("Performing batch analysis..."):
                try:
                    # Limit to first 10 users for performance
                    sample_users = user_identities[:10]
                    batch_results = identity_client.batch_analyze_identities(sample_users)
                    
                    # Create summary table
                    summary_data = []
                    for identity, result in batch_results.items():
                        if 'error' not in result:
                            risk_assessment = result.get('risk_assessment', {})
                            summary_data.append({
                                'Identity': identity,
                                'Risk Level': risk_assessment.get('overall_risk', 'unknown'),
                                'Risk Score': risk_assessment.get('risk_score', 0),
                                'Groups': len(result.get('group_memberships', {}).get('all_groups', [])),
                                'Activity Score': result.get('activity_tracking', {}).get('activity_score', 0)
                            })
                    
                    if summary_data:
                        df = pd.DataFrame(summary_data)
                        st.dataframe(df, use_container_width=True)
                        
                        # Risk level distribution
                        if 'Risk Level' in df.columns:
                            fig = px.histogram(df, x='Risk Level', title='Risk Level Distribution')
                            st.plotly_chart(fig, use_container_width=True)
                
                except Exception as e:
                    st.error(f"Batch analysis failed: {str(e)}")
    
    except Exception as e:
        st.error(f"Error in identity analysis: {str(e)}")


def render_role_management_tab(iam_data, config):
    """Render the advanced role management tab."""
    st.header("👑 Advanced Role Management")
    
    if not iam_data or not config['enable_advanced_features']:
        st.warning("Advanced features disabled or no data available.")
        return
    
    try:
        # Initialize role management client
        role_client = RoleManagementClient(st.session_state.credentials)
        
        # Tabs for different role management features
        tab1, tab2, tab3, tab4 = st.tabs([
            "🔍 Role Comparison",
            "🏗️ Custom Role Builder", 
            "📋 Role Templates",
            "📊 Role Usage Analysis"
        ])
        
        with tab1:
            st.subheader("Role Comparison Tool")
            
            # Get all unique roles
            all_roles = set()
            for policy in iam_data:
                for binding in policy.bindings:
                    all_roles.add(binding.role)
            
            role_list = sorted(list(all_roles))
            
            col1, col2 = st.columns(2)
            
            with col1:
                role_a = st.selectbox("Select first role:", role_list, key="role_a")
            
            with col2:
                role_b = st.selectbox("Select second role:", role_list, key="role_b")
            
            if role_a and role_b and role_a != role_b:
                if st.button("🔍 Compare Roles"):
                    with st.spinner("Comparing roles..."):
                        try:
                            comparison = role_client.compare_roles(role_a, role_b)
                            
                            # Display comparison results
                            col1, col2, col3 = st.columns(3)
                            
                            with col1:
                                st.metric("Similarity Score", f"{comparison.similarity_score:.1%}")
                            
                            with col2:
                                st.metric("Common Permissions", len(comparison.common_permissions))
                            
                            with col3:
                                st.metric("Risk Level", comparison.risk_difference.upper())
                            
                            # Detailed breakdown
                            if comparison.unique_to_a:
                                st.markdown(f"**Permissions unique to {role_a}:**")
                                for perm in sorted(list(comparison.unique_to_a))[:10]:
                                    st.write(f"• {perm}")
                                if len(comparison.unique_to_a) > 10:
                                    st.write(f"... and {len(comparison.unique_to_a) - 10} more")
                            
                            if comparison.unique_to_b:
                                st.markdown(f"**Permissions unique to {role_b}:**")
                                for perm in sorted(list(comparison.unique_to_b))[:10]:
                                    st.write(f"• {perm}")
                                if len(comparison.unique_to_b) > 10:
                                    st.write(f"... and {len(comparison.unique_to_b) - 10} more")
                            
                            # Recommendations
                            if comparison.recommendations:
                                st.markdown("**🎯 Recommendations:**")
                                for rec in comparison.recommendations:
                                    st.info(rec)
                        
                        except Exception as e:
                            st.error(f"Role comparison failed: {str(e)}")
        
        with tab2:
            st.subheader("Custom Role Builder")
            
            # Custom role specification form
            with st.form("custom_role_form"):
                title = st.text_input("Role Title*", placeholder="e.g., Developer Read-Only Access")
                description = st.text_area("Description", placeholder="Describe the purpose of this role")
                
                # Permission input
                permissions_text = st.text_area(
                    "Permissions (one per line)*",
                    placeholder="compute.instances.get\ncompute.instances.list\nstorage.objects.get",
                    height=150
                )
                
                # Include existing roles
                include_roles = st.multiselect(
                    "Include permissions from existing roles:",
                    options=role_list[:20],  # Limit for performance
                    help="Permissions from these roles will be added to your custom role"
                )
                
                # Exclude specific permissions
                exclude_permissions = st.text_area(
                    "Exclude specific permissions (one per line):",
                    placeholder="compute.instances.delete\nstorage.objects.delete",
                    help="These permissions will be removed even if included from other roles"
                )
                
                submitted = st.form_submit_button("🏗️ Build Custom Role")
                
                if submitted and title and permissions_text:
                    try:
                        from src.gcp.role_management_client import CustomRoleSpec
                        
                        # Parse permissions
                        permissions = set(line.strip() for line in permissions_text.split('\n') if line.strip())
                        exclude_perms = set(line.strip() for line in exclude_permissions.split('\n') if line.strip())
                        
                        # Create role specification
                        spec = CustomRoleSpec(
                            title=title,
                            description=description or f"Custom role: {title}",
                            permissions=permissions,
                            included_roles=include_roles,
                            excluded_permissions=exclude_perms
                        )
                        
                        # Build the role
                        result = role_client.build_custom_role(spec)
                        
                        if result['success']:
                            st.success(f"✅ Custom role '{result['role_id']}' built successfully!")
                            
                            # Display analysis
                            analysis = result['role_analysis']
                            
                            col1, col2, col3, col4 = st.columns(4)
                            with col1:
                                st.metric("Total Permissions", analysis['total_permissions'])
                            with col2:
                                st.metric("Services Affected", len(analysis['services_affected']))
                            with col3:
                                st.metric("Risk Level", analysis['risk_assessment']['overall_risk'].upper())
                            with col4:
                                st.metric("High-Risk Permissions", len(analysis['risk_assessment']['high_risk_permissions']))
                            
                            # Implementation steps
                            st.markdown("**Implementation Steps:**")
                            for step in result['implementation_steps']:
                                with st.expander(f"Step {step['step']}: {step['title']}"):
                                    st.write(step['description'])
                                    st.code(step['command'], language='bash')
                            
                            # Recommendations
                            if analysis['recommendations']:
                                st.markdown("**🎯 Recommendations:**")
                                for rec in analysis['recommendations']:
                                    st.info(rec)
                        else:
                            st.error("❌ Role building failed")
                            for error in result['validation_errors']:
                                st.error(f"• {error}")
                    
                    except Exception as e:
                        st.error(f"Error building custom role: {str(e)}")
        
        with tab3:
            st.subheader("Role Templates")
            
            # Get available templates
            templates = role_client.get_role_templates()
            
            if templates:
                template_names = list(templates.keys())
                selected_template = st.selectbox("Select a template:", template_names)
                
                if selected_template:
                    template = templates[selected_template]
                    
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        st.markdown(f"**{template.title}**")
                        st.write(template.description)
                        st.write(f"**Category:** {template.category}")
                        
                        # Show permissions
                        with st.expander(f"View {len(template.permissions)} permissions"):
                            for perm in sorted(template.permissions):
                                st.write(f"• {perm}")
                    
                    with col2:
                        st.markdown("**Use Cases:**")
                        for use_case in template.use_cases:
                            st.write(f"• {use_case}")
                        
                        st.markdown("**Required Services:**")
                        for service in template.required_services:
                            st.write(f"• {service}")
                    
                    # Customize template
                    if st.button(f"🎨 Customize {template.title}"):
                        try:
                            customizations = {
                                'title': f"Custom {template.title}",
                                'description': f"Customized version of {template.description}"
                            }
                            
                            custom_spec = role_client.create_role_from_template(selected_template, customizations)
                            
                            st.success("Template customized! You can now modify it further in the Custom Role Builder.")
                            st.json({
                                'title': custom_spec.title,
                                'description': custom_spec.description,
                                'permissions_count': len(custom_spec.permissions)
                            })
                        
                        except Exception as e:
                            st.error(f"Error customizing template: {str(e)}")
        
        with tab4:
            st.subheader("Role Usage Analysis")
            
            # Analyze role usage across the loaded IAM data
            if st.button("📊 Analyze Role Usage"):
                with st.spinner("Analyzing role usage patterns..."):
                    try:
                        # Convert IAM data to analysis format
                        bindings_data = []
                        for policy in iam_data:
                            for binding in policy.bindings:
                                bindings_data.append({
                                    'role': binding.role,
                                    'members': list(binding.members),
                                    'resource_name': policy.resource_name
                                })
                        
                        # Analyze usage for each unique role
                        usage_results = {}
                        for role in all_roles:
                            usage_results[role] = role_client.analyze_role_usage(role, bindings_data)
                        
                        # Display results
                        summary_data = []
                        for role, usage in usage_results.items():
                            summary_data.append({
                                'Role': role,
                                'Total Assignments': usage['total_assignments'],
                                'Unique Identities': usage['unique_identities_count'],
                                'Projects Used': usage['projects_used_count']
                            })
                        
                        if summary_data:
                            df = pd.DataFrame(summary_data)
                            df = df.sort_values('Total Assignments', ascending=False)
                            st.dataframe(df, use_container_width=True)
                            
                            # Usage distribution chart
                            fig = px.bar(df.head(15), x='Total Assignments', y='Role', 
                                       title='Top 15 Roles by Assignment Count', orientation='h')
                            st.plotly_chart(fig, use_container_width=True)
                            
                            # Generate optimization suggestions
                            optimizations = role_client.suggest_role_optimizations(usage_results)
                            
                            if optimizations:
                                st.markdown("**🎯 Optimization Opportunities:**")
                                for opt in optimizations:
                                    priority_color = {'high': '🔴', 'medium': '🟡', 'low': '🟢'}
                                    st.write(f"{priority_color.get(opt['priority'], '⚪')} **{opt['title']}**")
                                    st.write(f"   {opt['description']}")
                                    st.write(f"   *{opt['estimated_benefit']}*")
                    
                    except Exception as e:
                        st.error(f"Role usage analysis failed: {str(e)}")
    
    except Exception as e:
        st.error(f"Error in role management: {str(e)}")


def render_permission_analysis_tab(iam_data, config):
    """Render the permission deep dive analysis tab."""
    st.header("🔐 Permission Deep Dive Analysis")
    
    if not iam_data or not config['enable_advanced_features']:
        st.warning("Advanced features disabled or no data available.")
        return
    
    try:
        # Initialize permission analyzer
        permission_analyzer = PermissionAnalyzer()
        
        # Extract all permissions from IAM data
        all_permissions = set()
        role_permissions = {}
        
        # Get IAM client to fetch role details
        iam_client = IAMClient(st.session_state.credentials)
        
        # Collect all unique roles
        all_roles = set()
        for policy in iam_data:
            for binding in policy.bindings:
                all_roles.add(binding.role)
        
        with st.spinner("Loading role permissions..."):
            for role in list(all_roles)[:20]:  # Limit for performance
                try:
                    permissions = iam_client.get_role_permissions(role)
                    if permissions:
                        role_permissions[role] = permissions
                        all_permissions.update(permissions)
                except Exception as e:
                    logger.warning(f"Could not get permissions for role {role}: {e}")
                    continue
        
        if not all_permissions:
            st.warning("No permissions could be loaded. This might be due to API limitations.")
            return
        
        st.info(f"Loaded {len(all_permissions)} unique permissions from {len(role_permissions)} roles")
        
        # Tabs for different permission analyses
        tab1, tab2, tab3, tab4 = st.tabs([
            "🔍 Permission Risk Analysis",
            "📊 Permission Set Analysis", 
            "🎯 Individual Permission Lookup",
            "📋 Comprehensive Report"
        ])
        
        with tab1:
            st.subheader("Permission Risk Scoring")
            
            # Sample risk analysis on a subset of permissions
            sample_permissions = list(all_permissions)[:50]  # Analyze first 50 for performance
            
            if st.button("🔍 Analyze Permission Risks"):
                with st.spinner("Analyzing permission risks..."):
                    risk_results = []
                    
                    for permission in sample_permissions:
                        try:
                            assessment = permission_analyzer.analyze_permission_risk(permission)
                            risk_results.append({
                                'Permission': permission,
                                'Risk Level': assessment.risk_level.value,
                                'Risk Score': assessment.risk_score,
                                'Risk Factors': len(assessment.risk_factors),
                                'Compliance Concerns': len(assessment.compliance_concerns)
                            })
                        except Exception as e:
                            logger.warning(f"Error analyzing {permission}: {e}")
                            continue
                    
                    if risk_results:
                        df = pd.DataFrame(risk_results)
                        df = df.sort_values('Risk Score', ascending=False)
                        
                        # Display high-risk permissions
                        high_risk = df[df['Risk Level'].isin(['critical', 'high'])]
                        if not high_risk.empty:
                            st.markdown("**🚨 High-Risk Permissions:**")
                            st.dataframe(high_risk, use_container_width=True)
                        
                        # Risk level distribution
                        risk_dist = df['Risk Level'].value_counts()
                        fig = px.pie(values=risk_dist.values, names=risk_dist.index, 
                                   title="Risk Level Distribution")
                        st.plotly_chart(fig, use_container_width=True)
                        
                        # Risk score histogram
                        fig2 = px.histogram(df, x='Risk Score', bins=20, 
                                          title="Risk Score Distribution")
                        st.plotly_chart(fig2, use_container_width=True)
        
        with tab2:
            st.subheader("Permission Set Analysis")
            
            # Select a role for detailed permission analysis
            available_roles = list(role_permissions.keys())
            selected_role = st.selectbox("Select a role for detailed analysis:", available_roles)
            
            if selected_role and selected_role in role_permissions:
                role_perms = role_permissions[selected_role]
                
                if st.button("📊 Analyze Permission Set"):
                    with st.spinner(f"Analyzing {len(role_perms)} permissions in {selected_role}..."):
                        try:
                            analysis = permission_analyzer.analyze_permission_set(role_perms)
                            
                            # Display summary metrics
                            col1, col2, col3, col4 = st.columns(4)
                            
                            with col1:
                                st.metric("Total Permissions", analysis['total_permissions'])
                            
                            with col2:
                                st.metric("Average Risk Score", f"{analysis['average_risk_score']:.1f}/100")
                            
                            with col3:
                                st.metric("Services Affected", len(analysis['services_affected']))
                            
                            with col4:
                                st.metric("High-Risk Permissions", len(analysis['highest_risk_permissions']))
                            
                            # Risk distribution
                            risk_dist = analysis['risk_distribution']
                            fig = go.Figure(data=[
                                go.Bar(x=list(risk_dist.keys()), y=list(risk_dist.values()))
                            ])
                            fig.update_layout(title="Risk Level Distribution")
                            st.plotly_chart(fig, use_container_width=True)
                            
                            # Security concerns
                            if analysis['security_concerns']:
                                st.markdown("**🚨 Security Concerns:**")
                                for concern in analysis['security_concerns']:
                                    severity = concern.get('severity', 'medium')
                                    if severity == 'critical':
                                        st.error(f"• {concern['description']}")
                                    elif severity == 'high':
                                        st.warning(f"• {concern['description']}")
                                    else:
                                        st.info(f"• {concern['description']}")
                            
                            # Optimization opportunities
                            if analysis['optimization_opportunities']:
                                st.markdown("**🎯 Optimization Opportunities:**")
                                for opp in analysis['optimization_opportunities']:
                                    st.write(f"• **{opp['type']}**: {opp['recommendation']}")
                        
                        except Exception as e:
                            st.error(f"Permission set analysis failed: {str(e)}")
        
        with tab3:
            st.subheader("Individual Permission Lookup")
            
            # Permission search and analysis
            permission_query = st.text_input("Enter a permission to analyze:", 
                                           placeholder="e.g., compute.instances.delete")
            
            if permission_query:
                if st.button("🔍 Analyze Permission"):
                    try:
                        assessment = permission_analyzer.analyze_permission_risk(permission_query)
                        
                        # Display detailed assessment
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            st.metric("Risk Level", assessment.risk_level.value.upper())
                        
                        with col2:
                            st.metric("Risk Score", f"{assessment.risk_score}/100")
                        
                        with col3:
                            st.metric("Compliance Frameworks", len(assessment.compliance_concerns))
                        
                        # Security implications
                        if assessment.security_implications:
                            st.markdown("**🛡️ Security Implications:**")
                            for implication in assessment.security_implications:
                                st.write(f"• {implication}")
                        
                        # Risk factors
                        if assessment.risk_factors:
                            st.markdown("**⚠️ Risk Factors:**")
                            for factor in assessment.risk_factors:
                                st.write(f"• {factor}")
                        
                        # Mitigation strategies
                        if assessment.mitigation_strategies:
                            st.markdown("**🛠️ Recommended Mitigations:**")
                            for strategy in assessment.mitigation_strategies:
                                st.write(f"• {strategy}")
                        
                        # Similar permissions
                        if assessment.similar_permissions:
                            st.markdown("**🔗 Similar Permissions:**")
                            for similar in assessment.similar_permissions:
                                st.write(f"• {similar}")
                    
                    except Exception as e:
                        st.error(f"Permission analysis failed: {str(e)}")
        
        with tab4:
            st.subheader("Comprehensive Permission Report")
            
            # Generate comprehensive report for selected role
            if available_roles:
                report_role = st.selectbox("Select role for comprehensive report:", 
                                         available_roles, key="report_role")
                
                if report_role and st.button("📋 Generate Report"):
                    with st.spinner("Generating comprehensive report..."):
                        try:
                            role_perms = role_permissions[report_role]
                            report = permission_analyzer.generate_permission_report(role_perms)
                            
                            # Display report sections
                            st.markdown("## 📊 Executive Summary")
                            
                            summary = report['summary']
                            col1, col2, col3, col4 = st.columns(4)
                            
                            with col1:
                                st.metric("Total Permissions", summary['total_permissions'])
                            
                            with col2:
                                st.metric("Average Risk", f"{summary['average_risk_score']}/100")
                            
                            with col3:
                                st.metric("Services", summary['services_affected'])
                            
                            with col4:
                                st.metric("Compliance Frameworks", summary['compliance_frameworks_affected'])
                            
                            # Risk distribution
                            st.markdown("### Risk Distribution")
                            risk_data = summary['risk_distribution']
                            fig = px.bar(x=list(risk_data.keys()), y=list(risk_data.values()),
                                       title="Permissions by Risk Level")
                            st.plotly_chart(fig, use_container_width=True)
                            
                            # Priority actions
                            if 'priority_actions' in report['recommendations']:
                                st.markdown("### 🎯 Priority Actions")
                                for action in report['recommendations']['priority_actions']:
                                    st.write(f"**Priority {action['priority']}: {action['action']}**")
                                    st.write(f"• {action['description']}")
                                    st.write(f"• Timeline: {action['timeline']}")
                                    st.write(f"• Impact: {action['impact']}")
                                    st.write("")
                            
                            # Detailed findings
                            with st.expander("📋 Detailed Analysis"):
                                st.json(report)
                        
                        except Exception as e:
                            st.error(f"Report generation failed: {str(e)}")
    
    except Exception as e:
        st.error(f"Error in permission analysis: {str(e)}")


def render_audit_trail_tab(iam_data, config):
    """Render the audit trail integration tab."""
    st.header("📋 Audit Trail Analysis")
    
    if not config['enable_audit_logs']:
        st.warning("Audit log analysis is disabled. Enable it in the sidebar to use this feature.")
        st.info("Note: This feature requires Cloud Logging read permissions.")
        return
    
    try:
        # Initialize audit analyzer
        audit_analyzer = AuditAnalyzer(st.session_state.credentials, config['selected_projects'])
        
        # Tabs for different audit analyses
        tab1, tab2, tab3, tab4 = st.tabs([
            "📊 Historical IAM Changes",
            "🚨 Security Incident Detection",
            "👤 User Access Patterns",
            "📋 Compliance Reports"
        ])
        
        with tab1:
            st.subheader("Historical IAM Changes Analysis")
            
            # Date range selector
            col1, col2 = st.columns(2)
            
            with col1:
                start_date = st.date_input("Start Date", 
                                         value=datetime.now() - timedelta(days=config['days_back']))
            
            with col2:
                end_date = st.date_input("End Date", value=datetime.now())
            
            # Principal filter
            principal_filter = st.text_input("Filter by principal (optional):", 
                                           placeholder="user@example.com")
            
            if st.button("📊 Analyze IAM Changes"):
                with st.spinner("Analyzing historical IAM changes..."):
                    try:
                        start_time = datetime.combine(start_date, datetime.min.time())
                        end_time = datetime.combine(end_date, datetime.max.time())
                        
                        principals = [principal_filter] if principal_filter else None
                        
                        analysis = audit_analyzer.analyze_historical_iam_changes(
                            start_time, end_time, principals=principals
                        )
                        
                        if analysis.get('error'):
                            st.error(f"Analysis failed: {analysis['error']}")
                            return
                        
                        # Display summary
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            st.metric("Total IAM Changes", analysis['total_iam_changes'])
                        
                        with col2:
                            st.metric("High-Risk Changes", len(analysis['high_risk_changes']))
                        
                        with col3:
                            st.metric("Duration (hours)", f"{analysis['time_period']['duration_hours']:.1f}")
                        
                        # Changes by type
                        if analysis['changes_by_type']:
                            st.markdown("### Changes by Type")
                            changes_df = pd.DataFrame(list(analysis['changes_by_type'].items()), 
                                                    columns=['Change Type', 'Count'])
                            fig = px.bar(changes_df, x='Count', y='Change Type', orientation='h',
                                       title="IAM Changes by Type")
                            st.plotly_chart(fig, use_container_width=True)
                        
                        # High-risk changes
                        if analysis['high_risk_changes']:
                            st.markdown("### 🚨 High-Risk Changes")
                            high_risk_df = pd.DataFrame(analysis['high_risk_changes'])
                            st.dataframe(high_risk_df, use_container_width=True)
                        
                        # Timeline
                        if analysis['timeline']:
                            st.markdown("### Timeline")
                            timeline_df = pd.DataFrame(analysis['timeline'][:50])  # Show recent 50
                            st.dataframe(timeline_df, use_container_width=True)
                        
                        # Patterns detected
                        if analysis['patterns_detected']:
                            st.markdown("### 🔍 Patterns Detected")
                            for pattern in analysis['patterns_detected']:
                                st.write(f"• **{pattern['type']}**: {pattern['description']}")
                        
                        # Recommendations
                        if analysis['recommendations']:
                            st.markdown("### 🎯 Recommendations")
                            for rec in analysis['recommendations']:
                                st.info(rec)
                    
                    except Exception as e:
                        st.error(f"Historical analysis failed: {str(e)}")
        
        with tab2:
            st.subheader("Security Incident Detection")
            
            # Severity threshold
            severity = st.selectbox("Minimum severity:", ['low', 'medium', 'high', 'critical'], 
                                   index=1)
            
            if st.button("🚨 Detect Security Incidents"):
                with st.spinner("Analyzing for security incidents..."):
                    try:
                        start_time = datetime.now() - timedelta(days=config['days_back'])
                        end_time = datetime.now()
                        
                        incidents = audit_analyzer.detect_security_incidents(
                            start_time, end_time, severity_threshold=severity
                        )
                        
                        if incidents:
                            st.warning(f"🚨 {len(incidents)} potential security incidents detected!")
                            
                            for incident in incidents:
                                severity_color = {
                                    'critical': '🔴',
                                    'high': '🟠', 
                                    'medium': '🟡',
                                    'low': '🟢'
                                }
                                
                                with st.expander(f"{severity_color.get(incident.severity, '⚪')} {incident.incident_type.replace('_', ' ').title()} - {incident.severity.upper()}"):
                                    st.write(f"**Description:** {incident.description}")
                                    st.write(f"**Principal:** {incident.principal_email}")
                                    st.write(f"**Time:** {incident.timestamp}")
                                    
                                    if incident.affected_resources:
                                        st.write(f"**Affected Resources:** {', '.join(incident.affected_resources[:5])}")
                                    
                                    if incident.indicators:
                                        st.write("**Indicators:**")
                                        for indicator in incident.indicators:
                                            st.write(f"• {indicator}")
                                    
                                    if incident.recommended_actions:
                                        st.write("**Recommended Actions:**")
                                        for action in incident.recommended_actions:
                                            st.write(f"• {action}")
                        else:
                            st.success("✅ No security incidents detected in the specified time period.")
                    
                    except Exception as e:
                        st.error(f"Security incident detection failed: {str(e)}")
        
        with tab3:
            st.subheader("User Access Pattern Analysis")
            
            # User selection
            user_email = st.text_input("Enter user email to analyze:", 
                                     placeholder="user@example.com")
            
            if user_email and st.button("👤 Analyze User Patterns"):
                with st.spinner(f"Analyzing access patterns for {user_email}..."):
                    try:
                        pattern = audit_analyzer.analyze_user_access_patterns(
                            user_email, days_back=config['days_back']
                        )
                        
                        if pattern.anomaly_score == -1:
                            st.error("Analysis failed - see logs for details")
                            return
                        
                        # Display metrics
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            st.metric("Activity Score", f"{pattern.activity_score}/100")
                        
                        with col2:
                            st.metric("Anomaly Score", f"{pattern.anomaly_score}/100")
                        
                        with col3:
                            st.metric("IP Addresses", len(pattern.ip_addresses))
                        
                        # Normal vs unusual access hours
                        if pattern.normal_access_hours:
                            st.markdown("### ⏰ Access Hour Patterns")
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.write("**Normal Access Hours:**")
                                st.write(f"Hours: {sorted(pattern.normal_access_hours)}")
                            
                            with col2:
                                st.write("**Unusual Access Times:**")
                                if pattern.unusual_access_times:
                                    for time in pattern.unusual_access_times[:5]:
                                        st.write(f"• {time}")
                                    if len(pattern.unusual_access_times) > 5:
                                        st.write(f"... and {len(pattern.unusual_access_times) - 5} more")
                                else:
                                    st.write("No unusual access times detected")
                        
                        # Service usage
                        if pattern.frequent_services:
                            st.markdown("### 🔧 Service Usage Patterns")
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.write("**Frequent Services:**")
                                for service in pattern.frequent_services:
                                    st.write(f"• {service}")
                            
                            with col2:
                                st.write("**Unusual Services:**")
                                if pattern.unusual_services:
                                    for service in pattern.unusual_services:
                                        st.write(f"• {service}")
                                else:
                                    st.write("No unusual services detected")
                        
                        # IP address analysis
                        if pattern.ip_addresses:
                            st.markdown("### 🌐 IP Address Analysis")
                            st.write(f"**Total unique IPs:** {len(pattern.ip_addresses)}")
                            
                            # Show IPs in a expandable section
                            with st.expander("View IP addresses"):
                                for ip in list(pattern.ip_addresses)[:20]:
                                    st.write(f"• {ip}")
                                if len(pattern.ip_addresses) > 20:
                                    st.write(f"... and {len(pattern.ip_addresses) - 20} more")
                            
                            # Suspicious IP changes
                            if pattern.suspicious_ip_changes:
                                st.warning(f"🚨 {len(pattern.suspicious_ip_changes)} suspicious IP changes detected!")
                                for change in pattern.suspicious_ip_changes:
                                    st.write(f"• {change['timestamp']}: {change['from_ip']} → {change['to_ip']} "
                                           f"({change['time_difference_minutes']:.1f} minutes)")
                    
                    except Exception as e:
                        st.error(f"User pattern analysis failed: {str(e)}")
        
        with tab4:
            st.subheader("Compliance Reports")
            
            # Framework selection
            framework = st.selectbox("Select compliance framework:", 
                                    ['SOX', 'PCI-DSS', 'HIPAA', 'GDPR'])
            
            if st.button("📋 Generate Compliance Report"):
                with st.spinner(f"Generating {framework} compliance report..."):
                    try:
                        start_time = datetime.now() - timedelta(days=config['days_back'])
                        end_time = datetime.now()
                        
                        report = audit_analyzer.generate_compliance_report(
                            framework, start_time, end_time
                        )
                        
                        if report.get('error'):
                            st.error(f"Report generation failed: {report['error']}")
                            return
                        
                        # Display report summary
                        st.markdown(f"## {framework} Compliance Report")
                        
                        col1, col2, col3, col4 = st.columns(4)
                        
                        with col1:
                            st.metric("Total Events", report['statistics']['total_events'])
                        
                        with col2:
                            st.metric("Violations", report['statistics']['total_violations'])
                        
                        with col3:
                            st.metric("Violation Rate", f"{report['statistics']['violation_rate']:.1f}%")
                        
                        with col4:
                            st.metric("Unique Principals", report['statistics']['unique_principals'])
                        
                        # Risk summary
                        if any(report['risk_summary'].values()):
                            st.markdown("### Risk Distribution")
                            risk_data = report['risk_summary']
                            fig = px.bar(x=list(risk_data.keys()), y=list(risk_data.values()),
                                       title="Violations by Risk Level")
                            st.plotly_chart(fig, use_container_width=True)
                        
                        # Most active principals
                        if report['statistics']['most_active_principals']:
                            st.markdown("### Most Active Principals")
                            principals_df = pd.DataFrame(report['statistics']['most_active_principals'])
                            st.dataframe(principals_df, use_container_width=True)
                        
                        # Violations
                        if report['violations']:
                            st.markdown("### 🚨 Compliance Violations")
                            violations_df = pd.DataFrame(report['violations'])
                            st.dataframe(violations_df, use_container_width=True)
                        
                        # Recommendations
                        if report.get('recommendations'):
                            st.markdown("### 🎯 Recommendations")
                            for rec in report['recommendations']:
                                st.info(rec)
                        
                        # Audit trail
                        if report['audit_trail']:
                            with st.expander("📋 Detailed Audit Trail"):
                                audit_df = pd.DataFrame(report['audit_trail'])
                                st.dataframe(audit_df, use_container_width=True)
                    
                    except Exception as e:
                        st.error(f"Compliance report generation failed: {str(e)}")
    
    except Exception as e:
        st.error(f"Error in audit trail analysis: {str(e)}")


def main():
    """Main application function."""
    init_session_state()
    
    # Render sidebar and get configuration
    config = render_sidebar()
    
    if not config:
        st.info("👈 Please authenticate and select projects in the sidebar to get started.")
        return
    
    # Load IAM data
    if config['selected_projects']:
        if st.session_state.iam_data_advanced is None:
            st.session_state.iam_data_advanced = load_iam_data(config['selected_projects'])
        iam_data = st.session_state.iam_data_advanced
    else:
        iam_data = None
    
    # Main content area
    st.title("🔒 Advanced GCP IAM Janitor")
    st.markdown("*Comprehensive IAM analysis with advanced security features*")
    
    if config['selected_projects']:
        st.info(f"Analyzing {len(config['selected_projects'])} selected projects")
    else:
        st.warning("No projects selected. Please select projects in the sidebar.")
    
    # Create tabs for different analyses
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📊 Overview",
        "🔍 Identity Analysis",
        "👑 Role Management",
        "🔐 Permission Analysis",
        "📋 Audit Trail"
    ])
    
    with tab1:
        render_overview_tab(iam_data, config)
    
    with tab2:
        render_identity_analysis_tab(iam_data, config)
    
    with tab3:
        render_role_management_tab(iam_data, config)
    
    with tab4:
        render_permission_analysis_tab(iam_data, config)
    
    with tab5:
        render_audit_trail_tab(iam_data, config)


if __name__ == "__main__":
    main()