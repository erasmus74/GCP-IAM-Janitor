"""
GCP IAM Consolidation Dashboard

A specialized dashboard focused on identifying and implementing IAM policy consolidation
opportunities through intelligent grouping recommendations.
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
import networkx as nx
import numpy as np

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
        page_title="GCP IAM Consolidation Dashboard",
        page_icon="🎯",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Custom CSS for consolidation dashboard
    st.markdown("""
    <style>
    .main-header {
        font-size: 2.8rem;
        font-weight: bold;
        text-align: center;
        color: #1f77b4;
        margin-bottom: 2rem;
    }
    
    .consolidation-metric {
        background: linear-gradient(90deg, #e3f2fd 0%, #bbdefb 100%);
        border-left: 6px solid #1976d2;
        padding: 1.5rem;
        margin: 1rem 0;
        border-radius: 0.5rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .high-impact {
        background: linear-gradient(90deg, #ffebee 0%, #ffcdd2 100%);
        border-left: 6px solid #d32f2f;
        padding: 1.5rem;
        margin: 1rem 0;
        border-radius: 0.5rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .medium-impact {
        background: linear-gradient(90deg, #fff3e0 0%, #ffe0b2 100%);
        border-left: 6px solid #f57c00;
        padding: 1.5rem;
        margin: 1rem 0;
        border-radius: 0.5rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .low-impact {
        background: linear-gradient(90deg, #e8f5e8 0%, #c8e6c9 100%);
        border-left: 6px solid #388e3c;
        padding: 1.5rem;
        margin: 1rem 0;
        border-radius: 0.5rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .roadmap-phase {
        background-color: #fafafa;
        border: 1px solid #e0e0e0;
        border-radius: 0.5rem;
        padding: 1.5rem;
        margin: 1rem 0;
    }
    
    .command-block {
        background-color: #263238;
        color: #ffffff;
        padding: 1rem;
        border-radius: 0.5rem;
        font-family: 'Courier New', monospace;
        font-size: 0.9rem;
        white-space: pre-wrap;
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


def create_consolidation_overview(consolidation_impact):
    """Create the main consolidation impact overview."""
    st.subheader("🎯 Consolidation Impact Overview")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Policies to Eliminate",
            consolidation_impact.get('total_policies_that_can_be_eliminated', 0),
            help="Total individual IAM bindings that can be consolidated into groups"
        )
    
    with col2:
        st.metric(
            "Users to Group",
            consolidation_impact.get('total_users_that_can_be_grouped', 0),
            help="Number of users that can be consolidated into groups"
        )
    
    with col3:
        st.metric(
            "Groups to Create",
            consolidation_impact.get('total_groups_to_create', 0),
            help="Total number of Google Groups to create"
        )
    
    with col4:
        reduction_pct = consolidation_impact.get('estimated_management_reduction_percentage', 0)
        st.metric(
            "Management Reduction",
            f"{reduction_pct:.0f}%",
            help="Estimated reduction in IAM management complexity"
        )
    
    # Consolidation by type chart
    consolidation_by_type = consolidation_impact.get('consolidation_by_type', {})
    if consolidation_by_type:
        fig = px.pie(
            values=list(consolidation_by_type.values()),
            names=list(consolidation_by_type.keys()),
            title="Consolidation Opportunities by Type",
            color_discrete_sequence=px.colors.qualitative.Set3
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)


def create_grouping_opportunities_dashboard(grouping_data):
    """Create detailed grouping opportunities visualization."""
    st.subheader("👥 Detailed Grouping Opportunities")
    
    # Tabs for different group types
    tab1, tab2, tab3, tab4 = st.tabs(["🎯 Exact Matches", "🔍 Similar Users", "📁 Project-Based", "🏢 Domain-Based"])
    
    with tab1:
        show_exact_match_groups(grouping_data.get('role_based_groups', []))
    
    with tab2:
        show_similarity_groups(grouping_data.get('similarity_groups', []))
    
    with tab3:
        show_project_groups(grouping_data.get('project_based_groups', []))
    
    with tab4:
        show_domain_groups(grouping_data.get('domain_based_groups', []))


def show_exact_match_groups(groups):
    """Display exact role match groups."""
    if not groups:
        st.info("No exact role match opportunities found.")
        return
    
    st.write(f"**{len(groups)} exact match opportunities found** - These are the highest priority for consolidation.")
    
    for i, group in enumerate(groups[:5]):  # Show top 5
        priority_class = f"{group['priority'].lower()}-impact"
        
        st.markdown(f"""
        <div class="{priority_class}">
        <h4>🎯 {group['suggested_group_name']} ({group['priority']} Priority)</h4>
        <p><strong>Users:</strong> {group['user_count']} users with identical permissions</p>
        <p><strong>Projects:</strong> {group['project_count']} projects affected</p>
        <p><strong>Policies Saved:</strong> {group['policies_saved']} individual IAM bindings eliminated</p>
        <p><strong>Roles:</strong> {', '.join(group['roles'][:3])}{'...' if len(group['roles']) > 3 else ''}</p>
        </div>
        """, unsafe_allow_html=True)
        
        with st.expander(f"Details for {group['suggested_group_name']}"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Users to group:**")
                for user in group['users']:
                    st.write(f"• {user}")
            
            with col2:
                st.write("**Projects:**")
                for project in group['all_projects'][:5]:
                    st.write(f"• {project}")
                if len(group['all_projects']) > 5:
                    st.write(f"... and {len(group['all_projects']) - 5} more")
            
            st.write("**All Roles:**")
            for role in group['roles']:
                st.write(f"• {role}")
            
            if 'implementation_commands' in group:
                st.write("**Implementation Commands:**")
                commands = '\n'.join(group['implementation_commands'][:10])
                st.markdown(f'<div class="command-block">{commands}</div>', unsafe_allow_html=True)


def show_similarity_groups(groups):
    """Display similarity-based groups."""
    if not groups:
        st.info("No similarity-based grouping opportunities found.")
        return
    
    st.write(f"**{len(groups)} similarity-based opportunities found** - Users with overlapping permissions.")
    
    for group in groups[:3]:  # Show top 3
        st.markdown(f"""
        <div class="medium-impact">
        <h4>🔍 {group['suggested_group_name']}</h4>
        <p><strong>Users:</strong> {group['user_count']} users with similar access patterns</p>
        <p><strong>Suggested Roles:</strong> {', '.join(group['suggested_roles'][:3])}{'...' if len(group['suggested_roles']) > 3 else ''}</p>
        <p><strong>Consolidation Value:</strong> {group['consolidation_value']}</p>
        </div>
        """, unsafe_allow_html=True)
        
        with st.expander(f"Similarity Analysis for {group['suggested_group_name']}"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Current Role Overlap:**")
                for role in group['current_roles_overlap']:
                    st.write(f"• {role}")
            
            with col2:
                st.write("**Suggested Optimal Roles:**")
                for role in group['suggested_roles']:
                    st.write(f"• {role}")
            
            st.write("**Users in Group:**")
            for user in group['users']:
                st.write(f"• {user}")


def show_project_groups(groups):
    """Display project-based groups."""
    if not groups:
        st.info("No project-based grouping opportunities found.")
        return
    
    st.write(f"**{len(groups)} project-based opportunities found** - Users with similar project access patterns.")
    
    for group in groups[:3]:  # Show top 3
        st.markdown(f"""
        <div class="medium-impact">
        <h4>📁 {group['suggested_group_name']}</h4>
        <p><strong>Users:</strong> {group['user_count']} users across {group['project_count']} shared projects</p>
        <p><strong>Role Overlap:</strong> {group['role_overlap_percentage']:.1f}%</p>
        <p><strong>Common Roles:</strong> {', '.join(group['common_roles'][:3])}</p>
        </div>
        """, unsafe_allow_html=True)


def show_domain_groups(groups):
    """Display domain-based groups."""
    if not groups:
        st.info("No domain-based grouping opportunities found.")
        return
    
    st.write(f"**{len(groups)} domain-based opportunities found** - Users from the same organization domain.")
    
    for group in groups[:3]:  # Show top 3
        st.markdown(f"""
        <div class="low-impact">
        <h4>🏢 {group['suggested_group_name']}</h4>
        <p><strong>Domain:</strong> {group['domain']}</p>
        <p><strong>Users:</strong> {group['user_count']} users from this domain</p>
        <p><strong>Common Roles:</strong> {', '.join(group['common_roles'][:3]) if group['common_roles'] else 'None - consider role standardization'}</p>
        </div>
        """, unsafe_allow_html=True)


def create_consolidation_network_graph(grouping_data):
    """Create a network graph showing user-role relationships."""
    st.subheader("🕸️ User-Role Relationship Network")
    
    # Prepare data for network graph
    all_groups = (
        grouping_data.get('role_based_groups', []) +
        grouping_data.get('similarity_groups', []) +
        grouping_data.get('project_based_groups', [])
    )
    
    if not all_groups:
        st.info("No grouping data available for network visualization.")
        return
    
    # Create network graph
    G = nx.Graph()
    
    # Add nodes and edges
    group_colors = {'HIGH': '#d32f2f', 'MEDIUM': '#f57c00', 'LOW': '#388e3c'}
    node_data = []
    edge_data = []
    
    for group in all_groups[:10]:  # Limit to top 10 for readability
        group_name = group['suggested_group_name']
        priority = group.get('priority', 'MEDIUM')
        
        # Add group node
        G.add_node(group_name, type='group', priority=priority, size=len(group['users']) * 3)
        node_data.append({
            'name': group_name,
            'type': 'group',
            'priority': priority,
            'size': len(group['users']) * 3,
            'color': group_colors.get(priority, '#666666')
        })
        
        # Add user nodes and edges
        for user in group['users'][:5]:  # Limit users per group
            user_short = user.split('@')[0] if '@' in user else user
            if not G.has_node(user_short):
                G.add_node(user_short, type='user', size=10)
                node_data.append({
                    'name': user_short,
                    'type': 'user',
                    'priority': 'USER',
                    'size': 10,
                    'color': '#1f77b4'
                })
            
            G.add_edge(group_name, user_short)
            edge_data.append((group_name, user_short))
    
    # Create Plotly network graph
    pos = nx.spring_layout(G, k=1, iterations=50)
    
    # Prepare edge traces
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
    
    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines'
    )
    
    # Prepare node traces
    node_x = []
    node_y = []
    node_info = []
    node_colors = []
    node_sizes = []
    
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        
        node_data_item = next((item for item in node_data if item['name'] == node), None)
        if node_data_item:
            node_colors.append(node_data_item['color'])
            node_sizes.append(node_data_item['size'])
            if node_data_item['type'] == 'group':
                node_info.append(f"Group: {node}<br>Priority: {node_data_item['priority']}")
            else:
                node_info.append(f"User: {node}")
        else:
            node_colors.append('#666666')
            node_sizes.append(10)
            node_info.append(f"Node: {node}")
    
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        text=[node for node in G.nodes()],
        textposition="middle center",
        textfont_size=8,
        hovertext=node_info,
        marker=dict(
            size=node_sizes,
            color=node_colors,
            line=dict(width=2, color='white')
        )
    )
    
    fig = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(
                        title=dict(text="User-Group Consolidation Network", font=dict(size=16)),
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=20,l=5,r=5,t=40),
                        annotations=[ dict(
                            text="Groups (larger nodes) show consolidation opportunities. Lines connect users to suggested groups.",
                            showarrow=False,
                            xref="paper", yref="paper",
                            x=0.005, y=-0.002,
                            xanchor='left', yanchor='bottom',
                            font=dict(color="gray", size=10)
                        )],
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                    )
    
    st.plotly_chart(fig, use_container_width=True)


def create_implementation_roadmap(roadmap_data):
    """Create implementation roadmap visualization."""
    st.subheader("🛣️ Implementation Roadmap")
    
    if not roadmap_data:
        st.info("No implementation roadmap available.")
        return
    
    for phase in roadmap_data:
        st.markdown(f"""
        <div class="roadmap-phase">
        <h3>📅 {phase['title']}</h3>
        <p><strong>Estimated Effort:</strong> {phase['implementation_effort']}</p>
        <p><strong>Policies Saved:</strong> {phase['estimated_policies_saved']} IAM bindings</p>
        <p><strong>Groups in Phase:</strong> {len(phase['groups'])}</p>
        </div>
        """, unsafe_allow_html=True)
        
        with st.expander(f"Phase {phase['phase']} Details"):
            for group in phase['groups']:
                st.write(f"**🎯 {group['name']}** ({group['priority']} Priority)")
                st.write(f"- {group['user_count']} users across {len(group['projects'])} projects")
                st.write(f"- Saves {group['policies_saved']} policies")
                st.write(f"- Type: {group['type']}")
                
                if group.get('implementation_commands'):
                    with st.expander(f"Commands for {group['name']}"):
                        commands = '\n'.join(group['implementation_commands'][:15])
                        st.markdown(f'<div class="command-block">{commands}</div>', unsafe_allow_html=True)
                
                st.write("---")


def create_consolidation_matrix(grouping_data):
    """Create a consolidation impact matrix."""
    st.subheader("📊 Consolidation Impact Matrix")
    
    all_groups = (
        grouping_data.get('role_based_groups', []) +
        grouping_data.get('similarity_groups', []) +
        grouping_data.get('project_based_groups', []) +
        grouping_data.get('domain_based_groups', [])
    )
    
    if not all_groups:
        st.info("No grouping data available for matrix.")
        return
    
    # Prepare data for heatmap
    matrix_data = []
    for group in all_groups[:20]:  # Top 20 groups
        matrix_data.append({
            'Group': group['suggested_group_name'][:30],
            'Users': group['user_count'],
            'Projects': group.get('project_count', len(group.get('all_projects', group.get('projects', [])))),
            'Policies Saved': group.get('policies_saved', 0),
            'Consolidation Value': group['consolidation_value'],
            'Priority Score': {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(group.get('priority', 'LOW'), 1)
        })
    
    if matrix_data:
        df = pd.DataFrame(matrix_data)
        
        # Normalize values for heatmap
        numeric_cols = ['Users', 'Projects', 'Policies Saved', 'Consolidation Value', 'Priority Score']
        for col in numeric_cols:
            if col in df.columns:
                df[f'{col}_norm'] = df[col] / df[col].max() if df[col].max() > 0 else 0
        
        # Create heatmap
        fig = px.imshow(
            df[[f'{col}_norm' for col in numeric_cols]].T,
            labels=dict(x="Groups", y="Metrics", color="Normalized Value"),
            x=df['Group'],
            y=['Users', 'Projects', 'Policies Saved', 'Consolidation Value', 'Priority Score'],
            color_continuous_scale='RdYlBu_r',
            aspect="auto"
        )
        
        fig.update_layout(
            title="Consolidation Opportunities Heatmap",
            height=400,
            xaxis_tickangle=-45
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Show data table
        st.write("**Detailed Metrics:**")
        st.dataframe(df[['Group'] + numeric_cols], use_container_width=True)


def main():
    """Main application entry point."""
    configure_page()
    
    st.markdown('<h1 class="main-header">🎯 GCP IAM Consolidation Dashboard</h1>', unsafe_allow_html=True)
    st.markdown("*Intelligent IAM Policy Consolidation through Smart Grouping*")
    
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
        st.title("🎯 IAM Consolidation")
        st.markdown("*Smart Grouping Dashboard*")
        st.markdown("---")
        
        if st.button("🔄 Refresh Analysis"):
            # Clear all cache
            for key in list(st.session_state.keys()):
                if 'cache' in key or 'consolidation' in key:
                    del st.session_state[key]
        
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
            "🔍 Search projects:",
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
        col1, col2 = st.columns(2)
        with col1:
            if st.button("✅ Select All"):
                st.session_state.selected_projects_consolidation = project_options.copy()
                st.rerun()
        with col2:
            if st.button("❌ Clear All"):
                st.session_state.selected_projects_consolidation = []
                st.rerun()
        
        # Default to first 10 projects for performance
        if 'selected_projects_consolidation' not in st.session_state:
            default_selection = project_options[:10] if len(project_options) >= 10 else project_options
        else:
            # Ensure selected projects are still in the current filtered list
            default_selection = [p for p in st.session_state.selected_projects_consolidation if p in project_options]
        
        selected_projects = st.multiselect(
            f"Select projects ({len(filtered_projects)} available):",
            project_options,
            default=default_selection,
            format_func=lambda x: next((p['name'] for p in filtered_projects if p['project_id'] == x), x),
            help="Choose projects for consolidation analysis. More projects = better insights but slower processing.",
            key="project_selector_consolidation"
        )
        
        # Update session state with current selection
        st.session_state.selected_projects_consolidation = selected_projects
        
        # Analysis options
        st.markdown("---")
        st.subheader("Analysis Options")
        
        min_consolidation_value = st.slider(
            "Minimum Consolidation Value",
            min_value=1,
            max_value=50,
            value=5,
            help="Filter out low-impact grouping opportunities"
        )
        
        show_implementation_commands = st.checkbox(
            "Show Implementation Commands",
            value=True,
            help="Include gcloud commands for implementing groups"
        )
    
    if not selected_projects:
        st.info("Please select projects in the sidebar to begin consolidation analysis.")
        return
    
    # Load IAM data
    cache_key = f"consolidation_data_{'-'.join(selected_projects)}"
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
    
    # Run consolidation analysis
    insights_cache_key = f"consolidation_insights_{cache_key}_{min_consolidation_value}"
    
    if insights_cache_key not in st.session_state:
        with st.spinner("🧠 Analyzing consolidation opportunities..."):
            insights_engine = IAMInsights()
            insights_data = insights_engine.analyze_project_data(projects_data)
            
            # Filter by minimum consolidation value
            for group_type in ['role_based_groups', 'similarity_groups', 'project_based_groups', 'domain_based_groups']:
                if group_type in insights_data['grouping_opportunities']:
                    insights_data['grouping_opportunities'][group_type] = [
                        group for group in insights_data['grouping_opportunities'][group_type]
                        if group.get('consolidation_value', 0) >= min_consolidation_value
                    ]
            
            st.session_state[insights_cache_key] = insights_data
    
    consolidation_data = st.session_state[insights_cache_key]
    grouping_opportunities = consolidation_data.get('grouping_opportunities', {})
    
    # Main dashboard sections
    create_consolidation_overview(grouping_opportunities.get('consolidation_impact', {}))
    
    st.markdown("---")
    
    create_grouping_opportunities_dashboard(grouping_opportunities)
    
    st.markdown("---")
    
    create_consolidation_network_graph(grouping_opportunities)
    
    st.markdown("---")
    
    create_consolidation_matrix(grouping_opportunities)
    
    st.markdown("---")
    
    if 'implementation_roadmap' in grouping_opportunities:
        create_implementation_roadmap(grouping_opportunities['implementation_roadmap'])


if __name__ == "__main__":
    main()