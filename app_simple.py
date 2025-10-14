"""
GCP IAM Janitor - Simplified Version

A web application for inventorying and analyzing GCP IAM across projects.
This is a simplified version that works with the current library setup.
"""

import logging
import streamlit as st
from typing import Dict, Any, List, Optional
from google.cloud import resourcemanager
from google.auth import default
from google.auth.exceptions import DefaultCredentialsError
import pandas as pd
import plotly.express as px

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def configure_page():
    """Configure Streamlit page settings."""
    st.set_page_config(
        page_title="GCP IAM Janitor",
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
    
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
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
            state = 'ACTIVE'  # Default assumption
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
                'project_number': project.name.split('/')[-1] if '/' in project.name else 'N/A'  # Extract from name
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
        # Use the direct method call instead of request object
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


def main():
    """Main application entry point."""
    configure_page()
    
    st.markdown('<h1 class="main-header">🔐 GCP IAM Janitor</h1>', unsafe_allow_html=True)
    
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
        st.markdown("---")
        
        if st.button("🔄 Refresh Data"):
            if 'projects_cache' in st.session_state:
                del st.session_state['projects_cache']
            if 'iam_data_cache' in st.session_state:
                del st.session_state['iam_data_cache']
        
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
                st.session_state.selected_projects_simple = project_options.copy()
                st.rerun()
        with col2:
            if st.button("⭐ Select First 5"):
                st.session_state.selected_projects_simple = project_options[:5]
                st.rerun()
        with col3:
            if st.button("❌ Clear Selection"):
                st.session_state.selected_projects_simple = []
                st.rerun()
        
        # Default to first 3 projects for performance, but allow selection of any
        if 'selected_projects_simple' not in st.session_state:
            default_selection = project_options[:3] if len(project_options) >= 3 else project_options
        else:
            # Filter session state selection to only include projects that exist in filtered list
            default_selection = [p for p in st.session_state.selected_projects_simple if p in project_options]
        
        selected_projects = st.multiselect(
            f"Select projects to analyze (showing {len(filtered_projects)} projects):",
            project_options,
            default=default_selection,
            format_func=lambda x: next((p['name'] for p in filtered_projects if p['project_id'] == x), x),
            help=f"Choose from {len(filtered_projects)} projects. Use search above to filter. Use buttons above for bulk selection.",
            key="project_selector_simple"
        )
        
        # Update session state with current selection
        st.session_state.selected_projects_simple = selected_projects
    
    if not selected_projects:
        st.info("Please select projects in the sidebar to analyze.")
        return
    
    # Load IAM data for selected projects
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
    
    # Analyze data
    analysis = analyze_iam_data(projects_data)
    
    # Debug info
    if not analysis or analysis.get('projects_analyzed', 0) == 0:
        st.warning("No IAM data could be loaded for the selected projects. This might be due to permissions or project access issues.")
        st.info(f"Projects data keys: {list(projects_data.keys()) if projects_data else 'None'}")
        # Create empty analysis for display
        analysis = {
            'total_identities': 0,
            'total_roles': 0, 
            'total_bindings': 0,
            'identity_types': {},
            'projects_analyzed': 0
        }
    
    # Display metrics
    st.subheader("📊 Overview Metrics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Identities", analysis.get('total_identities', 0))
    
    with col2:
        st.metric("Total Roles", analysis.get('total_roles', 0))
    
    with col3:
        st.metric("IAM Bindings", analysis.get('total_bindings', 0))
    
    with col4:
        st.metric("Projects Analyzed", analysis.get('projects_analyzed', 0))
    
    st.markdown("---")
    
    # Visualizations
    col1, col2 = st.columns(2)
    
    with col1:
        # Identity type distribution
        identity_types = analysis.get('identity_types', {})
        if identity_types and any(identity_types.values()):
            fig = px.pie(
                values=list(identity_types.values()),
                names=list(identity_types.keys()),
                title="Identity Distribution by Type"
            )
            st.plotly_chart(fig, width='stretch')
        else:
            st.info("No identity data available for visualization")
    
    with col2:
        # Projects and bindings
        project_bindings = {}
        for project_id, policy in projects_data.items():
            if policy and 'bindings' in policy:
                project_bindings[project_id] = len(policy['bindings'])
        
        if project_bindings:
            fig = px.bar(
                x=list(project_bindings.keys()),
                y=list(project_bindings.values()),
                title="IAM Bindings per Project",
                labels={'x': 'Project ID', 'y': 'Number of IAM Bindings'}
            )
            fig.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig, width='stretch')
    
    st.markdown("---")
    
    # Detailed data
    st.subheader("📋 Detailed Analysis")
    
    # Show projects table
    projects_df = pd.DataFrame([
        {
            'Project ID': p['project_id'],
            'Name': p['name'],
            'State': p['lifecycle_state'],
            'IAM Bindings': len(projects_data.get(p['project_id'], {}).get('bindings', []))
        }
        for p in projects
        if p['project_id'] in selected_projects
    ])
    
    st.dataframe(projects_df, width='stretch')
    
    # Export functionality
    if st.button("📥 Export Analysis"):
        export_data = {
            'analysis_summary': analysis,
            'projects': projects_df.to_dict('records'),
            'raw_iam_data': projects_data
        }
        
        st.download_button(
            label="Download JSON",
            data=pd.DataFrame([export_data]).to_json(orient='records'),
            file_name=f"iam_analysis_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )


if __name__ == "__main__":
    main()