"""
GCP IAM Janitor - Main Streamlit Application

A comprehensive web application for inventorying and analyzing GCP IAM
across projects and organizations with visual insights and recommendations.
"""

import logging
import streamlit as st
from typing import Dict, Any, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import our modules
from src.auth.credentials import (
    initialize_auth, 
    is_authenticated, 
    display_auth_status,
    clear_auth
)
from src.gcp.project_client import ProjectClient
from src.gcp.org_client import OrganizationClient
from src.gcp.iam_client import IAMClient
from src.utils.cache import get_cache_manager, ProgressTracker
from src.models.iam_models import ResourceType


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
    
    .warning-card {
        background-color: #fff3cd;
        border: 1px solid #ffeaa7;
        border-radius: 0.5rem;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    
    .error-card {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        border-radius: 0.5rem;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    
    .success-card {
        background-color: #d1e7dd;
        border: 1px solid #badbcc;
        border-radius: 0.5rem;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    </style>
    """, unsafe_allow_html=True)


def create_sidebar_navigation():
    """Create sidebar navigation and filters."""
    st.sidebar.title("🔐 GCP IAM Janitor")
    st.sidebar.markdown("---")
    
    # Authentication status
    display_auth_status()
    st.sidebar.markdown("---")
    
    if not is_authenticated():
        st.sidebar.warning("Please authenticate to use the application")
        return None, {}
    
    # Page navigation
    st.sidebar.subheader("Navigation")
    page = st.sidebar.radio(
        "Choose a page:",
        ["Overview", "Identities", "Roles", "Permissions", "Settings"],
        key="page_selection"
    )
    
    st.sidebar.markdown("---")
    
    # Global filters
    st.sidebar.subheader("Filters")
    
    # Resource scope filter
    scope_options = ["All Resources", "Organization Level", "Project Level"]
    resource_scope = st.sidebar.selectbox("Resource Scope", scope_options)
    
    # Organization/Project selector
    if resource_scope in ["All Resources", "Organization Level"]:
        organizations = get_available_organizations()
        if organizations:
            selected_orgs = st.sidebar.multiselect(
                "Select Organizations",
                options=[org['organization_id'] for org in organizations],
                default=[],
                format_func=lambda x: next(
                    (org['display_name'] for org in organizations if org['organization_id'] == x), 
                    x
                )
            )
        else:
            selected_orgs = []
            st.sidebar.info("No organizations accessible")
    else:
        selected_orgs = []
    
    # Project selector (always show for project-level or all resources)
    if resource_scope in ["All Resources", "Project Level"]:
        projects = get_available_projects()
        if projects:
            selected_projects = st.sidebar.multiselect(
                "Select Projects",
                options=[proj['project_id'] for proj in projects],
                default=projects[:5] if len(projects) <= 5 else [],  # Default to first 5 or all if ≤5
                format_func=lambda x: next(
                    (proj['display_name'] for proj in projects if proj['project_id'] == x), 
                    x
                )
            )
        else:
            selected_projects = []
            st.sidebar.info("No projects accessible")
    else:
        selected_projects = []
    
    # Additional filters
    st.sidebar.markdown("### Additional Filters")
    
    identity_types = st.sidebar.multiselect(
        "Identity Types",
        ["User", "Service Account", "Group", "Domain"],
        default=["User", "Service Account", "Group"]
    )
    
    role_types = st.sidebar.multiselect(
        "Role Types", 
        ["Basic", "Predefined", "Custom"],
        default=["Basic", "Predefined", "Custom"]
    )
    
    # Cache controls
    st.sidebar.markdown("---")
    st.sidebar.subheader("Cache Controls")
    
    cache_stats = get_cache_manager().get_cache_stats()
    st.sidebar.metric("Cached Items", cache_stats['active_items'])
    
    if st.sidebar.button("🗑️ Clear Cache"):
        get_cache_manager().clear()
        st.sidebar.success("Cache cleared!")
        st.rerun()
    
    # Auto-refresh
    auto_refresh = st.sidebar.checkbox("Auto-refresh (30min)", value=True)
    if auto_refresh:
        st.sidebar.info("Data will auto-refresh every 30 minutes")
    
    filters = {
        'resource_scope': resource_scope,
        'selected_orgs': selected_orgs,
        'selected_projects': selected_projects,
        'identity_types': identity_types,
        'role_types': role_types,
        'auto_refresh': auto_refresh
    }
    
    return page, filters


@st.cache_data(ttl=1800)  # Cache for 30 minutes
def get_available_organizations() -> List[Dict[str, Any]]:
    """Get list of available organizations."""
    try:
        if not is_authenticated():
            return []
        
        credentials, _ = st.session_state.credentials, st.session_state.project_id
        org_client = OrganizationClient(credentials)
        return org_client.list_organizations()
    except Exception as e:
        logger.error(f"Error fetching organizations: {e}")
        return []


@st.cache_data(ttl=1800)  # Cache for 30 minutes
def get_available_projects() -> List[Dict[str, Any]]:
    """Get list of available projects."""
    try:
        if not is_authenticated():
            return []
        
        credentials, _ = st.session_state.credentials, st.session_state.project_id
        project_client = ProjectClient(credentials)
        return project_client.list_projects(filter_expression="lifecycleState:ACTIVE")
    except Exception as e:
        logger.error(f"Error fetching projects: {e}")
        return []


def show_welcome_message():
    """Show welcome message and authentication prompt."""
    st.markdown('<h1 class="main-header">🔐 GCP IAM Janitor</h1>', unsafe_allow_html=True)
    
    st.markdown("""
    <div class="metric-card">
    <h3>Welcome to GCP IAM Janitor!</h3>
    <p>Your comprehensive tool for analyzing and managing Google Cloud Platform IAM across projects and organizations.</p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="success-card">
        <h4>🔍 Analyze</h4>
        <p>Inventory identities, roles, and permissions across all your GCP resources</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="success-card">
        <h4>📊 Visualize</h4>
        <p>Interactive charts and graphs showing IAM relationships and usage patterns</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="success-card">
        <h4>🛡️ Secure</h4>
        <p>Identify overprivileged users and recommend security improvements</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Authentication instructions
    st.markdown("---")
    st.subheader("Getting Started")
    
    if not is_authenticated():
        st.markdown("""
        <div class="warning-card">
        <h4>⚠️ Authentication Required</h4>
        <p>To get started, please ensure you have authenticated with Google Cloud:</p>
        <ol>
        <li>Run <code>gcloud auth application-default login</code> in your terminal</li>
        <li>Or set up service account credentials</li>
        <li>Click "Retry Auth" in the sidebar</li>
        </ol>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("🔄 Try Authentication Now"):
            if initialize_auth():
                st.success("Authentication successful!")
                st.rerun()
            else:
                st.error("Authentication failed. Please check your credentials.")
    else:
        st.success("✅ Successfully authenticated! Use the sidebar to navigate through different views.")


def load_page_content(page: str, filters: Dict[str, Any]):
    """Load content for the selected page."""
    try:
        if page == "Overview":
            from src.pages.overview import render_overview_page
            render_overview_page(filters)
        
        elif page == "Identities":
            from src.pages.users import render_users_page
            render_users_page(filters)
        
        elif page == "Roles":
            from src.pages.roles import render_roles_page
            render_roles_page(filters)
        
        elif page == "Permissions":
            from src.pages.permissions import render_permissions_page
            render_permissions_page(filters)
        
        elif page == "Settings":
            render_settings_page()
        
        else:
            st.error(f"Unknown page: {page}")
    
    except ImportError as e:
        st.error(f"Page not implemented yet: {page}")
        st.info("This feature is coming soon!")
        logger.warning(f"Page {page} not implemented: {e}")
    
    except Exception as e:
        st.error(f"Error loading page {page}: {str(e)}")
        logger.error(f"Error in page {page}: {e}")


def render_settings_page():
    """Render the settings page."""
    st.title("⚙️ Settings")
    
    st.subheader("Application Settings")
    
    # Cache settings
    st.markdown("### Cache Management")
    cache_stats = get_cache_manager().get_cache_stats()
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Cached Items", cache_stats['total_items'])
    with col2:
        st.metric("Active Items", cache_stats['active_items'])
    with col3:
        st.metric("Expired Items", cache_stats['expired_items'])
    
    if st.button("Clear All Cache"):
        get_cache_manager().clear()
        st.success("Cache cleared successfully!")
    
    st.markdown("---")
    
    # Authentication settings
    st.subheader("Authentication")
    if is_authenticated():
        user_info = st.session_state.get('user_info', {})
        
        st.success(f"Authenticated as: {user_info.get('email', 'Unknown')}")
        st.info(f"Current project: {user_info.get('project_id', 'Unknown')}")
        
        if st.button("Sign Out"):
            clear_auth()
            st.success("Signed out successfully!")
            st.rerun()
    else:
        st.warning("Not authenticated")
        if st.button("Authenticate"):
            if initialize_auth():
                st.success("Authentication successful!")
                st.rerun()
            else:
                st.error("Authentication failed")
    
    st.markdown("---")
    
    # About section
    st.subheader("About")
    st.markdown("""
    **GCP IAM Janitor** is a comprehensive tool for analyzing and managing Google Cloud Platform IAM.
    
    **Features:**
    - 🔍 **Complete IAM Inventory**: Analyze identities, roles, and permissions across all GCP resources
    - 📊 **Interactive Visualizations**: Charts, graphs, and network diagrams showing IAM relationships
    - 🛡️ **Security Analysis**: Identify overprivileged users and security risks
    - 🎯 **Smart Recommendations**: AI-powered suggestions for IAM optimization
    - 📋 **Comprehensive Reporting**: Export data and generate compliance reports
    
    **Version:** 1.0.0  
    **Python:** {python_version}  
    **Streamlit:** {streamlit_version}
    """.format(
        python_version="3.13.7",
        streamlit_version=st.__version__
    ))


def main():
    """Main application entry point."""
    configure_page()
    
    # Initialize authentication
    if 'auth_initialized' not in st.session_state:
        initialize_auth()
        st.session_state.auth_initialized = True
    
    # Create navigation
    page, filters = create_sidebar_navigation()
    
    # Show content based on authentication status
    if not is_authenticated():
        show_welcome_message()
    elif page is None:
        st.error("Navigation error occurred")
    else:
        # Load the selected page
        load_page_content(page, filters)


if __name__ == "__main__":
    main()