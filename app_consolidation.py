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
from datetime import datetime
import json

# Import our analytics module
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from src.analytics.insights import IAMInsights
from src.compliance.compliance_analyzer import ComplianceAnalyzer, ComplianceFramework

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
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["🎯 Exact Matches", "🔍 Similar Users", "📁 Project-Based", "🏢 Domain-Based", "🔍 Inactive Analysis", "📃 Compliance"])
    
    with tab1:
        show_exact_match_groups(grouping_data.get('role_based_groups', []))
    
    with tab2:
        show_similarity_groups(grouping_data.get('similarity_groups', []))
    
    with tab3:
        show_project_groups(grouping_data.get('project_based_groups', []))
    
    with tab4:
        show_domain_groups(grouping_data.get('domain_based_groups', []))
    
    with tab5:
        show_inactive_analysis(grouping_data.get('inactive_analysis', {}))
    
    with tab6:
        show_compliance_analysis(grouping_data.get('compliance_analysis', {}))


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
                # Show more commands and use text area for better display
                commands = '\n'.join(group['implementation_commands'])
                
                # Create a downloadable script
                script_name = f"{group['suggested_group_name']}-consolidation.sh"
                st.download_button(
                    label=f"📥 Download {script_name}",
                    data=commands,
                    file_name=script_name,
                    mime='text/plain'
                )
                
                # Show preview with expandable view
                with st.expander(f"Preview Script ({len(group['implementation_commands'])} lines)", expanded=False):
                    st.code(commands, language='bash')


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


def show_inactive_analysis(inactive_data):
    """Display inactive identity analysis."""
    if not inactive_data:
        st.info("No inactive identity analysis available.")
        return
    
    usage_summary = inactive_data.get('usage_summary', {})
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Never Used",
            usage_summary.get('never_used_count', 0),
            help="Identities that appear to have never been used"
        )
    
    with col2:
        st.metric(
            "Inactive 30+ Days",
            usage_summary.get('inactive_30_count', 0),
            help="Identities potentially inactive for 30+ days"
        )
    
    with col3:
        st.metric(
            "Inactive 90+ Days",
            usage_summary.get('inactive_90_count', 0),
            help="Identities potentially inactive for 90+ days"
        )
    
    with col4:
        st.metric(
            "High Risk",
            len(inactive_data.get('inactive_users', [])),
            help="External users and other high-risk identities"
        )
    
    # Detailed analysis sections
    st.markdown("---")
    
    # Never used identities
    never_used = inactive_data.get('never_used_identities', [])
    if never_used:
        st.subheader("⚠️ Never Used Identities")
        st.write(f"**{len(never_used)} identities** appear to have never been used and could potentially be removed.")
        
        for identity in never_used[:5]:  # Show top 5
            st.markdown(f"""
            <div class="high-impact">
            <h5>🔴 {identity['identity']}</h5>
            <p><strong>Type:</strong> {identity['type']}</p>
            <p><strong>Projects:</strong> {', '.join(identity['projects'])}</p>
            <p><strong>Roles:</strong> {', '.join(identity['roles'])}</p>
            <p><strong>Reason:</strong> {identity['reason']}</p>
            <p><strong>Recommendation:</strong> {identity['recommendation']}</p>
            <p><strong>Confidence:</strong> {identity['confidence']}</p>
            </div>
            """, unsafe_allow_html=True)
    
    # 30-day inactive
    inactive_30 = inactive_data.get('inactive_30_days', [])
    if inactive_30:
        st.subheader("🟡 Potentially Inactive (30+ Days)")
        st.write(f"**{len(inactive_30)} identities** may be inactive for 30+ days.")
        
        with st.expander(f"View {len(inactive_30)} potentially inactive identities"):
            for identity in inactive_30[:10]:  # Show top 10
                st.write(f"**{identity['identity']}** ({identity['type']})")
                st.write(f"- Projects: {', '.join(identity['projects'])}")
                st.write(f"- Roles: {', '.join(identity['roles'])}")
                st.write(f"- Action: {identity['suggested_action']}")
                st.write("---")
    
    # 90-day inactive
    inactive_90 = inactive_data.get('inactive_90_days', [])
    if inactive_90:
        st.subheader("🟠 Potentially Inactive (90+ Days)")
        st.write(f"**{len(inactive_90)} identities** may be inactive for 90+ days.")
        
        with st.expander(f"View {len(inactive_90)} long-term inactive identities"):
            for identity in inactive_90[:10]:  # Show top 10
                st.write(f"**{identity['identity']}** ({identity['type']})")
                st.write(f"- Projects: {', '.join(identity['projects'])}")
                st.write(f"- Roles: {', '.join(identity['roles'])}")
                st.write(f"- Action: {identity['suggested_action']}")
                st.write("---")
    
    # High-risk identities (external users, etc.)
    high_risk = inactive_data.get('inactive_users', [])
    if high_risk:
        st.subheader("🔴 High-Risk External Access")
        st.write(f"**{len(high_risk)} external users** require immediate attention.")
        
        for user in high_risk[:5]:  # Show top 5
            st.markdown(f"""
            <div class="high-impact">
            <h5>🔴 {user['identity']}</h5>
            <p><strong>Domain:</strong> {user.get('domain', 'Unknown')}</p>
            <p><strong>Risk Level:</strong> {user.get('risk_level', 'HIGH')}</p>
            <p><strong>Projects:</strong> {len(user['projects'])} projects</p>
            <p><strong>Roles:</strong> {len(user['roles'])} roles</p>
            <p><strong>Reason:</strong> {user['reason']}</p>
            <p><strong>Recommendation:</strong> {user['recommendation']}</p>
            </div>
            """, unsafe_allow_html=True)
    
    # Stale service accounts
    stale_sas = inactive_data.get('stale_service_accounts', [])
    if stale_sas:
        st.subheader("🤖 Stale Service Accounts")
        st.write(f"**{len(stale_sas)} service accounts** may be abandoned or unused.")
        
        with st.expander(f"View {len(stale_sas)} stale service accounts"):
            for sa in stale_sas:
                st.write(f"**{sa['identity']}**")
                st.write(f"- Projects: {', '.join(sa['projects'])}")
                st.write(f"- Roles: {', '.join(sa['roles'])}")
                st.write(f"- Risk Level: {sa.get('risk_level', 'LOW')}")
                st.write(f"- Recommendation: {sa['recommendation']}")
                st.write("---")


def show_compliance_analysis(compliance_data):
    """Display compliance analysis across multiple frameworks."""
    if not compliance_data:
        st.info("No compliance analysis available. Run compliance analysis to see results.")
        return
    
    # Overall compliance summary
    overall_summary = compliance_data.get('overall_summary', {})
    
    if overall_summary:
        st.subheader("🏆 Overall Compliance Summary")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            score = overall_summary.get('overall_score', 0)
            st.metric("Overall Score", f"{score}%", help="Average compliance score across all frameworks")
        
        with col2:
            status = overall_summary.get('overall_status', 'UNKNOWN')
            status_color = {
                'COMPLIANT': '🟢',
                'PARTIAL': '🟡', 
                'NON_COMPLIANT': '🔴'
            }.get(status, '⚪')
            st.metric("Status", f"{status_color} {status}")
        
        with col3:
            frameworks = overall_summary.get('frameworks_count', 0)
            st.metric("Frameworks", frameworks, help="Number of compliance frameworks analyzed")
        
        with col4:
            findings = overall_summary.get('total_findings', 0)
            st.metric("Total Findings", findings, help="Total compliance findings across all frameworks")
        
        # Findings breakdown
        if overall_summary.get('critical_findings', 0) > 0 or overall_summary.get('high_findings', 0) > 0:
            st.markdown("---")
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                critical = overall_summary.get('critical_findings', 0)
                st.metric("🔴 Critical", critical)
            
            with col2:
                high = overall_summary.get('high_findings', 0)
                st.metric("🟠 High", high)
            
            with col3:
                medium = overall_summary.get('medium_findings', 0)
                st.metric("🟡 Medium", medium)
            
            with col4:
                low = overall_summary.get('low_findings', 0)
                st.metric("🟢 Low", low)
    
    # Framework-specific results
    framework_results = compliance_data.get('framework_results', {})
    
    if framework_results:
        st.markdown("---")
        st.subheader("📋 Framework-Specific Results")
        
        # Create tabs for each framework
        framework_names = list(framework_results.keys())
        if len(framework_names) > 0:
            tabs = st.tabs([f"{name}" for name in framework_names])
            
            for i, (framework_name, result) in enumerate(framework_results.items()):
                with tabs[i]:
                    show_framework_compliance_details(framework_name, result)
    
    # Cross-framework issues
    cross_issues = compliance_data.get('cross_framework_issues', [])
    if cross_issues:
        st.markdown("---")
        st.subheader("⚠️ Cross-Framework Issues")
        st.write(f"**{len(cross_issues)} issues** affect multiple compliance frameworks:")
        
        for issue in cross_issues:
            st.markdown(f"""
            <div class="high-impact">
            <h5>🔴 {issue['issue_type'].replace('_', ' ').title()}</h5>
            <p><strong>Affected Frameworks:</strong> {', '.join(issue['affected_frameworks'])}</p>
            <p><strong>Impact:</strong> {issue['impact']}</p>
            <p><strong>Priority:</strong> {issue['priority']}</p>
            </div>
            """, unsafe_allow_html=True)
    
    # Consolidated recommendations
    recommendations = compliance_data.get('recommendations', [])
    if recommendations:
        st.markdown("---")
        st.subheader("🎯 Consolidated Recommendations")
        
        for rec in recommendations[:5]:  # Show top 5
            priority_class = f"{rec['priority'].lower()}-impact"
            
            st.markdown(f"""
            <div class="{priority_class}">
            <h5>📋 {rec['control_area'].replace('_', ' ').title()} ({rec['priority']} Priority)</h5>
            <p><strong>Affected Controls:</strong> {rec['affected_controls']}</p>
            <p><strong>Frameworks Impacted:</strong> {rec['frameworks_impacted']}</p>
            <p><strong>Recommendation:</strong> {rec['recommendation']}</p>
            </div>
            """, unsafe_allow_html=True)
    
    # Export functionality
    if compliance_data:
        st.markdown("---")
        st.subheader("📥 Export Compliance Report")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            # Export as JSON
            json_data = json.dumps(compliance_data, indent=2, default=str)
            st.download_button(
                label="📥 Download JSON Report",
                data=json_data,
                file_name=f"compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
        
        with col2:
            # Export as CSV (summary)
            csv_data = generate_compliance_csv(compliance_data)
            st.download_button(
                label="📥 Download CSV Summary",
                data=csv_data,
                file_name=f"compliance_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        
        with col3:
            # Export as markdown report
            markdown_data = generate_compliance_markdown(compliance_data)
            st.download_button(
                label="📥 Download Markdown Report",
                data=markdown_data,
                file_name=f"compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown"
            )


def show_framework_compliance_details(framework_name: str, result: Dict[str, Any]):
    """Show detailed compliance results for a specific framework."""
    # Framework summary
    col1, col2, col3 = st.columns(3)
    
    with col1:
        score = result.get('overall_score', 0)
        st.metric("Framework Score", f"{score}%")
    
    with col2:
        compliant = result.get('compliant_controls', 0)
        total = result.get('total_controls', 0)
        st.metric("Compliant Controls", f"{compliant}/{total}")
    
    with col3:
        findings = len(result.get('findings', []))
        st.metric("Findings", findings)
    
    # Findings details
    findings = result.get('findings', [])
    if findings:
        st.write("### Detailed Findings")
        
        # Group findings by severity
        findings_by_severity = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': []
        }
        
        for finding in findings:
            severity = finding.get('severity', 'LOW')
            findings_by_severity[severity].append(finding)
        
        # Show findings by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_findings = findings_by_severity[severity]
            if severity_findings:
                severity_icon = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🟢'
                }[severity]
                
                with st.expander(f"{severity_icon} {severity} Findings ({len(severity_findings)})", expanded=(severity in ['CRITICAL', 'HIGH'])):
                    for finding in severity_findings:
                        st.write(f"**{finding['control_id']}: {finding['control_name']}**")
                        st.write(f"Status: {finding['status']}")
                        st.write(f"Area: {finding['control_area']}")
                        
                        if finding.get('findings'):
                            st.write("Issues:")
                            for issue in finding['findings']:
                                st.write(f"- {issue}")
                        
                        if finding.get('recommendation'):
                            st.write(f"**Recommendation:** {finding['recommendation']}")
                        
                        st.write("---")
    else:
        st.success(f"No compliance issues found for {framework_name}!")


def generate_compliance_csv(compliance_data: Dict[str, Any]) -> str:
    """Generate CSV summary of compliance results."""
    csv_lines = []
    csv_lines.append("Framework,Score,Status,Total_Controls,Compliant_Controls,Findings_Count")
    
    framework_results = compliance_data.get('framework_results', {})
    for framework_name, result in framework_results.items():
        score = result.get('overall_score', 0)
        compliant = result.get('compliant_controls', 0)
        total = result.get('total_controls', 0)
        findings_count = len(result.get('findings', []))
        status = "COMPLIANT" if score >= 90 else "PARTIAL" if score >= 70 else "NON_COMPLIANT"
        
        csv_lines.append(f"{framework_name},{score},{status},{total},{compliant},{findings_count}")
    
    return "\n".join(csv_lines)


def generate_compliance_markdown(compliance_data: Dict[str, Any]) -> str:
    """Generate markdown compliance report."""
    lines = []
    
    # Header
    lines.append("# GCP IAM Compliance Report")
    lines.append(f"Generated: {compliance_data.get('analysis_timestamp', datetime.now().isoformat())}")
    lines.append("")
    
    # Overall summary
    overall = compliance_data.get('overall_summary', {})
    if overall:
        lines.append("## Overall Summary")
        lines.append(f"- **Overall Score:** {overall.get('overall_score', 0)}%")
        lines.append(f"- **Status:** {overall.get('overall_status', 'UNKNOWN')}")
        lines.append(f"- **Frameworks Analyzed:** {overall.get('frameworks_count', 0)}")
        lines.append(f"- **Total Findings:** {overall.get('total_findings', 0)}")
        lines.append("")
        
        lines.append("### Findings Breakdown")
        lines.append(f"- **Critical:** {overall.get('critical_findings', 0)}")
        lines.append(f"- **High:** {overall.get('high_findings', 0)}")
        lines.append(f"- **Medium:** {overall.get('medium_findings', 0)}")
        lines.append(f"- **Low:** {overall.get('low_findings', 0)}")
        lines.append("")
    
    # Framework results
    framework_results = compliance_data.get('framework_results', {})
    if framework_results:
        lines.append("## Framework Results")
        lines.append("")
        
        for framework_name, result in framework_results.items():
            lines.append(f"### {framework_name}")
            lines.append(f"- **Score:** {result.get('overall_score', 0)}%")
            lines.append(f"- **Compliant Controls:** {result.get('compliant_controls', 0)}/{result.get('total_controls', 0)}")
            lines.append("")
            
            findings = result.get('findings', [])
            if findings:
                lines.append("#### Key Findings")
                for finding in findings[:5]:  # Top 5 findings
                    lines.append(f"- **{finding.get('control_id', 'N/A')}:** {finding.get('control_name', 'N/A')}")
                    lines.append(f"  - Status: {finding.get('status', 'UNKNOWN')}")
                    lines.append(f"  - Severity: {finding.get('severity', 'UNKNOWN')}")
                    if finding.get('recommendation'):
                        lines.append(f"  - Recommendation: {finding['recommendation']}")
                    lines.append("")
            else:
                lines.append("✅ No compliance issues found!")
                lines.append("")
    
    # Recommendations
    recommendations = compliance_data.get('recommendations', [])
    if recommendations:
        lines.append("## Recommendations")
        lines.append("")
        
        for rec in recommendations:
            lines.append(f"### {rec.get('control_area', 'General').replace('_', ' ').title()} ({rec.get('priority', 'MEDIUM')} Priority)")
            lines.append(f"- **Affected Controls:** {rec.get('affected_controls', 0)}")
            lines.append(f"- **Frameworks Impacted:** {rec.get('frameworks_impacted', 0)}")
            lines.append(f"- **Recommendation:** {rec.get('recommendation', 'Review and remediate')}")
            lines.append("")
    
    return "\n".join(lines)

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
                    commands = '\n'.join(group['implementation_commands'])
                    script_name = f"{group['name']}-consolidation.sh"
                    
                    col1, col2 = st.columns([1, 3])
                    with col1:
                        st.download_button(
                            label=f"📥 Download Script",
                            data=commands,
                            file_name=script_name,
                            mime='text/plain',
                            key=f"download_{group.get('group_id', group['name'])}"
                        )
                    
                    with st.expander(f"View Commands for {group['name']} ({len(group['implementation_commands'])} lines)"):
                        st.code(commands, language='bash')
                
                st.write("---")


def create_org_level_opportunities(org_data):
    """Create organization-level opportunities visualization."""
    st.subheader("🏢 Organization-Level Opportunities")
    
    if not org_data:
        st.info("No organization-level opportunities identified.")
        return
    
    # Summary metrics
    summary = org_data.get('implementation_summary', {})
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Org-Level Candidates",
            summary.get('total_org_opportunities', 0),
            help="Roles that should be moved to organization or folder level"
        )
    
    with col2:
        st.metric(
            "Policies Reduced",
            summary.get('estimated_policies_reduced', 0),
            help="Estimated IAM bindings that can be eliminated"
        )
    
    with col3:
        st.metric(
            "Affected Identities",
            summary.get('affected_identities', 0),
            help="Identities that would benefit from org-level assignment"
        )
    
    with col4:
        st.metric(
            "High Priority",
            summary.get('high_priority_count', 0),
            help="High-impact opportunities requiring immediate attention"
        )
    
    # Organization-level candidates
    org_candidates = org_data.get('org_level_candidates', [])
    if org_candidates:
        st.subheader("🎯 Organization-Level Role Assignments")
        st.write(f"**{len(org_candidates)} roles** should be moved to organization level for maximum efficiency.")
        
        for i, candidate in enumerate(org_candidates[:5]):
            priority_class = f"{candidate['priority'].lower()}-impact"
            
            st.markdown(f"""
            <div class="{priority_class}">
            <h4>🏢 {candidate['role']} ({candidate['priority']} Priority)</h4>
            <p><strong>Scope:</strong> {candidate['project_count']} projects, {candidate['identity_count']} identities</p>
            <p><strong>Consolidation Value:</strong> {candidate['consolidation_value']}</p>
            <p><strong>Policies Saved:</strong> {candidate['estimated_policies_saved']} IAM bindings</p>
            <p><strong>Recommendation:</strong> {candidate['recommendation']}</p>
            </div>
            """, unsafe_allow_html=True)
            
            with st.expander(f"Details for {candidate['role']}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**Affected Identities:**")
                    for identity in candidate['identities'][:10]:
                        identity_email = identity.split(':')[-1] if ':' in identity else identity
                        st.write(f"• {identity_email}")
                    if len(candidate['identities']) > 10:
                        st.write(f"... and {len(candidate['identities']) - 10} more")
                
                with col2:
                    st.write("**Affected Projects:**")
                    for project in candidate['projects'][:10]:
                        st.write(f"• {project}")
                    if len(candidate['projects']) > 10:
                        st.write(f"... and {len(candidate['projects']) - 10} more")
    
    # Folder-level candidates
    folder_candidates = org_data.get('folder_level_candidates', [])
    if folder_candidates:
        st.subheader("📁 Folder-Level Opportunities")
        st.write(f"**{len(folder_candidates)} roles** could be optimized at folder level.")
        
        with st.expander(f"View {len(folder_candidates)} folder-level opportunities"):
            for candidate in folder_candidates:
                st.write(f"**{candidate['role']}**")
                st.write(f"- Projects: {candidate['project_count']}")
                st.write(f"- Identities: {candidate['identity_count']}")
                st.write(f"- Consolidation Value: {candidate['consolidation_value']}")
                st.write("---")
    
    # Suggested org-level groups
    org_groups = org_data.get('org_level_groups', [])
    if org_groups:
        st.subheader("👥 Suggested Organization-Level Groups")
        st.write(f"**{len(org_groups)} groups** could be created at organization level for maximum consolidation.")
        
        for group in org_groups[:3]:
            st.markdown(f"""
            <div class="medium-impact">
            <h4>🏢 {group['suggested_group_name']}</h4>
            <p><strong>Identities:</strong> {group['identity_count']} identities with similar org-wide access</p>
            <p><strong>Projects:</strong> {group['project_count']} projects affected</p>
            <p><strong>Common Roles:</strong> {len(group['common_roles'])} roles</p>
            <p><strong>Estimated Savings:</strong> {group['estimated_savings']} IAM bindings</p>
            </div>
            """, unsafe_allow_html=True)
    
    # Suggested policies
    suggested_policies = org_data.get('suggested_org_policies', [])
    if suggested_policies:
        st.subheader("📋 Recommended Organization Policies")
        st.write(f"**{len(suggested_policies)} specific policies** are recommended for implementation.")
        
        for policy in suggested_policies[:3]:
            priority_class = f"{policy['priority'].lower()}-impact"
            
            st.markdown(f"""
            <div class="{priority_class}">
            <h4>📋 {policy['policy_type'].replace('_', ' ').title()}</h4>
            <p><strong>Role:</strong> {policy['role']}</p>
            <p><strong>Suggested Group:</strong> {policy['suggested_group']}</p>
            <p><strong>Impact:</strong> {policy['estimated_reduction']}</p>
            <p><strong>Complexity:</strong> {policy['complexity']}</p>
            </div>
            """, unsafe_allow_html=True)
            
            with st.expander(f"Implementation steps for {policy['role']}"):
                st.write("**Implementation Steps:**")
                for step in policy['implementation_steps']:
                    st.write(f"• {step}")


def create_master_script_download(grouping_data):
    """Create master script download section."""
    st.subheader("📦 Download Consolidation Scripts")
    
    # Collect all groups with implementation commands
    all_groups = []
    for group_type in ['role_based_groups', 'similarity_groups', 'project_based_groups', 'domain_based_groups']:
        groups = grouping_data.get(group_type, [])
        for group in groups:
            if 'implementation_commands' in group and group['implementation_commands']:
                all_groups.append({
                    'name': group['suggested_group_name'],
                    'type': group_type.replace('_', ' ').title(),
                    'priority': group.get('priority', 'MEDIUM'),
                    'commands': group['implementation_commands'],
                    'policies_saved': group.get('policies_saved', 0),
                    'user_count': group.get('user_count', len(group.get('users', []))),
                    'project_count': group.get('project_count', len(group.get('all_projects', group.get('projects', []))))
                })
    
    if not all_groups:
        st.info("No consolidation scripts available for download.")
        return
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Available Scripts", len(all_groups))
    
    with col2:
        total_policies = sum(g['policies_saved'] for g in all_groups)
        st.metric("Total Policies Saved", total_policies)
    
    with col3:
        total_users = sum(g['user_count'] for g in all_groups)
        st.metric("Users Affected", total_users)
    
    with col4:
        high_priority = len([g for g in all_groups if g['priority'] == 'HIGH'])
        st.metric("High Priority", high_priority)
    
    # Individual script downloads
    st.write("### Individual Scripts")
    
    # Group by priority for better organization
    priority_groups = {'HIGH': [], 'MEDIUM': [], 'LOW': []}
    for group in all_groups:
        priority_groups[group['priority']].append(group)
    
    for priority in ['HIGH', 'MEDIUM', 'LOW']:
        if priority_groups[priority]:
            with st.expander(f"{priority} Priority Scripts ({len(priority_groups[priority])} scripts)", expanded=(priority == 'HIGH')):
                for group in priority_groups[priority]:
                    col1, col2, col3 = st.columns([2, 1, 1])
                    
                    with col1:
                        st.write(f"**{group['name']}** ({group['type']})")
                        st.write(f"• {group['user_count']} users, {group['project_count']} projects")
                        st.write(f"• Saves {group['policies_saved']} policies")
                    
                    with col2:
                        script_content = '\n'.join(group['commands'])
                        st.download_button(
                            label="📥 Download",
                            data=script_content,
                            file_name=f"{group['name']}-consolidation.sh",
                            mime='text/plain',
                            key=f"individual_{group['name']}"
                        )
                    
                    with col3:
                        st.write(f"{len(group['commands'])} lines")
                    
                    st.write("---")
    
    # Master script combining all
    st.write("### Master Consolidation Script")
    st.write("Download a single script containing all consolidation operations in priority order.")
    
    # Generate master script
    master_script = []
    master_script.append("#!/bin/bash")
    master_script.append("# GCP IAM Consolidation Master Script")
    master_script.append(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    master_script.append(f"# Total groups: {len(all_groups)}")
    master_script.append(f"# Total policies to be saved: {sum(g['policies_saved'] for g in all_groups)}")
    master_script.append("")
    master_script.append("set -e  # Exit on any error")
    master_script.append("")
    master_script.append("echo 'GCP IAM Consolidation Master Script'")
    master_script.append("echo '======================================'")
    master_script.append("")
    
    # Add each group's script with separators
    sorted_groups = sorted(all_groups, key=lambda x: {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}[x['priority']], reverse=True)
    
    for i, group in enumerate(sorted_groups):
        master_script.append(f"echo 'Starting consolidation {i+1}/{len(sorted_groups)}: {group["name"]} ({group["priority"]} Priority)'")
        master_script.append("echo '========================================'")
        master_script.append("")
        
        # Add the group's commands (skip the shebang line since we have one at the top)
        group_commands = [cmd for cmd in group['commands'] if not cmd.startswith('#!')]
        master_script.extend(group_commands)
        
        master_script.append("")
        master_script.append(f"echo 'Completed: {group["name"]}'")
        master_script.append("echo '========================================'")
        master_script.append("")
        
        if i < len(sorted_groups) - 1:
            master_script.append("echo 'Press Enter to continue to next consolidation...'")
            master_script.append("read -r")
            master_script.append("")
    
    master_script.append("echo 'All IAM consolidations completed!'")
    master_script.append("echo 'Review the changes and update your documentation.'")
    
    master_content = '\n'.join(master_script)
    
    col1, col2 = st.columns([1, 2])
    with col1:
        st.download_button(
            label="📦 Download Master Script",
            data=master_content,
            file_name="gcp-iam-consolidation-master.sh",
            mime='text/plain',
            help=f"Downloads a single script with all {len(all_groups)} consolidation operations"
        )
    
    with col2:
        st.info(f"Master script contains {len(master_script)} lines covering {len(all_groups)} consolidation operations")


def create_consolidation_matrix(grouping_data):
    """Create a consolidation impact matrix."""
    st.subheader("📄 Consolidation Impact Matrix")
    
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
        
        # Compliance analysis options
        st.markdown("---")
        st.subheader("Compliance Analysis")
        
        enable_compliance = st.checkbox(
            "Enable Compliance Analysis",
            value=False,
            help="Run compliance analysis against major frameworks (HITRUST, SOC2, HIPAA, etc.)"
        )
        
        if enable_compliance:
            available_frameworks = [
                "HITRUST", "HIPAA", "SOC2", "SOC3", 
                "ISO27001", "NIST", "PCI_DSS", "FEDRAMP"
            ]
            
            selected_frameworks = st.multiselect(
                "Select Compliance Frameworks",
                available_frameworks,
                default=["SOC2", "HITRUST"],
                help="Choose which compliance frameworks to analyze against"
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
    compliance_suffix = ""
    if enable_compliance and selected_frameworks:
        compliance_suffix = f"_compliance_{'_'.join(selected_frameworks)}"
    
    insights_cache_key = f"consolidation_insights_{cache_key}_{min_consolidation_value}{compliance_suffix}"
    
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
            
            # Run compliance analysis if enabled
            if enable_compliance and selected_frameworks:
                with st.spinner("📃 Running compliance analysis..."):
                    compliance_analyzer = ComplianceAnalyzer()
                    
                    # Convert framework names to enum values
                    frameworks_to_analyze = []
                    for fw_name in selected_frameworks:
                        try:
                            framework_enum = ComplianceFramework[fw_name]
                            frameworks_to_analyze.append(framework_enum)
                        except KeyError:
                            st.warning(f"Unknown framework: {fw_name}")
                    
                    if frameworks_to_analyze:
                        compliance_results = compliance_analyzer.analyze_compliance(
                            insights_data, frameworks_to_analyze
                        )
                        insights_data['compliance_analysis'] = compliance_results
            
            st.session_state[insights_cache_key] = insights_data
    
    consolidation_data = st.session_state[insights_cache_key]
    grouping_opportunities = consolidation_data.get('grouping_opportunities', {})
    
    # Add inactive analysis data to grouping opportunities for the dashboard
    if 'unused_access_analysis' in consolidation_data:
        grouping_opportunities['inactive_analysis'] = consolidation_data['unused_access_analysis']
    
    # Main dashboard sections
    create_consolidation_overview(grouping_opportunities.get('consolidation_impact', {}))
    
    st.markdown("---")
    
    create_grouping_opportunities_dashboard(grouping_opportunities)
    
    st.markdown("---")
    
    create_consolidation_network_graph(grouping_opportunities)
    
    st.markdown("---")
    
    create_consolidation_matrix(grouping_opportunities)
    
    st.markdown("---")
    
    # Organization-level opportunities
    if 'organization_level_opportunities' in consolidation_data:
        create_org_level_opportunities(consolidation_data['organization_level_opportunities'])
    st.markdown("---")
    
    # Master script download section
    create_master_script_download(grouping_opportunities)
    
    st.markdown("---")
    
    if 'implementation_roadmap' in grouping_opportunities:
        create_implementation_roadmap(grouping_opportunities['implementation_roadmap'])


if __name__ == "__main__":
    main()