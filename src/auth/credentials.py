"""
Authentication module for GCP IAM Janitor.

Handles Application Default Credentials (ADC) and provides extensible
authentication framework for future auth methods.
"""

import os
import logging
from typing import Optional, Tuple
from google.auth import default
from google.auth.credentials import Credentials
from google.auth.exceptions import DefaultCredentialsError, RefreshError
import streamlit as st

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Custom exception for authentication-related errors."""
    pass


class CredentialsManager:
    """
    Manages authentication credentials for GCP services.
    
    Currently supports Application Default Credentials (ADC) with
    extensible design for future authentication methods.
    """
    
    def __init__(self):
        self._credentials: Optional[Credentials] = None
        self._project_id: Optional[str] = None
        self._auth_method = "adc"  # Default to ADC
    
    def get_credentials(self) -> Tuple[Credentials, str]:
        """
        Get authenticated credentials and project ID.
        
        Returns:
            Tuple[Credentials, str]: The credentials and project ID
            
        Raises:
            AuthenticationError: If credentials cannot be obtained
        """
        if self._credentials is None or self._project_id is None:
            self._load_credentials()
        
        if not self._credentials or not self._project_id:
            raise AuthenticationError("Failed to load credentials")
            
        return self._credentials, self._project_id
    
    def _load_credentials(self) -> None:
        """Load credentials using ADC."""
        try:
            logger.info("Loading Application Default Credentials...")
            
            # Try to get default credentials
            credentials, project_id = default()
            
            if not credentials:
                raise AuthenticationError("No default credentials found")
            
            # Validate credentials by attempting a refresh if needed
            if credentials.expired:
                credentials.refresh(default.Request())
            
            self._credentials = credentials
            self._project_id = project_id
            
            logger.info(f"Successfully loaded ADC for project: {project_id}")
            
        except DefaultCredentialsError as e:
            logger.error(f"Default credentials not found: {e}")
            raise AuthenticationError(
                "Application Default Credentials not found. "
                "Please run 'gcloud auth application-default login' or set up service account credentials."
            ) from e
        except RefreshError as e:
            logger.error(f"Failed to refresh credentials: {e}")
            raise AuthenticationError(
                "Failed to refresh credentials. Please re-authenticate with 'gcloud auth application-default login'."
            ) from e
        except Exception as e:
            logger.error(f"Unexpected error loading credentials: {e}")
            raise AuthenticationError(f"Unexpected authentication error: {e}") from e
    
    def validate_credentials(self) -> bool:
        """
        Validate that credentials are working and not expired.
        
        Returns:
            bool: True if credentials are valid, False otherwise
        """
        try:
            credentials, _ = self.get_credentials()
            
            # Check if credentials are expired and try to refresh
            if credentials.expired:
                credentials.refresh(default.Request())
            
            return not credentials.expired
        except Exception as e:
            logger.warning(f"Credential validation failed: {e}")
            return False
    
    def get_authenticated_user_info(self) -> dict:
        """
        Get information about the authenticated user.
        
        Returns:
            dict: User information including email and auth method
        """
        try:
            credentials, project_id = self.get_credentials()
            
            # Extract user info from credentials if available
            user_info = {
                "project_id": project_id,
                "auth_method": self._auth_method,
                "is_valid": self.validate_credentials(),
                "token_expired": getattr(credentials, 'expired', False)
            }
            
            # Try to get user email from service account or user credentials
            if hasattr(credentials, 'service_account_email'):
                user_info["email"] = credentials.service_account_email
                user_info["account_type"] = "service_account"
            elif hasattr(credentials, '_id_token') and credentials._id_token:
                # For user credentials, we might be able to extract email from ID token
                user_info["account_type"] = "user"
                user_info["email"] = "user_account"  # Placeholder - actual email extraction would require JWT parsing
            else:
                user_info["account_type"] = "unknown"
                user_info["email"] = "unknown"
            
            return user_info
            
        except Exception as e:
            logger.error(f"Failed to get user info: {e}")
            return {
                "error": str(e),
                "is_valid": False,
                "auth_method": self._auth_method
            }
    
    def clear_credentials(self) -> None:
        """Clear cached credentials."""
        self._credentials = None
        self._project_id = None
        logger.info("Cleared cached credentials")


# Global credentials manager instance
_credentials_manager = CredentialsManager()


def get_credentials_manager() -> CredentialsManager:
    """Get the global credentials manager instance."""
    return _credentials_manager


def initialize_auth() -> bool:
    """
    Initialize authentication and store in Streamlit session state.
    
    Returns:
        bool: True if authentication successful, False otherwise
    """
    try:
        cred_manager = get_credentials_manager()
        credentials, project_id = cred_manager.get_credentials()
        
        # Store in session state for Streamlit
        st.session_state.authenticated = True
        st.session_state.credentials = credentials
        st.session_state.project_id = project_id
        st.session_state.user_info = cred_manager.get_authenticated_user_info()
        
        return True
        
    except AuthenticationError as e:
        st.session_state.authenticated = False
        st.session_state.auth_error = str(e)
        logger.error(f"Authentication failed: {e}")
        return False


def is_authenticated() -> bool:
    """Check if user is authenticated in current session."""
    return st.session_state.get("authenticated", False)


def get_session_credentials() -> Optional[Tuple[Credentials, str]]:
    """Get credentials from Streamlit session state."""
    if is_authenticated():
        return st.session_state.get("credentials"), st.session_state.get("project_id")
    return None


def display_auth_status():
    """Display authentication status in Streamlit sidebar."""
    if is_authenticated():
        user_info = st.session_state.get("user_info", {})
        
        with st.sidebar:
            st.success("✅ Authenticated")
            st.write(f"**Project:** {user_info.get('project_id', 'Unknown')}")
            st.write(f"**Account:** {user_info.get('email', 'Unknown')}")
            st.write(f"**Type:** {user_info.get('account_type', 'Unknown')}")
            
            if st.button("🔄 Refresh Auth", help="Refresh authentication credentials"):
                clear_auth()
                if initialize_auth():
                    st.rerun()
    else:
        with st.sidebar:
            st.error("❌ Not Authenticated")
            auth_error = st.session_state.get("auth_error", "Unknown error")
            st.write(f"**Error:** {auth_error}")
            
            if st.button("🔑 Retry Auth", help="Retry authentication"):
                if initialize_auth():
                    st.rerun()


def clear_auth():
    """Clear authentication from session state."""
    for key in ["authenticated", "credentials", "project_id", "user_info", "auth_error"]:
        if key in st.session_state:
            del st.session_state[key]
    
    get_credentials_manager().clear_credentials()