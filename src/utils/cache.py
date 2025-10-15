"""
Caching utilities and helper functions for GCP IAM operations.

Provides session-based caching, progress tracking, and utility functions
for IAM policy analysis.
"""

import logging
import time
import hashlib
from typing import Any, Dict, List, Optional, Callable, TypeVar, Set, Tuple
from functools import wraps
from datetime import datetime, timedelta
import streamlit as st
import pandas as pd

from ..models.iam_models import (
    Identity, 
    Role, 
    Permission, 
    IdentityType, 
    RoleType,
    PermissionRiskLevel
)

logger = logging.getLogger(__name__)

T = TypeVar('T')


class CacheManager:
    """Manages session-based caching for API responses and processed data."""
    
    def __init__(self, default_ttl_minutes: int = 30):
        """
        Initialize cache manager.
        
        Args:
            default_ttl_minutes: Default TTL for cached items in minutes
        """
        self.default_ttl = timedelta(minutes=default_ttl_minutes)
        self._ensure_cache_initialized()
    
    def _ensure_cache_initialized(self):
        """Ensure cache containers exist in session state."""
        if 'iam_cache' not in st.session_state:
            st.session_state.iam_cache = {}
        if 'cache_timestamps' not in st.session_state:
            st.session_state.cache_timestamps = {}
    
    def _generate_cache_key(self, *args, **kwargs) -> str:
        """Generate a cache key from function arguments."""
        key_data = str(args) + str(sorted(kwargs.items()))
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get item from cache if it exists and hasn't expired.
        
        Args:
            key: Cache key
            
        Returns:
            Optional[Any]: Cached value or None if not found/expired
        """
        self._ensure_cache_initialized()
        
        if key not in st.session_state.iam_cache:
            return None
        
        # Check expiration
        if key in st.session_state.cache_timestamps:
            cached_time = st.session_state.cache_timestamps[key]
            if datetime.now() - cached_time > self.default_ttl:
                self.delete(key)
                return None
        
        return st.session_state.iam_cache[key]
    
    def set(self, key: str, value: Any, ttl: Optional[timedelta] = None) -> None:
        """
        Store item in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live (uses default if not specified)
        """
        self._ensure_cache_initialized()
        
        st.session_state.iam_cache[key] = value
        st.session_state.cache_timestamps[key] = datetime.now()
        
        logger.debug(f"Cached item with key: {key}")
    
    def delete(self, key: str) -> None:
        """Remove item from cache."""
        self._ensure_cache_initialized()
        
        if key in st.session_state.iam_cache:
            del st.session_state.iam_cache[key]
        if key in st.session_state.cache_timestamps:
            del st.session_state.cache_timestamps[key]
    
    def clear(self) -> None:
        """Clear all cached items."""
        st.session_state.iam_cache = {}
        st.session_state.cache_timestamps = {}
        logger.info("Cleared all cached items")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        self._ensure_cache_initialized()
        
        total_items = len(st.session_state.iam_cache)
        expired_items = 0
        
        current_time = datetime.now()
        for key, timestamp in st.session_state.cache_timestamps.items():
            if current_time - timestamp > self.default_ttl:
                expired_items += 1
        
        return {
            'total_items': total_items,
            'expired_items': expired_items,
            'active_items': total_items - expired_items,
            'cache_hit_rate': getattr(self, '_hit_rate', 0.0)
        }


# Global cache manager instance
_cache_manager = CacheManager()


def get_cache_manager() -> CacheManager:
    """Get the global cache manager instance."""
    return _cache_manager


def cached(ttl_minutes: int = 30, key_prefix: str = ""):
    """
    Decorator for caching function results.
    
    Args:
        ttl_minutes: Time to live in minutes
        key_prefix: Prefix for cache key
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            cache_manager = get_cache_manager()
            
            # Generate cache key
            cache_key = f"{key_prefix}_{func.__name__}_{cache_manager._generate_cache_key(*args, **kwargs)}"
            
            # Try to get from cache
            cached_result = cache_manager.get(cache_key)
            if cached_result is not None:
                logger.debug(f"Cache hit for {func.__name__}")
                return cached_result
            
            # Execute function and cache result
            logger.debug(f"Cache miss for {func.__name__}, executing...")
            result = func(*args, **kwargs)
            cache_manager.set(cache_key, result, timedelta(minutes=ttl_minutes))
            
            return result
        return wrapper
    return decorator


class ProgressTracker:
    """Track progress for long-running operations with Streamlit integration."""
    
    def __init__(self, total_steps: int, description: str = "Processing"):
        """
        Initialize progress tracker.
        
        Args:
            total_steps: Total number of steps to track
            description: Description of the operation
        """
        self.total_steps = total_steps
        self.current_step = 0
        self.description = description
        self.start_time = time.time()
        
        # Create Streamlit progress bar
        self.progress_bar = st.progress(0)
        self.status_text = st.empty()
        
        self.update_display()
    
    def step(self, description: Optional[str] = None):
        """Advance progress by one step."""
        self.current_step += 1
        if description:
            self.description = description
        self.update_display()
    
    def set_progress(self, current: int, description: Optional[str] = None):
        """Set absolute progress."""
        self.current_step = current
        if description:
            self.description = description
        self.update_display()
    
    def update_display(self):
        """Update the Streamlit progress display."""
        progress = self.current_step / self.total_steps if self.total_steps > 0 else 0
        self.progress_bar.progress(progress)
        
        elapsed_time = time.time() - self.start_time
        if self.current_step > 0:
            avg_time_per_step = elapsed_time / self.current_step
            estimated_remaining = (self.total_steps - self.current_step) * avg_time_per_step
            
            self.status_text.text(
                f"{self.description} - Step {self.current_step}/{self.total_steps} "
                f"(~{estimated_remaining:.0f}s remaining)"
            )
        else:
            self.status_text.text(f"{self.description} - Starting...")
    
    def complete(self, final_message: str = "Complete!"):
        """Mark progress as complete."""
        self.progress_bar.progress(1.0)
        self.status_text.text(final_message)
    
    def cleanup(self):
        """Clean up Streamlit UI elements."""
        try:
            self.progress_bar.empty()
            self.status_text.empty()
        except Exception:
            pass  # Ignore cleanup errors


def create_identity_dataframe(identities: List[Identity]) -> pd.DataFrame:
    """
    Convert list of Identity objects to pandas DataFrame for display.
    
    Args:
        identities: List of Identity objects
        
    Returns:
        pd.DataFrame: DataFrame with identity information
    """
    data = []
    
    for identity in identities:
        data.append({
            'Email': identity.email,
            'Type': identity.identity_type.value.title(),
            'Domain': identity.domain or 'N/A',
            'Total Roles': len(identity.roles_assigned),
            'Projects': len(identity.projects_with_access),
            'Permissions': len(identity.effective_permissions),
            'Deleted': '❌' if identity.deleted else '✅'
        })
    
    return pd.DataFrame(data)


def create_roles_dataframe(roles: List[Role]) -> pd.DataFrame:
    """
    Convert list of Role objects to pandas DataFrame for display.
    
    Args:
        roles: List of Role objects
        
    Returns:
        pd.DataFrame: DataFrame with role information
    """
    data = []
    
    for role in roles:
        data.append({
            'Role Name': role.name,
            'Title': role.title,
            'Type': role.role_type.value.title(),
            'Permissions': len(role.permissions),
            'Usage Count': role.usage_count,
            'Projects': len(role.used_in_projects),
            'Stage': role.stage or 'GA'
        })
    
    return pd.DataFrame(data)


def analyze_permission_patterns(permissions: Set[str]) -> Dict[str, Any]:
    """
    Analyze patterns in a set of permissions.
    
    Args:
        permissions: Set of permission names
        
    Returns:
        Dict[str, Any]: Analysis results including services, actions, and risk levels
    """
    analysis = {
        'total_permissions': len(permissions),
        'services': {},
        'actions': {},
        'risk_levels': {level.value: 0 for level in PermissionRiskLevel},
        'high_risk_permissions': [],
        'admin_permissions': [],
        'read_permissions': [],
        'write_permissions': []
    }
    
    for permission in permissions:
        # Parse service and action
        parts = permission.split('.')
        if len(parts) >= 2:
            service = parts[0]
            action = '.'.join(parts[2:]) if len(parts) > 2 else parts[1]
            
            # Count services
            analysis['services'][service] = analysis['services'].get(service, 0) + 1
            
            # Count actions
            analysis['actions'][action] = analysis['actions'].get(action, 0) + 1
        
        # Analyze risk level
        risk_level = analyze_permission_risk_level(permission)
        analysis['risk_levels'][risk_level.value] += 1
        
        if risk_level in [PermissionRiskLevel.HIGH, PermissionRiskLevel.CRITICAL]:
            analysis['high_risk_permissions'].append(permission)
        
        # Categorize by action type
        permission_lower = permission.lower()
        if any(pattern in permission_lower for pattern in ['admin', 'owner', 'setiam']):
            analysis['admin_permissions'].append(permission)
        elif any(pattern in permission_lower for pattern in ['get', 'list', 'read', 'view']):
            analysis['read_permissions'].append(permission)
        elif any(pattern in permission_lower for pattern in ['create', 'update', 'write', 'delete']):
            analysis['write_permissions'].append(permission)
    
    return analysis


def analyze_permission_risk_level(permission: str) -> PermissionRiskLevel:
    """
    Analyze the risk level of a permission.
    
    Args:
        permission: Permission name
        
    Returns:
        PermissionRiskLevel: Risk level assessment
    """
    # Define risk patterns
    critical_patterns = ['iam.', 'setIamPolicy', 'admin', 'owner', 'delete']
    high_patterns = ['create', 'update', 'write', 'edit', 'modify']
    medium_patterns = ['get', 'list', 'read', 'view']
    
    permission_lower = permission.lower()
    
    for pattern in critical_patterns:
        if pattern.lower() in permission_lower:
            return PermissionRiskLevel.CRITICAL
    
    for pattern in high_patterns:
        if pattern.lower() in permission_lower:
            return PermissionRiskLevel.HIGH
    
    for pattern in medium_patterns:
        if pattern.lower() in permission_lower:
            return PermissionRiskLevel.MEDIUM
    
    return PermissionRiskLevel.LOW


def find_role_overlaps(roles: List[Role]) -> List[Dict[str, Any]]:
    """
    Find roles with overlapping permissions.
    
    Args:
        roles: List of Role objects
        
    Returns:
        List[Dict[str, Any]]: List of role overlap analysis
    """
    overlaps = []
    
    for i, role1 in enumerate(roles):
        for j, role2 in enumerate(roles[i+1:], i+1):
            common_permissions = role1.permissions.intersection(role2.permissions)
            
            if common_permissions:
                overlap_percentage = len(common_permissions) / len(role1.permissions.union(role2.permissions)) * 100
                
                overlaps.append({
                    'role1': role1.name,
                    'role1_title': role1.title,
                    'role2': role2.name,
                    'role2_title': role2.title,
                    'common_permissions': len(common_permissions),
                    'overlap_percentage': overlap_percentage,
                    'common_permissions_list': list(common_permissions)
                })
    
    # Sort by overlap percentage descending
    overlaps.sort(key=lambda x: x['overlap_percentage'], reverse=True)
    
    return overlaps


def generate_recommendations(
    identities: List[Identity], 
    roles: List[Role], 
    bindings: List[Any]
) -> List[str]:
    """
    Generate security and optimization recommendations.
    
    Args:
        identities: List of Identity objects
        roles: List of Role objects  
        bindings: List of policy bindings
        
    Returns:
        List[str]: List of recommendations
    """
    recommendations = []
    
    # Analyze overprivileged identities
    overprivileged = [identity for identity in identities if len(identity.roles_assigned) > 5]
    if overprivileged:
        recommendations.append(
            f"Review {len(overprivileged)} identities with more than 5 roles assigned for potential over-privileging"
        )
    
    # Analyze unused roles
    unused_roles = [role for role in roles if role.usage_count == 0]
    if unused_roles:
        recommendations.append(
            f"Consider removing {len(unused_roles)} unused custom roles to reduce complexity"
        )
    
    # Analyze external users
    external_users = [
        identity for identity in identities 
        if identity.identity_type == IdentityType.USER and 
        identity.domain and ('gmail.com' in identity.domain or 'googlemail.com' in identity.domain)
    ]
    if external_users:
        recommendations.append(
            f"Review {len(external_users)} external users (Gmail accounts) for security compliance"
        )
    
    # Analyze service accounts
    service_accounts = [identity for identity in identities if identity.identity_type == IdentityType.SERVICE_ACCOUNT]
    if service_accounts:
        recommendations.append(
            f"Audit {len(service_accounts)} service accounts for principle of least privilege"
        )
    
    # Analyze basic roles usage
    basic_roles_usage = sum(1 for role in roles if role.role_type == RoleType.BASIC and role.usage_count > 0)
    if basic_roles_usage > 0:
        recommendations.append(
            f"Replace {basic_roles_usage} basic roles (Owner/Editor/Viewer) with more specific predefined roles"
        )
    
    return recommendations


def cache_data(key: str, value: Any, ttl: int = 600) -> None:
    """
    Convenience function to cache data.
    
    Args:
        key: Cache key
        value: Value to cache
        ttl: Time to live in seconds (default 600 = 10 minutes)
    """
    ttl_delta = timedelta(seconds=ttl)
    _cache_manager.set(key, value, ttl_delta)


def get_cached_data(key: str) -> Optional[Any]:
    """
    Convenience function to get cached data.
    
    Args:
        key: Cache key
        
    Returns:
        Optional[Any]: Cached value or None if not found/expired
    """
    return _cache_manager.get(key)


def clear_cache() -> None:
    """
    Convenience function to clear all cached data.
    """
    _cache_manager.clear()


def format_time_ago(timestamp: datetime) -> str:
    """
    Format a timestamp as a human-readable "time ago" string.
    
    Args:
        timestamp: Datetime timestamp
        
    Returns:
        str: Formatted time string
    """
    now = datetime.now()
    diff = now - timestamp
    
    if diff.days > 0:
        return f"{diff.days} days ago"
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f"{hours} hours ago"
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f"{minutes} minutes ago"
    else:
        return "Just now"
