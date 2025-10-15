"""
GCP IAM Compliance Module

Provides compliance analysis and reporting for major frameworks.
"""

from .compliance_analyzer import (
    ComplianceAnalyzer,
    ComplianceFramework,
    ComplianceStatus,
    ComplianceSeverity
)

__all__ = [
    'ComplianceAnalyzer',
    'ComplianceFramework', 
    'ComplianceStatus',
    'ComplianceSeverity'
]