"""
CloudFast Pattern Analyzer for Cloud Foundation Fabric architectures.

This module detects and analyzes CloudFast organizational patterns including:
- Squad-based folder structures
- Environment separation by squad/team
- Cloud Foundation Fabric naming conventions
- IAM inheritance patterns
"""

import logging
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class CloudFastPattern(Enum):
    """CloudFast organizational pattern types."""
    SQUAD_BASED = "squad_based"
    BUSINESS_UNIT = "business_unit"
    ENVIRONMENT_FIRST = "environment_first"
    HYBRID = "hybrid"
    UNKNOWN = "unknown"


@dataclass
class EnvironmentInfo:
    """Information about an environment (dev, staging, prod, etc.)."""
    name: str
    folder_id: str
    squad: Optional[str] = None
    environment_type: Optional[str] = None
    project_count: int = 0


@dataclass
class SquadInfo:
    """Information about a squad/team."""
    name: str
    environments: List[EnvironmentInfo]
    folder_id: Optional[str] = None
    total_projects: int = 0


@dataclass
class CloudFastAnalysis:
    """Analysis results for CloudFast patterns."""
    pattern_type: CloudFastPattern
    confidence_score: float
    squads: List[SquadInfo]
    environments: List[str]
    folder_structure: Dict[str, Any]
    recommendations: List[str]
    iam_inheritance_analysis: Dict[str, Any]


class CloudFastAnalyzer:
    """Analyzer for CloudFast and Cloud Foundation Fabric patterns."""
    
    def __init__(self):
        """Initialize the CloudFast analyzer."""
        # Common CloudFast naming patterns
        self.squad_patterns = [
            r"^(squad|team|group)[-_]?([a-z0-9]+)$",
            r"^([a-z0-9]+)[-_](squad|team|group)$",
            r"^([a-z0-9]+)$"  # Generic squad names
        ]
        
        self.environment_patterns = [
            r"^(dev|development)$",
            r"^(test|testing|tst)$",
            r"^(stage|staging|stg)$",
            r"^(prod|production|prd)$",
            r"^(sandbox|sbx)$",
            r"^(demo|dmz)$"
        ]
        
        # Cloud Foundation Fabric common folder structures
        self.fabric_patterns = [
            r"^bootstrap$",
            r"^foundation$",
            r"^security$",
            r"^networking$",
            r"^shared[-_]?services$",
            r"^workloads?$",
            r"^data[-_]?platform$"
        ]

    def analyze_organization(self, hierarchy: Dict[str, Any]) -> CloudFastAnalysis:
        """
        Analyze organization hierarchy for CloudFast patterns.
        
        Args:
            hierarchy: Organization hierarchy from org_client
            
        Returns:
            CloudFastAnalysis: Detailed analysis of CloudFast patterns
        """
        logger.info("Starting CloudFast pattern analysis")
        
        if not hierarchy or 'folders' not in hierarchy:
            return self._create_empty_analysis()
        
        # Analyze folder structure
        folder_analysis = self._analyze_folder_structure(hierarchy['folders'])
        
        # Detect pattern type
        pattern_type, confidence = self._detect_pattern_type(folder_analysis)
        
        # Extract squads and environments
        squads = self._extract_squads(folder_analysis)
        environments = self._extract_environments(folder_analysis)
        
        # Analyze IAM inheritance
        iam_analysis = self._analyze_iam_inheritance(hierarchy)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(pattern_type, folder_analysis, squads)
        
        return CloudFastAnalysis(
            pattern_type=pattern_type,
            confidence_score=confidence,
            squads=squads,
            environments=environments,
            folder_structure=folder_analysis,
            recommendations=recommendations,
            iam_inheritance_analysis=iam_analysis
        )
    
    def _create_empty_analysis(self) -> CloudFastAnalysis:
        """Create empty analysis for invalid hierarchies."""
        return CloudFastAnalysis(
            pattern_type=CloudFastPattern.UNKNOWN,
            confidence_score=0.0,
            squads=[],
            environments=[],
            folder_structure={},
            recommendations=["No organizational hierarchy detected"],
            iam_inheritance_analysis={}
        )
    
    def _analyze_folder_structure(self, folders: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze the folder structure to identify patterns.
        
        Args:
            folders: List of folder metadata
            
        Returns:
            Dict containing structure analysis
        """
        structure = {
            'total_folders': len(folders),
            'depth_analysis': {},
            'naming_patterns': {},
            'squad_folders': [],
            'environment_folders': [],
            'fabric_folders': [],
            'max_depth': 0
        }
        
        def analyze_folder_recursive(folder_list: List[Dict[str, Any]], depth: int = 1):
            """Recursively analyze folders."""
            structure['max_depth'] = max(structure['max_depth'], depth)
            
            if depth not in structure['depth_analysis']:
                structure['depth_analysis'][depth] = []
            
            for folder in folder_list:
                folder_name = folder.get('display_name', '').lower()
                folder_info = {
                    'name': folder_name,
                    'id': folder.get('folder_id'),
                    'depth': depth,
                    'children_count': len(folder.get('children', []))
                }
                
                structure['depth_analysis'][depth].append(folder_info)
                
                # Check for squad patterns
                if self._is_squad_folder(folder_name):
                    structure['squad_folders'].append(folder_info)
                
                # Check for environment patterns
                if self._is_environment_folder(folder_name):
                    structure['environment_folders'].append(folder_info)
                
                # Check for Cloud Foundation Fabric patterns
                if self._is_fabric_folder(folder_name):
                    structure['fabric_folders'].append(folder_info)
                
                # Recurse into children
                if folder.get('children'):
                    analyze_folder_recursive(folder['children'], depth + 1)
        
        analyze_folder_recursive(folders)
        return structure
    
    def _is_squad_folder(self, folder_name: str) -> bool:
        """Check if folder name matches squad patterns."""
        for pattern in self.squad_patterns:
            if re.match(pattern, folder_name, re.IGNORECASE):
                return True
        return False
    
    def _is_environment_folder(self, folder_name: str) -> bool:
        """Check if folder name matches environment patterns."""
        for pattern in self.environment_patterns:
            if re.match(pattern, folder_name, re.IGNORECASE):
                return True
        return False
    
    def _is_fabric_folder(self, folder_name: str) -> bool:
        """Check if folder name matches Cloud Foundation Fabric patterns."""
        for pattern in self.fabric_patterns:
            if re.match(pattern, folder_name, re.IGNORECASE):
                return True
        return False
    
    def _detect_pattern_type(self, folder_analysis: Dict[str, Any]) -> Tuple[CloudFastPattern, float]:
        """
        Detect the primary CloudFast pattern type.
        
        Args:
            folder_analysis: Results from folder structure analysis
            
        Returns:
            Tuple of (pattern_type, confidence_score)
        """
        squad_count = len(folder_analysis['squad_folders'])
        env_count = len(folder_analysis['environment_folders'])
        fabric_count = len(folder_analysis['fabric_folders'])
        total_folders = folder_analysis['total_folders']
        
        if total_folders == 0:
            return CloudFastPattern.UNKNOWN, 0.0
        
        # Calculate pattern scores
        squad_score = squad_count / total_folders if total_folders > 0 else 0
        env_score = env_count / total_folders if total_folders > 0 else 0
        fabric_score = fabric_count / total_folders if total_folders > 0 else 0
        
        # Analyze structure depth and organization
        depth_scores = self._analyze_depth_patterns(folder_analysis['depth_analysis'])
        
        # Determine pattern type based on scores
        if squad_score > 0.3 and depth_scores.get('squad_env_pattern', 0) > 0.5:
            return CloudFastPattern.SQUAD_BASED, min(0.9, squad_score + depth_scores['squad_env_pattern'])
        elif env_score > 0.3 and depth_scores.get('env_squad_pattern', 0) > 0.5:
            return CloudFastPattern.ENVIRONMENT_FIRST, min(0.9, env_score + depth_scores['env_squad_pattern'])
        elif fabric_score > 0.2:
            return CloudFastPattern.BUSINESS_UNIT, min(0.8, fabric_score + 0.3)
        elif squad_score > 0.1 and env_score > 0.1:
            return CloudFastPattern.HYBRID, min(0.7, (squad_score + env_score) / 2)
        else:
            return CloudFastPattern.UNKNOWN, 0.2
    
    def _analyze_depth_patterns(self, depth_analysis: Dict[int, List[Dict]]) -> Dict[str, float]:
        """Analyze folder depth patterns to identify organizational structures."""
        patterns = {
            'squad_env_pattern': 0.0,
            'env_squad_pattern': 0.0,
            'fabric_pattern': 0.0
        }
        
        # Check for squad -> environment pattern (depth 1 = squads, depth 2 = environments)
        if 1 in depth_analysis and 2 in depth_analysis:
            depth1_squads = sum(1 for folder in depth_analysis[1] if self._is_squad_folder(folder['name']))
            depth2_envs = sum(1 for folder in depth_analysis[2] if self._is_environment_folder(folder['name']))
            
            if depth1_squads > 0 and depth2_envs > 0:
                patterns['squad_env_pattern'] = min(0.8, (depth1_squads + depth2_envs) / 
                                                   (len(depth_analysis[1]) + len(depth_analysis[2])))
        
        # Check for environment -> squad pattern
        if 1 in depth_analysis and 2 in depth_analysis:
            depth1_envs = sum(1 for folder in depth_analysis[1] if self._is_environment_folder(folder['name']))
            depth2_squads = sum(1 for folder in depth_analysis[2] if self._is_squad_folder(folder['name']))
            
            if depth1_envs > 0 and depth2_squads > 0:
                patterns['env_squad_pattern'] = min(0.8, (depth1_envs + depth2_squads) / 
                                                   (len(depth_analysis[1]) + len(depth_analysis[2])))
        
        return patterns
    
    def _extract_squads(self, folder_analysis: Dict[str, Any]) -> List[SquadInfo]:
        """Extract squad information from folder analysis."""
        squads = []
        squad_folders = folder_analysis['squad_folders']
        
        for squad_folder in squad_folders:
            squad_name = squad_folder['name']
            
            # Find environments for this squad
            environments = self._find_squad_environments(squad_folder, folder_analysis)
            
            squad_info = SquadInfo(
                name=squad_name,
                environments=environments,
                folder_id=squad_folder['id'],
                total_projects=sum(env.project_count for env in environments)
            )
            squads.append(squad_info)
        
        return squads
    
    def _find_squad_environments(self, squad_folder: Dict[str, Any], 
                                folder_analysis: Dict[str, Any]) -> List[EnvironmentInfo]:
        """Find environments associated with a squad."""
        environments = []
        
        # Look for environment folders at the next depth level
        squad_depth = squad_folder['depth']
        next_depth = squad_depth + 1
        
        if next_depth in folder_analysis['depth_analysis']:
            for folder in folder_analysis['depth_analysis'][next_depth]:
                if self._is_environment_folder(folder['name']):
                    env_info = EnvironmentInfo(
                        name=folder['name'],
                        folder_id=folder['id'],
                        squad=squad_folder['name'],
                        environment_type=self._classify_environment_type(folder['name']),
                        project_count=0  # Would need project data to populate
                    )
                    environments.append(env_info)
        
        return environments
    
    def _classify_environment_type(self, env_name: str) -> str:
        """Classify environment type based on name."""
        env_lower = env_name.lower()
        
        if any(pattern in env_lower for pattern in ['dev', 'develop']):
            return 'development'
        elif any(pattern in env_lower for pattern in ['test', 'tst']):
            return 'testing'
        elif any(pattern in env_lower for pattern in ['stage', 'staging', 'stg']):
            return 'staging'
        elif any(pattern in env_lower for pattern in ['prod', 'production', 'prd']):
            return 'production'
        elif any(pattern in env_lower for pattern in ['sandbox', 'sbx']):
            return 'sandbox'
        else:
            return 'unknown'
    
    def _extract_environments(self, folder_analysis: Dict[str, Any]) -> List[str]:
        """Extract unique environment names."""
        environments = set()
        
        for env_folder in folder_analysis['environment_folders']:
            env_type = self._classify_environment_type(env_folder['name'])
            environments.add(env_type)
        
        return sorted(list(environments))
    
    def _analyze_iam_inheritance(self, hierarchy: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze IAM inheritance patterns in the organization."""
        # This would integrate with the IAM policy data
        # For now, return basic structure analysis
        return {
            'inheritance_depth': self._calculate_inheritance_depth(hierarchy),
            'policy_distribution': 'squad_based',  # Would analyze actual IAM policies
            'recommendations': [
                'Consider implementing group-based access at squad folder level',
                'Review environment-specific role assignments',
                'Implement principle of least privilege across squads'
            ]
        }
    
    def _calculate_inheritance_depth(self, hierarchy: Dict[str, Any]) -> int:
        """Calculate the depth of IAM policy inheritance."""
        max_depth = 0
        
        def calculate_depth(folders: List[Dict], depth: int = 1):
            nonlocal max_depth
            max_depth = max(max_depth, depth)
            
            for folder in folders:
                if folder.get('children'):
                    calculate_depth(folder['children'], depth + 1)
        
        if hierarchy.get('folders'):
            calculate_depth(hierarchy['folders'])
        
        return max_depth
    
    def _generate_recommendations(self, pattern_type: CloudFastPattern, 
                                 folder_analysis: Dict[str, Any], 
                                 squads: List[SquadInfo]) -> List[str]:
        """Generate CloudFast-specific recommendations."""
        recommendations = []
        
        if pattern_type == CloudFastPattern.SQUAD_BASED:
            recommendations.extend([
                "✅ Squad-based organization detected - CloudFast pattern confirmed",
                f"🔍 Optimize IAM policies across {len(squads)} squads for consistency",
                "🚀 Consider implementing automated group management per squad",
                "📊 Review cross-squad permission overlaps for consolidation opportunities"
            ])
        
        elif pattern_type == CloudFastPattern.ENVIRONMENT_FIRST:
            recommendations.extend([
                "⚠️ Environment-first structure detected - consider squad-based refactoring",
                "🔄 Migrate to squad-based folders for better team autonomy",
                "📋 Standardize environment naming conventions across teams"
            ])
        
        elif pattern_type == CloudFastPattern.HYBRID:
            recommendations.extend([
                "🔀 Hybrid organization structure detected",
                "📐 Standardize folder hierarchy to pure squad-based model",
                "🎯 Focus IAM consolidation on squad-level groupings"
            ])
        
        else:
            recommendations.extend([
                "❓ CloudFast patterns not clearly detected",
                "🏗️ Consider implementing Cloud Foundation Fabric structure",
                "👥 Organize folders by squad/team for better governance"
            ])
        
        # Add general CloudFast recommendations
        if len(squads) > 0:
            recommendations.append(f"🎯 {len(squads)} squads identified - focus consolidation efforts here")
        
        if folder_analysis['max_depth'] > 4:
            recommendations.append("📏 Deep folder hierarchy detected - consider flattening for simplicity")
        
        return recommendations