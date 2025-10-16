# Intelligent Auto-Refresh Feature

## Overview

This update implements intelligent auto-refresh functionality across all dashboard variants, providing a near-live experience without manual refresh requirements.

## What Changed

### 1. Enhanced Cache System

**File: `src/utils/cache.py`**
- Added `invalidate_by_filter_change()` method to `CacheManager` class
- Tracks previous filter states in session state
- Automatically detects when filters change
- Intelligently invalidates only relevant cache entries

### 2. Updated Data Loading

**File: `src/pages/overview.py`**
- Integrated intelligent cache invalidation in `load_iam_data()` function
- Data automatically refreshes when filters change
- Cache hit/miss logic now respects filter changes

### 3. Updated All Dashboard Variants

**Files Updated:**
- `app.py` - Main modular application
- `app_simple.py` - Simple dashboard
- `app_enhanced.py` - Enhanced dashboard with AI insights
- `app_consolidation.py` - IAM consolidation dashboard

**UI Changes:**
- Removed: "🔄 Refresh Data" and "Auto-refresh (30min)" checkbox
- Added: "💡 Data auto-refreshes when selection changes" info message
- Updated: "🗑️ Clear All Cache" button for manual cache clearing

## How It Works

### Automatic Refresh Flow

1. **User Action**: User changes any filter setting (projects, organizations, identity types, role types, resource scope)
2. **Change Detection**: `CacheManager.invalidate_by_filter_change()` compares current filters with previous state
3. **Selective Invalidation**: If filters changed, relevant cache entries are cleared
4. **Auto Reload**: Data loading functions automatically fetch fresh data with new filters
5. **Instant Display**: Results appear immediately without manual intervention

### Example: Identity Profiler Use Case

When a user types a username in the identity profiler:
1. The username becomes part of the filter state
2. Filter change is detected automatically
3. Cache is invalidated for that context
4. Fresh search results load instantly
5. User sees results without clicking "refresh"

### Cache Key Generation

Cache keys now include all filter parameters:
```python
cache_key = f"overview_load_iam_data_{cache_manager._generate_cache_key(filters)}"
```

This ensures that different filter combinations create different cache entries, and changing filters automatically loads the right data.

## Benefits

1. **✨ Near-Live Experience**: No manual refresh needed
2. **🎯 Intelligent Caching**: Data cached until settings actually change
3. **⚡ Performance**: Unchanged data remains cached for speed
4. **🔄 Consistency**: Unified behavior across all dashboard variants
5. **💡 User-Friendly**: Clear indication that auto-refresh is active

## Technical Details

### Filter Tracking

The system tracks filter changes by storing the previous filter state in session state:
```python
if 'previous_filters' not in st.session_state:
    st.session_state.previous_filters = {}
```

### Context-Based Invalidation

Cache invalidation is context-aware (e.g., "overview", "identities"):
```python
cache_manager.invalidate_by_filter_change(filters, context="overview")
```

### Backward Compatibility

- Existing cache entries remain functional
- Manual "Clear All Cache" button still available for edge cases
- Cache TTL (30 minutes) still enforced for data freshness

## Migration Notes

### For Users

- No action required - auto-refresh is automatic
- The "Refresh Data" button has been replaced with "Clear All Cache"
- Filter changes now trigger immediate data refresh

### For Developers

If extending the dashboard:
1. Use `cache_manager.invalidate_by_filter_change(filters, context="your_context")` in data loading functions
2. Ensure filter parameters are passed to caching functions
3. Use unique context identifiers for different dashboard sections

## Future Enhancements

Potential improvements for future iterations:
- More granular cache invalidation (e.g., only clear project cache when projects change)
- Debouncing for text inputs to avoid excessive reloads
- Cache warmth indicators showing data age
- Predictive preloading based on user patterns

## Related Issue

Resolves: #2 - Intelligent auto refresh on setting change
