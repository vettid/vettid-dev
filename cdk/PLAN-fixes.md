# Plan: Fix Multiple Admin and Account Portal Issues

## Issues to Fix

### 1. Subscription Type Spelling ("monthss")
**File:** `frontend/admin/js/modules/membership.js:404`
**Problem:** Pluralization logic appends 's' even when term_unit already ends with 's'
**Fix:** Check if term_unit already ends with 's' before adding another

### 2. Disable Subscription Type Button Not Working
**File:** `frontend/admin/js/modules/main.js`
**Problem:** The button has `data-action='toggle-subscription-type'` but there's no event handler
**Fix:** Add event delegation for 'toggle-subscription-type' action in main.js

### 3. Subscription Type Filter Not Working
**File:** `frontend/admin/js/modules/membership.js`
**Problem:** Filter state starts as 'all' but UI shows 'enabled' as active
**Fix:** Ensure filter state matches UI and filter logic is applied correctly

### 4. Vault Metrics Not Loading
**Files:** `frontend/admin/js/modules/system.js:505-510` and `lambda/handlers/admin/getVaultMetrics.ts`
**Problem:** Frontend expects flat fields (`data.total_vaults`) but handler returns nested (`data.key_metrics.total_enrolled`)
**Fix:** Update frontend to read from nested structure or update handler to return flat structure

### 5. Account Portal Tab Switching Issue
**File:** `frontend/account/js/account.js`
**Problem:** Getting Started shows briefly then jumps to Vault tab
**Fix:** Investigate if getting_started_complete is being set incorrectly or if there's a second tab switch

### 6. Rename Help Requests to Help Offers
**Files:** Multiple HTML, JS, and Lambda files
**Changes:**
- Update tab label in HTML
- Update all UI text references
- Update API endpoints (keep old ones as aliases for backwards compatibility)
- Update Lambda handlers
- Update DynamoDB table references (may need migration)

### 7. Membership Terms Mismatch
**Files:** Lambda handlers for membership terms
**Problem:** Terms shown may not match admin-defined terms
**Fix:** Verify the current term is being correctly identified and returned

## Implementation Order

1. Fix subscription type spelling (quick fix)
2. Fix subscription type toggle button (add event handler)
3. Fix subscription type filter state
4. Fix vault metrics field mapping
5. Investigate and fix account portal tab switching
6. Rename Help Requests to Help Offers (comprehensive change)
7. Verify membership terms
