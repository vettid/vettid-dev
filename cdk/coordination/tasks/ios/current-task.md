# Phase 10: Build for Physical Device Testing

## Overview
Configure the Xcode project for testing on a physical iOS device with the user's registered Apple ID.

## Priority Task: Device Build

### 1. Configure Signing with Personal Team
Open Xcode and configure automatic signing:

1. Open `VettID.xcodeproj` in Xcode
2. Select the VettID target
3. Go to "Signing & Capabilities" tab
4. Check "Automatically manage signing"
5. Select your Personal Team (your Apple ID)
6. Xcode will create a provisioning profile automatically

### 2. Update Bundle Identifier (if needed)
If signing fails due to bundle ID conflict:
- Change Bundle Identifier to something unique, e.g., `com.yourname.vettid`
- This is required for free developer accounts

### 3. Trust Developer Certificate on Device
When you first run on device:
1. Go to Settings > General > VPN & Device Management on your iPhone
2. Find your developer certificate
3. Tap "Trust"

### 4. Build and Run
```bash
# From Xcode:
# 1. Connect your iPhone via USB
# 2. Select your device from the device dropdown (not simulator)
# 3. Press Cmd+R to build and run

# Or from command line:
xcodebuild -project VettID.xcodeproj \
  -scheme VettID \
  -destination 'platform=iOS,name=YOUR_DEVICE_NAME' \
  -configuration Debug \
  build
```

### 5. Archive for Distribution (Optional)
If you want to create an IPA for sharing:
```bash
# Create archive
xcodebuild -project VettID.xcodeproj \
  -scheme VettID \
  -configuration Release \
  -archivePath build/VettID.xcarchive \
  archive

# Export IPA (Ad Hoc or Development)
xcodebuild -exportArchive \
  -archivePath build/VettID.xcarchive \
  -exportPath build/ \
  -exportOptionsPlist ExportOptions.plist
```

### 6. API Configuration
Ensure the app is configured to connect to the correct API:
```swift
// Update Configuration.swift or similar
struct APIConfig {
    static let baseURL = "https://api.vettid.dev"
}
```

## Pre-flight Checklist
Before building:
- [ ] iOS 16.0+ target configured
- [ ] Apple ID added to Xcode (Xcode > Preferences > Accounts)
- [ ] iPhone connected and trusted
- [ ] Developer certificate created
- [ ] Bundle identifier is unique for free account

## Deliverables
- [ ] Project configured for personal team signing
- [ ] App successfully installed on physical device
- [ ] All features verified working on device
- [ ] Confirm API connectivity works
- [ ] Report any device-specific issues

## Notes
- Free Apple Developer accounts have limitations:
  - Apps expire after 7 days (need to reinstall)
  - Limited to 3 apps at a time
  - No push notifications
- For TestFlight distribution, a paid Apple Developer account ($99/year) is required
- The app should work on any iPhone running iOS 16.0 or later
