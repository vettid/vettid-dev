# Phase 10: Build Release APK

## Overview
Build and publish a release APK for testing on physical devices.

## Priority Task: Build Release APK

### 1. Configure Release Signing
Ensure release keystore is configured:
```kotlin
// app/build.gradle.kts
android {
    signingConfigs {
        create("release") {
            storeFile = file("release-keystore.jks")
            storePassword = System.getenv("KEYSTORE_PASSWORD") ?: ""
            keyAlias = "vettid"
            keyPassword = System.getenv("KEY_PASSWORD") ?: ""
        }
    }
    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
}
```

### 2. Generate Release Keystore (if not exists)
```bash
keytool -genkey -v -keystore release-keystore.jks -keyalg RSA -keysize 2048 -validity 10000 -alias vettid
```

### 3. Build Release APK
```bash
# Clean and build release
./gradlew clean assembleRelease

# APK will be at: app/build/outputs/apk/release/app-release.apk
```

### 4. Upload to Repository
Upload the APK to the vettid-android repository for download:
```bash
# Create releases directory if not exists
mkdir -p releases

# Copy APK with version name
cp app/build/outputs/apk/release/app-release.apk releases/vettid-v1.0.0.apk

# Commit and push
git add releases/vettid-v1.0.0.apk
git commit -m "Release v1.0.0 APK for testing"
git push
```

Alternatively, create a GitHub Release with the APK attached.

### 5. Verify APK
Before uploading:
- Test on physical device
- Verify all features work
- Check ProGuard/R8 didn't break anything
- Verify certificate pinning works
- Test biometric authentication
- Verify RASP protections are active

## API Configuration
Ensure the app is configured to connect to the correct API endpoint:
```kotlin
// Update BuildConfig or config file with production API URL
const val API_BASE_URL = "https://api.vettid.dev"
```

## Deliverables
- [ ] Release keystore configured
- [ ] Release APK built successfully
- [ ] APK tested on physical device
- [ ] APK uploaded to vettid-android repo (releases/ folder or GitHub Release)
- [ ] Download URL provided

## Notes
- Do NOT commit the keystore or passwords to the repository
- Use environment variables for signing credentials
- The APK should be signed with a release key, not debug
- Keep the keystore backed up securely
