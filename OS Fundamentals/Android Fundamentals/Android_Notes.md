## Android Fundamentals — Introduction

### About Android
- Android is a mobile operating system for touchscreen devices like smartphones and tablets.
- Based on a modified **Linux Kernel**.
- Developed by the **Open Handset Alliance** and commercially backed by **Google**.
- Most devices come with **Google Mobile Services (GMS)**, including:
  - Google Play
  - Google Chrome
- Vendors like **Samsung** and **HTC** can customize the UI and features.
- Extended usage in:
  - Smart TVs
  - Wearables (e.g., smartwatches)
- Apps are distributed via:
  - **Official stores**: Google Play Store, Amazon Appstore, Samsung Galaxy Store, Huawei AppGallery
  - **Alternative/open-source**: Aptoide, F-Droid, APKPure, APKMirror

---

### History
- **2003**: Android Inc. founded by Andy Rubin, Rich Miner, Nick Sears, and Chris White in Palo Alto, CA.
- **2005**: Acquired by Google for ~$50M.
- **2007**: Early Android prototype with no touchscreen, QWERTY keyboard.
- **2008**: First commercial Android device released — HTC Dream (T-Mobile G1).
- **Version naming**: Initially based on desserts (Cupcake, Donut, Eclair, Froyo, etc.)
- **2010**: Launch of **Nexus series** by Google.
- **2013**: Introduction of Google Play Editions of popular phones.
- **2014**: Launch of **Android One** program — affordable high-quality phones by OEMs.
- **2016**: Nexus replaced by **Pixel series** — designed and marketed entirely by Google.
- **2019**: Release of **Android 10**, ending dessert naming convention.

---

### Android Versions Overview

| Name                   | Version           | API Level | Release Date       |
|------------------------|-------------------|-----------|--------------------|
| Android 1.0            | 1.0               | 1         | September 23, 2008 |
| Android 1.1            | 1.1               | 2         | February 9, 2009   |
| Cupcake                | 1.5               | 3         | April 27, 2009     |
| Donut                  | 1.6               | 4         | September 15, 2009 |
| Eclair                 | 2.0 – 2.1         | 5–7       | Oct 2009 – Jan 2010|
| Froyo                  | 2.2 – 2.2.3       | 8         | May 20, 2010       |
| Gingerbread            | 2.3 – 2.3.7       | 9–10      | Dec 2010 – Feb 2011|
| Honeycomb              | 3.0 – 3.2.6       | 11–13     | Feb – Jul 2011     |
| Ice Cream Sandwich     | 4.0 – 4.0.4       | 14–15     | Oct – Dec 2011     |
| Jelly Bean             | 4.1 – 4.3         | 16–18     | 2012 – 2013        |
| KitKat                 | 4.4 – 4.4W.2      | 19–20     | 2013 – 2014        |
| Lollipop               | 5.0 – 5.1.1       | 21–22     | 2014 – 2015        |
| Marshmallow            | 6.0 – 6.0.1       | 23        | October 2, 2015    |
| Nougat                 | 7.0 – 7.1.2       | 24–25     | 2016               |
| Oreo                   | 8.0 – 8.1         | 26–27     | 2017               |
| Pie                    | 9                 | 28        | August 6, 2018     |
| Android 10             | 10                | 29        | September 3, 2019  |
| Android 11             | 11                | 30        | September 8, 2020  |
| Android 12             | 12                | 31        | October 4, 2021    |
| Android 12L            | 12.1              | 32        | March 7, 2022      |
| Android 13             | 13                | 33        | August 15, 2022    |
| Android 14             | 14                | 34        | October 4, 2023    |
| Android 15             | 15                | 35        | September 3, 2024  |
| Android 16 (Beta)      | 16 Beta           | 36        | March 13, 2025     |

- **To view Android version**:  
  `Settings → About emulated device → Android version`

- **Example (Android 13 details)**:
  - Security Update: November 5, 2022
  - Google Play Update: October 1, 2022
  - Baseband: 1.0.0.0
  - Kernel: 5.15.41
  - Build Number: 9302419

---

### Hardware
- **Primary architecture**: ARM (AArch64)
- **Also supported**: x86, x86-64
- **Android-x86**: Community project enabling x86 support even before official adoption
- **Emulators**:
  - Android SDK Emulator
  - 3rd-party emulators (e.g., BlueStacks, Genymotion)
- **Typical sensors and components** in Android devices:
  - Video camera, GPS, accelerometer, gyroscope
  - Thermometer, barometer, magnetometer
  - Proximity & pressure sensors
  - Touchscreen
  - Orientation sensors
  - Dedicated gaming controls (on some models)

---

# Operating System & Architecture

## Android Shell & Linux Integration
- Android is based on the Linux kernel and supports command-line access.
- Users can interact with the system using a shell (e.g., `adb shell`) to execute Linux commands.
- Shell access enables navigation (e.g., `cd /sdcard/`) and inspection of the filesystem (`ls -l`).

---

# Android Software Stack
The Android architecture consists of six core components:

## Linux Kernel
- Acts as the foundation of Android OS.
- Manages hardware (e.g., display, camera, Wi-Fi, Bluetooth, audio).
- Provides system-level features like:
  - Process isolation
  - User-based permissions
  - Resource protection (CPU, memory, hardware access)

## Hardware Abstraction Layer (HAL)
- Provides a consistent API for Android to communicate with device hardware.
- Abstracts hardware-specific logic into shared libraries.
- Enables manufacturers to implement drivers without modifying the Android framework.

## Android Runtime (ART)
- Executes Android apps using the DEX format.
- Replaced Dalvik in Android 5.0.
- Uses Ahead-of-Time (AOT) compilation for better performance.
- Supports multiple concurrent virtual machines.

### ART Advantages:
- Faster app launch times
- Efficient garbage collection
- Optimized memory management
- Enhanced debugging tools
- DEX compression for reduced app size

## Native C/C++ Libraries
- Core OS components and performance-critical features use native libraries.
- Components like ART and HAL are written in C/C++.
- Apps can interface via:
  - **JNI (Java Native Interface)**
  - **NDK (Native Development Kit)**

## Java API Framework
- Provides tools and APIs for building Android applications.
- Includes core system services and managers like:
  - View System
  - Resource Manager
  - Notification Manager
  - Activity Manager
  - Content Providers
  - Location Manager
  - Package Manager

## System Apps
- Pre-installed applications (e.g., Contacts, Camera, Messaging, Maps).
- Serve as both user-facing apps and examples for API usage.
- Typically only modifiable on rooted devices.

---

# Dalvik, Rooting & File System

## Dalvik Virtual Machine (DVM)
- Developed by Google; introduced in Android 1.0 (2008).
- Apps written in Java/Kotlin are compiled into:
  - **Java bytecode → Dalvik bytecode → .dex / .odex files**
- DVM is **register-based**, unlike the **stack-based JVM**.
  - More efficient for low-resource mobile environments.

**Runtime Context:**
| Runtime | Compilation | API Level | Notes                            |
|---------|-------------|-----------|----------------------------------|
| Dalvik  | JIT         | ≤ 20      | Legacy default runtime           |
| ART     | AOT (initially) + JIT/PGO | 21+ | Default since Android 5.0 (Lollipop) |

- ART introduced in 4.4 (preview), default in 5.0.
- Maintains `.dex` compatibility.
- Enhancements: **Hybrid JIT + AOT**, **Profile-Guided Optimization (PGO)**.

---

## Rooting
- Flash storage is split into two key partitions:
  - `/system/` → OS files (read-only)
  - `/data/` → User data & installed apps

- **Rooting**: Gaining privileged access to the OS by:
  - Exploiting system vulnerabilities
  - Unlocking bootloader (e.g., on Pixel, OnePlus)

**Pros:**
- Customization
- Debugging
- Full control for security assessments

**Cons:**
- Disables built-in protections
- Increases exposure to malware/viruses

---

## Key Android Directories

| Directory                              | Description                                                                 |
|----------------------------------------|-----------------------------------------------------------------------------|
| `/data/data/`                          | Contains all installed applications                                        |
| `/data/user/0/`                        | App-specific private data                                                  |
| `/data/app/`                           | APKs of user-installed applications                                        |
| `/system/app/`                         | Pre-installed system apps                                                  |
| `/system/bin/`                         | System binary executables                                                  |
| `/data/local/tmp/`                     | World-writable temp directory                                              |
| `/data/system/`                        | System configuration files                                                 |
| `/etc/apns-conf.xml`                   | APN settings for cellular network connectivity                             |
| `/data/misc/wifi/`                     | Wi-Fi configuration data                                                   |
| `/data/misc/user/0/cacerts-added/`     | User-installed SSL certificates                                            |
| `/etc/security/cacerts/`               | System certificate store (non-root users have no access)                   |
| `/sdcard/`                             | Symbolic link to media directories (DCIM, Downloads, Music, etc.)          |

---

# Security Features

## APK & App Isolation
- Android apps are written in **Kotlin** or **Java** and compiled into **APK** files (.apk).
- APK includes: compiled `.dex` bytecode, manifest, assets, resources, and native libraries.
- Each app runs in its **own process**, with a **unique Linux UID**, enforced by the kernel.
- Apps operate in isolated **sandboxes**, preventing access to system resources or other apps unless explicitly granted.
- Memory, file system, and runtime isolation is applied uniformly, including native binaries and services.

## Discretionary Access Control (DAC) & Process UIDs
- Each installed app has a unique UID:
  - Verified via: `ls -l /data/data/`
  - E.g., `com.android.chrome` → UID `u0_a114`, `com.android.camera2` → `u0_a119`
- File access is limited to the assigned UID owner.
- Kernel-enforced; escaping sandbox requires kernel-level privilege escalation.

## Additional Security Protections

| Protection                     | Purpose                                                                 |
|-------------------------------|-------------------------------------------------------------------------|
| **SELinux (MAC)**             | Isolates system and apps using mandatory access control                |
| **SELinux per user**          | Further isolates apps across device users                              |
| **seccomp-bpf filtering**     | Limits syscall access for apps                                         |
| **Filesystem view restrictions** | Disallows raw access to paths like `/sdcard/DCIM`                  |
| **World-readable ban**        | targetSdkVersion ≥ 28 disallows world-readable data                    |

- App data sharing must be explicit; implicit sharing is blocked.

## Application Signing

| Signature Scheme | Android Version | Key Features & Notes                                                    |
|------------------|------------------|-------------------------------------------------------------------------|
| v1 (JAR)         | ≤ Android 6.0    | Vulnerable (e.g., Janus CVE-2017-13156); ZIP metadata not covered       |
| v2               | Android 7.0+     | Full-file integrity verification; invalidates modified APKs            |
| v3               | Android 9.0+     | Adds metadata support                                                  |
| v4               | Android 11.0+    | Merkle tree (fs-verity style); requires v2 or v3 base                  |

- **Janus Vulnerability (CVE-2017-13156)**:
  - Affects APKs signed with v1 (Android 5.0–8.1).
  - Allows DEX injection without breaking signature.
  - Dalvik loads injected code as if it’s an update.

## APK Signing Methods

| Method                     | Description                                                        |
|----------------------------|--------------------------------------------------------------------|
| **Android Studio**         | GUI option: *Generate Signed App Bundle / APK*                    |
| **apksigner / jarsigner**  | CLI tools for manual signing and verification                     |
| **Play App Signing**       | Managed by Google, offloads key storage to Play infrastructure     |

## Verified Boot

- Ensures only authenticated & untampered OS versions are booted.
- Each boot stage verifies the next via cryptographic signatures.

## Tampered systems:

- Trigger user warnings or prevent boot.
- Rollback Protection: Blocks downgrades to vulnerable versions.

## Boot Flow Summary:
- Device starts → checks bootloader lock state.
- Verifies root of trust.
- Validates OS signature.
- Applies rollback protection.
- Boots OS or shows warning/block screen if tampered.

---

# APK Structure

## Overview

- APK (Android Package Kit) is the standard file format used to distribute and install Android applications.
- It is a ZIP-based archive containing:
- Compiled executable code (.dex)
- Application resources (images, UI layouts)
- The AndroidManifest.xml metadata file
- Native libraries (.so)
- Source code is compiled from Java/Kotlin → Java bytecode → DEX (Dalvik Executable) → packaged into an APK.
- Executed by either Dalvik VM or ART depending on Android version.

## Compilation & Unpacking

- APKs use the .apk extension and can be unpacked using tools like unzip.

- Example:
  unzip myapp.apk
  ls -l
- Sample output:
  AndroidManifest.xml
  META-INF/
  assets/
  classes.dex
  kotlin/
  lib/
  res/
  resources.arsc

- Extracted files are encoded; contents are not human-readable without proper tooling.
  
# Core Components

| Component           | Description                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| AndroidManifest.xml | Metadata about the app: package name, permissions, SDKs, components         |
| classes.dex         | Compiled DEX code, executed by ART or Dalvik                                |
| resources.arsc      | Precompiled resources and binary XML data                                   |
| META-INF/           | Signing info: integrity and authenticity metadata                           |
| assets/             | Raw developer files (images, DBs, docs, binaries), used via AssetManager    |
| lib/                | Native libraries organized by CPU architecture                              |
| res/                | Static, precompiled resources (layouts, drawables, strings, XML configs)    |
| kotlin/             | Kotlin-specific runtime metadata (if Kotlin is used in app)                 |

## META-INF/
- Auto-generated during signing process.
- Any modification to the APK invalidates the signature.

**Files:**
- **CERT.RSA**: Public key and signature for CERT.SF
- **CERT.SF**: List of hashes for files listed in MANIFEST.MF
- **MANIFEST.MF**: SHA256 Base64 hashes for all APK files

---

## assets/
- Contains raw bundled files accessed at runtime.
- Used for images, videos, documents, databases, or even DLLs.
- Common in cross-platform frameworks like:
  - Xamarin
  - Cordova
  - React Native

---

## lib/
- Holds compiled native libraries (`.so` files) for multiple architectures.

### Typical subfolders:
- arm64-v8a/
- armeabi-v7a/
- x86/
- x86_64/

- Used when the app includes NDK-based components (C/C++)

---

## res/
- Contains resources compiled at build time, not modifiable at runtime.

**Includes:**
- UI layouts
- Drawable resources
- Fonts
- Value XMLs (strings, colors)
- Configuration folders (screen size, orientation, etc)

---

## AndroidManifest.xml
- Defines essential attributes and app structure.

**Common fields:**
- package name
- minSdkVersion / targetSdkVersion
- versionCode / versionName
- permissions
- NetworkSecurityConfig
- declared components (activities, services, providers)

---

## classes.dex
- Contains all compiled classes in DEX format.
- Executed by ART (Android 5.0+) or Dalvik VM (older versions).

**Large apps may include:**
- classes2.dex
- classes3.dex
- etc. (multi-dex setup)

---

## resources.arsc
- Holds precompiled resources used at runtime.
- Maps resource IDs (e.g. R.string.app_name) to actual values.
- Includes binary versions of XML resources (styles, strings, layouts)

---
