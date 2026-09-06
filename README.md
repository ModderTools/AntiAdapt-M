# AntiAdapt M

<div align="center">

**APK · XAPK · AAB · ZIP → Installable APK**

A clean, modern APK conversion & build utility for Android.

![Platform](https://img.shields.io/badge/Platform-Android-green)
![Language](https://img.shields.io/badge/Language-Java%20100%25-orange)
![Min SDK](https://img.shields.io/badge/Min%20SDK-24-blue)
![Build](https://img.shields.io/badge/Build-GitHub%20Actions-success)

</div>

---

## ✨ Features

- 📦 **Select File from Storage** — Process `APK`, `XAPK`, `APKS`, `AAB` and `ZIP` packages
- 📱 **Select App from Installed** — Extract APK directly from any installed application
- ⚡ **Kill Verification** — Removes old signature blocks and prepares the package for re-signing
- 🔐 **Secure Signing** — Automatic RSA-2048 key generation + APK Signature Scheme v1 / v2 / v3
- ✅ **APK Validation** — Every output is verified with Google's apksig verifier
- 📁 **Auto Output Folder** — Final files saved to `Internal Storage/AntiAdapt M`
- 🎨 **Premium UI** — Pearl (#FFF7E6) & Midnight (#102E4A) minimalist theme
- 🌗 **Theme Modes** — Dark / Light / Follow System
- 📜 **Live Logs** — Detailed real-time processing logs with progress bar
- 🛑 **Cancellation** — Cancel any running process with one tap

## 🔄 Processing Stages

| # | Stage | Description |
|---|---|---|
| 1 | **Analyzing** | Input package structure check |
| 2 | **Converting / Building** | Extract & prepare APK |
| 3 | **Kill Verification** | Strip old signature blocks |
| 4 | **APK Signing** | Sign with managed key (v1+v2+v3) |
| 5 | **APK Validation** | Verify structure & signature |
| 6 | **Completed** | Save to output folder |

## 📥 Installation

1. Download the latest APK from [Releases](../../releases)
2. Enable **Install from unknown sources** in Android settings
3. Install & open
4. Grant **All files access** when prompted (required to save APKs)

> **Requires:** Android 7.0 (API 24) or higher

## 🛠️ Supported Inputs

| Input | Result |
|---|---|
| `.apk` | Processed → signed APK |
| `.xapk` / `.apks` | Single APK extracted, or `.apks` bundle for splits |
| `.zip` (containing APK) | APK extracted & processed |
| `.aab` | Analyzed — full conversion needs Google bundletool |
| Installed app | APK / `.apks` bundle exported |
| OBB data (in XAPK) | Auto-copied to `Android/obb/` |

## ⚙️ Settings

- **Theme** — Dark / Light / Follow System
- **Output Directory** — Custom folder via system folder picker
- **Signing Key** — Auto-managed RSA-2048 key with regenerate option
- **Kill Verification toggle** — Enable/disable re-signing of outputs

## 🚀 Build from Source (GitHub Actions)

1. Fork or clone this repository
2. Push any commit — build runs automatically
3. Open **Actions** tab → latest run → download artifact `AntiAdapt-M-APK`

No local setup required — builds run 100% on GitHub.

## 📁 Project Structure

```
AntiAdaptM/
├── .github/workflows/build.yml
├── settings.gradle
├── build.gradle
├── gradle.properties
└── app/
    ├── build.gradle
    └── src/main/
        ├── AndroidManifest.xml
        ├── java/com/antiadapt/m/
        │   ├── ApkEngine.java
        │   ├── MainActivity.java
        │   └── SettingsActivity.java
        └── res/drawable/logo.png
```

## 📄 Legal Notice

Kill Verification only removes **signature blocks** so packages can be re-signed safely. This app does **not** bypass DRM, licensing, anti-tampering mechanisms, or any protection belonging to applications without authorization. Use only with packages you own or have rights to modify.

## 📌 Tech Stack

- **Language:** Java (100% — zero XML layouts, fully programmatic UI)
- **Min SDK:** 24 · **Target SDK:** 34
- **Libraries:** apksig, BouncyCastle, DocumentFile
- **CI/CD:** GitHub Actions (Gradle 8.2 · AGP 8.1.4 · JDK 17)

---

<div align="center">

**AntiAdapt M** — Simple for beginners, powerful for pros.

</div>
