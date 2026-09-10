
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:102E4A,50:1E466B,100:63D1FF&height=210&section=header&text=AntiAdapt%20M&fontSize=48&fontColor=FFF7E6&fontAlignY=30&desc=APK%20%C2%B7%20XAPK%20%C2%B7%20AAB%20%C2%B7%20ZIP%20%E2%86%92%20Installable%20APK&descSize=17&descAlignY=53&descColor=8FA9C4&animation=fadeIn" width="100%"/>

[![Typing SVG](https://readme-typing-svg.herokuapp.com?font=JetBrains+Mono&weight=700&size=22&pause=1100&color=63D1FF&center=true&vCenter=true&width=640&lines=Split+APK+%E2%86%92+Single+Installable+APK+%F0%9F%A7%AC;Powerful+Kill+Verification+%E2%9A%A1;Custom+Binary+ARSC+Merger+%F0%9F%94%A2;Built+100%25+in+Java+%F0%9F%98%8E;MT+Manager+Level+Power+%F0%9F%94%A5)](#)

<br>

![Version](https://img.shields.io/badge/Version-v1.1.0-102E4A?style=for-the-badge&logo=android&logoColor=FFF7E6)
![Java](https://img.shields.io/badge/Java-100%25-FF7800?style=for-the-badge&logo=openjdk&logoColor=white)
![Min SDK](https://img.shields.io/badge/Min_SDK-24-3DDC84?style=for-the-badge&logo=android&logoColor=white)
![Build](https://img.shields.io/badge/GitHub_Actions-Building-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)
![Release](https://img.shields.io/badge/Release-Stable-63D1FF?style=for-the-badge&logo=github&logoColor=white)

<br>

**A premium, modern APK conversion & build utility — simple for beginners, powerful for pros.**

</div>

---

## 🌟 Highlights

| | Feature | Description |
|:---:|---|---|
| 🧬 | **SmartMerge Engine** | Split APKs (Instagram-style) merge into **ONE installable APK** with a custom binary ARSC resource-table merger |
| ⚡ | **Powerful Kill Verification** | Detects v1 (JAR) signature files **and** v2/v3 signature blocks — then replaces them with fresh signatures |
| 📦 | **Universal Input** | `APK` · `XAPK` · `APKS` · `ZIP` · Installed Apps · OBB auto-copy |
| 🔐 | **Secure Signing** | Auto-managed RSA-2048 key + APK Signature Scheme **v1 + v2 + v3** |
| ✅ | **Validation Engine** | Every output verified with Google's **apksig** verifier + full CRC self-check |
| 🎨 | **Premium UI** | Pearl `#FFF7E6` × Midnight `#102E4A` theme with animations & ripple effects |
| 🌙 | **Aesthetic Dark Mode** | Deep navy gradient with glow accents |
| 🛟 | **Smart Fallback** | Exotic merge fails? Auto-exports `.apks` bundle — **never a dead end** |

---

## 🔄 Processing Pipeline

<div align="center">

```
   📂 Input        🧠 Analyze       ⚙️ Convert/Build
     ─────────────────►────────────────►
                                        
   ⚡ Kill Verify    🔏 Sign           ✅ Validate
     ─────────────────►────────────────►
                                        
   💾 Completed      →  /storage/emulated/0/AntiAdapt M/
```

**6 Stages · Real-time Logs · Live Progress · One-tap Cancel**

</div>

---

## 🎬 What Makes It Powerful

<details>
<summary><b>🧬 SmartMerge Engine (tap to expand)</b></summary>
<br>

- **Binary ARSC Merger** written from scratch — string pools, type chunks, config tables, resource ID remapping
- **ABI auto-selection** → `arm64-v8a` → `armeabi-v7a` → `x86_64` → `x86`
- **Dex collision auto-rename** → `classes2.dex`, `classes3.dex`...
- **Native libs 16KB-aligned** for modern devices
- **ZIP Integrity Self-Check** → every merged entry CRC-verified before saving

</details>

<details>
<summary><b>⚡ Kill Verification — MT Manager Style (tap to expand)</b></summary>
<br>

- Scans for **v1 (JAR)** signatures: `MANIFEST.MF` · `.SF` · `.RSA` · `.DSA` · `.EC`
- Detects **v2/v3 blocks** via `APK Sig Block 42` magic-byte scan
- Full transparency — logs exactly what was found & what action is taken
- Old blocks **replaced** with fresh v1 + v2 + v3 signatures (RSA-2048)

</details>

<details>
<summary><b>🎨 Animated UI (tap to expand)</b></summary>
<br>

- ✨ Staggered entrance animations
- 🔵 Blinking active-stage dots
- 📊 Smooth animated progress bar
- 🌀 FAB spin-on-tap with overshoot bounce
- 💧 Ripple feedback on every button
- 🌗 Dark / Light / Follow System themes

</details>

---

## 📥 Installation

<div align="center">

**1️⃣** Download APK from [**Releases**](../../releases) → **2️⃣** Allow *unknown sources* → **3️⃣** Install & grant **All files access** → **4️⃣** Done! 🎉

</div>

> **Requires:** Android 7.0 (API 24)+

---

## 🛠️ Supported Inputs

| Input | Result |
|---|:---:|
| `.apk` | ✅ Signed APK |
| `.xapk` / `.apks` / `.zip` | ✅ Single APK (SmartMerge) |
| Installed app | ✅ APK / merged APK |
| OBB data (in XAPK) | 📁 Auto-copied to `Android/obb/` |
| `.aab` | ℹ️ Analyzed (bundletool needed on PC) |
| Decompiled project | ℹ️ Clear guidance error |

---

## 🚀 Build with GitHub Actions

```
1. Fork this repo          →  🍴
2. Push any commit         →  ⚡ auto-build
3. Actions tab → artifact  →  📦 AntiAdapt-M-APK
4. Install                 →  ✅
```

**Zero local setup** — builds run 100% on GitHub.

<details>
<summary><b>📁 Project Structure</b></summary>

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
        │   ├── ApkEngine.java        # Core engine
        │   ├── MainActivity.java     # Animated UI
        │   └── SettingsActivity.java
        └── res/drawable/logo.png
```

</details>

---

## ⚙️ Settings

| Option | Detail |
|---|---|
| 🌗 **Theme** | Dark / Light / Follow System |
| 📂 **Output Directory** | Custom folder picker |
| 🔑 **Signing Key** | Auto RSA-2048 · regenerate anytime |
| ⚡ **Kill Verification** | Toggle on/off |

---

## 📌 Tech Stack

<div align="center">

![Java](https://img.shields.io/badge/Java-ED8B00?style=flat-square&logo=openjdk&logoColor=white)
![Android](https://img.shields.io/badge/Android-3DDC84?style=flat-square&logo=android&logoColor=white)
![Gradle](https://img.shields.io/badge/Gradle-02303A?style=flat-square&logo=gradle&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=flat-square&logo=githubactions&logoColor=white)
![apksig](https://img.shields.io/badge/apksig-102E4A?style=flat-square&logo=google&logoColor=white)
![BouncyCastle](https://img.shields.io/badge/BouncyCastle-63D1FF?style=flat-square&logo=lock&logoColor=white)

**AGP 8.1.4 · Gradle 8.2 · JDK 17 · Target SDK 34**

</div>

---

## 📄 Legal Notice

> ⚠️ Kill Verification only removes **signature blocks** so packages can be re-signed safely. This tool does **not** bypass DRM, licensing, or anti-tampering protections. Use only with packages **you own** or have **rights** to modify.

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:63D1FF,50:1E466B,100:102E4A&height=130&section=footer&text=AntiAdapt%20M%20—%20Simple%20for%20beginners%2C%20powerful%20for%20pros.&fontSize=15&fontColor=FFF7E6&fontAlignY=65&animation=twinkling" width="100%"/>

**⭐ Star this repo if you find it useful!**

</div>
