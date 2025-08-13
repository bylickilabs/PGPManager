# PGP Key Manager (Tkinter)



## Overview

The **PGP Key Manager** is a production-ready desktop application built with **Python + Tkinter** for generating **OpenPGP keypairs**. It supports **RSA 2048/3072/4096** and **Ed25519** (with automatic fallback to RSA 4096 if Ed25519 is unavailable). The application includes a **German/English language switch**, a **GitHub button** to your profile, and a localized **Info dialog**. Keys are displayed in **ASCII-armored** format with options to **copy** or **save**.

- **Title format:** `{APP_TITEL} v{APP_VERSION} — {APP_AUTHOR}`
- **Tech stack:** Python 3.11/3.12, Tkinter, PGPy, cryptography
- **Target audience:** Developers, security professionals, and power users needing a simple, local PGP key generator.

---

## Features

- ✅ **Generate OpenPGP keys:** RSA 2048/3072/4096, Ed25519 (fallback to RSA 4096)
- 🔐 **Passphrase protection:** AES-256 + SHA-256
- 🧭 **Key usage flags:** Sign, Encrypt (communications/storage), Certify, Authenticate
- ⏱️ **Expiration:** Optional in days (0 = no expiry)
- 🧩 **Metadata:** Fingerprint, Key ID, Algorithm, Bits, Created, Expires
- 📋 **Copy & Save:** ASCII-armored public/private keys to clipboard or file
- 🌍 **Full i18n:** Complete German/English translations for all UI elements
- 🔗 **Buttons:** GitHub → `https://github.com/bylickilabs`, Info dialog with app metadata
- 🧵 **UX:** Non-blocking key generation (threaded) with progress indicator
- 🖥️ **Wide layout:** All buttons fully visible without resizing

---

## Requirements

- **Python:** 3.11 or 3.12
- **Packages:**
  ```
  pgpy>=0.6.0
  cryptography>=41.0.0
  pyasn1>=0.6.0
  ```
  > Tkinter is usually bundled; on Linux: `sudo apt install python3-tk`

---

## Usage

1. Enter **Name**, **Email**, and optional **Comment**.
2. Choose **Algorithm** and **Expiration**.
3. Select **Key Usage** flags.
4. Enter and confirm a strong **Passphrase**.
5. Click **Generate Key**.
6. View metadata, copy or save keys.
7. Use **Info** for help, **GitHub** to open your profile.
8. Toggle **DE/EN** at any time.

> **Security note:** Keys remain in memory only until cleared or app is closed.

<br>

---

<br>

# PGP Schlüssel-Manager (Tkinter)

## Übersicht

Der **PGP Schlüssel-Manager** ist eine produktionsreife Desktop-Anwendung, entwickelt mit **Python + Tkinter**, zum Erzeugen von **OpenPGP-Schlüsselpaaren**. Unterstützt werden **RSA 2048/3072/4096** und **Ed25519** (mit automatischem Fallback auf RSA 4096, falls Ed25519 nicht verfügbar ist). Die Anwendung bietet eine **Deutsch/Englisch-Sprachumschaltung**, einen **GitHub-Button** zu deinem Profil und einen lokalisierten **Info-Dialog**. Schlüssel werden im **ASCII-Armor** angezeigt, mit Optionen zum **Kopieren** oder **Speichern**.

- **Titelformat:** `{APP_TITEL} v{APP_VERSION} — {APP_AUTHOR}`
- **Technologien:** Python 3.11/3.12, Tkinter, PGPy, cryptography
- **Zielgruppe:** Entwickler, Sicherheitsexperten und Power-User, die einen einfachen, lokalen PGP-Schlüsselgenerator benötigen.

---

## Funktionen

- ✅ **OpenPGP-Schlüssel erzeugen:** RSA 2048/3072/4096, Ed25519 (Fallback auf RSA 4096)
- 🔐 **Passphrase-Schutz:** AES-256 + SHA-256
- 🧭 **Schlüsselverwendungs-Flags:** Signieren, Verschlüsseln (Kommunikation/Speicher), Zertifizieren, Authentifizieren
- ⏱️ **Ablauf:** Optional in Tagen (0 = kein Ablauf)
- 🧩 **Metadaten:** Fingerprint, Schlüssel-ID, Algorithmus, Bits, Erstellt, Läuft ab
- 📋 **Kopieren & Speichern:** Öffentliche/private Schlüssel im ASCII-Armor in Zwischenablage oder Datei
- 🌍 **Komplette i18n:** Vollständige Übersetzungen aller UI-Elemente in Deutsch/Englisch
- 🔗 **Buttons:** GitHub → `https://github.com/bylickilabs`, Info-Dialog mit App-Details
- 🧵 **UX:** Nicht-blockierende Schlüsselerzeugung (Thread) mit Fortschrittsanzeige
- 🖥️ **Breites Layout:** Alle Buttons ohne Fensteranpassung sichtbar

---

## Voraussetzungen

- **Python:** 3.11 oder 3.12
- **Pakete:**
  ```
  pgpy>=0.6.0
  cryptography>=41.0.0
  pyasn1>=0.6.0
  ```
  > Tkinter ist in der Regel enthalten; unter Linux: `sudo apt install python3-tk`

---

## Nutzung

1. **Name**, **E-Mail** und optional **Kommentar** eingeben.
2. **Algorithmus** und **Ablaufdatum** wählen.
3. **Schlüsselverwendungs-Flags** setzen.
4. Starke **Passphrase** eingeben und bestätigen.
5. **Schlüssel erzeugen** klicken.
6. Metadaten ansehen, Schlüssel kopieren oder speichern.
7. **Info** für Hilfe, **GitHub** zum Profil.
8. **DE/EN** jederzeit umschalten.

> **Sicherheitshinweis:** Schlüssel verbleiben nur im Speicher, bis sie gelöscht oder die App geschlossen wird.
