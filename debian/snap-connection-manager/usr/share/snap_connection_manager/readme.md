# SNAP Connection Manager – User & Technical Guide

## Table of Contents
1. [Introduction](#introduction)  
2. [Core Features](#core-features)  
   - [Server & Folder Management](#server--folder-management)  
   - [Connection & Automation](#connection--automation)  
   - [Data Management & Logging](#data-management--logging)  
3. [The "Super Safe" Encryption System](#the-super-safe-encryption-system)  
   - [How It Works](#how-it-works)  
   - [Data Storage Location](#data-storage-location)  
   - [Changing Your Passphrase](#changing-your-passphrase)  
4. [Appearance & Customization](#appearance--customization)  
   - [Global Settings](#global-settings)  
5. [Getting Started](#getting-started)  
6. [Installation Instructions](#installation-instructions)  
7. [Troubleshooting & Dependencies](#troubleshooting--dependencies)  

---

## 1. Introduction
SNAP Connection Manager is a secure GTK3-based desktop application for managing and launching SSH and SFTP connections. It organizes server configurations into folders, automates login sequences, and supports port forwarding.  
Sensitive data is protected using a robust GnuPG-based encryption system.

---

## 2. Core Features

### 2.1 Server & Folder Management
- Hierarchical organization of servers into folders  
- Add, edit, delete servers and folders  
- Inline renaming (slow double-click to edit)  
- Drag-and-drop reordering  
- Copy & paste servers via menu or shortcuts (`Ctrl+C` / `Ctrl+V`)  
- Keyboard shortcuts: `Delete` removes selected item, `Ctrl+C`/`Ctrl+V` copy/paste  
- Natural alphanumeric sorting (e.g., `server10` after `server9`)  

### 2.2 Connection & Automation
- SSH and SFTP protocol support  
- Embedded VTE terminal with:  
  - Smart copy/paste (`Ctrl+C` copies highlighted text or sends interrupt if none selected)  
  - Context menu for copy/paste  
  - Auto-resize sync with remote host  
- Authentication: password (via `expect`) or key file (`-i` flag)  
- Automated login sequences with Expect/Send steps (passwords can be hidden in UI)  
- Advanced port forwarding: Local (-L), Remote (-R), Dynamic (-D)  

### 2.3 Data Management & Logging
- Export/import data as JSON (plaintext) or GPG (encrypted)  
- GUI log pane for real-time feedback  
- Per-server session logging to local files  

---

## 3. The "Super Safe" Encryption System

### 3.1 How It Works
1. Master passphrase creation on first launch  
2. Passphrase hashed with PBKDF2-HMAC-SHA256 (600,000 iterations, salted)  
3. Server data stored in `ssh_servers.json.gpg` encrypted with AES256 via GnuPG  
4. Data decrypted only in memory during active sessions  

### 3.2 Data Storage Location
- Path: `~/.local/share/snap_connection_manager/`  
- Files:  
  - `snap_cm_settings.json` → settings, hash + salt of passphrase  
  - `ssh_servers.json.gpg` → encrypted server configurations  

### 3.3 Changing Your Passphrase
- Accessible via `File -> Change Passphrase...`  
- Requires current passphrase, then re-encrypts data atomically with new passphrase  
- Generates new salt + hash  

---

## 4. Appearance & Customization

### 4.1 Per-Server Customization
- Font & colors per server  
- Scrollback buffer size (default: 10,000 lines)  
- Palettes: Tango, Solarized, None  

### 4.2 Global Settings
Accessed via `File -> Global Settings...`, this dialog defines **default configuration** for the application:
- Default appearance (font, colors, palette) applied to all new servers  
- Default log folder for session logs  
- Reset to Defaults button in server editor restores settings to match Global Settings  

---

## 5. Getting Started
1. First launch → set master passphrase  
2. Add servers via right-click on “Session” folder → Add Server  
3. Connect by double-clicking a server  

---

## 6. Installation Instructions

### 6.1 Quick Install Script
```bash
curl -sL https://raw.githubusercontent.com/larreblarsson/SNAP-Connection-Manager/main/install.sh | bash
```

### 6.2 Manual Installation
```bash
# Add the GPG key
curl -sL https://larreblarsson.github.io/SNAP-Connection-Manager/public.key | sudo gpg --dearmor -o /usr/share/keyrings/SNAP-Connection-Manager-keyring.gpg

# Add the repository
echo "deb [signed-by=/usr/share/keyrings/SNAP-Connection-Manager-keyring.gpg] https://larreblarsson.github.io/SNAP-Connection-Manager stable main" | sudo tee /etc/apt/sources.list.d/SNAP-Connection-Manager.list

# Update and install
sudo apt update
sudo apt install snap-connection-manager
```

---

## 7. Troubleshooting & Dependencies
- **Incorrect master passphrase** → unrecoverable, delete `~/.local/share/snap_connection_manager/` to reset  
- **Dependencies required**:  
  - `python3-gi`  
  - `gir1.2-gtk-3.0`  
  - `gir1.2-vte-2.91`  
  - `expect`  
  - `gnupg` 
