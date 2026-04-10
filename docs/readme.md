# Scarpa Connection Manager – User & Technical Guide

## Table of Contents
1. [Introduction](#1-introduction)  
2. [Core Features](#2-core-features)  
   - [Server & Folder Management](#21-server--folder-management)  
   - [Connection & Automation](#22-connection--automation)  
   - [Data Management & Logging](#23-data-management--logging)  
   - [SFTP File Manager](#24-sftp-file-manager)
3. [The "Super Safe" Encryption System](#3-the-super-safe-encryption-system)  
   - [How It Works](#31-how-it-works)  
   - [Data Storage Location](#32-data-storage-location)  
   - [Changing Your Passphrase](#33-changing-your-passphrase)  
4. [Appearance & Customization](#4-appearance--customization)  
   - [Global Settings](#42-global-settings)  
5. [Getting Started](#5-getting-started)  
6. [Installation Instructions](#6-installation-instructions)  
7. [Troubleshooting & Dependencies](#7-troubleshooting--dependencies)

## 1. Introduction
Scarpa Connection Manager is a secure GTK3-based desktop application for managing and launching SSH and SFTP connections. It organizes server configurations into folders, automates login sequences, and supports port forwarding.  
Sensitive data is protected using a robust GnuPG-based encryption system.

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

### 2.4 SFTP File Manager
- **Dual-Pane Interface:** Visually manage files between your Local machine and Remote server side-by-side.
- **Intuitive Navigation:** Navigate directories using standard clickable breadcrumb paths instead of manually typing locations. Dedicated refresh buttons keep both panes up to date.
- **Recursive Search:** Quickly locate files deep within your file system using the binoculars button or by right-clicking any folder. Double-click a search result to instantly navigate to its location.
- **Drag & Drop:** Seamlessly upload, download, or move files by dragging them between panes.
- **Smart Transfers:** Support for pausing and resuming partial transfers to save bandwidth and time.
- **Context Menus & Shortcuts:** Right-click or use keyboard shortcuts (`Ctrl+C`, `Ctrl+X`, `Ctrl+V`, `Delete`, `Shift+Delete`, `F2`) to easily manage files. Local files deleted with `Delete` are safely moved to your system's Rubbish Bin, while `Shift+Delete` (or any deletion on the remote server) permanently destroys them.
- **Real-Time Status:** A bottom status bar provides live feedback on transfer progress, successful actions, and errors.

## 3. The "Super Safe" Encryption System

### 3.1 How It Works
1. Master passphrase creation on first launch  
2. Passphrase hashed with PBKDF2-HMAC-SHA256 (600,000 iterations, salted)  
3. Server data stored in `ssh_servers.json.gpg` encrypted with AES256 via GnuPG  
4. Data decrypted only in memory during active sessions  

### 3.2 Data Storage Location
- Path: `~/.local/share/scarpa_connection_manager/`  
- Files:  
  - `scarpa_cm_settings.json` → settings, hash + salt of passphrase  
  - `ssh_servers.json.gpg` → encrypted server configurations  

### 3.3 Changing Your Passphrase
- Accessible via `File -> Change Passphrase...`  
- Requires current passphrase, then re-encrypts data atomically with new passphrase  
- Generates new salt + hash  

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

## 5. Getting Started
1. First launch → set master passphrase  
2. Add servers via right-click on “Session” folder → Add Server  
3. Connect by double-clicking a server  

## 6. Installation Instructions

Scarpa Connection Manager is officially hosted on an Ubuntu Personal Package Archive (PPA) for easy installation and automatic updates.
### 🚀 Install via PPA (Recommended)
#### Add the repository
sudo add-apt-repository ppa:larre-b-larsson/scarpa-connection-manager

#### Update and install
sudo apt update
sudo apt install scarpa-connection-manager

### 🚀 Install via Snap Store 
sudo snap install connection-manager-scarpa


## 7. Troubleshooting & Dependencies
- **Incorrect master passphrase** → unrecoverable, delete `~/.local/share/scarpa_connection_manager/` to reset  
- **Dependencies required**:  
  - `python3-gi`  
  - `gir1.2-gtk-3.0`  
  - `gir1.2-vte-2.91`  
  - `python3-paramiko`
  - `expect`  
  - `gnupg`  


