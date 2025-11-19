# SNAP Connection Manager - User & Technical Guide

## 1. Introduction

Welcome to the **SNAP Connection Manager**, a powerful and secure GTK3-based desktop application for managing and launching SSH and SFTP connections. Designed with security and usability in mind, this tool allows you to organize numerous server configurations into folders, automate complex login sequences, and tunnel traffic with port forwarding.

The cornerstone of this application is its robust, GnuPG-based encryption system, which ensures that all your sensitive connection details (passwords, key file paths, etc.) are never stored unencrypted on your disk.

## 2. Core Features

### 2.1 Server & Folder Management

* **Hierarchical Organization**: Organize your servers into user-defined folders for clarity. Servers not assigned to a specific folder reside in the default `Session` root.
* **Full CRUD Operations**: Easily **Add**, **Edit**, and **Delete** server configurations and folders through intuitive menus and right-click context menus.
* **Drag-and-Drop**: Reorder servers within a folder or move servers between folders simply by dragging and dropping them in the main list. The application intelligently maintains the visual order.
* **Inline Folder Renaming**: Quickly rename a folder by double-clicking its name in the tree view and pressing `Enter` to confirm.
* **Copy & Paste Servers**: Duplicate an existing server configuration with a simple copy/paste action, which intelligently renames the copy to avoid conflicts.
* **Natural Sorting**: All servers and folders are sorted using a natural alphanumeric algorithm (e.g., `server10` appears after `server9`), making lists easy to navigate.

### 2.2 Connection & Automation

* **Dual Protocol Support**: Launch connections using either **SSH** (for interactive shell access) or **SFTP** (for file transfers) for any configured server.
* **Embedded Terminal**: Connections are launched in a new, dedicated terminal window powered by the VTE (Virtual Terminal Emulator) widget. This provides a native, feature-rich terminal experience separate from the main application.
* **Flexible Authentication**:
    * **Password-based**: The application automatically handles password prompts using the `expect` utility.
    * **Key File-based**: Specify the path to a private key file, which will be passed to the `ssh` or `sftp` command using the `-i` flag.
* **Automated Login Sequences**: For each server, you can define a series of "Expect/Send" steps. This is perfect for automating multi-step logins, entering `sudo` passwords, running initial commands, or navigating to specific directories upon connection.
* **Advanced Port Forwarding**: Configure port forwarding rules for each server directly within the UI:
    * **Local Forwarding (`-L`)**: Access a service on a remote network as if it were on your local machine.
    * **Remote Forwarding (`-R`)**: Expose a service on your local machine to a remote server.
    * **Dynamic Forwarding (`-D`)**: Create a SOCKS proxy for dynamic, on-the-fly tunneling of your network traffic through the remote server.

### 2.3 Data Management & Logging

* **Encrypted Import/Export**: Export all your servers and folder structures into a single file. You can choose between a standard plaintext `JSON` file or a securely encrypted `GPG` file, which can only be imported by another instance of the application using the same master passphrase.
* **GUI Log Pane**: A log view at the bottom of the main window provides real-time feedback on application actions, connection attempts, and errors.
* **Per-Server Session Logging**: For debugging or auditing purposes, you can enable logging for individual servers. The entire terminal output of a session will be saved to a specified file on your local disk.

## 3. The "Super Safe" Encryption System

Your security is paramount. The application's design ensures that your sensitive server credentials are never left vulnerable on your hard drive.

### 3.1 How It Works

1.  **Master Passphrase Creation**: On the very first launch, you are required to set a **Master Passphrase**. This is the single most important key to your data. *If you lose it, your data cannot be recovered.*

2.  **State-of-the-Art Hashing**: Your Master Passphrase is never stored directly. Instead, it is converted into a secure hash using the **PBKDF2-HMAC-SHA256** algorithm.
    * A unique, cryptographically secure **salt** (16 bytes) is generated to protect against rainbow table attacks.
    * The hashing function is performed **600,000 times** (`iterations`). This high number makes brute-force attacks extremely slow and computationally expensive.

3.  **Symmetric GPG Encryption**: Your actual server data (including hosts, usernames, passwords, key file paths, and auto-sequences) is saved in a file named `ssh_servers.json.gpg`. This file is symmetrically encrypted using the industry-standard **AES256** cipher via GnuPG (GPG). The key used for this encryption is your Master Passphrase.

4.  **On-Demand Decryption**: Each time you start the application, you must enter your Master Passphrase. This is used to decrypt `ssh_servers.json.gpg` in memory for the current session. When you close the application, the data only exists in its encrypted form on the disk.

### 3.2 Data Storage Location

The application respects the XDG Base Directory Specification and stores its data in a hidden directory:

* **Path**: `~/.local/share/snap_connection_manager/`
* **Files**:
    * `snap_cm_settings.json`: This file stores non-sensitive settings, your custom folder list, and the **hash and salt** of your master passphrase. The hash is computationally infeasible to reverse, protecting your actual passphrase.
    * `ssh_servers.json.gpg`: This is the **fully encrypted** file containing all your sensitive server configurations.

### 3.3 Changing Your Passphrase

You can change your master passphrase at any time via the `File -> Change Passphrase...` menu. The process is secure:
1. You are prompted for your *current* passphrase to authorize the change.
2. You are asked to provide and confirm a *new* passphrase.
3. The application then re-encrypts your server data file (`ssh_servers.json.gpg`) with the new passphrase in an atomic operation to prevent data loss.
4. Finally, it generates a new salt and hash for the new passphrase and updates the settings file.

## 4. Getting Started

1.  **First Launch**: The application will prompt you to **Set Master Passphrase**. Enter a strong, memorable passphrase and confirm it. This initializes your secure storage.
2.  **Subsequent Launches**: You will be prompted to enter your master passphrase to unlock and load your server list. For security, you have a limited number of attempts.
3.  **Add Servers and Folders**: Use the `Servers` and `Folders` menus or the right-click context menu to begin building your connection list.
4.  **Connect**: Select a server and double-click it, or use the `Connect` menu or right-click menu to launch an SSH or SFTP session.

## 5. Troubleshooting & Dependencies

* **"Incorrect master passphrase."**: Your passphrase is case-sensitive. If you have forgotten it, the data is unrecoverable. You would need to delete the files in the data directory (see section 3.2) to start over, which will erase all saved servers.
* **"GPG decryption failed."**: This indicates that the `ssh_servers.json.gpg` file may be corrupt or was encrypted with a different key than what your current settings expect. This can happen if a passphrase change was interrupted. Starting fresh by deleting the data files is the recommended recovery method.
* **"expect not found."**: The application relies on the `expect` command-line utility to automate password entry and login sequences. Please install it using your system's package manager (e.g., `sudo apt-get install expect` on Debian/Ubuntu).
* **"VTE library not found."**: The embedded terminal requires the VTE GObject introspection library. Please install it using your system's package manager (e.g., `sudo apt-get install gir1.2-vte-2.91` on Debian/Ubuntu).
* **GnuPG is Required**: The core encryption functionality depends on having `gpg` installed and available in your system's `PATH`.
