 SNAP Connection Manager - User Guide

The SNAP Connection Manager is a powerful yet intuitive GTK-based application designed to help you securely manage and launch your SSH and SFTP connections. It allows for organized storage of server configurations, automated login sequences, and robust data encryption, ensuring your sensitive connection details are protected.

## 1. Core Features Overview

### 1.1 Server Management

* **Add Server:** Easily add new server configurations including Name, Host, Port, Username, and authentication details.

* **Edit Server:** Modify existing server configurations.

* **Delete Server:** Remove server entries from your list.

### 1.2 Folder Organization

* **Folders vs. Session:** Servers can be organized into user-defined folders or kept directly under the default "Session" root.

* **Create/Rename/Delete Folders:** Manage your organizational structure by adding new folders, renaming existing ones, or deleting them. Deleting a folder will move its contained servers back to the "Session" root.

* **Natural Sorting:** Both folders and servers are displayed in a natural alphanumeric order, making lists easy to scan.

* **Drag-and-Drop:** Visually reorder servers within a folder or the "Session" root. You can also drag and drop servers onto folders to quickly reassign them to a new organizational group.

### 1.3 Connection Launching

* **SSH & SFTP:** Launch secure shell (SSH) or secure file transfer protocol (SFTP) sessions directly from the application.

* **Authentication Methods:** Supports both password-based and key file-based authentication. If using password, the application will handle the `expect` prompts. If using a key file, it will pass the `-i` option to `ssh` or `sftp`.

* **Automated Login Sequences:** Configure custom "Expect/Send" sequences to automate repetitive login tasks (e.g., entering sudo passwords, navigating to a specific directory).

* **Inline Folder Rename:** Double-click a folder name in the main window to quickly edit its name in place. Press Enter to commit the change.

### 1.4 GUI & File-Level Logging

* **GUI Log Pane:** A dedicated "Log" pane within the application window displays real-time events and messages, providing immediate feedback on application actions and connection attempts.

* **Per-Server Session Logging:** Each server configuration can have logging enabled, directing the full session output (including prompts and responses) to a specified file. This is useful for debugging or auditing.

## 2. Super Safe Encryption Feature

This application now incorporates a robust encryption layer to protect your sensitive server data (hosts, usernames, passwords, key file paths, and auto-sequences) when it's stored on your disk.

### 2.1 How it Works

1. **Master Passphrase:** On the **very first launch** of the application, you will be prompted to "Set Master Passphrase". This is a crucial step for securing your data. Choose a strong, unique passphrase that you can remember, as it cannot be recovered if lost.

2. **Passphrase Hashing:** Your master passphrase is not stored directly. Instead, it is used to generate a highly secure hash using **PBKDF2-HMAC-SHA256** with a high number of iterations (600,000) and a randomly generated **salt** (16 bytes). This process makes it extremely difficult for an attacker to reverse-engineer your passphrase even if they gain access to your settings file.

3. **Encrypted Server Data:** Your actual server configurations are stored in an encrypted file named `ssh_servers.json.gpg`. This file is symmetrically encrypted using **GnuPG (GPG)** with **AES256** cipher algorithm. The key for this encryption is derived from your master passphrase.

4. **Decryption on Launch:** Every time you open the application (after the initial setup), you will be prompted to enter your master passphrase. This is necessary because the `ssh_servers.json.gpg` file needs to be decrypted to load your server list into the application's memory. Without the correct passphrase, the data remains encrypted and inaccessible. This ensures that even if someone gains access to your system or the data files, they cannot read your sensitive connection details without your master passphrase.

### 2.2 Data Storage Location

All application-specific data, including your encrypted server list and settings, are stored in a hidden directory within your user's local data directory:

* **Linux (XDG Base Directory compliant):** `~/.local/share/snap_connection_manager/`

* **Specifically:**

  * `snap_cm_settings.json`: Contains your master passphrase hash and salt, along with your custom folder names. This file is not directly encrypted itself, as the hash/salt are designed to protect against passphrase recovery, and the folders list is not sensitive data.

  * `ssh_servers.json.gpg`: This is your securely encrypted server data file.

### 2.3 Security and Convenience Trade-off

The design prioritizes security:

* **Enhanced Security:** By requiring your master passphrase on each launch, your server credentials are never left unencrypted on disk while the application is closed. This provides a strong defense against unauthorized access to your server data.

* **No Persistent Unencrypted Passphrase:** The application does not store your passphrase in plain text anywhere. It's only held in memory temporarily after you successfully enter it to decrypt the data for the current session.

While this means a small inconvenience of entering the passphrase each time, it is a standard and recommended practice for managing sensitive credentials.

## 3. Getting Started

1. **First Launch:** The application will prompt you to "Set Master Passphrase". Enter your chosen passphrase and confirm it. This will create your secure data files.

2. **Subsequent Launches:** Enter your master passphrase when prompted to unlock and load your server data.

3. **Add Your First Server:** Use the "Servers" menu or right-click in the main view to "Add Server". Fill in the details.

4. **Connect:** Select a server and use "Connect" -> "SSH" or "SFTP", or simply double-click the server entry.

## 4. Troubleshooting & Help

* **"Incorrect master passphrase."**: Double-check your passphrase. Remember it's case-sensitive. You have a limited number of attempts before the application quits for security.

* **"GPG decryption failed." / "Bad session key."**: This can happen if your `ssh_servers.json.gpg` file is corrupted or was encrypted with a different passphrase than the one currently stored in your `snap_cm_settings.json`. If this is the first time you've encountered this after setting a *new* passphrase, the application attempts to clean up old files automatically. If it persists, you may need to manually delete `snap_cm_settings.json` and `ssh_servers.json.gpg` from the `APP_DATA_DIR` (see section 2.2) to start fresh. **WARNING: Deleting these files will permanently remove any existing server configurations.**

* **"expect not found."**: Ensure you have the `expect` package installed on your system.

* **General Issues:** Check the "Log:" pane for any detailed error messages.

For further assistance, bug reports, or feature requests, please refer to the application's source or contact the developer.

