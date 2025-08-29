#!/usr/bin/env python3

# ── Chunk 1: Imports, Globals & Helpers ─────────────────────────────────────────────
import os
import json
import shutil
import subprocess
import tempfile
import re
import gi
import termios # Not directly used in the provided code snippet, but keeping for completeness
import gnupg   # Not directly used in the provided code snippet, but keeping for completeness
import hashlib
import secrets
import sys # Added for fallback console logging

gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gio, GLib, GdkPixbuf
from gi.repository import Gdk
from gi.repository import Pango # Moved here as it's used in init_ui_elements

# ── User Guide Text ────────────────────────────────────────────────────────────────
USER_GUIDE = """
# SNAP Connection Manager - User Guide

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
"""

# --- Globals & Paths ---
def natural_key(s):
    """Provides a key for natural sorting (e.g., sorts 'file10' after 'file9')."""
    parts = re.split(r'(\d+)', s)
    return [int(p) if p.isdigit() else p.lower() for p in parts]

def get_user_data_dir():
    """
    Determines the appropriate user-specific data directory based on XDG Base Directory Specification.
    """
    xdg_data_home = os.environ.get('XDG_DATA_HOME')
    if xdg_data_home:
        return os.path.join(xdg_data_home, 'snap_connection_manager')
    return os.path.join(os.path.expanduser('~'), '.local', 'share', 'snap_connection_manager')

APP_DATA_DIR = get_user_data_dir()
# Directory creation will now happen in do_startup, after the application object is created

SERVER_FILE   = os.path.join(APP_DATA_DIR, "ssh_servers.json")
SETTINGS_FILE = os.path.join(APP_DATA_DIR, "snap_cm_settings.json")
APP_ID        = "com.example.SnapCM"
APP_TITLE     = "Snap Connection Manager"
ROOT_FOLDER   = "Session"

# --- Passphrase Hashing Globals ---
PBKDF2_ITERATIONS = 600000  # Number of iterations for PBKDF2. Higher = more secure but slower.
SALT_SIZE = 16              # Salt size in bytes (16 bytes = 128 bits)
# --- End Passphrase Hashing Globals ---

# --- Passphrase Hashing Helper Functions ---
def generate_salt(size=SALT_SIZE):
    """Generates a random salt as bytes."""
    return secrets.token_bytes(size)

def hash_passphrase(passphrase, salt_bytes, iterations=PBKDF2_ITERATIONS):
    """
    Hashes the passphrase using PBKDF2-HMAC-SHA256.
    Expects salt_bytes as bytes. Returns the hash as a hex string.
    """
    dk = hashlib.pbkdf2_hmac(
        'sha256',
        passphrase.encode('utf-8'), # Passphrase converted to bytes
        salt_bytes,                 # Salt as bytes
        iterations
    )
    return dk.hex()
# --- End Passphrase Hashing Helper Functions ---

# --- File Operations (load/save settings and servers) ---
def load_settings():
    """Loads application settings from JSON."""
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r") as f:
                settings_data = json.load(f)
            return settings_data
        return {}
    except Exception as ex:
        # For initial load, if settings file is corrupted or unreadable, we return empty settings
        print(f"Warning: Could not load settings from {SETTINGS_FILE}: {ex}", file=sys.stderr)
        return {}


def save_settings(settings):
    """Saves application settings to JSON."""
    try:
        # Create a copy to handle salt conversion for saving
        settings_to_save = settings.copy()
        if "master_passphrase_salt" in settings_to_save and isinstance(settings_to_save["master_passphrase_salt"], bytes):
            settings_to_save["master_passphrase_salt"] = settings_to_save["master_passphrase_salt"].hex() # Convert salt to hex string for JSON
        
        with open(SETTINGS_FILE, "w") as f:
            json.dump(settings_to_save, f, indent=4)
    except Exception as ex:
        # Display a GTK error dialog here, as save_settings might be called from various places
        # For now, print to stderr as GUI might not be ready
        print(f"Error: Could not save settings to {SETTINGS_FILE}: {ex}", file=sys.stderr)


def load_servers(passphrase): # NOW REQUIRES PASSPHRASE
    """
    Decrypts ssh_servers.json.gpg and loads the server list from it.
    """
    enc_path = SERVER_FILE + ".gpg"
    if not os.path.exists(enc_path):
        return []

    tf = None # Initialize tf to None
    try:
        # Create a temp file to decrypt into
        tf = tempfile.NamedTemporaryFile("w", delete=False)
        tf.close()
        
        # Run GPG to decrypt the file
        result = subprocess.run(
            [
                "gpg", "--batch", "--yes",
                "--passphrase", passphrase,
                "--output", tf.name,
                "--decrypt", enc_path
            ],
            check=False,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            # Handle decryption failure specifically
            if os.path.exists(tf.name): # Clean up temp file on GPG error
                os.remove(tf.name)
            
            # Use a more specific error message for passphrase issues if stderr indicates it
            err_msg = result.stderr.strip()
            if "bad passphrase" in err_msg.lower() or "invalid passphrase" in err_msg.lower():
                raise ValueError("Incorrect master passphrase.")
            else:
                raise RuntimeError(f"GPG decryption failed with exit code {result.returncode}.\n\n"
                                   f"STDOUT:\n{result.stdout}\n\n"
                                   f"STDERR:\n{err_msg}") # Use err_msg as it's already stripped

        # Load the data from the decrypted temp file
        with open(tf.name, "r") as f:
            data = json.load(f)
            # Ensure folder and auto_sequence defaults are set, as in your original load_servers
            for s in data:
                s.setdefault("folder", ROOT_FOLDER)
                s.setdefault("auto_sequence", [])
        
        # Clean up the temp file
        os.remove(tf.name)
        
        return data

    except Exception as ex:
        # Clean up the temp file if an error occurred before it was removed
        if tf and os.path.exists(tf.name):
            os.remove(tf.name)

        # Re-raise the exception for SnapConnectionManager to handle with its _error method
        raise ex

def save_servers(servers, passphrase): # NOW REQUIRES PASSPHRASE
    """
    Serialize servers to a temp JSON, then encrypt it symmetrically with GPG.
    """
    tf = None # Initialize tf to None
    try:
        # 1) write JSON to a temp file
        tf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".json")
        json.dump(servers, tf, indent=4)
        tf.flush()
        tf.close()

        # 2) encrypt with GPG → ssh_servers.json.gpg
        enc_path = SERVER_FILE + ".gpg"
        
        result = subprocess.run(
            [
                "gpg", "--batch", "--yes",
                "--symmetric", "--cipher-algo", "AES256",
                "--passphrase", passphrase,
                "-o", enc_path,
                tf.name
            ],
            check=False,
            capture_output=True,
            text=True
        )

        # 3) clean up temp and any old plaintext
        os.remove(tf.name)
        if os.path.exists(SERVER_FILE): # Remove old plaintext file if it exists
            os.remove(SERVER_FILE)

        if result.returncode != 0:
            raise RuntimeError(f"GPG encryption failed with exit code {result.returncode}.\n\n"
                               f"STDOUT:\n{result.stdout}\n\n"
                               f"STDERR:\n{result.stderr.strip()}") # Strip whitespace from stderr

    except Exception as ex:
        if tf and os.path.exists(tf.name): # Clean up temp file on GPG error
            os.remove(tf.name)
        # Re-raise the exception for SnapConnectionManager to handle with its _error method
        raise ex

# --- Helper functions for dialogs ---
def browse_key(parent, entry):
    dlg = Gtk.FileChooserDialog(
        title="Select private key", parent=parent,
        action=Gtk.FileChooserAction.OPEN
    )
    dlg.add_buttons(
        Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
        Gtk.STOCK_OPEN,   Gtk.ResponseType.OK
    )
    if dlg.run() == Gtk.ResponseType.OK:
        entry.set_text(dlg.get_filename())
    dlg.destroy()


def browse_log(parent, entry):
    dlg = Gtk.FileChooserDialog(
        title="Select log file", parent=parent,
        action=Gtk.FileChooserAction.SAVE
    )
    dlg.add_buttons(
        Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
        Gtk.STOCK_SAVE,   Gtk.ResponseType.OK
    )
    if dlg.run() == Gtk.ResponseType.OK:
        entry.set_text(dlg.get_filename())
    dlg.destroy()


def center(window):
    """Centers the window. Only call if window is already shown."""
    # Ensure window is not None before calling show_all or set_position
    if window:
        window.show_all()
        window.set_position(Gtk.WindowPosition.CENTER)

# ── NEW Chunk: Passphrase Input Dialog Class ──────────────────────────────────────
# THIS IS THE CLASS THAT NEEDS TO BE CORRECT IN YOUR FILE
class PassphraseInputDialog(Gtk.Dialog):
    def __init__(self, parent, title, prompt_text, confirm_text=None, show_retry_message=False):
        super().__init__(
            title=title,
            transient_for=parent, # parent can now be None for early dialogs
            flags=Gtk.DialogFlags.MODAL
        )
        self.add_buttons(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
            Gtk.STOCK_OK, Gtk.ResponseType.OK
        )
        self.set_default_size(350, 150)
        self.set_resizable(False)

        box = self.get_content_area()
        
        # Main prompt label
        lbl_prompt = Gtk.Label(label=prompt_text)
        lbl_prompt.set_margin_top(10)
        box.pack_start(lbl_prompt, False, False, 0)

        # Passphrase input entry
        self.entry_pass = Gtk.Entry(visibility=False, primary_icon_name="security-high")
        self.entry_pass.set_activates_default(True)
        box.pack_start(self.entry_pass, False, False, 5)

        # Confirmation field (if needed, e.g., for setting a new passphrase)
        self.entry_confirm = None
        if confirm_text:
            lbl_confirm = Gtk.Label(label=confirm_text)
            box.pack_start(lbl_confirm, False, False, 0)
            self.entry_confirm = Gtk.Entry(visibility=False, primary_icon_name="security-high")
            self.entry_confirm.set_activates_default(True)
            box.pack_start(self.entry_confirm, False, False, 5)

        # Retry error message (hidden by default)
        self.lbl_retry_msg = Gtk.Label(label="Incorrect passphrase. Please try again.")
        self.lbl_retry_msg.set_markup("<span foreground='red'>Incorrect passphrase. Please try again.</span>")
        self.lbl_retry_msg.set_no_show_all(True) # Don't show by default
        if show_retry_message:
            self.lbl_retry_msg.show() # Show it initially if it's a retry scenario
        box.pack_start(self.lbl_retry_msg, False, False, 5)

        self.show_all() # Show dialog elements before run()

    # <<< IMPORTANT: THIS METHOD MUST BE PRESENT >>>
    def get_passphrases(self):
        """Returns the passphrase and confirmation passphrase (if applicable)."""
        passphrase = self.entry_pass.get_text()
        confirm_passphrase = self.entry_confirm.get_text() if self.entry_confirm else None
        return passphrase, confirm_passphrase

    def show_retry_error(self):
        """Shows the retry error message."""
        self.lbl_retry_msg.show()
# ── End NEW Chunk: Passphrase Input Dialog Class ──────────────────────────────────

# ── Chunk 2: Application & Main Window Setup ────────────────────────────────────────
class SnapConnectionManager(Gtk.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID)
        # Initialize log_buffer early so log() method can always write to it
        self.log_buffer = Gtk.TextBuffer() 
        self.log_text_view = None # Will be set in init_ui_elements

        # Settings are loaded immediately to check for passphrase status
        # Servers will be loaded AFTER passphrase verification in do_startup
        self.settings     = load_settings() 
        self.servers      = [] # Initialize empty, actual load happens later
        self.user_folders = self.settings.get("folders", [])
        self.subfolders   = []
        self.master_passphrases = None # Will store the user's entered passphrase for the session
        # Initialize logging parameters
        self.current_logging_enabled = False
        self.current_log_path = ""
        self.win = None # Initialize main window to None

        # load folder/server icons
        base = os.path.dirname(__file__)
        self.folder_icon = GdkPixbuf.Pixbuf.new_from_file(
            os.path.join(base, "folder.png")
        )
        self.server_icon = GdkPixbuf.Pixbuf.new_from_file(
            os.path.join(base, "server.png")
        )

        # register actions
        for name, handler in (
            ("import",   self.on_import),
            ("export",   self.on_export),
            ("quit",     self.on_quit),
            ("add_srv",  self.on_add_server),
            ("edit_srv", self.on_edit_server),
            ("del_srv",  self.on_delete_server),
            ("new_fld",  self.on_new_folder),
            ("ren_fld",  self.on_rename_folder),
            ("del_fld",  self.on_delete_folder),
            ("ssh",      self.on_ssh),
            ("sftp",     self.on_sftp),
            ("about",    self.on_about),
            ("user_guide", self.on_user_guide),
        ):
            act = Gio.SimpleAction.new(name, None)
            act.connect("activate", handler)
            self.add_action(act)

    def do_startup(self):
        Gtk.Application.do_startup(self)
        
        # --- NEW PASSPHRASE MANAGEMENT AT STARTUP ---
        # First, ensure that the application's data directory exists
        os.makedirs(APP_DATA_DIR, exist_ok=True)

        # Pass None as parent for early dialogs since self.win doesn't exist yet
        # These dialogs will appear as top-level windows.
        
        # Check if master passphrase is set in settings
        if not self.settings.get("master_passphrase_hash") or \
           not self.settings.get("master_passphrase_salt"):
            # First run or passphrase not set: prompt user to set it
            self.log("First launch detected or master passphrase not set. Please set a new passphrase.")
            self.set_master_passphrase()
        else:
            # Passphrase already set: prompt user to enter it
            self.log("Master passphrase detected. Please enter it to unlock server data.")
            self.verify_master_passphrase()

        # If we failed to get/verify passphrase, self.master_passphrase will be None.
        # In that case, we should not proceed with UI activation or server loading.
        if not self.master_passphrase:
            self._error("Application startup failed: Master passphrase not set or verified.")
            self.quit() # Exit application if passphrase cannot be set/verified
            return

        # Now that we have the master_passphrase, attempt to load the servers
        try:
            self.servers = load_servers(self.master_passphrase)
            self.log("Server data loaded successfully.")
        except ValueError as e: # Catch specific 'Incorrect passphrase' error
            self._error(f"Failed to load server data: {e}\nPlease restart the application and try again.")
            self.servers = [] # Start with empty data if loading fails due to incorrect passphrase
            self.quit() # Quit if passphrase is wrong
            return
        except Exception as e:
            self._error(f"Failed to load server data: {e}\nApplication will start with empty data.")
            self.servers = [] # Start with empty data if loading fails for other reasons

    def do_activate(self):
        # main window + header bar
        if not hasattr(self, 'win') or not self.win: # Prevent recreating window on subsequent activations
            self.win = Gtk.ApplicationWindow(application=self)
            self.win.set_default_size(700, 500)
            self.win.set_title(APP_TITLE)
            hb = Gtk.HeaderBar(show_close_button=True, title=APP_TITLE)
            self.win.set_titlebar(hb)

            # layout: menubar + paned
            vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            self.win.add(vbox)

            self.init_ui_elements(vbox) # Call helper method for UI setup

        # Only show window if master_passphrase was successfully set/verified
        if self.master_passphrase:
            self.win.show_all()
            self.populate_tree() # Ensure tree is populated after servers are loaded
            self.tree.expand_row(Gtk.TreePath.new_from_string("0"), False)
        else:
            # If passphrase failed, quit() was called in do_startup, but destroy window if still exists
            if hasattr(self, 'win') and self.win:
                self.win.destroy()

    def init_ui_elements(self, vbox):
        # This method creates all GUI elements AFTER the main window (self.win) is available.

        # ── Menu Bar ─────────────────────────────────────────────
        menu_bar = Gtk.MenuBar()
        vbox.pack_start(menu_bar, False, False, 0)
        menus = {
            "File":    [
                ("Import…", self.on_import),
                ("Export…", self.on_export),
                ("Quit",    self.on_quit),
            ],
            "Servers": [
                ("Add",    self.on_add_server),
                ("Edit",   self.on_edit_server),
                ("Delete", self.on_delete_server),
            ],
            "Folders": [
                ("New",    self.on_new_folder),
                ("Rename", self.on_rename_folder),
                ("Delete", self.on_delete_folder),
            ],
            "Connect": [
                ("SSH",  self.on_ssh),
                ("SFTP", self.on_sftp),
            ],
            "Help": [
                ("About", self.on_about),
                ("User Guide", self.on_user_guide),
            ],
        }
        for top, items in menus.items():
            root = Gtk.MenuItem(label=top)
            submenu = Gtk.Menu()
            root.set_submenu(submenu)
            for lbl, fn in items:
                mi = Gtk.MenuItem(label=lbl)
                mi.connect("activate", lambda w, f=fn: f(None, None))
                submenu.append(mi)
            menu_bar.append(root)

        # ── Paned: TreeView + Log ─────────────────────────────────
        paned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        vbox.pack_start(paned, True, True, 0)

        # TreeStore: icon, text, metadata
        self.store = Gtk.TreeStore(GdkPixbuf.Pixbuf, str, object)
        self.reload_folders() # This should be called *after* servers are loaded if it relies on them

        # TreeView with Pixbuf + Text
        self.tree = Gtk.TreeView(model=self.store)
        self.tree.set_headers_visible(False)

        # ── enable drag-and-drop within this TreeView ───────────────
        from gi.repository import Gdk
        dnd_target = Gtk.TargetEntry.new("dnd-row", Gtk.TargetFlags.SAME_WIDGET, 0)
        self.tree.enable_model_drag_source(
            Gdk.ModifierType.BUTTON1_MASK,
            [dnd_target],
            Gdk.DragAction.MOVE,
        )
        self.tree.enable_model_drag_dest(
            [dnd_target],
            Gdk.DragAction.MOVE,
        )
        # supply the drag payload (selected row-paths)
        self.tree.connect("drag-data-get",       self.on_drag_data_get)
        # handle the drop (correct signal name)
        self.tree.connect("drag-data-received",  self.on_tree_row_dropped)

        # Cell renderers & column with inline‐rename for folders
        pix_renderer = Gtk.CellRendererPixbuf()
        txt_renderer = Gtk.CellRendererText()

        txt_renderer.set_property("editable", False)
        txt_renderer.connect("edited", self._on_folder_cell_edited)

        col = Gtk.TreeViewColumn()
        col.pack_start(pix_renderer, False)
        col.pack_start(txt_renderer, True)

        col.add_attribute(pix_renderer, "pixbuf", 0)
        col.add_attribute(txt_renderer, "text",   1)

        # Only folder rows (not Session root) become editable
        col.set_cell_data_func(txt_renderer, self._folder_cell_data_func)

        self.tree.append_column(col)
        self.tree.connect("row-activated", self.on_tree_activate)
        self.tree.add_events(Gdk.EventMask.BUTTON_PRESS_MASK)
        self.tree.connect("button-press-event", self.on_tree_button_press)

        # pack TreeView
        tree_sw = Gtk.ScrolledWindow()
        tree_sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        tree_sw.add(self.tree)
        paned.pack1(tree_sw, resize=True, shrink=True)

        # ── Log pane (6 lines high) ───────────────────────────────
        # self.log_buffer is already initialized in __init__
        self.log_text_view = Gtk.TextView(buffer=self.log_buffer, editable=False) # Assign to self.log_text_view
        self.log_text_view.set_wrap_mode(Gtk.WrapMode.NONE)
        ctx    = self.log_text_view.get_pango_context() # Use self.log_text_view
        layout = Pango.Layout.new(ctx)
        layout.set_text("X", -1)
        _, line_h = layout.get_pixel_size()

        log_sw = Gtk.ScrolledWindow()
        log_sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        log_sw.set_size_request(-1, line_h * 6)
        log_sw.set_vexpand(False)
        log_sw.add(self.log_text_view) # Use self.log_text_view

        log_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, margin=6)
        lbl = Gtk.Label(label="Log:")
        lbl.set_xalign(0)
        log_box.pack_start(lbl, False, False, 0)
        log_box.pack_start(log_sw, False, False, 0)
        paned.pack2(log_box, resize=False, shrink=False)


    # --- New Passphrase Management Methods (add these inside SnapConnectionManager) ---
    def set_master_passphrase(self):
        """Prompts user to set a new master passphrase for the first time."""
        while True:
            # Pass None as parent as self.win might not exist yet during initial startup
            dlg = PassphraseInputDialog(
                None, # Parent is None for initial dialogs before main window is created
                "Set Master Passphrase",
                "Please set a master passphrase for your server data:",
                confirm_text="Confirm passphrase:"
            )
            response = dlg.run()
            
            if response == Gtk.ResponseType.OK:
                passphrase, confirm_passphrase = dlg.get_passphrases()
                
                if not passphrase:
                    self._error("Passphrase cannot be empty.")
                    dlg.show_retry_error() # Show error message on dialog
                    continue # Loop back to prompt again
                
                if passphrase != confirm_passphrase:
                    self._error("Passphrases do not match. Please try again.")
                    dlg.show_retry_error()
                    continue # Loop back
                
                # Generate salt and hash the passphrase
                salt = generate_salt()
                hashed_passphrase = hash_passphrase(passphrase, salt)
                
                # Store the hash and salt in settings
                self.settings["master_passphrase_hash"] = hashed_passphrase
                self.settings["master_passphrase_salt"] = salt.hex() # Store salt as hex string
                save_settings(self.settings)
                
                self.master_passphrase = passphrase # Store passphrase for current session
                dlg.destroy()
                self._info("Master passphrase set successfully!")

                # --- FIX: Clear old encrypted server file if it exists on FIRST TIME SETUP ---
                encrypted_server_file = SERVER_FILE + ".gpg"
                if os.path.exists(encrypted_server_file):
                    try:
                        os.remove(encrypted_server_file)
                        self.log(f"Removed old encrypted server data file: {encrypted_server_file}")
                    except OSError as e:
                        self._error(f"Failed to remove old encrypted server data: {e}")
                # --- END FIX ---
                return
            else: # User cancelled
                dlg.destroy()
                self._error("Master passphrase not set. Application will quit.")
                self.master_passphrase = None # Ensure it's None if user cancels
                return


    def verify_master_passphrase(self):
        """Prompts user to verify their master passphrase."""
        max_retries = 3
        for attempt in range(max_retries):
            # Pass None as parent as self.win might not exist yet during initial startup
            dlg = PassphraseInputDialog(
                None, # Parent is None for initial dialogs before main window is created
                "Enter Master Passphrase",
                "Please enter your master passphrase to unlock server data:",
                show_retry_message=(attempt > 0) # Show retry message after first failed attempt
            )
            response = dlg.run()
            
            if response == Gtk.ResponseType.OK:
                entered_passphrase, _ = dlg.get_passphrases()
                
                if not entered_passphrase:
                    self._error("Passphrase cannot be empty.")
                    dlg.show_retry_error()
                    continue

                stored_hash = self.settings.get("master_passphrase_hash")
                stored_salt_hex = self.settings.get("master_passphrase_salt")
                
                if not stored_hash or not stored_salt_hex:
                    self._error("Error: Passphrase hash or salt missing from settings.")
                    self.master_passphrase = None # Force quit
                    dlg.destroy()
                    return

                # This conversion should always happen here, as stored_salt_hex is *expected* to be a string.
                # The fix ensures load_settings does not prematurely convert it.
                try:
                    stored_salt = bytes.fromhex(stored_salt_hex) # Convert salt hex string back to bytes
                except ValueError:
                    self._error("Error: Invalid salt format in settings. Please delete settings file and restart.")
                    self.master_passphrase = None # Force quit
                    dlg.destroy()
                    return

                if hash_passphrase(entered_passphrase, stored_salt) == stored_hash:
                    self.master_passphrase = entered_passphrase # Store for current session
                    dlg.destroy()
                    self._info("Passphrase verified. Welcome back!")
                    return
                else:
                    self._error("Incorrect passphrase. Please try again.")
                    dlg.show_retry_error()
                    # Loop will continue to next attempt
            else: # User cancelled
                dlg.destroy()
                self._error("Passphrase verification cancelled. Application will quit.")
                self.master_passphrase = None # Ensure it's None if user cancels
                return
        
        # If max_retries reached
        self._error("Maximum passphrase attempts reached. Application will quit.")
        self.master_passphrase = None
    # --- End New Passphrase Management Methods ---


    # ── Simple Input Dialog ────────────────────────────────────────────────
    def _simple_input(self, title, prompt=None, default_text=""):
        # Make parent transient_for self.win only if self.win exists
        parent_window = self.win if hasattr(self, 'win') and self.win else None
        dlg = Gtk.Dialog(
            title=title,
            transient_for=parent_window,
            modal=True,
        )
        dlg.add_buttons(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
            Gtk.STOCK_OK,     Gtk.ResponseType.OK,
        )
        dlg.set_default_size(300, 100)
        box = dlg.get_content_area()
        if prompt:
            lbl = Gtk.Label(label=prompt)
            lbl.set_margin_bottom(6)
            box.pack_start(lbl, False, False, 0)
        entry = Gtk.Entry()
        entry.set_text(default_text)
        entry.set_activates_default(True)
        box.pack_start(entry, False, False, 0)
        dlg.set_default_response(Gtk.ResponseType.OK)
        dlg.show_all()
        resp = dlg.run()
        text = entry.get_text().strip() if resp == Gtk.ResponseType.OK else ""
        dlg.destroy()
        return text

    # ── Build drag payload: serialize selected row-paths ────────────────────
    def on_drag_data_get(self, treeview, context, selection, info, time):
        model, paths = treeview.get_selection().get_selected_rows()
        data = "\n".join(path.to_string() for path in paths)
        selection.set(selection.get_target(), 8, data.encode("utf-8"))

# ── Chunk 3: TreeView, Drag-and-Drop, CRUD, Connect & Logging ────────────────────

    # Quit application
    def on_quit(self, action, param):
        self.quit()

    # Rebuild the list of subfolders from servers + user_folders
    def reload_folders(self):
        folders = {s.get("folder", ROOT_FOLDER) for s in self.servers}
        folders |= set(self.user_folders)
        self.subfolders = sorted(folders - {ROOT_FOLDER})

    # Populate the TreeStore with folder and server icons
    def populate_tree(self):
        """
        Rebuild the TreeStore so that:
          - Folders (self.subfolders) are sorted alphabetically (natural sort)
          - “Default Session” (ROOT_FOLDER) is always the root node
          - Under it:
              • First each folder (sorted) and its servers (sorted by name)
              • Then the session-scoped servers (sorted by name)
          - Expansion state of the root and each folder is preserved
        Assumes:
          - self.store is a Gtk.TreeStore(icon, text, payload)
          - self.tree is the Gtk.TreeView using self.store
          - ROOT_FOLDER and natural_key() are defined globally
        """
        # 1) Capture which rows are expanded
        sorted_subs = sorted(self.subfolders, key=lambda f: natural_key(f))
        root_path = Gtk.TreePath.new_from_string("0")
        # Ensure self.tree exists before calling row_expanded
        root_open = self.tree.row_expanded(root_path) if hasattr(self, 'tree') and self.tree else False
    
        expanded_folders = set()
        if hasattr(self, 'tree') and self.tree: # Ensure tree exists before iterating
            for idx, fld in enumerate(sorted_subs):
                p = Gtk.TreePath.new_from_string(f"0:{idx}")
                if self.tree.row_expanded(p):
                    expanded_folders.add(fld)
    
        # 2) Clear & rebuild
        self.store.clear()
        root_it = self.store.append(
            None,
            [self.folder_icon,
             ROOT_FOLDER,
             ("folder", ROOT_FOLDER)]
        )
    
        # 2a) Append each folder (alphabetical) + its servers (alphabetical)
        for fld in sorted_subs:
            fld_it = self.store.append(
                root_it,
                [self.folder_icon,
                 fld,
                 ("folder", fld)]
            )
            # collect servers in this folder
            folder_servers = [
                (i, s) for i, s in enumerate(self.servers)
                if s.get("folder") == fld
            ]
            # sort by server name
            for i, s in sorted(folder_servers,
                               key=lambda x: natural_key(x[1]["name"])):
                self.store.append(
                    fld_it,
                    [self.server_icon,
                     s["name"],
                     ("server", i)]
                )
    
        # 2b) Append session-scoped servers under ROOT_FOLDER
        session_servers = [
            (i, s) for i, s in enumerate(self.servers)
            if s.get("folder", ROOT_FOLDER) == ROOT_FOLDER
        ]
        for i, s in sorted(session_servers,
                           key=lambda x: natural_key(x[1]["name"])):
            self.store.append(
                root_it,
                [self.server_icon,
                 s["name"],
                 ("server", i)]
            )
    
        # 3) Restore expanded rows
        if root_open and hasattr(self, 'tree') and self.tree: # Ensure self.tree exists before expanding
            self.tree.expand_row(root_path, False)
    
        if hasattr(self, 'tree') and self.tree: # Ensure tree exists before iterating
            for idx, fld in enumerate(sorted_subs):
                if fld in expanded_folders:
                    p = Gtk.TreePath.new_from_string(f"0:{idx}")
                    self.tree.expand_row(p, False)
    
    # Double-click on a server row → launch SSH
    def on_tree_activate(self, tree, path, column):
        model, it = tree.get_selection().get_selected()
        if not it:
            return
        node_type, _ = model.get_value(it, 2)
        if node_type == "server":
            self.on_ssh(None, None)

    # Drag-and-drop: reorder servers and assign them to folders
    def on_tree_row_dropped(self, treeview, context, x, y, selection, info, time):
        data = selection.get_data()
        moved_idxs = []
        if data:
            for line in data.decode().splitlines():
                src_path = Gtk.TreePath.new_from_string(line)
                it = self.store.get_iter(src_path)
                node, idx = self.store.get_value(it, 2)
                if node == "server":
                    moved_idxs.append(idx)

        # Determine target folder from drop position
        target_folder = ROOT_FOLDER
        dest = treeview.get_dest_row_at_pos(x, y)
        if dest:
            path_dest, _ = dest
            it_dest = self.store.get_iter(path_dest)
            dtype, val = self.store.get_value(it_dest, 2)
            if dtype == "folder":
                target_folder = val
            elif dtype == "server":
                parent = self.store.iter_parent(it_dest)
                if parent:
                    ptype, pfld = self.store.get_value(parent, 2)
                    if ptype == "folder":
                        target_folder = pfld

        # Update folder property on moved servers
        for idx in moved_idxs:
            self.servers[idx]["folder"] = target_folder

        # Rebuild servers list in order shown by the TreeView
        new_order = []
        root_it = self.store.get_iter(Gtk.TreePath.new_from_string("0"))
        def walk(it):
            while it:
                ntype, payload = self.store.get_value(it, 2)
                if ntype == "server":
                    new_order.append(self.servers[payload])
                elif ntype == "folder":
                    walk(self.store.iter_children(it))
                it = self.store.iter_next(it)
        walk(self.store.iter_children(root_it))

        self.servers = new_order
        try:
            save_servers(self.servers, self.master_passphrase) # UPDATED CALL
        except Exception as e:
            self._error(f"Failed to save servers after drag/drop: {e}")
        
        # Refresh the tree to update indices & icons
        self.reload_folders()
        self.populate_tree()
        self.tree.expand_row(Gtk.TreePath.new_from_string("0"), False)

        context.finish(True, False, time)

    # ── File Menu: Import Servers ───────────────────────────────────────
    def on_import(self, action, param):
        # Pass self.win as parent for dialogs called from UI actions
        dlg = Gtk.FileChooserDialog(
            title="Import Servers…",
            parent=self.win,
            action=Gtk.FileChooserAction.OPEN,
        )
        dlg.add_buttons(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
            Gtk.STOCK_OPEN,   Gtk.ResponseType.OK,
        )
        filt = Gtk.FileFilter()
        filt.set_name("JSON files")
        filt.add_pattern("*.json")
        dlg.add_filter(filt)
    
        # Add filter for GPG encrypted files
        filt_gpg = Gtk.FileFilter()
        filt_gpg.set_name("GPG Encrypted Files")
        filt_gpg.add_pattern("*.gpg")
        dlg.add_filter(filt_gpg)
    
        if dlg.run() == Gtk.ResponseType.OK:
            filename = dlg.get_filename()
            dlg.destroy()
            try:
                is_encrypted = filename.lower().endswith(".gpg")
                payload = None
    
                if is_encrypted:
                    # Decrypt GPG file to a temporary file
                    tf = tempfile.NamedTemporaryFile("w", delete=False)
                    tf.close()
                    
                    # Ensure subprocess captures output for debugging
                    result = subprocess.run(
                        [
                            "gpg", "--batch", "--yes",
                            "--passphrase", self.master_passphrase, # USE MASTER PASSPHRASE
                            "--output", tf.name,
                            "--decrypt", filename
                        ],
                        check=False, # Don't raise exception automatically
                        capture_output=True,
                        text=True
                    )
                    
                    if result.returncode != 0:
                        if os.path.exists(tf.name): os.remove(tf.name) # Clean up temp file
                        raise RuntimeError(f"GPG decryption failed during import: {result.stderr.strip()}")

                    with open(tf.name, "r") as f:
                        payload = json.load(f)
                    
                    os.remove(tf.name)
                else:
                    # Read JSON file directly
                    with open(filename, "r") as f:
                        payload = json.load(f)
    
                if isinstance(payload, dict):
                    servers = payload.get("servers", [])
                    imported_folders = payload.get("folders", [])
                elif isinstance(payload, list):
                    servers = payload
                    imported_folders = []
                else:
                    raise ValueError("Unexpected format; must be list or dict")
    
                # Normalize each server entry
                for srv in servers:
                    srv.setdefault("folder", ROOT_FOLDER)
                    srv.setdefault("auto_sequence", [])
    
                # 1) Restore servers
                self.servers = servers
                try:
                    save_servers(self.servers, self.master_passphrase) # UPDATED CALL
                except Exception as e:
                    self._error(f"Failed to save imported servers: {e}")
    
                # 2) Restore folders: union imported folder list with any folders
                #    that servers are actually assigned to
                folders_from_servers = {
                    srv["folder"] for srv in servers
                    if srv.get("folder") != ROOT_FOLDER
                }
                all_folders = set(imported_folders) | folders_from_servers
                self.user_folders = sorted(all_folders, key=natural_key)
                self.settings["folders"] = self.user_folders
                save_settings(self.settings) # No passphrase needed for settings
    
                # rebuild the UI tree
                self.reload_folders()
                self.populate_tree()
                self.tree.expand_row(Gtk.TreePath.new_from_string("0"), False)
    
                self.log(
                    f"Imported {len(self.servers)} servers and "
                    f"{len(self.user_folders)} folders from '{filename}'"
                )
    
            except Exception as e:
                self._error(f"Import failed:\n{e}")
        else:
            dlg.destroy()


    # ── File Menu: Export Servers ───────────────────────────────────────
    def on_export(self, action, param):
        # Pass self.win as parent for dialogs called from UI actions
        dlg = Gtk.FileChooserDialog(
            title="Export Servers…",
            parent=self.win,
            action=Gtk.FileChooserAction.SAVE,
        )
        dlg.add_buttons(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
            Gtk.STOCK_SAVE,   Gtk.ResponseType.OK,
        )
        dlg.set_do_overwrite_confirmation(True)
    
        # Add filter for plaintext JSON
        filt_json = Gtk.FileFilter()
        filt_json.set_name("JSON files")
        filt_json.add_pattern("*.json")
        dlg.add_filter(filt_json)
    
        # Add filter for GPG encrypted files
        filt_gpg = Gtk.FileFilter()
        filt_gpg.set_name("GPG Encrypted Files")
        filt_gpg.add_pattern("*.gpg")
        dlg.add_filter(filt_gpg)
    
        dlg.set_current_name("ssh_servers_export.json")
    
        if dlg.run() == Gtk.ResponseType.OK:
            filename = dlg.get_filename()
            dlg.destroy()
            try:
                is_encrypted = filename.lower().endswith(".gpg")
                
                # Build a combined export payload
                export_data = {
                    "servers": self.servers,
                    "folders": self.user_folders
                }
    
                if is_encrypted:
                    # Write to a temporary file and encrypt it
                    tf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".json")
                    json.dump(export_data, tf, indent=4)
                    tf.flush()
                    tf.close()
                    
                    # Ensure subprocess captures output for debugging
                    result = subprocess.run(
                        [
                            "gpg", "--batch", "--yes",
                            "--symmetric", "--cipher-algo", "AES256",
                            "--passphrase", self.master_passphrase, # USE MASTER PASSPHRASE
                            "-o", filename,
                            tf.name
                        ],
                        check=False, # Don't raise exception automatically
                        capture_output=True,
                        text=True
                    )
                    os.remove(tf.name) # Clean up temp file
                    
                    if result.returncode != 0:
                        raise RuntimeError(f"GPG encryption failed during export: {result.stderr.strip()}")
                else:
                    # Write to a regular JSON file
                    with open(filename, "w") as f:
                        json.dump(export_data, f, indent=4)
    
                self.log(
                    f"Exported {len(self.servers)} servers "
                    f"and {len(self.user_folders)} folders to '{filename}'"
                )
            except Exception as e:
                self._error(f"Export failed:\n{e}")
        else:
            dlg.destroy()

    # ── Folder Commands (New/Rename/Delete) ───────────────────────────────────────
    def on_new_folder(self, action, param):
        # prompt for folder name
        name = self._simple_input("New Folder")
        # require non‐empty name
        if not name:
            self._error("Folder name is required.")
            return
        # avoid duplicates
        if name in self.user_folders:
            self._error(f"Folder '{name}' already exists.")
            return

        # all good → add folder
        self.user_folders.append(name)
        self.settings["folders"] = self.user_folders
        save_settings(self.settings) # No passphrase needed for settings
        self.reload_folders()
        self.populate_tree()
        self.tree.expand_row(Gtk.TreePath.new_from_string("0"), False)

    def on_rename_folder(self, action, param):
        model, it = self.tree.get_selection().get_selected()
        if not it:
            return self._info("Select a folder to rename.")
        node, fld = model.get_value(it, 2)
        if node != "folder" or fld == ROOT_FOLDER:
            return self._info("Select a user-defined folder.")

        # prompt for the new name
        new_name = self._simple_input("Rename Folder", default_text=fld)

        # require non-empty
        if not new_name:
            self._error("Folder name is required.")
            return

        # no-op if unchanged
        if new_name == fld:
            return

        # avoid duplicates
        if new_name in self.user_folders:
            self._error(f"Folder '{new_name}' already exists.")
            return

        # perform rename
        idx = self.user_folders.index(fld)
        self.user_folders[idx] = new_name
        self.settings["folders"] = self.user_folders
        save_settings(self.settings) # No passphrase needed for settings

        # update any servers in this folder
        for s in self.servers:
            if s.get("folder") == fld:
                s["folder"] = new_name
        try:
            save_servers(self.servers, self.master_passphrase) # UPDATED CALL
        except Exception as e:
            self._error(f"Failed to save servers after folder rename: {e}")

        # refresh UI
        self.reload_folders()
        self.populate_tree()
        self.tree.expand_row(Gtk.TreePath.new_from_string("0"), False)

    def on_delete_folder(self, action, param):
        model, it = self.tree.get_selection().get_selected()
        if not it:
            return self._info("Select a folder first.")
        node, fld = model.get_value(it, 2)
        if node != "folder" or fld == ROOT_FOLDER:
            return self._info("Select a non-Session folder.")
        # Make parent transient_for self.win only if self.win exists
        parent_window = self.win if hasattr(self, 'win') and self.win else None
        if not self._confirm("Delete Folder", f"Delete '{fld}'? Servers move to Session.", parent_window): # Pass parent
            return
        for srv in self.servers:
            if srv.get("folder") == fld:
                srv["folder"] = ROOT_FOLDER
        try:
            save_servers(self.servers, self.master_passphrase) # UPDATED CALL
        except Exception as e:
            self._error(f"Failed to save servers after folder deletion: {e}")
        self.user_folders.remove(fld)
        self.settings["folders"] = self.user_folders
        save_settings(self.settings) # No passphrase needed for settings
        self.reload_folders()
        self.populate_tree()
        self.tree.expand_row(Gtk.TreePath.new_from_string("0"), False)

    # ── Server Commands (Add/Edit/Delete) ────────────────────────────────────────
    def on_add_server(self, action, param):
        self._open_server_dialog(None)
        self.populate_tree()
        self.tree.expand_row(Gtk.TreePath.new_from_string("0"), False)

    def on_edit_server(self, action, param):
        model, it = self.tree.get_selection().get_selected()
        if not it:
            return self._info("Select a server first.")
        node, idx = model.get_value(it, 2)
        if node != "server":
            return self._info("Select a server first.")
        self._open_server_dialog(self.servers[idx], idx)
        self.populate_tree()
        self.tree.expand_row(Gtk.TreePath.new_from_string("0"), False)

    def on_delete_server(self, action, param):
        model, it = self.tree.get_selection().get_selected()
        if not it:
            return self._info("Select a server first.")
        node, idx = model.get_value(it, 2)
        if node != "server":
            return self._info("Select a server first.")
        name = self.servers[idx]["name"]
        # Make parent transient_for self.win only if self.win exists
        parent_window = self.win if hasattr(self, 'win') and self.win else None
        if not self._confirm("Delete Server", f"Delete '{name}'?", parent_window): # Pass parent
            return
        del self.servers[idx]
        try:
            save_servers(self.servers, self.master_passphrase) # UPDATED CALL
        except Exception as e:
            self._error(f"Failed to save servers after deletion: {e}")
        self.reload_folders()
        self.populate_tree()
        self.tree.expand_row(Gtk.TreePath.new_from_string("0"), False)

    # ── Connect Actions (SSH & SFTP) ─────────────────────────────────────────
    def on_ssh(self, action, param):
        """
        Spawn an SSH session via Expect.  If auth_method == "password",
        we force password auth (disable pubkey); if "key_file", we pass -i.
        After login we run any auto_sequence steps, then drop to interact().
        """
        model, it = self.tree.get_selection().get_selected()
        if not it:
            return self._info("Select a server first.")
        node, idx = model.get_value(it, 2)
        if node != "server":
            return self._info("Select a server first.")
    
        cfg = self.servers[idx]

        # --- FIX: Set current logging status and path before launching expect ---
        self.current_logging_enabled = cfg.get("logging_enabled", False)
        self.current_log_path = cfg.get("log_path", "") # Ensure default is empty string if not set
        # --- END FIX ---

        self.log(f"Launching SSH: {cfg['name']}")
    
        lines = []
        auth       = cfg.get("auth_method")
        key_opt    = f"-i {cfg['key_file']} " if auth == "key_file" else ""
        pubkey_opt = "-o PubkeyAuthentication=no " if auth == "password" else ""
        port       = cfg.get("port", 22)
    
        # 1) spawn with the right auth flags
        lines.append(
            f'spawn ssh {pubkey_opt}-t {key_opt}-p {port} '
            f'{cfg["user"]}@{cfg["host"]}\n'
        )
        lines.append("log_user 1\n")   # echo everything
    
        # 2) password login if needed
        if auth == "password":
            lines.append('expect "*assword:*"\n')
            lines.append(f'send -- "{cfg["password"]}\\r"\n')
            lines.append("after 500\n")
    
        # 3) auto_sequence steps
        for step in cfg.get("auto_sequence", []):
            exp, snd = step["expect"], step["send"]
            lines.append(f'expect "*{exp}*"\n')
            lines.append(f'send -- "{snd}\\r"\n')
            lines.append("after 500\n")
    
        # 4) hand off to the user
        lines.append("interact\n")
    
        self._launch_expect(lines, f"{cfg['name']} SSH")

    def on_sftp(self, action, param):
        """
        Spawn an SFTP session via Expect.
        Honors auth_method: “password” disables pubkey, “key_file” uses -i.
        Runs auto_sequence, then hand off to the user.
        """
        model, it = self.tree.get_selection().get_selected()
        if not it:
            return self._info("Select a server first.")
        node, idx = model.get_value(it, 2)
        if node != "server":
            return self._info("Select a server first.")
    
        cfg = self.servers[idx]

        # --- FIX: Set current logging status and path before launching expect ---
        self.current_logging_enabled = cfg.get("logging_enabled", False)
        self.current_log_path = cfg.get("log_path", "") # Ensure default is empty string if not set
        # --- END FIX ---

        self.log(f"Launching SFTP: {cfg['name']}")
        lines = []
    
        auth       = cfg.get("auth_method")
        key_opt    = f"-i {cfg['key_file']} " if auth == "key_file" else ""
        pubkey_opt = "-o PubkeyAuthentication=no " if auth == "password" else ""
        port       = cfg.get("port", 22)
    
        # Spawn sftp without -t, allow password prompts
        spawn_cmd = (
            f"spawn sftp "
            f"-oBatchMode=no {pubkey_opt}"
            f"-P {port} "
            f"{key_opt}"
            f"{cfg['user']}@{cfg['host']}\n"
        )
        lines.append(spawn_cmd)
        lines.append("log_user 1\n")
    
        # Debug: print the entire script
        self.log("Expect script:\n" + "".join(lines))
    
        # Password login if needed
        if auth == "password":
            lines.append('expect "*assword:*"\n')
            lines.append(f'send -- "{cfg["password"]}\\r"\n')
            lines.append("after 500\n")
    
        # Auto-sequence steps
        for step in cfg.get("auto_sequence", []):
            exp, snd = step["expect"], step["send"]
            lines.append(f'expect "*{exp}*"\n')
            lines.append(f'send -- "{snd}\\r"\n')
            lines.append("after 500\n")
    
        # Drop to interactive SFTP shell
        lines.append("interact\n")
    
        self._launch_expect(lines, f"{cfg['name']} SFTP")

    # ── Generate & Launch Expect Script ───────────────────────────────────────
    def _launch_expect(self, lines, title):
        expect = shutil.which("expect")
        if not expect:
            return self._error("'expect' not found.")
        header = [
            "#!/usr/bin/env expect\n",
            "set env(TERM) \"dumb\"\n", ]             
        if getattr(self, "current_logging_enabled", False) and self.current_log_path:
            os.makedirs(os.path.dirname(self.current_log_path), exist_ok=True)
            header.append(f"log_file -a {self.current_log_path}\n")
        header.append("set timeout -1\n")
        script = header + lines
        tf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".exp")
        tf.writelines(script)
        tf.close()
        os.chmod(tf.name, 0o700)
        subprocess.Popen([
            "gnome-terminal", "--title", title,
            "--", expect, "-f", tf.name
        ])

    # ── Logging to GUI & to File ─────────────────────────────────────────
    def log(self, msg):
        # Always try to write to log_buffer if it exists
        if hasattr(self, 'log_buffer') and self.log_buffer is not None:
            end = self.log_buffer.get_end_iter()
            self.log_buffer.insert(end, msg + "\n")
            # Only scroll if the TextView is actually created and packed
            # Ensure self.log_text_view is not None *before* calling .get_parent()
            if self.log_text_view and self.log_text_view.get_parent():
                 self.log_text_view.scroll_to_mark(self.log_buffer.get_mark("insert"), 0.0, True, 0.0, 1.0)
        else:
            # Fallback for very early messages before GUI is ready
            print(f"LOG (early): {msg}", file=sys.stderr) # Print to stderr for early debugging

        # File logging (independent of GUI)
        if getattr(self, "current_logging_enabled", False) and self.current_log_path:
            try:
                os.makedirs(os.path.dirname(self.current_log_path), exist_ok=True)
                with open(self.current_log_path, "a") as f:
                    f.write(msg + "\n")
            except Exception as e:
                # Log this error to stderr if file logging fails
                print(f"Error writing to file log: {e}", file=sys.stderr)

    # ── Info / Error / Confirm Dialogs ───────────────────────────────────
    def _info(self, text):
        # Make parent transient_for self.win only if self.win exists
        parent_window = self.win if hasattr(self, 'win') and self.win else None
        dlg = Gtk.MessageDialog(
            transient_for=parent_window, # Can be None
            flags=0,
            message_type=Gtk.MessageType.INFO,
            buttons=Gtk.ButtonsType.OK,
            text=text
        )
        dlg.run()
        dlg.destroy()

    def _error(self, text):
        # Make parent transient_for self.win only if self.win exists
        parent_window = self.win if hasattr(self, 'win') and self.win else None
        dlg = Gtk.MessageDialog(
            transient_for=parent_window, # Can be None
            flags=0,
            message_type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.CLOSE,
            text=text
        )
        dlg.run()
        dlg.destroy()
        print(f"ERROR: {text}", file=sys.stderr) # Also print to console for debugging

    def _confirm(self, title, text, parent_window=None): # Added parent_window argument
        # Use provided parent_window or default to self.win if available, else None
        parent_to_use = parent_window if parent_window else (self.win if hasattr(self, 'win') and self.win else None)
        
        dlg = Gtk.MessageDialog(
            transient_for=parent_to_use, # Can be None
            flags=0,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.YES_NO,
            text=text
        )
        dlg.set_title(title)
        res = dlg.run()
        dlg.destroy()
        return res == Gtk.ResponseType.YES

    # ── Help: About Dialog ─────────────────────────────────────────────
    def on_about(self, action, param):
        # Make parent transient_for self.win only if self.win exists
        parent_window = self.win if hasattr(self, 'win') and self.win else None
        about = Gtk.AboutDialog(
            transient_for=parent_window, # Can be None
            modal=True,
            program_name=APP_TITLE,
            version="1.0.0",
            authors=["Copilot"],
            artists=["Tomas"],
            comments="A GTK-based SSH/SFTP session manager"
        )
        about.run()
        about.destroy()

    # catch right-clicks and popup a menu
    def on_tree_button_press(self, tree, event):
        if event.button == Gdk.BUTTON_SECONDARY:
            # figure out what was clicked
            x, y = int(event.x), int(event.y)
            hit = tree.get_path_at_pos(x, y)
            if not hit:
                return False
            path, col, cx, cy = hit
            tree.grab_focus()
            tree.set_cursor(path, col, False)

            # get the selected node info
            model, it = tree.get_selection().get_selected()
            node, val = model.get_value(it, 2)

            # build & show the context menu
            menu = self._create_context_menu(node, val)
            menu.popup_at_pointer(event)
            return True
        return False

    # build a context menu based on whether it's a folder, server or root
    def _create_context_menu(self, node, val):
        menu = Gtk.Menu()

        # root Session node
        if node == "folder" and val == ROOT_FOLDER:
            mi = Gtk.MenuItem(label="Add Server")
            mi.connect("activate", lambda w: self.on_add_server(None, None))
            menu.append(mi)

            mi = Gtk.MenuItem(label="New Folder")
            mi.connect("activate", lambda w: self.on_new_folder(None, None))
            menu.append(mi)

        # any user-defined folder
        elif node == "folder":
            for lbl, fn in (
                ("Add Server", self.on_add_server),
                ("New Folder", self.on_new_folder),
                ("Rename Folder", self.on_rename_folder),
                ("Delete Folder", self.on_delete_folder),
            ):
                mi = Gtk.MenuItem(label=lbl)
                mi.connect("activate", lambda w, f=fn: f(None, None))
                menu.append(mi)

        # a server
        elif node == "server":
            for lbl, fn in (
                ("SSH",         self.on_ssh),
                ("SFTP",        self.on_sftp),
                ("Edit Server", self.on_edit_server),
                ("Delete Server", self.on_delete_server),
            ):
                mi = Gtk.MenuItem(label=lbl)
                mi.connect("activate", lambda w, f=fn: f(None, None))
                menu.append(mi)

        menu.show_all()
        return menu

    # natural_key already in your file above
    
    def _folder_cell_data_func(self, column, renderer, model, tree_iter, data):
        """
        Only user-defined folders (not the root Session) are inline-editable.
        """
        node, val = model.get_value(tree_iter, 2)
        editable = (node == "folder" and val in self.user_folders)
        renderer.set_property("editable", editable)

    def _on_folder_cell_edited(self, widget, path, new_text):
        """
        Validate and commit an inline rename of a user-defined folder.
        """
        it = self.store.get_iter(path)
        node, old_name = self.store.get_value(it, 2)

        # Only allow renaming of folders in user_folders
        if node != "folder" or old_name not in self.user_folders:
            return

        new_name = new_text.strip()
        # No-op if name didn't change
        if new_name == old_name:
            return

        if not new_name:
            self._error("Folder name cannot be empty.")
            return

        if new_name in self.user_folders:
            self._error(f"Folder '{new_name}' already exists.")
            return

        # 1) Update the user_folders list & save settings
        idx = self.user_folders.index(old_name)
        self.user_folders[idx] = new_name
        self.settings["folders"] = self.user_folders
        save_settings(self.settings) # No passphrase needed for settings

        # 2) Update any servers assigned to this folder & save
        for s in self.servers:
            if s.get("folder") == old_name:
                s["folder"] = new_name
        try:
            save_servers(self.servers, self.master_passphrase) # UPDATED CALL
        except Exception as e:
            self._error(f"Failed to save servers after folder rename: {e}")

        # 3) Rebuild and refresh the tree view
        self.reload_folders()
        self.populate_tree()
        self.tree.expand_row(Gtk.TreePath.new_from_string("0"), False)

    def on_user_guide(self, action, param):
        # Make parent transient_for self.win only if self.win exists
        parent_window = self.win if hasattr(self, 'win') and self.win else None
        dlg = Gtk.Dialog(
            title="User Guide",
            transient_for=parent_window, # Can be None
            modal=True,
        )
        dlg.add_buttons(
            Gtk.STOCK_CLOSE, Gtk.ResponseType.CLOSE,
        )
        dlg.set_default_size(600, 400)

        # ── Scrolled TextView ────────────────────────────────────
        sw = Gtk.ScrolledWindow()
        sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sw.set_min_content_height(300)     # ensure you see many lines
        sw.set_hexpand(True)
        sw.set_vexpand(True)

        tv = Gtk.TextView(editable=False, wrap_mode=Gtk.WrapMode.WORD)
        buf = tv.get_buffer()
        buf.set_text(USER_GUIDE)           # no .strip() needed
        sw.add(tv)

        # ── Pack into the dialog ─────────────────────────────────
        content = dlg.get_content_area()
        content.set_margin_top(10)
        content.set_margin_bottom(10)
        content.set_margin_start(10)
        content.set_margin_end(10)
        content.pack_start(sw, True, True, 0)

        dlg.show_all()
        dlg.run()
        dlg.destroy()

# ── Chunk 4: Add/Edit Server Dialog & Sequence Editor (with Hide/Mask Send) ────────────

    def _open_server_dialog(self, cfg=None, idx=None):
        is_edit = cfg is not None

        # Make parent transient_for self.win only if self.win exists
        parent_window = self.win if hasattr(self, 'win') and self.win else None
        dlg = Gtk.Dialog(
            title="Edit Server" if is_edit else "Add Server",
            transient_for=parent_window, # Can be None
            modal=True
        )
        dlg.add_buttons(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
            Gtk.STOCK_OK,     Gtk.ResponseType.OK
        )
        # allow resizing and a sensible default size
        dlg.set_default_size(600, 500)
        dlg.set_resizable(True)

        # ---------- Build UI ----------
        content = dlg.get_content_area()
        nb = Gtk.Notebook()
        nb.set_hexpand(True)
        nb.set_vexpand(True)
        content.pack_start(nb, True, True, 0)

        # -- General Tab --
        grid = Gtk.Grid(column_spacing=6, row_spacing=6, margin=10)
        nb.append_page(grid, Gtk.Label(label="General"))

        def add_row(label, widget, row):
            lbl = Gtk.Label(label=label)
            lbl.set_halign(Gtk.Align.START)
            grid.attach(lbl, 0, row, 1, 1)
            grid.attach(widget, 1, row, 1, 1)

        en_name = Gtk.Entry();   en_name.set_size_request(300, -1)
        en_host = Gtk.Entry();   en_host.set_size_request(300, -1)
        en_port = Gtk.Entry();   en_port.set_size_request(300, -1)
        en_user = Gtk.Entry();   en_user.set_size_request(300, -1)
        folder_cb = Gtk.ComboBoxText(); folder_cb.set_size_request(300, -1)

        # populate with existing data if editing
        en_port.set_text(str(cfg.get("port", 22)) if cfg else "22")
        if cfg:
            en_name.set_text(cfg["name"])
            en_host.set_text(cfg["host"])
            en_user.set_text(cfg.get("user", ""))

        folder_cb.append_text(ROOT_FOLDER)
        for f in self.subfolders:
            folder_cb.append_text(f)
        idx_f = 0
        if cfg and cfg.get("folder") != ROOT_FOLDER:
            idx_f = self.subfolders.index(cfg["folder"]) + 1
        folder_cb.set_active(idx_f)

        add_row("Name:",   en_name,   0)
        add_row("Host:",   en_host,   1)
        add_row("Port:",   en_port,   2)
        add_row("User:",   en_user,   3)
        add_row("Folder:", folder_cb, 4)

        # -- Auth Tab --
        auth_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                            spacing=6, margin=10)
        nb.append_page(auth_page, Gtk.Label(label="Auth"))

        auth_pw  = Gtk.RadioButton.new_with_label(None, "Password")
        auth_key = Gtk.RadioButton.new_with_label_from_widget(auth_pw,
                                                              "Key File")

        pw_entry = Gtk.Entry()
        pw_entry.set_size_request(300, -1)
        pw_entry.set_visibility(False)
        pw_entry.set_placeholder_text("Enter password")

        key_entry = Gtk.Entry(); key_entry.set_size_request(300, -1)
        key_btn   = Gtk.Button(label="Browse")
        key_btn.connect("clicked", lambda w: browse_key(dlg, key_entry))
        key_box   = Gtk.Box(spacing=6)
        key_box.pack_start(key_entry, True, True, 0)
        key_box.pack_start(key_btn,   False, False, 0)

        for w in (auth_pw, pw_entry, auth_key, key_box):
            auth_page.pack_start(w, False, False, 0)

        # gray-out password entry when key-file is selected
        def _toggle_pw(rb, entry, sensitive):
            if rb.get_active():
                entry.set_sensitive(sensitive)
        auth_pw.connect("toggled", _toggle_pw, pw_entry, True)
        auth_key.connect("toggled", _toggle_pw, pw_entry, False)

        if cfg:
            mode = cfg.get("auth_method", "password")
            auth_pw.set_active(mode == "password")
            auth_key.set_active(mode == "key_file")
            pw_entry.set_text(cfg.get("password", ""))
            key_entry.set_text(cfg.get("key_file", ""))

        pw_entry.set_sensitive(auth_pw.get_active())

        # -- Logging Tab --
        log_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                           spacing=6, margin=10)
        nb.append_page(log_page, Gtk.Label(label="Logging"))

        log_enable = Gtk.CheckButton(label="Enable Logging")
        log_enable.set_active(cfg.get("logging_enabled", False)
                              if cfg else False)
        log_entry = Gtk.Entry(); log_entry.set_size_request(300, -1)
        log_btn   = Gtk.Button(label="Browse")
        log_btn.connect("clicked", lambda w: browse_log(dlg, log_entry))
        log_box   = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,
                            spacing=6)
        log_box.pack_start(log_entry, True, True, 0)
        log_box.pack_start(log_btn,   False, False, 0)

        log_page.pack_start(log_enable, False, False, 0)
        log_page.pack_start(log_box,    False, False, 0)
        log_entry.set_text(
            cfg.get("log_path", "/tmp/snapcm_log.txt") if cfg
            else "/tmp/snapcm_log.txt"
        )

        # -- Login Actions Tab --
        seq_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                           spacing=6, margin=10)
        nb.append_page(seq_page, Gtk.Label(label="Login Actions"))

        # 3-column store: expect, send, hide-flag
        seq_store = Gtk.ListStore(str, str, bool)
        seq_view = Gtk.TreeView(model=seq_store)
        seq_view.set_grid_lines(Gtk.TreeViewGridLines.BOTH)

        sw = Gtk.ScrolledWindow()
        sw.set_policy(Gtk.PolicyType.AUTOMATIC,
                      Gtk.PolicyType.AUTOMATIC)
        sw.set_hexpand(True); sw.set_vexpand(True)
        sw.add(seq_view)
        seq_page.pack_start(sw, True, True, 0)

        # cell-data functions
        def _exp_cell(col, renderer, model, it, data):
            renderer.set_property("text", model.get_value(it, 0))

        def _snd_cell(col, renderer, model, it, data):
            txt  = model.get_value(it, 1)
            hide = model.get_value(it, 2)
            renderer.set_property("text",
                "*" * len(txt) if hide else txt
            )

        # build & append columns
        for title, func in (("Expect", _exp_cell),
                            ("Send",   _snd_cell)):
            rnd = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(title, rnd)
            col.set_cell_data_func(rnd, func)
            col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
            col.set_fixed_width(165)
            seq_view.append_column(col)

        # Add/Edit/Delete + Up/Down
        btn_box = Gtk.Box(spacing=6)
        btn_add  = Gtk.Button(label="Add")
        btn_edit = Gtk.Button(label="Edit")
        btn_del  = Gtk.Button(label="Delete")
        up_btn   = Gtk.Button(); up_btn.add(
                        Gtk.Arrow(Gtk.ArrowType.UP,
                                  Gtk.ShadowType.NONE))
        dn_btn   = Gtk.Button(); dn_btn.add(
                        Gtk.Arrow(Gtk.ArrowType.DOWN,
                                  Gtk.ShadowType.NONE))

        btn_add.connect("clicked",
            lambda w: self._open_seq_editor(dlg, seq_store, None))
        btn_edit.connect("clicked",
            lambda w: self._edit_seq_selected(seq_view,
                                              seq_store, dlg))
        btn_del.connect("clicked",
            lambda w: self._delete_seq_selected(seq_view,
                                                seq_store))
        up_btn.connect("clicked",
            lambda w: self._move_seq_up(seq_view, seq_store))
        dn_btn.connect("clicked",
            lambda w: self._move_seq_down(seq_view,
                                          seq_store))

        for b in (btn_add, btn_edit, btn_del,
                  up_btn, dn_btn):
            btn_box.pack_start(b, False, False, 0)
        seq_page.pack_start(btn_box, False, False, 0)

        # pre-populate steps (default hide=True)
        if cfg:
            for step in cfg.get("auto_sequence", []):
                seq_store.append([
                    step["expect"],
                    step["send"],
                    step.get("hide", True)
                ])

        # ---------- Validation Loop ----------
        center(dlg)
        # dlg.show_all() # Already called in center(dlg)
        result = None

        while True:
            resp = dlg.run()
            if resp != Gtk.ResponseType.OK:
                break

            # validate name
            name = en_name.get_text().strip()
            if not name:
                self._error("Server Name is required.")
                continue

            # gather fields
            result = {
                "name":         name,
                "host":         en_host.get_text().strip(),
                "port":         int(en_port.get_text().strip()),
                "user":         en_user.get_text().strip(),
                "folder":       folder_cb.get_active_text(),
                "auth_method":  "password" if auth_pw.get_active()
                                 else "key_file",
                "password":     pw_entry.get_text().strip(),
                "key_file":     key_entry.get_text().strip(),
                "logging_enabled": log_enable.get_active(),
                "log_path":        log_entry.get_text().strip(),
                "auto_sequence": [
                    {
                        "expect": seq_store[i][0],
                        "send":   seq_store[i][1],
                        "hide":   seq_store[i][2]
                    }
                    for i in range(len(seq_store))
                ]
            }
            break

        dlg.destroy()

        if result:
            # post-save actions...
            if result["logging_enabled"]:
                os.makedirs(
                    os.path.dirname(result["log_path"]),
                    exist_ok=True
                )
                if not os.path.exists(result["log_path"]):
                    open(result["log_path"], "w").close()

            if is_edit:
                self.servers[idx] = result
                self.log(f"Edited '{result['name']}'")
            else:
                self.servers.append(result)
                self.log(f"Added '{result['name']}'")
            try:
                save_servers(self.servers, self.master_passphrase) # UPDATED CALL
            except Exception as e:
                self._error(f"Failed to save servers after add/edit: {e}")
            self.reload_folders()
            self.populate_tree()
            self.tree.expand_row(Gtk.TreePath.new_from_string("0"),
                                 False)


    def _edit_seq_selected(self, view, store, parent):
        model, paths = view.get_selection().get_selected_rows()
        if paths:
            it = store.get_iter(paths[0])
            self._open_seq_editor(parent, store, it)


    def _delete_seq_selected(self, view, store):
        model, paths = view.get_selection().get_selected_rows()
        for p in sorted(paths, reverse=True):
            it = store.get_iter(p)
            store.remove(it)


    def _move_seq_up(self, view, store):
        model, paths = view.get_selection().get_selected_rows()
        if not paths: return
        row = paths[0][0]
        if row <= 0: return
        it = store.get_iter(paths[0])
        e, s, h = store.get_value(it, 0), store.get_value(it, 1), store.get_value(it, 2)
        store.remove(it)
        new_it = store.insert(row-1, [e, s, h])
        view.get_selection().select_iter(new_it)


    def _move_seq_down(self, view, store):
        model, paths = view.get_selection().get_selected_rows()
        if not paths: return
        row = paths[0][0]
        if row >= len(store)-1: return
        it = store.get_iter(paths[0])
        e, s, h = store.get_value(it, 0), store.get_value(it, 1), store.get_value(it, 2)
        store.remove(it)
        new_it = store.insert(row+1, [e, s, h])
        view.get_selection().select_iter(new_it)

    def _open_seq_editor(self, parent, seq_store, tree_iter):
        """
        Add/Edit a single Login-Action step.
        seq_store: Gtk.ListStore(str expect, str send, bool hide)
        tree_iter: iter to edit, or None to append new.
        """
        # Make parent transient_for self.win only if self.win exists
        parent_window = self.win if hasattr(self, 'win') and self.win else None # Use parent_window for dlg
        dlg = Gtk.Dialog(
            title="Edit Step" if tree_iter else "Add Step",
            transient_for=parent_window, # Can be None
            modal=True
        )
        dlg.add_buttons(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
            Gtk.STOCK_OK,     Gtk.ResponseType.OK
        )
        dlg.set_default_size(360, 160)
        dlg.set_resizable(False)
    
        box = dlg.get_content_area()
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)
    
        # ── Expect / Send entries row ───────────────────────────────
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        ent_exp = Gtk.Entry(); ent_exp.set_size_request(165, -1)
        ent_snd = Gtk.Entry(); ent_snd.set_size_request(165, -1)
        row.pack_start(ent_exp, False, False, 0)
        row.pack_start(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL),
                      False, False, 0)
        row.pack_start(ent_snd, False, False, 0)
        box.pack_start(row, False, False, 0)
    
        # ── Hide-Send checkbox ───────────────────────────────────────
        mask_chk = Gtk.CheckButton(label="Hide Send Input")
        mask_chk.set_tooltip_text("When unselected, show and clear Send text")
        mask_chk.set_active(False)   # default: unchecked → always show
        box.pack_start(mask_chk, False, False, 6)
    
        # ── Pre-fill if editing ─────────────────────────────────────
        if tree_iter:
            # get each column separately
            e0 = seq_store.get_value(tree_iter, 0)
            s0 = seq_store.get_value(tree_iter, 1)
            h0 = seq_store.get_value(tree_iter, 2)
            ent_exp.set_text(e0)
            ent_snd.set_text(s0)
            mask_chk.set_active(h0)
    
        # set visibility based on the checkbox’s state
        ent_snd.set_visibility(not mask_chk.get_active())
    
        # ── Now wire up the toggle handler *after* pre-fill ────────────
        def _on_mask_toggled(cb):
            # cb.get_active()==True  → hide/mask
            # cb.get_active()==False → show & clear
            ent_snd.set_visibility(not cb.get_active())
            if not cb.get_active():
                ent_snd.set_text("")
        mask_chk.connect("toggled", _on_mask_toggled)
    
        dlg.show_all()
        resp = dlg.run()
    
        if resp == Gtk.ResponseType.OK:
            exp_txt = ent_exp.get_text().strip()
            snd_txt = ent_snd.get_text().strip()
            hide_fl = mask_chk.get_active()
            if tree_iter:
                seq_store.set(tree_iter, [0,1,2], [exp_txt, snd_txt, hide_fl])
            else:
                seq_store.append([exp_txt, snd_txt, hide_fl])
    
        dlg.destroy()

# ── main() ─────────────────────────────────────────────────────────────────────────────

def main():
    app = SnapConnectionManager()
    import sys
    sys.exit(app.run(sys.argv))


if __name__ == "__main__":
    main()
