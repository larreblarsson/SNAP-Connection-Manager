#!/usr/bin/env python3

# ── Chunk 1: Imports, Globals & Helpers ─────────────────────────────────────────────
import os
import json
import shutil
import subprocess
import tempfile
import re
import gi
import hashlib
import secrets
import sys # Added for fallback console logging
import webbrowser
import http.server 
import socketserver
import threading 


gi.require_version('Gtk', '3.0')
try:
    gi.require_version('Vte', '2.91')
    from gi.repository import Vte
except (ValueError, ImportError):
    print("ERROR: VTE library not found. Please install gir1.2-vte-2.91", file=sys.stderr)
    sys.exit(1)
# --- END NEW ---
from gi.repository import Gtk, Gio, GLib, GdkPixbuf
from gi.repository import Gdk
from gi.repository import Pango # Moved here as it's used in init_ui_elements
from pathlib import Path

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
SERVER_FILE    = os.path.join(APP_DATA_DIR, "ssh_servers.json")
SETTINGS_FILE  = os.path.join(APP_DATA_DIR, "snap_cm_settings.json")
DATA_DIR       = "/usr/share/snap_connection_manager/"
FOLDER_ICON    = os.path.join(DATA_DIR, "folder.png")
SERVER_ICON    = os.path.join(DATA_DIR, "server.png")
HELP_FILE_PATH = os.path.join(DATA_DIR, "user_guide.html")
APP_ID         = "com.example.SnapCM"
APP_TITLE      = "Snap Connection Manager"
ROOT_FOLDER    = "Session"
DEFAULT_TERM_FONT = "Ubuntu Mono 12"
DEFAULT_TERM_FG = "#000000"
DEFAULT_TERM_BG = "#FFFFDD"
DEFAULT_TERM_PALETTE = "None"
DEFAULT_TERM_SCROLLBACK = 10000
# Terminal color schemes used by the Appearance tab / server dialog
BUILTIN_SCHEMES = {
    "Black on light yellow": {"term_fg": "#000000", "term_bg": "#FFFFDD", "term_palette": "None"},
    "Black on white":        {"term_fg": "#000000", "term_bg": "#FFFFFF", "term_palette": "None"},
    "Gray on black":         {"term_fg": "#AAAAAA", "term_bg": "#000000", "term_palette": "None"},
    "Green on black":        {"term_fg": "#00FF00", "term_bg": "#000000", "term_palette": "None"},
    "White on black":        {"term_fg": "#FFFFFF", "term_bg": "#000000", "term_palette": "None"},
    "GNOME light":           {"term_fg": "#2E3436", "term_bg": "#EEEEEC", "term_palette": "Tango"},
    "GNOME dark":            {"term_fg": "#D3D7CF", "term_bg": "#2E3436", "term_palette": "Tango"},
    "Tango light":           {"term_fg": "#2E3436", "term_bg": "#F7F7F7", "term_palette": "Tango"},
    "Tango dark":            {"term_fg": "#D3D7CF", "term_bg": "#2E3436", "term_palette": "Tango"},
    "Solarized light":       {"term_fg": "#586E75", "term_bg": "#FDF6E3", "term_palette": "Solarized Light"},
    "Solarized dark":        {"term_fg": "#839496", "term_bg": "#002B36", "term_palette": "Solarized Dark"},
    "Custom": None,
}


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
                s.setdefault("port_forwards", [])
        
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
        self.set_default_response(Gtk.ResponseType.OK) # Set OK as default button

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

    def get_passphrases(self):
        """Returns the passphrase and confirmation passphrase (if applicable)."""
        passphrase = self.entry_pass.get_text()
        confirm_passphrase = self.entry_confirm.get_text() if self.entry_confirm else None
        return passphrase, confirm_passphrase

    def show_retry_error(self):
        """Shows the retry error message."""
        self.lbl_retry_msg.show()

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
        self.folder_icon = GdkPixbuf.Pixbuf.new_from_file(FOLDER_ICON)
        self.server_icon = GdkPixbuf.Pixbuf.new_from_file(SERVER_ICON)

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
            ("change_pass", self.on_change_passphrase),
            ("copy_srv", self.on_copy_server),
            ("paste_srv", self.on_paste_server),
        ):
            act = Gio.SimpleAction.new(name, None)
            act.connect("activate", handler)
            self.add_action(act)

    def do_startup(self):
        Gtk.Application.do_startup(self)
        # Show disclaimer first thing in startup
        self._show_disclaimer_if_needed()
        
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

    def _show_disclaimer_if_needed(self):
        accepted = self.settings.get("disclaimer_accepted", False)
        if accepted:
            return
    
        dlg = Gtk.Dialog(
            title="Disclaimer",
            transient_for=None,
            modal=True
        )
        dlg.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                        Gtk.STOCK_OK, Gtk.ResponseType.OK)
        dlg.set_default_response(Gtk.ResponseType.OK)
    
        # Overall dialog size (width x height in px)
        dlg.set_default_size(700, 500)
    
        box = dlg.get_content_area()
        box.set_spacing(10)
        box.set_margin_top(5)
        box.set_margin_bottom(5)
        box.set_margin_start(10)
        box.set_margin_end(10)
    
        disclaimer_text = """SNAP Connection Manager – Legal Disclaimer
    
        This software is provided "as is", without warranty of any kind, express or implied,
        including but not limited to the warranties of merchantability, fitness for a particular
        purpose, and noninfringement. In no event shall the author or contributors be held liable
        for any claim, damages, or other liability, whether in an action of contract, tort, or
        otherwise, arising from, out of, or in connection with the software or the use or other
        dealings in the software.
        
        By installing or using this application, you acknowledge that:
        
        - You are solely responsible for any actions performed using this software.
        - You understand that SSH and SFTP connections may expose systems to security risks.
        - You agree not to hold the author liable for any data loss, system compromise, or
          unintended consequences resulting from use of this application.
    
        This software is intended for educational and administrative purposes only.
        Use at your own risk.
        
        © Bo Tomas Larsson, 2025. All rights reserved."""
    
        # Wrap the label in a scrolled window to constrain height
        label = Gtk.Label(label=disclaimer_text)
        label.set_line_wrap(True)
        label.set_justify(Gtk.Justification.LEFT)
        label.set_xalign(0)  # left-align text horizontally
    
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroller.set_min_content_height(180)   # visible height for text area
        scroller.set_min_content_width(460)    # width inside the dialog
        scroller.add(label)
    
        box.pack_start(scroller, True, True, 0)
    
        checkbox = Gtk.CheckButton(label="I accept the terms")
        box.pack_start(checkbox, False, False, 0)
    
        dlg.show_all()
        while True:
            resp = dlg.run()
            if resp != Gtk.ResponseType.OK:
                dlg.destroy()
                Gtk.main_quit()
                sys.exit(0)
            if not checkbox.get_active():
                self._error("You must accept the terms to use this application.")
                continue
            break
    
        dlg.destroy()
        self.settings["disclaimer_accepted"] = True
        save_settings(self.settings)

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
                ("Change Passphrase…", self.on_change_passphrase),
                ("Quit",    self.on_quit),
            ],
            "Servers": [
                ("Add",    self.on_add_server),
                ("Edit",   self.on_edit_server),
                ("Delete", self.on_delete_server),
                ("Copy",   self.on_copy_server),
                ("Paste",  self.on_paste_server),
            ],
            "Folders": [
                ("Add",    self.on_new_folder),
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
                ("Reset Disclaimer", self.on_reset_disclaimer),
            ],
        }
        for top, items in menus.items():
            root = Gtk.MenuItem(label=top)
            submenu = Gtk.Menu()
            root.set_submenu(submenu)
        
            if top == "Servers":
                # Store refs so we can enable/disable later
                self.servers_menu_items = {}
                for lbl, fn in items:
                    mi = Gtk.MenuItem(label=lbl)
                    mi.connect("activate", lambda w, f=fn: f(None, None))
                    submenu.append(mi)
                    self.servers_menu_items[lbl] = mi
            else:
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
        sel = self.tree.get_selection()
        sel.connect("changed", self.on_tree_selection_changed)

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

    def on_tree_selection_changed(self, selection):
        model, it = selection.get_selected()
        is_srv = bool(it and model.get_value(it, 2)[0] == "server")
        if hasattr(self, "servers_menu_items"):
            self.servers_menu_items["Copy"].set_sensitive(is_srv)
        # Paste is enabled only if a copy exists
        can_paste = hasattr(self, "_copied_server")
        if hasattr(self, "servers_menu_items"):
            self.servers_menu_items["Paste"].set_sensitive(can_paste)


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
                    # dlg.show_retry_error() # No need, dialog is destroyed and re-shown
                    continue # Loop back to prompt again
                
                if passphrase != confirm_passphrase:
                    self._error("Passphrases do not match. Please try again.")
                    # dlg.show_retry_error() # No need
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
                    dlg.destroy() # Destroy dialog before looping
                    continue

                stored_hash = self.settings.get("master_passphrase_hash")
                stored_salt_hex = self.settings.get("master_passphrase_salt")
                
                if not stored_hash or not stored_salt_hex:
                    self._error("Error: Passphrase hash or salt missing from settings.")
                    self.master_passphrase = None # Force quit
                    dlg.destroy()
                    return

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
                    self.log("Passphrase verified.") # Log instead of showing dialog
                    return
                else:
                    self._error("Incorrect passphrase. Please try again.")
                    dlg.destroy() # Destroy dialog before looping
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

    def _start_help_server(self):
        """
        Starts a simple, temporary HTTP server in a background thread to serve
        the help file, bypassing any browser sandboxing issues.
        Returns the URL to the help file and the server object.
        """
        try:
            # The directory where user_guide.html is located
            serve_directory = os.path.dirname(HELP_FILE_PATH)
            # The filename of the guide
            file_name = os.path.basename(HELP_FILE_PATH)

            # A special handler that serves files from our specific directory
            class HelpRequestHandler(http.server.SimpleHTTPRequestHandler):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, directory=serve_directory, **kwargs)

            # Find a free port to run the server on
            httpd = socketserver.TCPServer(("", 0), HelpRequestHandler)
            port = httpd.server_address[1]
            
            # Run the server in a daemon thread. This means the thread will
            # automatically shut down when the main application exits.
            server_thread = threading.Thread(target=httpd.serve_forever)
            server_thread.daemon = True
            server_thread.start()

            url = f"http://127.0.0.1:{port}/{file_name}"
            self.log(f"Help server started at {url}")
            return url, httpd

        except Exception as e:
            self.log(f"Failed to start help server: {e}")
            return None, None



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
                    srv.setdefault("port_forwards", [])
    
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

    def on_change_passphrase(self, action, param):
        # 0) Ensure we have servers in memory and a verified session passphrase
        if not getattr(self, "master_passphrase", None):
            return self._error("No active passphrase in session. Restart the app and unlock first.")
    
        # 1) Confirm current passphrase
        dlg = PassphraseInputDialog(self.win, "Change Passphrase", "Enter current passphrase:")
        if dlg.run() != Gtk.ResponseType.OK:
            dlg.destroy(); return
        current_pass, _ = dlg.get_passphrases()
        dlg.destroy()
    
        stored_hash = self.settings.get("master_passphrase_hash")
        stored_salt_hex = self.settings.get("master_passphrase_salt")
        if not stored_hash or not stored_salt_hex:
            return self._error("Settings are missing passphrase hash/salt.")
    
        try:
            stored_salt = bytes.fromhex(stored_salt_hex)
        except ValueError:
            return self._error("Invalid salt format in settings. Cannot proceed.")
    
        if hash_passphrase(current_pass, stored_salt) != stored_hash:
            return self._error("Current passphrase is incorrect.")
    
        # 2) Prompt for new passphrase + confirm
        dlg2 = PassphraseInputDialog(self.win, "Change Passphrase", "Enter new passphrase:", confirm_text="Confirm new passphrase:")
        if dlg2.run() != Gtk.ResponseType.OK:
            dlg2.destroy(); return
        new_pass, new_confirm = dlg2.get_passphrases()
        dlg2.destroy()
    
        if not new_pass:
            return self._error("New passphrase cannot be empty.")
        if new_pass != new_confirm:
            return self._error("New passphrases do not match.")
        if new_pass == current_pass:
            return self._error("New passphrase is identical to the current passphrase.")
    
        # 3) Re-encrypt to a temporary .gpg file using the new passphrase
        enc_path = SERVER_FILE + ".gpg"
        enc_tmp  = enc_path + ".new"
        enc_bak  = enc_path + ".bak"
    
        tf = None
        try:
            # Write current in-memory servers to a temp JSON
            tf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".json")
            json.dump(self.servers, tf, indent=4)
            tf.flush(); tf.close()
    
            result = subprocess.run(
                [
                    "gpg", "--batch", "--yes",
                    "--symmetric", "--cipher-algo", "AES256",
                    "--passphrase", new_pass,
                    "-o", enc_tmp, tf.name
                ],
                check=False, capture_output=True, text=True
            )
            os.remove(tf.name); tf = None
    
            if result.returncode != 0:
                # Do not touch existing enc file or settings
                return self._error(f"GPG encryption failed:\n{result.stderr.strip()}")
    
            # 4) Atomic swap with backup
            if os.path.exists(enc_bak):
                os.remove(enc_bak)
            if os.path.exists(enc_path):
                os.rename(enc_path, enc_bak)
            os.rename(enc_tmp, enc_path)
            if os.path.exists(enc_bak):
                os.remove(enc_bak)
    
            # 5) Update settings (new salt+hash) and session passphrase
            new_salt = generate_salt()
            self.settings["master_passphrase_salt"] = new_salt.hex()
            self.settings["master_passphrase_hash"] = hash_passphrase(new_pass, new_salt)
            save_settings(self.settings)
    
            self.master_passphrase = new_pass
            self.log("Passphrase changed successfully.")
            self._info("Passphrase changed.")
    
        except Exception as e:
            # Cleanup temp/new file on error; restore from backup if needed
            try:
                if tf and os.path.exists(tf.name):
                    os.remove(tf.name)
                if os.path.exists(enc_tmp):
                    os.remove(enc_tmp)
                # If we moved the original aside but failed after, restore it
                if os.path.exists(enc_bak) and not os.path.exists(enc_path):
                    os.rename(enc_bak, enc_path)
            finally:
                self._error(f"Failed to change passphrase: {e}")
    
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
        model, it = self.tree.get_selection().get_selected()
        if not it:
            return self._info("Select a server first.")
        node, idx = model.get_value(it, 2)
        if node != "server":
            return self._info("Select a server first.")
    
        cfg = self.servers[idx]
        self.current_logging_enabled = cfg.get("logging_enabled", False)
        self.current_log_path = cfg.get("log_path", "")
    
        self.log(f"Launching SSH: {cfg['name']}")
    
        # Build forwarding flags using -L/-R/-D syntax (avoids the -o parsing issue)
        forward_opts = []
        for rule in cfg.get("port_forwards", []):
            t = rule.get("type")
            if t == "Dynamic":
                forward_opts.append(f'-D {int(rule["source_port"])}')
            elif t == "Local":
                forward_opts.append(f'-L {int(rule["source_port"])}:{rule["dest_host"]}:{int(rule["dest_port"])}')
            elif t == "Remote":
                forward_opts.append(f'-R {int(rule["source_port"])}:{rule["dest_host"]}:{int(rule["dest_port"])}')
    
        auth      = cfg.get("auth_method")
        cmd_parts = ["spawn", "ssh"]
        if auth == "password":
            cmd_parts.append("-o PubkeyAuthentication=no")
        cmd_parts.append("-t")
        cmd_parts.extend(forward_opts)
        if auth == "key_file" and cfg.get("key_file"):
            cmd_parts.extend(["-i", cfg["key_file"]])
        cmd_parts.extend(["-p", str(cfg.get("port", 22))])
        cmd_parts.append(f'{cfg["user"]}@{cfg["host"]}')
    
        # First line: spawn ssh...
        lines = [" ".join(cmd_parts) + "\n", "log_user 1\n"]
    
        # Password prompt handling with timeout
        if auth == "password":
            lines.append('expect -timeout 5 "*assword:*" {\n')
            lines.append(f'    send -- "{cfg["password"]}\\r"\n')
            lines.append("    after 500\n")
            lines.append("} timeout {\n")
            lines.append("    # skip password prompt\n")
            lines.append("}\n")
    
        # Auto sequence steps with timeout and safe skip
        for step in cfg.get("auto_sequence", []):
            exp, snd = step["expect"], step["send"]
            lines.append(f'expect -timeout 1 "*{exp}*" {{\n')
            lines.append(f'    send -- "{snd}\\r"\n')
            lines.append("    after 500\n")
            lines.append("} timeout {\n")
            lines.append("    # no match, skip\n")
            lines.append("}\n")
    
        # Hand control to user
        lines.append("interact\n")
    
        self._launch_expect(lines, f"{cfg['name']} SSH", cfg)



    def on_sftp(self, action, param):
        model, it = self.tree.get_selection().get_selected()
        if not it:
            return self._info("Select a server first.")
        node, idx = model.get_value(it, 2)
        if node != "server":
            return self._info("Select a server first.")
    
        cfg = self.servers[idx]
        self.current_logging_enabled = cfg.get("logging_enabled", False)
        self.current_log_path = cfg.get("log_path", "")
    
        self.log(f"Launching SFTP: {cfg['name']}")
    
        auth       = cfg.get("auth_method")
        port       = cfg.get("port", 22)
    
        key_opt    = f"-i {cfg['key_file']}" if auth == "key_file" and cfg.get("key_file") else ""
        pubkey_opt = "-o PubkeyAuthentication=no" if auth == "password" else ""
        
        cmd_parts = ["spawn", "sftp", "-oBatchMode=no"]
        if pubkey_opt:
            cmd_parts.append(pubkey_opt)
        if key_opt:
            cmd_parts.extend(key_opt.split())
        cmd_parts.extend(["-P", str(port), f'{cfg["user"]}@{cfg["host"]}'])
        
        lines = [" ".join(cmd_parts) + "\n", "log_user 1\n"]
        
        if auth == "password" and cfg.get("password"):
            lines.append('expect -timeout 5 "*assword:*" {\n')
            lines.append(f'    send -- "{cfg["password"]}\\r"\n')
            lines.append("    after 500\n")
            lines.append("} timeout {\n")
            lines.append("    # skip password prompt\n")
            lines.append("}\n")
        
        for step in cfg.get("auto_sequence", []):
            exp, snd = step["expect"], step["send"]
            lines.append(f'expect -timeout 1 "*{exp}*" {{\n')
            lines.append(f'    send -- "{snd}\\r"\n')
            lines.append("    after 500\n")
            lines.append("} timeout {\n")
            lines.append("    # no match, skip\n")
            lines.append("}\n")
        
        lines.append("interact\n")
        self._launch_expect(lines, f"{cfg['name']} SFTP", cfg)



    # ── Generate & Launch Expect Script ───────────────────────────────────────
    def _launch_expect(self, lines, title, cfg):
        expect = shutil.which("expect")
        if not expect:
            return self._error("'expect' not found. Please install the 'expect' package.")

        # --- Create the expect script ---
        header = [
            "#!/usr/bin/env expect\n",
            "set env(TERM) \"xterm-256color\"\n", # Use a common TERM
        ]
        if getattr(self, "current_logging_enabled", False) and self.current_log_path:
            os.makedirs(os.path.dirname(self.current_log_path), exist_ok=True)
            header.append(f"log_file -a {self.current_log_path}\n")
        header.append("set timeout -1\n")
        script_content = "".join(header + lines)

        #NEW: RESIZE TRAP LOGIC
        # This Tcl code catches the Window Resize signal (WINCH) and
        # forces the inner SSH PTY to match the outer VTE PTY dimensions.
        resize_trap = [
            "\n# --- Sync Window Size with SSH ---\n",
            "trap {\n",
            "  set rows [stty rows]\n",
            "  set cols [stty columns]\n",
            "  stty rows $rows columns $cols < $spawn_out(slave,name)\n",
            "} WINCH\n\n"
        ]

        final_lines = list(lines)
        
        # We must insert the trap AFTER the 'spawn' command, because 
        # $spawn_out(slave,name) is only created after spawn runs.
        spawn_index = -1
        for i, line in enumerate(final_lines):
            if line.strip().startswith("spawn"):
                spawn_index = i
                break
        
        if spawn_index != -1:
            final_lines[spawn_index+1:spawn_index+1] = resize_trap
        else:
            # Fallback: append to header if no spawn found (unlikely)
            header.extend(resize_trap)
            
        script_content = "".join(header + final_lines)

        tf = None
        try:
            # Write script to a temporary file
            tf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".exp")
            tf.write(script_content)
            tf.close()
            os.chmod(tf.name, 0o700)

            # --- Create the VTE Terminal Window ---
            term_window = Gtk.Window(title=title)
            term_window.set_default_size(800, 600)
            term_window.set_modal(False) # Allows interaction with main window
            term_window.set_destroy_with_parent(True)

            terminal = Vte.Terminal()
            self.apply_appearance_to_terminal(terminal, cfg)
            # Connect the Key Press (for Ctrl+C/V)
            terminal.connect("key-press-event", self._on_terminal_key_press)
            #Right click menu
            terminal.connect("button-press-event", self._on_terminal_button_press)
            
            # This makes sure the temp file is deleted when the terminal exits
            def on_child_exited(_terminal, _status):
                term_window.close()
                if os.path.exists(tf.name):
                    os.remove(tf.name)
            
            terminal.connect("child-exited", on_child_exited)
            
            # Command to run: expect -f /path/to/temp/script.exp
            argv = [expect, "-f", tf.name]

            # Spawn the process in the VTE terminal
            terminal.spawn_sync(
                Vte.PtyFlags.DEFAULT,
                os.environ['HOME'],
                argv,
                [],
                GLib.SpawnFlags.DO_NOT_REAP_CHILD,
                None,
                None,
            )

            scrolled_window = Gtk.ScrolledWindow()
            scrolled_window.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
            scrolled_window.add(terminal)
            
            term_window.add(scrolled_window)
            term_window.show_all()
            
        except Exception as e:
            self._error(f"Failed to launch terminal: {e}")
            # Cleanup temp file on error
            if tf and os.path.exists(tf.name):
                os.remove(tf.name)

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
        dlg.set_default_response(Gtk.ResponseType.OK) # Set OK as default button
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
            version="1.2.0",
            authors=["Copilot, Gemini, Tomas Larsson"],
            artists=["Tomas Larsson"],
            comments="A GTK-based SSH/SFTP session manager"
        )
        about.run()
        about.destroy()
    def on_reset_disclaimer(self, action, param):
        self.settings["disclaimer_accepted"] = False
        save_settings(self.settings)
        self._info("Disclaimer will be shown again on next launch.")

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

            mi = Gtk.MenuItem(label="Copy Server")
            mi.connect("activate", lambda w: self.on_copy_server(None, None))
            menu.append(mi)
                
            mi = Gtk.MenuItem(label="Paste Server")
            mi.set_sensitive(hasattr(self, "_copied_server"))  # only if something copied
            mi.connect("activate", lambda w: self.on_paste_server(None, None))
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
            """
            Opens the user guide by starting a local web server and pointing
            the default browser to it.
            """
            self.log(f"Attempting to launch help guide via local web server.")
            
            # We need to keep a reference to the server, otherwise it might
            # get garbage collected in some Python versions.
            if not hasattr(self, "_help_server"):
                self._help_server = None
    
            # Start the server (or reuse if already running, though this simple
            # version starts a new one each time for simplicity).
            url, self._help_server = self._start_help_server()
    
            if url and self._help_server:
                try:
                    webbrowser.open_new(url)
                except Exception as e:
                    self._error(f"Failed to open the web browser.\n\nError: {e}")
                    self.log(f"webbrowser.open_new failed: {e}")
            else:
                self._error("Could not start the local help server to display the user guide.")

# ── Chunk 4: Add/Edit Server Dialog & Sequence Editor (with Hide/Mask Send) ────────────

    def _open_server_dialog(self, cfg=None, idx=None):
        is_edit = cfg is not None
    
        parent_window = self.win if hasattr(self, 'win') and self.win else None
        dlg = Gtk.Dialog(
            title="Edit Server" if is_edit else "Add Server",
            transient_for=parent_window,
            modal=True
        )
        dlg.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                        Gtk.STOCK_OK,     Gtk.ResponseType.OK)
        dlg.set_default_response(Gtk.ResponseType.OK)
        dlg.set_default_size(700, 600)
        dlg.set_resizable(True)
    
        content = dlg.get_content_area()
        nb = Gtk.Notebook()
        nb.set_hexpand(True)
        nb.set_vexpand(True)
        content.pack_start(nb, True, True, 0)
    
        # General tab
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
    
        # Auth tab
        auth_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, margin=10)
        nb.append_page(auth_page, Gtk.Label(label="Auth"))
    
        auth_pw  = Gtk.RadioButton.new_with_label(None, "Password")
        auth_key = Gtk.RadioButton.new_with_label_from_widget(auth_pw, "Key File")
    
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
    
        # Logging tab
        log_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, margin=10)
        nb.append_page(log_page, Gtk.Label(label="Logging"))
    
        log_enable = Gtk.CheckButton(label="Enable Logging")
        log_enable.set_active(cfg.get("logging_enabled", False) if cfg else False)
        log_entry = Gtk.Entry(); log_entry.set_size_request(300, -1)
        log_btn   = Gtk.Button(label="Browse")
        log_btn.connect("clicked", lambda w: browse_log(dlg, log_entry))
        log_box   = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        log_box.pack_start(log_entry, True, True, 0)
        log_box.pack_start(log_btn,   False, False, 0)
    
        log_page.pack_start(log_enable, False, False, 0)
        log_page.pack_start(log_box,    False, False, 0)
        log_entry.set_text(cfg.get("log_path", "/tmp/snapcm_log.txt") if cfg else "/tmp/snapcm_log.txt")
    
        # Login Actions tab
        seq_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, margin=10)
        nb.append_page(seq_page, Gtk.Label(label="Login Actions"))
    
        seq_store = Gtk.ListStore(str, str, bool)  # expect, send, hide
        seq_view = Gtk.TreeView(model=seq_store)
        seq_view.set_grid_lines(Gtk.TreeViewGridLines.BOTH)
    
        sw = Gtk.ScrolledWindow()
        sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sw.set_hexpand(True); sw.set_vexpand(True)
        sw.add(seq_view)
        seq_page.pack_start(sw, True, True, 0)
    
        def _exp_cell(col, renderer, model, it, data):
            renderer.set_property("text", model.get_value(it, 0))
    
        def _snd_cell(col, renderer, model, it, data):
            txt  = model.get_value(it, 1)
            hide = model.get_value(it, 2)
            renderer.set_property("text", "*" * len(txt) if hide else txt)
    
        for title, func in (("Expect", _exp_cell), ("Send", _snd_cell)):
            rnd = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(title, rnd)
            col.set_cell_data_func(rnd, func)
            col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
            col.set_fixed_width(165)
            seq_view.append_column(col)
    
        btn_box = Gtk.Box(spacing=6)
        btn_add  = Gtk.Button(label="Add")
        btn_edit = Gtk.Button(label="Edit")
        btn_del  = Gtk.Button(label="Delete")
        up_btn   = Gtk.Button(); up_btn.add(Gtk.Arrow(Gtk.ArrowType.UP, Gtk.ShadowType.NONE))
        dn_btn   = Gtk.Button(); dn_btn.add(Gtk.Arrow(Gtk.ArrowType.DOWN, Gtk.ShadowType.NONE))
    
        btn_add.connect("clicked", lambda w: self._open_seq_editor(dlg, seq_store, None))
        btn_edit.connect("clicked", lambda w: self._edit_seq_selected(seq_view, seq_store, dlg))
        btn_del.connect("clicked", lambda w: self._delete_seq_selected(seq_view, seq_store))
        up_btn.connect("clicked", lambda w: self._move_seq_up(seq_view, seq_store))
        dn_btn.connect("clicked", lambda w: self._move_seq_down(seq_view, seq_store))
    
        for b in (btn_add, btn_edit, btn_del, up_btn, dn_btn):
            btn_box.pack_start(b, False, False, 0)
        seq_page.pack_start(btn_box, False, False, 0)
    
        if cfg:
            for step in cfg.get("auto_sequence", []):
                seq_store.append([step["expect"], step["send"], step.get("hide", True)])
    
        # Port Forwarding tab
        fwd_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, margin=10)
        nb.append_page(fwd_page, Gtk.Label(label="Port Forwarding"))
    
        fwd_store = Gtk.ListStore(str, int, str, int, object)
        fwd_view = Gtk.TreeView(model=fwd_store)
        fwd_view.set_grid_lines(Gtk.TreeViewGridLines.BOTH)
    
        sw_fwd = Gtk.ScrolledWindow()
        sw_fwd.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sw_fwd.set_hexpand(True); sw_fwd.set_vexpand(True)
        sw_fwd.add(fwd_view)
        fwd_page.pack_start(sw_fwd, True, True, 0)
    
        for i, title in enumerate(["Type", "Source Port", "Destination Host", "Destination Port"]):
            renderer = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(title, renderer, text=i)
            fwd_view.append_column(col)
    
        fwd_btn_box = Gtk.Box(spacing=6)
        btn_add_fwd  = Gtk.Button(label="Add")
        btn_edit_fwd = Gtk.Button(label="Edit")
        btn_del_fwd  = Gtk.Button(label="Delete")
        fwd_btn_box.pack_start(btn_add_fwd,  False, False, 0)
        fwd_btn_box.pack_start(btn_edit_fwd, False, False, 0)
        fwd_btn_box.pack_start(btn_del_fwd,  False, False, 0)
        fwd_page.pack_start(fwd_btn_box, False, False, 0)
    
        btn_add_fwd.connect("clicked", lambda w: self._add_edit_forward_rule(dlg, fwd_store))
        btn_edit_fwd.connect("clicked", lambda w: self._add_edit_forward_rule(dlg, fwd_store, fwd_view))
        btn_del_fwd.connect("clicked", lambda w: self._delete_selected_from_view(fwd_view, fwd_store))
    
        if cfg:
            for rule in cfg.get("port_forwards", []):
                fwd_store.append([
                    rule["type"],
                    int(rule["source_port"]),
                    rule.get("dest_host", ""),
                    int(rule.get("dest_port", 0)),
                    rule
                ])

        # ── Appearance tab (Grid layout for alignment) ───────────────────────────────
        app_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin=12)
        nb.append_page(app_page, Gtk.Label(label="Appearance"))
        
        grid = Gtk.Grid(column_spacing=12, row_spacing=8)
        app_page.pack_start(grid, False, False, 0)
        
        row = 0
        
        # Palette
        lbl_palette = Gtk.Label(); lbl_palette.set_markup("<b>Palette:</b>")
        lbl_palette.set_halign(Gtk.Align.START)
        pal_cb = Gtk.ComboBoxText(); pal_cb.set_size_request(240, -1)
        for p in ["None", "Tango", "Solarized Light", "Solarized Dark", "GNOME"]:
            pal_cb.append_text(p)
        grid.attach(lbl_palette, 0, row, 1, 1)
        grid.attach(pal_cb,     1, row, 1, 1)
        row += 1
        
        # Color scheme
        lbl_scheme = Gtk.Label(); lbl_scheme.set_markup("<b>Color scheme:</b>")
        lbl_scheme.set_halign(Gtk.Align.START)
        scheme_cb = Gtk.ComboBoxText(); scheme_cb.set_size_request(240, -1)
        for name in BUILTIN_SCHEMES.keys():
            scheme_cb.append_text(name)
        grid.attach(lbl_scheme, 0, row, 1, 1)
        grid.attach(scheme_cb,  1, row, 1, 1)
        row += 1
        
        # Text color
        lbl_fg = Gtk.Label(label="Text color:"); lbl_fg.set_halign(Gtk.Align.START)
        btn_fg = Gtk.ColorButton(); btn_fg.set_use_alpha(False)
        grid.attach(lbl_fg, 0, row, 1, 1)
        grid.attach(btn_fg, 1, row, 1, 1)
        row += 1
        
        # Background
        lbl_bg = Gtk.Label(label="Background:"); lbl_bg.set_halign(Gtk.Align.START)
        btn_bg = Gtk.ColorButton(); btn_bg.set_use_alpha(False)
        grid.attach(lbl_bg, 0, row, 1, 1)
        grid.attach(btn_bg, 1, row, 1, 1)
        row += 1
        
        # Font
        lbl_font = Gtk.Label(); lbl_font.set_markup("<b>Font:</b>")
        lbl_font.set_halign(Gtk.Align.START)
        en_font = Gtk.Entry(); en_font.set_size_request(240, -1)
        btn_font = Gtk.Button(label="Select")
        
        def on_choose_font(_btn):
            parent_window = dlg if dlg else (self.win if hasattr(self, 'win') and self.win else None)
            fd = Gtk.FontChooserDialog(title="Select Font", transient_for=parent_window)
            current = en_font.get_text().strip()
            if current:
                try: fd.set_font(current)
                except Exception: pass
            if fd.run() == Gtk.ResponseType.OK:
                en_font.set_text(fd.get_font())
            fd.destroy()
        
        btn_font.connect("clicked", on_choose_font)
        font_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        font_box.pack_start(en_font, False, False, 0)
        font_box.pack_start(btn_font, False, False, 0)
        grid.attach(lbl_font, 0, row, 1, 1)
        grid.attach(font_box, 1, row, 1, 1)
        row += 1
        
        # Buffer
        lbl_buf = Gtk.Label(); lbl_buf.set_markup("<b>Buffer:</b>")
        lbl_buf.set_halign(Gtk.Align.START)
        spin_buf = Gtk.SpinButton.new_with_range(100, 100000, 100)
        buf_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        buf_box.pack_start(Gtk.Label(label="Lines:"), False, False, 0)
        buf_box.pack_start(spin_buf, False, False, 0)
        grid.attach(lbl_buf, 0, row, 1, 1)
        grid.attach(buf_box, 1, row, 1, 1)
        row += 1
        
        # Defaults
        lbl_defaults = Gtk.Label(); lbl_defaults.set_markup("<b>Defaults:</b>")
        lbl_defaults.set_halign(Gtk.Align.START)
        btn_reset = Gtk.Button(label="Reset to Defaults")
        
        def on_reset_defaults(_):
            en_font.set_text(getattr(self, "DEFAULT_TERM_FONT", "Ubuntu Mono 12"))
            fg = Gdk.RGBA(); fg.parse(getattr(self, "DEFAULT_TERM_FG", "#000000")); btn_fg.set_rgba(fg)
            bg = Gdk.RGBA(); bg.parse(getattr(self, "DEFAULT_TERM_BG", "#FFFFDD")); btn_bg.set_rgba(bg)
            pal_default = getattr(self, "DEFAULT_TERM_PALETTE", "None")
            try:
                pal_cb.set_active(["None", "Tango", "Solarized Light", "Solarized Dark", "GNOME"].index(pal_default))
            except ValueError:
                pal_cb.set_active(0)
            spin_buf.set_value(getattr(self, "DEFAULT_TERM_SCROLLBACK", 1000))
            try:
                idx_scheme = list(BUILTIN_SCHEMES.keys()).index("Black on light yellow")
            except Exception:
                idx_scheme = 0
            scheme_cb.set_active(idx_scheme)
        
        btn_reset.connect("clicked", on_reset_defaults)
        grid.attach(lbl_defaults, 0, row, 1, 1)
        grid.attach(btn_reset,   1, row, 1, 1)
        row += 1
        
        # --- Pre-fill when editing ---
        if cfg:
            en_font.set_text(cfg.get("term_font", getattr(self, "DEFAULT_TERM_FONT", "Ubuntu Mono 12")))
            fg = Gdk.RGBA(); fg.parse(cfg.get("term_fg", getattr(self, "DEFAULT_TERM_FG", "#000000"))); btn_fg.set_rgba(fg)
            bg = Gdk.RGBA(); bg.parse(cfg.get("term_bg", getattr(self, "DEFAULT_TERM_BG", "#FFFFDD"))); btn_bg.set_rgba(bg)
            pal = cfg.get("term_palette", getattr(self, "DEFAULT_TERM_PALETTE", "None"))
            try:
                pal_cb.set_active(["None", "Tango", "Solarized Light", "Solarized Dark", "GNOME"].index(pal))
            except ValueError:
                pal_cb.set_active(0)
            spin_buf.set_value(int(cfg.get("term_scrollback", getattr(self, "DEFAULT_TERM_SCROLLBACK", 1000))))
            scheme_name = cfg.get("term_scheme")
            if scheme_name and scheme_name in BUILTIN_SCHEMES:
                scheme_cb.set_active(list(BUILTIN_SCHEMES.keys()).index(scheme_name))
            else:
                scheme_cb.set_active(list(BUILTIN_SCHEMES.keys()).index("Custom"))
        if not cfg:
            # Font
            en_font.set_text(DEFAULT_TERM_FONT)
        
            # Colors
            fg = Gdk.RGBA(); fg.parse(DEFAULT_TERM_FG); btn_fg.set_rgba(fg)
            bg = Gdk.RGBA(); bg.parse(DEFAULT_TERM_BG); btn_bg.set_rgba(bg)
        
            # Palette
            try:
                pal_cb.set_active(["None", "Tango", "Solarized Light", "Solarized Dark", "GNOME"].index(DEFAULT_TERM_PALETTE))
            except ValueError:
                pal_cb.set_active(0)
        
            # Buffer
            spin_buf.set_value(DEFAULT_TERM_SCROLLBACK)
        
            # Scheme
            try:
                idx_scheme = list(BUILTIN_SCHEMES.keys()).index(DEFAULT_TERM_SCHEME)
            except Exception:
                idx_scheme = 0
            scheme_cb.set_active(idx_scheme)



        
        # --- Scheme change handler ---
        def on_scheme_changed(cb):
            idx = cb.get_active()
            if idx is None or idx < 0: return
            name = list(BUILTIN_SCHEMES.keys())[idx]
            scheme = BUILTIN_SCHEMES.get(name)
            if scheme:
                fg = Gdk.RGBA(); fg.parse(scheme.get("term_fg", btn_fg.get_rgba().to_string())); btn_fg.set_rgba(fg)
                bg = Gdk.RGBA(); bg.parse(scheme.get("term_bg", btn_bg.get_rgba().to_string())); btn_bg.set_rgba(bg)
                pal = scheme.get("term_palette")
                if pal and pal != "None":
                    try:
                        pal_idx = ["None", "Tango", "Solarized Light", "Solarized Dark", "GNOME"].index(pal)
                    except ValueError:
                        pal_idx = 0
                    pal_cb.set_active(pal_idx)
        
        scheme_cb.connect("changed", on_scheme_changed)
        
        # Validation loop
        center(dlg)
        result = None
    
        while True:
            resp = dlg.run()
            if resp != Gtk.ResponseType.OK:
                break
    
            name = en_name.get_text().strip()
            if not name:
                self._error("Server Name is required.")
                continue
    
            result = {
                "name":         name,
                "host":         en_host.get_text().strip(),
                "port":         int(en_port.get_text().strip()),
                "user":         en_user.get_text().strip(),
                "folder":       folder_cb.get_active_text(),
                "auth_method":  "password" if auth_pw.get_active() else "key_file",
                "password":     pw_entry.get_text().strip(),
                "key_file":     key_entry.get_text().strip(),
                "logging_enabled": log_enable.get_active(),
                "log_path":        log_entry.get_text().strip(),
                "auto_sequence": [
                    {"expect": seq_store[i][0], "send": seq_store[i][1], "hide": seq_store[i][2]}
                    for i in range(len(seq_store))
                ],
                "port_forwards": []
            }
    
            # Read final appearance values directly from widgets
            result["term_font"] = en_font.get_text().strip()
            result["term_fg"]   = btn_fg.get_rgba().to_string()
            result["term_bg"]   = btn_bg.get_rgba().to_string()
            result["term_palette"]    = pal_cb.get_active_text() or "None"
            result["term_scrollback"] = spin_buf.get_value_as_int()
            result["term_scheme"] = scheme_cb.get_active_text() or "Custom"
    
            for i in range(len(fwd_store)):
                rule = fwd_store[i][4]
                if rule["type"] == "Dynamic":
                    result["port_forwards"].append({
                        "type": "Dynamic",
                        "source_port": int(rule["source_port"])
                    })
                else:
                    result["port_forwards"].append({
                        "type": rule["type"],
                        "source_port": int(rule["source_port"]),
                        "dest_host": rule.get("dest_host", "localhost"),
                        "dest_port": int(rule.get("dest_port", 0)),
                    })
    
            break
    
        dlg.destroy()
    
        if result:
            if result["logging_enabled"]:
                os.makedirs(os.path.dirname(result["log_path"]), exist_ok=True)
                if not os.path.exists(result["log_path"]):
                    open(result["log_path"], "w").close()
    
            if is_edit:
                self.servers[idx] = result
                self.log(f"Edited '{result['name']}'")
            else:
                self.servers.append(result)
                self.log(f"Added '{result['name']}'")
    
            try:
                save_servers(self.servers, self.master_passphrase)
            except Exception as e:
                self._error(f"Failed to save servers after add/edit: {e}")
    
            self.reload_folders()
            self.populate_tree()
            self.tree.expand_row(Gtk.TreePath.new_from_string("0"), False)

    def _add_edit_forward_rule(self, parent, store, view=None):
        """Add a new port forward rule, or edit the selected one."""
        rule_to_edit = None
        tree_iter = None
        if view:
            model, paths = view.get_selection().get_selected_rows()
            if not paths:
                return
            tree_iter = store.get_iter(paths[0])
            rule_to_edit = store.get_value(tree_iter, 4)
    
        dlg = Gtk.Dialog(
            title="Edit Forwarding Rule" if rule_to_edit else "Add Forwarding Rule",
            transient_for=parent,
            modal=True
        )
        dlg.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                        Gtk.STOCK_OK,     Gtk.ResponseType.OK)
    
        grid = Gtk.Grid(column_spacing=6, row_spacing=6, margin=10)
        dlg.get_content_area().add(grid)
    
        # Type
        grid.attach(Gtk.Label(label="Type:", halign=Gtk.Align.START), 0, 0, 1, 1)
        type_cb = Gtk.ComboBoxText()
        for t in ("Local", "Remote", "Dynamic"):
            type_cb.append_text(t)
        type_cb.set_active(0)
        grid.attach(type_cb, 1, 0, 1, 1)
    
        # Source Port
        grid.attach(Gtk.Label(label="Source Port:", halign=Gtk.Align.START), 0, 1, 1, 1)
        src_port_spin = Gtk.SpinButton.new_with_range(1, 65535, 1)
        grid.attach(src_port_spin, 1, 1, 1, 1)
    
        # Destination Host
        grid.attach(Gtk.Label(label="Destination Host:", halign=Gtk.Align.START), 0, 2, 1, 1)
        dest_host_entry = Gtk.Entry(text="localhost")
        grid.attach(dest_host_entry, 1, 2, 1, 1)
    
        # Destination Port
        grid.attach(Gtk.Label(label="Destination Port:", halign=Gtk.Align.START), 0, 3, 1, 1)
        dest_port_spin = Gtk.SpinButton.new_with_range(1, 65535, 1)
        grid.attach(dest_port_spin, 1, 3, 1, 1)
    
        # Disable dest fields if Dynamic selected
        def update_dest_visibility(*_):
            is_dynamic = (type_cb.get_active_text() == "Dynamic")
            dest_host_entry.set_sensitive(not is_dynamic)
            dest_port_spin.set_sensitive(not is_dynamic)
        type_cb.connect("changed", update_dest_visibility)
        update_dest_visibility()
    
        if rule_to_edit:
            type_cb.set_active({"Local": 0, "Remote": 1, "Dynamic": 2}[rule_to_edit.get("type", "Local")])
            src_port_spin.set_value(rule_to_edit.get("source_port", 1080))
            dest_host_entry.set_text(rule_to_edit.get("dest_host", "localhost"))
            dest_port_spin.set_value(rule_to_edit.get("dest_port", 80))
            update_dest_visibility()
    
        dlg.show_all()
        if dlg.run() == Gtk.ResponseType.OK:
            t = type_cb.get_active_text()
            rule = {"type": t, "source_port": int(src_port_spin.get_value())}
            if t != "Dynamic":
                rule["dest_host"] = dest_host_entry.get_text().strip() or "localhost"
                rule["dest_port"] = int(dest_port_spin.get_value())
    
            row = [rule["type"], rule["source_port"], rule.get("dest_host",""), rule.get("dest_port",0), rule]
            if tree_iter:
                store.set(tree_iter, [0,1,2,3,4], row)
            else:
                store.append(row)
        dlg.destroy()
    
    
    def _delete_selected_from_view(self, view, store):
        """Delete the currently selected rows from a Gtk.TreeView/ListStore."""
        model, paths = view.get_selection().get_selected_rows()
        for p in sorted(paths, reverse=True):
            it = store.get_iter(p)
            store.remove(it)
    

    

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
            snd_txt = ent_snd.get_text()
            hide_fl = mask_chk.get_active()
            if tree_iter:
                seq_store.set(tree_iter, [0,1,2], [exp_txt, snd_txt, hide_fl])
            else:
                seq_store.append([exp_txt, snd_txt, hide_fl])
    
        dlg.destroy()

    def on_copy_server(self, action, param):
        model, it = self.tree.get_selection().get_selected()
        if not it:
            return self._info("Select a server to copy.")
        node, idx = model.get_value(it, 2)
        if node != "server":
            return self._info("Select a server to copy.")
        # Make a deep copy to avoid mutating original
        import copy
        self._copied_server = copy.deepcopy(self.servers[idx])
        self.log(f"Copied server '{self._copied_server['name']}' to clipboard.")
    
    def on_paste_server(self, action, param):
        if not hasattr(self, "_copied_server"):
            return self._info("No server copied.")
        # Determine target folder from selection
        folder = ROOT_FOLDER
        model, it = self.tree.get_selection().get_selected()
        if it:
            node, val = model.get_value(it, 2)
            if node == "folder":
                folder = val
            elif node == "server":
                # same folder as selected server
                folder = self.servers[val].get("folder", ROOT_FOLDER)
        import copy
        new_srv = copy.deepcopy(self._copied_server)
        # Ensure new name is unique
        base_name = new_srv["name"]
        existing_names = {s["name"] for s in self.servers}
        suffix = 1
        while new_srv["name"] in existing_names:
            new_srv["name"] = f"{base_name} Copy {suffix}"
            suffix += 1
        new_srv["folder"] = folder
        self.servers.append(new_srv)
        try:
            save_servers(self.servers, self.master_passphrase)
        except Exception as e:
            return self._error(f"Failed to save after paste: {e}")
        self.reload_folders()
        self.populate_tree()
        self.tree.expand_row(Gtk.TreePath.new_from_string("0"), False)
        self.log(f"Pasted server as '{new_srv['name']}' into folder '{folder}'.")

    def apply_appearance_to_terminal(self, terminal, cfg):
        """Apply font, colors, palette and scrollback to a Vte.Terminal."""
    
        # --- Font ---
        fontname = cfg.get("term_font", DEFAULT_TERM_FONT)
        if fontname:
            try:
                desc = Pango.FontDescription(fontname)
                terminal.set_font(desc)
            except Exception as e:
                self.log(f"Could not set font '{fontname}': {e}")
    
        # --- Foreground / Background ---
        fg = Gdk.RGBA(); fg.parse(cfg.get("term_fg", DEFAULT_TERM_FG))
        bg = Gdk.RGBA(); bg.parse(cfg.get("term_bg", DEFAULT_TERM_BG))
          
        # --- Palette selection ---
        pal_name = cfg.get("term_palette", DEFAULT_TERM_PALETTE)
        palette = []
    
        if pal_name == "Tango":
            # Tango 16‑color palette
            tango_hex = [
                "#2e3436", "#cc0000", "#4e9a06", "#c4a000",
                "#3465a4", "#75507b", "#06989a", "#d3d7cf",
                "#555753", "#ef2929", "#8ae234", "#fce94f",
                "#729fcf", "#ad7fa8", "#34e2e2", "#eeeeec",
            ]
            palette = [Gdk.RGBA() for _ in tango_hex]
            for i, h in enumerate(tango_hex):
                palette[i].parse(h)
    
        elif pal_name == "Solarized Light":
            solarized_light_hex = [
                "#073642", "#dc322f", "#859900", "#b58900",
                "#268bd2", "#d33682", "#2aa198", "#eee8d5",
                "#002b36", "#cb4b16", "#586e75", "#657b83",
                "#839496", "#6c71c4", "#93a1a1", "#fdf6e3",
            ]
            palette = [Gdk.RGBA() for _ in solarized_light_hex]
            for i, h in enumerate(solarized_light_hex):
                palette[i].parse(h)
    
        elif pal_name == "Solarized Dark":
            solarized_dark_hex = [
                "#073642", "#dc322f", "#859900", "#b58900",
                "#268bd2", "#d33682", "#2aa198", "#eee8d5",
                "#002b36", "#cb4b16", "#586e75", "#657b83",
                "#839496", "#6c71c4", "#93a1a1", "#fdf6e3",
            ]
            palette = [Gdk.RGBA() for _ in solarized_dark_hex]
            for i, h in enumerate(solarized_dark_hex):
                palette[i].parse(h)
    
        # "None" or unknown → leave palette empty to use VTE defaults
    
        # --- Apply colors ---
        try:
            terminal.set_colors(fg, bg, palette)
        except Exception as e:
            self.log(f"Could not set colors: {e}")
    
        # --- Scrollback ---
        terminal.set_scrollback_lines(cfg.get("term_scrollback", DEFAULT_TERM_SCROLLBACK))

    def _on_terminal_key_press(self, terminal, event):
            """
            Handles Ctrl+C (Smart Copy) and Ctrl+V (Paste) in the terminal.
            """
            # Check if Control key is held down
            if event.state & Gdk.ModifierType.CONTROL_MASK:
                
                # --- Handle Ctrl+C ---
                if event.keyval == Gdk.KEY_c:
                    # Smart Copy: Only copy if there is an active selection.
                    # If no selection, return False to let the default SIGINT (Interrupt) happen.
                    if terminal.get_has_selection():
                        terminal.copy_clipboard_format(Vte.Format.TEXT)
                        return True # Return True to consume the event (block SIGINT)
                
                # --- Handle Ctrl+V ---
                elif event.keyval == Gdk.KEY_v:
                    terminal.paste_clipboard()
                    return True # Return True to consume the event (block literal insert)
    
            # For all other keys, return False to let VTE handle them normally
            return False

    def _on_terminal_button_press(self, terminal, event):
            """
            Handles mouse clicks to show a context menu on right-click.
            """
            from gi.repository import Gdk
            
            # Check for Right Click (Button 3)
            if event.type == Gdk.EventType.BUTTON_PRESS and event.button == 3:
                menu = Gtk.Menu()
    
                # ── Copy Item ──
                # Only enable "Copy" if there is text selected
                copy_item = Gtk.MenuItem(label="Copy")
                if terminal.get_has_selection():
                    copy_item.set_sensitive(True)
                    copy_item.connect("activate", lambda w: terminal.copy_clipboard_format(Vte.Format.TEXT))
                else:
                    copy_item.set_sensitive(False)
                menu.append(copy_item)
    
                # ── Paste Item ──
                paste_item = Gtk.MenuItem(label="Paste")
                paste_item.connect("activate", lambda w: terminal.paste_clipboard())
                menu.append(paste_item)
    
                # ── Show Menu ──
                menu.show_all()
                # Use popup_at_pointer for modern GTK (3.22+)
                menu.popup_at_pointer(event)
                
                return True # Return True to stop other handlers from processing the click
            
            return False

# ── main() ─────────────────────────────────────────────────────────────────────────────

def main():
    app = SnapConnectionManager()
    import sys
    sys.exit(app.run(sys.argv))


if __name__ == "__main__":
    main()
