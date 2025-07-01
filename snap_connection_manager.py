#!/usr/bin/env python3
"""
Snap Connection Manager v1.6.5

– Foldered server list (ttk.Treeview + context menus)  
– Add/Edit/Delete servers with folder selection  
– SSH/SFTP launched via snap- or apt-installed Expect via here-doc  
– RoundedEntry inputs, Ubuntu 12 font  
– Persists geometry, folders, servers in JSON  
– Renamed log widget/method to avoid name collision
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import subprocess, json, shutil

FONT           = ("Ubuntu", 12)
APP_TITLE      = "Snap Connection Manager"
SERVER_FILE    = "ssh_servers.json"
SETTINGS_FILE  = "snap_cm_settings.json"
UNCAT_FOLDER   = "Uncategorized"


class RoundedEntry(tk.Canvas):
    """Entry with true rounded-corner grey border."""
    def __init__(self, master, width=200, height=28, radius=6,
                 border_color="#cccccc", border_width=1,
                 bg_color=None, fg_color="#ffffff", **entry_kwargs):
        bg = bg_color or master["bg"]
        total_h = height + border_width * 2
        super().__init__(master, width=width, height=total_h,
                         bg=bg, highlightthickness=0)
        r, w, h = radius, width, total_h

        # white fill
        self.create_rectangle(r,   0, w-r,   h,   fill=fg_color, outline=fg_color)
        self.create_rectangle(0,   r, w,     h-r, fill=fg_color, outline=fg_color)
        for cx, cy in ((0,0), (w-2*r,0), (0,h-2*r), (w-2*r,h-2*r)):
            self.create_oval(cx, cy, cx+2*r, cy+2*r,
                             fill=fg_color, outline=fg_color)

        # grey border
        self._draw_border(0, 0, w, h, r, border_color, border_width)

        # embed Entry
        inset = r + border_width
        ent_w, ent_h = w - 2*inset, h - 2*inset
        self.entry = tk.Entry(self, bd=0, bg=fg_color,
                              highlightthickness=0, **entry_kwargs)
        self.create_window((inset, inset), window=self.entry,
                           anchor="nw", width=ent_w, height=ent_h)

    def _draw_border(self, x1, y1, x2, y2, r, col, w):
        # corner arcs
        self.create_arc(x1, y1,   x1+2*r, y1+2*r, start=90,  extent=90,
                        style="arc", outline=col, width=w)
        self.create_arc(x2-2*r, y1, x2,     y1+2*r, start=0,   extent=90,
                        style="arc", outline=col, width=w)
        self.create_arc(x2-2*r, y2-2*r, x2, y2,    start=270, extent=90,
                        style="arc", outline=col, width=w)
        self.create_arc(x1,     y2-2*r, x1+2*r, y2, start=180, extent=90,
                        style="arc", outline=col, width=w)
        # edges
        self.create_line(x1+r, y1,   x2-r, y1,   fill=col, width=w)
        self.create_line(x2,   y1+r, x2,   y2-r, fill=col, width=w)
        self.create_line(x1+r, y2,   x2-r, y2,   fill=col, width=w)
        self.create_line(x1,   y1+r, x1,   y2-r, fill=col, width=w)

    # proxy methods
    def insert(self, idx, s):             return self.entry.insert(idx, s)
    def get(self):                        return self.entry.get()
    def delete(self, first, last=None):   return self.entry.delete(first, last)
    def bind(self, sequence, func, add=None):
        return self.entry.bind(sequence, func, add)


def make_entry(master, initial="", width=260, **kwargs):
    """Create a RoundedEntry with Ubuntu12 font + Ctrl+V paste."""
    kwargs.setdefault("font", FONT)
    r = RoundedEntry(master, width=width, height=28, radius=6, **kwargs)
    if initial:
        r.insert(0, initial)
    r.bind("<Control-v>", lambda e: r.entry.event_generate("<<Paste>>"))
    return r


def load_settings():
    try:
        return json.load(open(SETTINGS_FILE))
    except:
        return {}

def save_settings(settings):
    try:
        json.dump(settings, open(SETTINGS_FILE, "w"), indent=4)
    except:
        pass

def center(win, parent=None):
    win.update_idletasks()
    w, h = win.winfo_width(), win.winfo_height()
    if parent:
        px, py = parent.winfo_x(), parent.winfo_y()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        x = px + (pw - w)//2
        y = py + (ph - h)//2
    else:
        sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
        x = (sw - w)//2
        y = (sh - h)//2
    win.geometry(f"+{x}+{y}")

def setup_styles(root):
    s = ttk.Style(root); s.theme_use("clam")
    root.configure(bg="#f6f6f6")
    s.configure(".", background="#f6f6f6", foreground="#333333", font=FONT)
    s.configure("TLabel", background="#f6f6f6", font=FONT)
    s.configure("TLabelframe", background="#f6f6f6", borderwidth=0)
    s.configure("TButton", relief="flat", padding=5, background="#f6f6f6")
    s.map("TButton", background=[("active","#e0e0e0"),("!active","#f6f6f6")])

def browse_key(parent, entry):
    p = filedialog.askopenfilename(title="Select private key", parent=parent)
    if p:
        entry.delete(0, tk.END)
        entry.insert(0, p)

def browse_log(parent, entry):
    p = filedialog.asksaveasfilename(title="Select log file", parent=parent)
    if p:
        entry.delete(0, tk.END)
        entry.insert(0, p)


def load_servers(fp):
    try:
        data = json.load(open(fp))
        for s in data:
            if not all(k in s for k in ("name","host","port","user","auth_method")):
                raise ValueError("Invalid entry")
            s.setdefault("auto_sequence", [])
            s.setdefault("folder", UNCAT_FOLDER)
        return data
    except FileNotFoundError:
        return []
    except Exception as ex:
        messagebox.showerror("Error", f"Could not load servers:\n{ex}")
        return []

def save_servers(data, fp):
    try:
        json.dump(data, open(fp, "w"), indent=4)
    except Exception as ex:
        messagebox.showerror("Error", f"Could not save servers:\n{ex}")


class SSHClientGUI:
    def __init__(self, root):
        self.root     = root
        self.settings = load_settings()
        self.servers  = load_servers(SERVER_FILE)

        root.withdraw()
        root.title(APP_TITLE)
        setup_styles(root)
        self._build_gui()

        self._reload_folders()
        self._populate_tree()

        geom = self.settings.get("main_geometry")
        if geom:
            root.geometry(geom)
        else:
            center(root)

        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.deiconify()

    def on_close(self):
        self.settings["main_geometry"] = self.root.geometry()
        save_settings(self.settings)
        self.root.destroy()

    def _build_gui(self):
        sf = ttk.Labelframe(self.root, text="Saved Servers")
        sf.pack(fill="both", expand=True, padx=10, pady=5)

        self.tree = ttk.Treeview(sf, show="tree")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<Double-1>", self._on_double)
        self.tree.bind("<Button-3>",   self._on_right)
        sb = ttk.Scrollbar(sf, command=self.tree.yview)
        sb.pack(side="right", fill="y")
        self.tree.config(yscrollcommand=sb.set)

        bf = tk.Frame(self.root, bg="#f6f6f6")
        bf.pack(pady=5)
        for txt, cmd in [
            ("Add",    self.add_server),
            ("Edit",   self.edit_server),
            ("Delete", self.delete_server),
            ("SSH",    self.connect_to_ssh),
            ("SFTP",   self.connect_to_sftp),
        ]:
            ttk.Button(bf, text=txt, width=8, command=cmd).pack(side="left", padx=5)

        lf = ttk.Labelframe(self.root, text="Log")
        lf.pack(fill="both", expand=True, padx=10, pady=5)
        li = tk.Frame(lf, bg="#f6f6f6")
        li.pack(fill="both", expand=True)

        self.log_widget = tk.Text(
            li, font=FONT, bg="#ffffff",
            relief="flat", state="disabled", height=6
        )
        self.log_widget.pack(side="left", fill="both", expand=True)
        sb2 = ttk.Scrollbar(li, command=self.log_widget.yview)
        sb2.pack(side="right", fill="y")
        self.log_widget.config(yscrollcommand=sb2.set)

    # ─── Folders & Tree ─────────────────────────────────────────────────
    def _reload_folders(self):
        names = {s.get("folder", UNCAT_FOLDER) for s in self.servers}
        names.add(UNCAT_FOLDER)
        self.folders = sorted(names)

    def _populate_tree(self):
        self.tree.delete(*self.tree.get_children())
        for fld in self.folders:
            fid = f"folder::{fld}"
            self.tree.insert("", "end", fid, text=fld, open=True)
            for idx, s in enumerate(self.servers):
                if s.get("folder") == fld:
                    sid = f"server::{idx}"
                    self.tree.insert(fid, "end", sid, text=s["name"])

    def _on_double(self, event):
        sel = self.tree.selection()
        if sel and sel[0].startswith("server::"):
            self.connect_to_ssh()

    def _on_right(self, event):
        iid = self.tree.identify_row(event.y)
        self.tree.selection_set(iid)
        menu = tk.Menu(self.root, tearoff=0)
        if not iid:
            menu.add_command(label="New Folder", command=self._new_folder)
            menu.add_command(label="Add",        command=self.add_server)
        elif iid.startswith("folder::"):
            fld = iid.split("::",1)[1]
            menu.add_command(label="New Folder",    command=self._new_folder)
            menu.add_command(label="Rename Folder", command=lambda f=fld: self._rename_folder(f))
            menu.add_command(label="Delete Folder", command=lambda f=fld: self._delete_folder(f))
            menu.add_separator()
            menu.add_command(label="Add",            command=self.add_server)
        else:
            menu.add_command(label="Edit",   command=self.edit_server)
            menu.add_command(label="Delete", command=self.delete_server)
            menu.add_separator()
            mv = tk.Menu(menu, tearoff=0)
            for f in self.folders:
                mv.add_command(label=f, command=lambda f=f: self._move_to_folder(f))
            menu.add_cascade(label="Move To", menu=mv)

        menu.post(event.x_root, event.y_root)

    def _new_folder(self):
        name = simpledialog.askstring("New Folder", "Name:", parent=self.root)
        if name and name not in self.folders:
            self.folders.append(name)
            self.folders.sort()
            self._populate_tree()

    def _rename_folder(self, old):
        new = simpledialog.askstring(
            "Rename Folder", "New name:", initialvalue=old, parent=self.root
        )
        if new and new != old and new not in self.folders:
            for s in self.servers:
                if s.get("folder") == old:
                    s["folder"] = new
            save_servers(self.servers, SERVER_FILE)
            self._reload_folders()
            self._populate_tree()

    def _delete_folder(self, fld):
        if fld == UNCAT_FOLDER:
            messagebox.showwarning(
                "Cannot delete", "Cannot delete Uncategorized.", parent=self.root
            )
            return
        if messagebox.askyesno(
            "Delete Folder",
            f"Delete folder '{fld}'? Move servers to {UNCAT_FOLDER}.",
            parent=self.root
        ):
            for s in self.servers:
                if s.get("folder") == fld:
                    s["folder"] = UNCAT_FOLDER
            save_servers(self.servers, SERVER_FILE)
            self._reload_folders()
            self._populate_tree()

    def _move_to_folder(self, folder):
        sel = self.tree.selection()
        if sel and sel[0].startswith("server::"):
            idx = int(sel[0].split("::",1)[1])
            self.servers[idx]["folder"] = folder
            save_servers(self.servers, SERVER_FILE)
            self._reload_folders()
            self._populate_tree()

    # ─── CRUD ───────────────────────────────────────────────────────────
    def add_server(self):
        self._edit_flow(edit=False)

    def edit_server(self):
        sel = self.tree.selection()
        if not sel or not sel[0].startswith("server::"):
            messagebox.showwarning("Select server", parent=self.root)
            return
        self._edit_flow(edit=True)

    def delete_server(self):
        sel = self.tree.selection()
        if not sel or not sel[0].startswith("server::"):
            messagebox.showwarning("Select server", parent=self.root)
            return
        idx = int(sel[0].split("::",1)[1])
        name = self.servers[idx]["name"]
        if messagebox.askyesno("Delete Server", f"Delete '{name}'?", parent=self.root):
            del self.servers[idx]
            save_servers(self.servers, SERVER_FILE)
            self._reload_folders()
            self._populate_tree()
            self.log_msg(f"Deleted '{name}'")

    def _edit_flow(self, edit):
        cfg, idx = None, None
        if edit:
            sel = self.tree.selection()[0]
            idx = int(sel.split("::",1)[1])
            cfg = self.servers[idx]

        new = self._open_dialog(cfg)
        if not new:
            return

        if edit:
            self.servers[idx] = new
            self.log_msg(f"Edited '{cfg['name']}'")
        else:
            self.servers.append(new)
            self.log_msg(f"Added '{new['name']}'")

        save_servers(self.servers, SERVER_FILE)
        self._reload_folders()
        self._populate_tree()

    # ─── Dialog & Sequence Editor ─────────────────────────────────────
    def _open_dialog(self, cfg=None):
        server_result = None
        dlg = tk.Toplevel(self.root)
        dlg.withdraw()
        dlg.transient(self.root)
        dlg.grab_set()
        setup_styles(dlg)
        dlg.title("Server Details")

        # freeze parent
        rx, ry = self.root.winfo_x(), self.root.winfo_y()
        try:
            self.root.attributes("-disabled", True)
            using_attr = True
        except:
            self.root.bind("<Configure>", lambda e: self.root.geometry(f"+{rx}+{ry}"))
            using_attr = False

        def release():
            if using_attr:
                try:
                    self.root.attributes("-disabled", False)
                except:
                    pass
            else:
                self.root.unbind("<Configure>")
            dlg.destroy()

        dlg.protocol("WM_DELETE_WINDOW", release)

        # Tab bar
        bar = tk.Frame(dlg, bg="#f6f6f6")
        bar.pack(fill="x", padx=5, pady=(5,0))
        underline = tk.Frame(dlg, height=3, bg="#22aa22")
        underline.place(x=0, y=0)

        pages = {
            "General":       tk.Frame(dlg, bg="#f6f6f6"),
            "Auth":          tk.Frame(dlg, bg="#f6f6f6"),
            "Logging":       tk.Frame(dlg, bg="#f6f6f6"),
            "Login Actions": tk.Frame(dlg, bg="#f6f6f6"),
        }

        def show_page(name, btn):
            for p in pages.values():
                p.pack_forget()
            pages[name].pack(fill="both", expand=True, padx=10, pady=5)
            x = btn.winfo_x() + bar.winfo_x()
            w = btn.winfo_width()
            underline.place(x=x, y=bar.winfo_y()+btn.winfo_height(), width=w)

        btns = {}
        for name in pages:
            b = ttk.Button(bar, text=name)
            b.pack(side="left", padx=2, pady=2)
            btns[name] = b
            b.bind("<Button-1>", lambda e, n=name: show_page(n, e.widget))

        dlg.update_idletasks()
        show_page("General", btns["General"])

        # --- General tab ---
        t1 = pages["General"]
        entries = {}
        for i, label in enumerate(("Name:","Host:","Port:","User:")):
            tk.Label(t1, text=label, font=FONT, bg="#f6f6f6")\
              .grid(row=i, column=0, sticky="w", padx=5, pady=4)
            key = label[:-1].lower()
            init = str(cfg.get(key,"")) if cfg else ""
            e = make_entry(t1, initial=init, width=300)
            e.grid(row=i, column=1, sticky="ew", padx=5, pady=4)
            entries[key] = e

        # Folder selector
        tk.Label(t1, text="Folder:", font=FONT, bg="#f6f6f6")\
          .grid(row=4, column=0, sticky="w", padx=5, pady=4)
        folder_var = tk.StringVar(
            t1, value=(cfg.get("folder",UNCAT_FOLDER) if cfg else UNCAT_FOLDER)
        )
        ttk.OptionMenu(t1, folder_var, folder_var.get(), *self.folders)\
           .grid(row=4, column=1, sticky="w", padx=5, pady=4)
        entries["folder"] = folder_var
        t1.columnconfigure(1, weight=1)

        # --- Auth tab ---
        t2 = pages["Auth"]
        tk.Label(t2, text="Auth Method:", font=FONT, bg="#f6f6f6")\
          .grid(row=0, column=0, sticky="w", padx=5, pady=4)
        auth_var = tk.StringVar(t2, value=(cfg.get("auth_method") if cfg else "password"))
        ttk.OptionMenu(t2, auth_var, auth_var.get(), "password","key_file")\
           .grid(row=0, column=1, sticky="w", padx=5, pady=4)

        fb = tk.Frame(t2, bg="#f6f6f6")
        fk = tk.Frame(t2, bg="#f6f6f6")
        # password
        tk.Label(fb, text="Password:", font=FONT, bg="#f6f6f6")\
          .grid(row=0, column=0, sticky="w", padx=5, pady=4)
        e_pass = make_entry(fb, width=300, show="*")
        e_pass.grid(row=0, column=1, sticky="ew", padx=5, pady=4)
        fb.columnconfigure(1, weight=1)
        # key file
        tk.Label(fk, text="Key File:", font=FONT, bg="#f6f6f6")\
          .grid(row=0, column=0, sticky="w", padx=5, pady=4)
        e_key = make_entry(fk, width=300)
        e_key.grid(row=0, column=1, sticky="ew", padx=5, pady=4)
        ttk.Button(fk, text="Browse", command=lambda: browse_key(dlg, e_key))\
           .grid(row=0, column=2, padx=5, pady=4)
        fk.columnconfigure(1, weight=1)

        def swap_auth(*_):
            fb.grid_forget(); fk.grid_forget()
            if auth_var.get()=="password":
                fb.grid(row=1, column=0, columnspan=2, sticky="ew", padx=5, pady=4)
            else:
                fk.grid(row=1, column=0, columnspan=2, sticky="ew", padx=5, pady=4)

        auth_var.trace_add("write", swap_auth)
        swap_auth()
        if cfg:
            if cfg["auth_method"]=="password":
                e_pass.insert(0, cfg.get("password",""))
            else:
                e_key.insert(0, cfg.get("key_file",""))

        # --- Logging tab ---
        t3 = pages["Logging"]
        tk.Label(t3, text="Logging Enabled:", font=FONT, bg="#f6f6f6")\
          .grid(row=0, column=0, sticky="w", padx=5, pady=4)
        log_var = tk.BooleanVar(
            t3, value=(cfg.get("logging_enabled",False) if cfg else False)
        )
        ttk.Checkbutton(t3, variable=log_var).grid(row=0, column=1, sticky="w", padx=5, pady=4)
        tk.Label(t3, text="Log File Path:", font=FONT, bg="#f6f6f6")\
          .grid(row=1, column=0, sticky="w", padx=5, pady=4)
        e_log = make_entry(t3, width=300)
        e_log.grid(row=1, column=1, sticky="ew", padx=5, pady=4)
        ttk.Button(t3, text="Browse", command=lambda: browse_log(dlg, e_log))\
           .grid(row=1, column=2, padx=5, pady=4)
        t3.columnconfigure(1, weight=1)
        if cfg and cfg.get("log_path"):
            e_log.insert(0, cfg["log_path"])

        # --- Login Actions tab ---  
        t4 = pages["Login Actions"]
        cols = self.settings.get("login_actions_cols", {})
        w_e = cols.get("expect", 200)
        w_s = cols.get("send",   300)
        tv = ttk.Treeview(t4, columns=("expect","send"),
                          show="headings", height=6)
        tv.heading("expect", text="Expected Text"); tv.column("expect", width=w_e)
        tv.heading("send",   text="Command to Send"); tv.column("send", width=w_s)
        tv.grid(row=0, column=0, sticky="nsew", padx=5, pady=4)
        sbx = ttk.Scrollbar(t4, orient="vertical", command=tv.yview)
        sbx.grid(row=0, column=1, sticky="ns", pady=4); tv.configure(yscrollcommand=sbx.set)
        if cfg and cfg.get("auto_sequence"):
            for st in cfg["auto_sequence"]:
                tv.insert("", "end", values=(st["expect"], st["send"]))

        btnf = tk.Frame(t4, bg="#f6f6f6")
        btnf.grid(row=1, column=0, columnspan=2, pady=(5,10))
        ttk.Button(btnf, text="Add Step",
                   command=lambda: self._open_seq_editor(tv)).pack(side="left", padx=5)
        ttk.Button(btnf, text="Edit Step",
                   command=lambda: self._open_seq_editor(
                       tv,
                       tv.selection()[0] if tv.selection() else None,
                       tv.item(tv.selection()[0])["values"] if tv.selection() else None
                   )).pack(side="left", padx=5)
        ttk.Button(btnf, text="Delete Step",
                   command=lambda: [tv.delete(i) for i in tv.selection()]).pack(side="left", padx=5)

        # lock tab sizes
        dlg.update_idletasks()
        sizes = []
        for name, btn in btns.items():
            show_page(name, btn)
            dlg.update_idletasks()
            sizes.append((dlg.winfo_width(), dlg.winfo_height()))
        mw = max(w for w,h in sizes); mh = max(h for w,h in sizes)
        dlg.minsize(mw, mh)
        show_page("General", btns["General"])

        # OK / Cancel
        okf = tk.Frame(dlg, bg="#f6f6f6"); okf.pack(side="bottom", fill="x", padx=10, pady=(0,10))
        ttk.Button(okf, text="Cancel", command=release).pack(side="right", padx=(0,5))
        b_ok = ttk.Button(okf, text="OK"); b_ok.pack(side="right")

        def on_ok():
            nonlocal server_result
            try:
                out = {
                    "name": entries["name"].get().strip(),
                    "host": entries["host"].get().strip(),
                    "port": int(entries["port"].get().strip()),
                    "user": entries["user"].get().strip(),
                    "folder": folder_var.get(),
                    "auth_method": auth_var.get(),
                    "logging_enabled": log_var.get(),
                    "log_path": e_log.get().strip(),
                    "auto_sequence": []
                }
                if out["auth_method"] == "password":
                    out["password"] = e_pass.get()
                else:
                    out["key_file"] = e_key.get().strip()

                # save column widths
                self.settings["login_actions_cols"] = {
                    "expect": tv.column("expect","width"),
                    "send":   tv.column("send","width")
                }
                save_settings(self.settings)

                for iid in tv.get_children():
                    a, b = tv.item(iid)["values"]
                    out["auto_sequence"].append({"expect": a, "send": b})

                if not (out["name"] and out["host"] and out["user"]):
                    raise ValueError("Name, host, and user required")

                server_result = out
                release()
            except Exception as ex:
                messagebox.showerror("Error", str(ex), parent=dlg)

        b_ok.config(command=on_ok)
        center(dlg, self.root)
        dlg.deiconify()
        dlg.wait_window()
        return server_result

    def _open_seq_editor(self, tree, iid=None, values=None):
        parent = tree.winfo_toplevel()
        edit = tk.Toplevel(parent); edit.withdraw()
        edit.transient(parent); edit.grab_set()
        setup_styles(edit); edit.title("Edit Auto Command Step")

        px,py = parent.winfo_x(), parent.winfo_y()
        try:
            parent.attributes("-disabled", True)
            ua = True
        except:
            parent.bind("<Configure>", lambda e: parent.geometry(f"+{px}+{py}"))
            ua = False

        def close_seq():
            if ua:
                try: parent.attributes("-disabled", False)
                except: pass
            else:
                parent.unbind("<Configure>")
            edit.destroy()

        edit.protocol("WM_DELETE_WINDOW", close_seq)

        tk.Label(edit, text="Expected Text:", font=FONT, bg=edit["bg"])\
          .grid(row=0, column=0, sticky="w", padx=5, pady=5)
        e_ent = make_entry(edit, width=300); e_ent.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(edit, text="Command to Send:", font=FONT, bg=edit["bg"])\
          .grid(row=1, column=0, sticky="w", padx=5, pady=5)
        s_ent = make_entry(edit, width=300); s_ent.grid(row=1, column=1, padx=5, pady=5)

        if values:
            e_ent.insert(0, values[0])
            s_ent.insert(0, values[1])

        def save_seq():
            a = e_ent.get().strip(); b = s_ent.get().strip()
            if not a:
                messagebox.showwarning("Validation", "Expected text required", parent=edit)
                return
            if iid:
                tree.item(iid, values=(a,b))
            else:
                tree.insert("", "end", values=(a,b))
            close_seq()

        ttk.Button(edit, text="Save", command=save_seq).grid(row=2, column=0, padx=5, pady=10)
        ttk.Button(edit, text="Cancel", command=close_seq).grid(row=2, column=1, padx=5, pady=10)
        center(edit, parent); edit.deiconify(); edit.wait_window()

    # ─── Expect via here-doc ─────────────────────────────────────────
    def _launch_expect(self, lines, title):
        expect_bin = shutil.which("expect")
        if not expect_bin:
            messagebox.showerror(
                "Expect Missing",
                "Cannot find 'expect'.",
                parent=self.root
            )
            return

        # strip shebang lines
        script = "".join(ln for ln in lines if not ln.startswith("#!"))

        # build bash -ic here-doc (no pause at the end)
        cmd = (
            f"{expect_bin} -f - << 'EOF'\n"
            f"{script}\n"
            "EOF"  
        )

        # launch inside an interactive bash to preserve autocomplete
        launcher = [
            "gnome-terminal", "--title", title,
            "--", "bash", "-ic", cmd
        ]
        subprocess.Popen(launcher)

    def connect_to_ssh(self):
        sel = self.tree.selection()
        if not sel or not sel[0].startswith("server::"):
            messagebox.showwarning("Select server", parent=self.root)
            return
        idx = int(sel[0].split("::",1)[1]); cfg = self.servers[idx]
        self.log_msg(f"Launching SSH for '{cfg['name']}'")

        lines = [
            "#!/usr/bin/env expect\n", "set timeout -1\n",
            "spawn ssh " +
            (f"-i {cfg.get('key_file')} " if cfg["auth_method"]=="key_file" else "") +
            f"{cfg['user']}@{cfg['host']} -p {cfg['port']}\n"
        ]
        for st in cfg.get("auto_sequence", []):
            lines.append(f"expect \"*{st['expect']}*\"\n")
            lines.append(f"send -- \"{st['send']}\\r\"\nafter 500\n")
        lines.append("interact\n")
        self._launch_expect(lines, f"{cfg['name']} SSH")

    def connect_to_sftp(self):
        sel = self.tree.selection()
        if not sel or not sel[0].startswith("server::"):
            messagebox.showwarning("Select server", parent=self.root)
            return
        idx = int(sel[0].split("::",1)[1]); cfg = self.servers[idx]
        self.log_msg(f"Launching SFTP for '{cfg['name']}'")

        lines = [
            "#!/usr/bin/env expect\n", "set timeout -1\n",
            "spawn sftp " +
            (f"-i {cfg.get('key_file')} " if cfg["auth_method"]=="key_file" else "") +
            f"-P {cfg['port']} {cfg['user']}@{cfg['host']}\n"
        ]
        for st in cfg.get("auto_sequence", []):
            lines.append(f"expect \"*{st['expect']}*\"\n")
            lines.append(f"send -- \"{st['send']}\\r\"\nafter 500\n")
        lines.append("interact\n")
        self._launch_expect(lines, f"{cfg['name']} SFTP")

    def log_msg(self, msg):
        self.log_widget.config(state="normal")
        self.log_widget.insert(tk.END, msg + "\n")
        self.log_widget.see(tk.END)
        self.log_widget.config(state="disabled")


if __name__ == "__main__":
    root = tk.Tk()
    app  = SSHClientGUI(root)
    root.mainloop()

