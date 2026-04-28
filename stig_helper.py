#!/usr/bin/env python3
"""
stig_helper.py - STIG Helper main menu.

Unified launcher for:
  - CKL Merger   (combine ACAS + Evaluate-STIG)
  - CKL Diff     (compare Before / After CKLs)
  - History      (activity log viewer)

Usage:
    Double-click main.bat           (Windows, recommended for most users)
    py stig_helper.py               (Windows CLI)
    python3 stig_helper.py          (Linux/macOS)

Zero external dependencies. Python 3.8+ stdlib + tkinter only.
"""

import sys
import io
import contextlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from datetime import datetime

# Ensure all sibling modules resolve correctly regardless of cwd
BASE_DIR = Path(__file__).parent.resolve()
EXPORTS_DIR = BASE_DIR / "Exports"
NAMING_PROFILES_PATH = BASE_DIR / "naming_profiles.json"
LOGS_DIR = BASE_DIR / "Logs"
ACTIVITY_LOG_PATH = LOGS_DIR / "activity_log.jsonl"
sys.path.insert(0, str(BASE_DIR))

ZONE_OPTIONS = ["Production", "Omaha", "ZoneB"]
OS_TECHNOLOGIES = {
    "Windows 2016",
    "Windows 2019",
    "Windows 2022",
    "Windows 10",
    "Windows 11",
    "Ubuntu",
    "RHEL 8",
    "RHEL 9",
    "Operating System SRG",
}
TECH_SUBCATEGORY_OPTIONS = {
    "Windows 2016": [],
    "Windows 2019": [],
    "Windows 2022": [],
    "Windows 10": [],
    "Windows 11": [],
    "Ubuntu": [],
    "RHEL 8": [],
    "RHEL 9": [],
    "Chrome": ["Chrome"],
    "Edge": ["Edge"],
    "Firefox": ["Firefox"],
    "IIS": ["IIS Site", "IIS Server"],
    "DotNET": ["DotNET"],
    "App Server SRG": ["Traksys", "ARAS"],
    "Web Server SRG": ["Web Server SRG"],
    "Database SRG": ["Database SRG"],
    "Operating System SRG": [],
    "Active Directory": ["Active Directory"],
    "SQL Server": ["SQL Server"],
    "Oracle": ["Oracle"],
    "Application": [],
}

TITLE_HINTS = [
    ("windows server 2019", ("Windows 2019", "")),
    ("windows server 2022", ("Windows 2022", "")),
    ("windows server 2016", ("Windows 2016", "")),
    ("windows 11", ("Windows 11", "")),
    ("windows 10", ("Windows 10", "")),
    ("ubuntu", ("Ubuntu", "")),
    ("red hat enterprise linux 9", ("RHEL 9", "")),
    ("red hat enterprise linux 8", ("RHEL 8", "")),
    ("rhel 9", ("RHEL 9", "")),
    ("rhel 8", ("RHEL 8", "")),
    ("google chrome", ("Chrome", "Chrome")),
    ("microsoft edge", ("Edge", "Edge")),
    ("mozilla firefox", ("Firefox", "Firefox")),
    ("internet information services", ("IIS", "IIS Site")),
    ("iis", ("IIS", "IIS Site")),
    ("dotnet", ("DotNET", "DotNET")),
    ("application security requirements guide", ("App Server SRG", "")),
    ("app server srg", ("App Server SRG", "")),
    ("web server security requirements guide", ("Web Server SRG", "")),
    ("web server srg", ("Web Server SRG", "")),
    ("database security requirements guide", ("Database SRG", "")),
    ("operating system security requirements guide", ("Operating System SRG", "")),
    ("active directory", ("Active Directory", "Active Directory")),
    ("sql server", ("SQL Server", "SQL Server")),
    ("oracle", ("Oracle", "Oracle")),
]

# ============================================================
# Lazy imports of tool modules (avoids top-level import noise)
# ============================================================
def _import_diff():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "stig_diff", BASE_DIR / "stig_diff.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def _import_merge():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "combine_stig", BASE_DIR / "combine_stig.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ============================================================
# Colour / style constants (DoD blue theme)
# ============================================================
DOD_BLUE   = "#003366"
DOD_BLUE2  = "#004080"
ACCENT     = "#0066CC"
WHITE      = "#FFFFFF"
LIGHT_BG   = "#F0F4F8"
CARD_BG    = "#FFFFFF"
CARD_HOVER = "#E8F0FA"
TEXT_DARK  = "#1A1A2E"
TEXT_GREY  = "#555555"
RED_FLAG   = "#C62828"
GREEN_OK   = "#2E7D32"
AMBER      = "#F57C00"
MAIN_BG          = "#F7FBFF"
MAIN_HEADER_BG   = "#DCEEFF"
MAIN_FOOTER_BG   = "#EAF4FF"
MAIN_HEADER_TEXT = "#123A63"
MAIN_SUBTEXT     = "#4E759A"
MAIN_CARD_BORDER = "#C9DFF3"
MAIN_CARD_HOVER  = "#F2F8FF"
FONT_MAIN  = ("Segoe UI", 10) if sys.platform == "win32" else ("TkDefaultFont", 10)
FONT_BOLD  = ("Segoe UI", 10, "bold") if sys.platform == "win32" else ("TkDefaultFont", 10, "bold")
FONT_TITLE = ("Segoe UI", 13, "bold") if sys.platform == "win32" else ("TkDefaultFont", 13, "bold")
FONT_SMALL = ("Segoe UI", 8) if sys.platform == "win32" else ("TkDefaultFont", 8)
FONT_MONO  = ("Consolas", 9) if sys.platform == "win32" else ("Monospace", 9)


# ============================================================
# Utility helpers
# ============================================================
def open_path(path):
    """Open a file or folder in the OS default viewer."""
    target = Path(path).expanduser()
    if not target.is_absolute():
        target = (BASE_DIR / target).resolve()
    else:
        target = target.resolve()
    if not target.exists():
        raise FileNotFoundError(f"Path not found: {target}")
    try:
        if sys.platform == "win32":
            import os
            os.startfile(str(target))  # nosemgrep: validated local path, no shell
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(target)])  # nosemgrep: constant command, validated local path
        else:
            subprocess.Popen(["xdg-open", str(target)])  # nosemgrep: constant command, validated local path
    except Exception as e:
        return str(e)
    return None


def open_folder(path):
    """Open the parent folder of a file in Explorer/Finder/Nautilus."""
    target = Path(path).expanduser()
    if not target.is_absolute():
        target = (BASE_DIR / target).resolve()
    else:
        target = target.resolve()
    if not target.exists():
        raise FileNotFoundError(f"Path not found: {target}")
    folder = target.parent
    try:
        if sys.platform == "win32":
            os.startfile(str(folder))  # nosemgrep: validated local path, no shell
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(folder)])  # nosemgrep: constant command, validated local path
        else:
            subprocess.Popen(["xdg-open", str(folder)])  # nosemgrep: constant command, validated local path
    except Exception as e:
        return str(e)
    return None


def browse_initial_dir(current_value=""):
    """Return the best starting folder for file pickers."""
    if current_value:
        candidate = Path(current_value).expanduser()
        if candidate.is_file():
            return str(candidate.parent)
        if candidate.is_dir():
            return str(candidate)
    return str(BASE_DIR)


def load_naming_profiles():
    if not NAMING_PROFILES_PATH.is_file():
        return {}
    try:
        return json.loads(NAMING_PROFILES_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_naming_profiles(profiles):
    NAMING_PROFILES_PATH.write_text(json.dumps(profiles, indent=2, sort_keys=True),
                                    encoding="utf-8")


def _json_safe(value):
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return value


def record_activity(action_type, status, summary, inputs=None, outputs=None, log_text="", details=None):
    entry = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "action_type": action_type,
        "status": status,
        "summary": summary,
        "inputs": _json_safe(inputs or []),
        "outputs": _json_safe(outputs or []),
        "log_text": str(log_text or ""),
        "details": _json_safe(details or {}),
    }
    try:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        with ACTIVITY_LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=True) + "\n")
    except Exception:
        pass


def read_activity_entries():
    if not ACTIVITY_LOG_PATH.is_file():
        return []
    entries = []
    for line in ACTIVITY_LOG_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except Exception:
            continue
    entries.sort(key=lambda item: item.get("timestamp", ""), reverse=True)
    return entries


def normalize_title_key(title):
    return " ".join((title or "").strip().lower().split())


def is_ipv4(value):
    value = (value or "").strip()
    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value):
        return False
    return all(0 <= int(part) <= 255 for part in value.split("."))


def mask_ip_address(value):
    value = (value or "").strip()
    if not is_ipv4(value):
        return ""
    parts = value.split(".")
    return f"x.x.{parts[2]}.{parts[3]}"


def sanitize_name_part(value, allow_spaces=False):
    allowed = "-_." + (" " if allow_spaces else "")
    cleaned = "".join(c if c.isalnum() or c in allowed else "_" for c in (value or "").strip())
    return re.sub(r"\s+", " ", cleaned).strip(" _")


def extract_server_name(asset):
    host_name = str((asset or {}).get("HOST_NAME", "") or "").strip()
    if host_name and not is_ipv4(host_name):
        return host_name.split(".")[0].strip()

    host_fqdn = str((asset or {}).get("HOST_FQDN", "") or "").strip()
    if host_fqdn and not is_ipv4(host_fqdn):
        return host_fqdn.split(".")[0].strip()

    host_ip = str((asset or {}).get("HOST_IP", "") or "").strip()
    if host_ip:
        return host_ip

    if host_name:
        return host_name
    if host_fqdn:
        return host_fqdn
    return ""


def extract_server_name_from_filename(path, technology="", category=""):
    stem = Path(path).stem.strip()
    if not stem:
        return ""

    ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", stem)
    if ip_match:
        return ip_match.group(0)

    lowered = stem.lower()
    suffixes = []
    if technology:
        suffixes.append(technology.lower().replace(" ", ""))
        suffixes.append(technology.lower().replace(" ", "_"))
        suffixes.append(technology.lower().replace(" ", "-"))
    if category:
        suffixes.append(category.lower().replace(" ", ""))
        suffixes.append(category.lower().replace(" ", "_"))
        suffixes.append(category.lower().replace(" ", "-"))

    parts = re.split(r"[_-]+", stem)
    if len(parts) > 1 and parts[-1].lower() in {s for s in suffixes if s}:
        return "_".join(parts[:-1]).strip("._-")

    return stem


def default_subcategory_for_technology(technology, saved_subcategory=""):
    if saved_subcategory:
        return saved_subcategory.strip()
    technology = (technology or "").strip()
    if technology in OS_TECHNOLOGIES:
        return ""
    if technology in {"Chrome", "Edge", "Firefox", "DotNET"}:
        return technology
    if technology in {"Web Server SRG", "Database SRG", "Active Directory", "SQL Server", "Oracle"}:
        return technology
    return ""


def naming_suffix(technology, subcategory):
    technology = (technology or "").strip()
    subcategory = (subcategory or "").strip()
    if not technology or technology in OS_TECHNOLOGIES:
        return ""
    if subcategory:
        if subcategory.lower() == technology.lower():
            return sanitize_name_part(technology, allow_spaces=True)
        if subcategory.lower().startswith(technology.lower()):
            return sanitize_name_part(subcategory, allow_spaces=True)
        return f"{sanitize_name_part(technology, allow_spaces=True)}_{sanitize_name_part(subcategory, allow_spaces=True)}"
    return sanitize_name_part(technology, allow_spaces=True)


def build_recommended_name(zone, project_name, server_name, technology="", subcategory=""):
    zone_part = sanitize_name_part(zone or "Production") or "Production"
    project_part = sanitize_name_part(project_name or "Project") or "Project"
    server_token = mask_ip_address(server_name) or "x.x.x.x"
    parts = [zone_part, project_part, server_token]
    suffix = naming_suffix(technology, subcategory)
    if suffix:
        parts.append(suffix)
    return "_".join(part for part in parts if part)


def detect_checklist_timestamp(path):
    """Return (datetime, source_label) for the best original checklist timestamp."""
    path = Path(path).expanduser().resolve()
    stem = path.stem

    for pattern, dt_format, label in (
        (r"(\d{4}_\d{2}_\d{2}_\d{6})", "%Y_%m_%d_%H%M%S", "filename timestamp"),
        (r"(\d{4}-\d{2}-\d{2}_\d{6})", "%Y-%m-%d_%H%M%S", "filename timestamp"),
        (r"(\d{4}_\d{2}_\d{2})", "%Y_%m_%d", "filename date"),
        (r"(\d{4}-\d{2}-\d{2})", "%Y-%m-%d", "filename date"),
    ):
        match = re.search(pattern, stem)
        if match:
            try:
                return datetime.strptime(match.group(1), dt_format), label
            except ValueError:
                pass

    try:
        stat = path.stat()
        created_ts = getattr(stat, "st_birthtime", None)
        if created_ts is None:
            created_ts = stat.st_ctime
        return datetime.fromtimestamp(created_ts), "file created time"
    except Exception:
        return datetime.fromtimestamp(path.stat().st_mtime), "file modified time"


def recommended_name_for_checklist(ckl_path, default_server_name="", default_zone="Production",
                                   default_project_name=""):
    suggestion = detect_naming_suggestions(ckl_path)
    server_name = default_server_name or suggestion["server_name"]
    zone = default_zone or suggestion["zone"]
    project_name = default_project_name or suggestion["project_name"]
    return build_recommended_name(
        zone,
        project_name,
        server_name,
        suggestion["technology"],
        suggestion["subcategory"],
    )


def detect_naming_suggestions(ckl_path):
    merge_mod = _import_merge()
    _, _, asset, _, _, stig_info = merge_mod.parse_any_checklist(ckl_path)
    title = stig_info.get("title", "") or ""
    title_key = normalize_title_key(title)

    profiles = load_naming_profiles()
    defaults = profiles.get("__defaults__", {})
    profile = profiles.get(title_key, {})
    tech = profile.get("technology", "")
    subcategory = profile.get("subcategory", profile.get("category", ""))
    zone = defaults.get("zone", "Production")
    project_name = defaults.get("project_name", "")

    if not tech:
        lower_title = title.lower()
        for pattern, suggestion in TITLE_HINTS:
            if pattern in lower_title:
                tech, subcategory = suggestion
                break

    if not tech:
        tech = "Windows 2019" if "windows" in title.lower() else ""

    subcategory_options = list(TECH_SUBCATEGORY_OPTIONS.get(tech, []))
    if subcategory and subcategory not in subcategory_options:
        subcategory_options.append(subcategory)
    subcategory = default_subcategory_for_technology(tech, subcategory)

    server_name = extract_server_name(asset)
    if not server_name:
        server_name = extract_server_name_from_filename(ckl_path, tech, subcategory)
    return {
        "server_name": server_name,
        "technology": tech,
        "subcategory": subcategory,
        "category": subcategory,
        "subcategory_options": subcategory_options,
        "zone": zone,
        "project_name": project_name,
        "title": title,
        "title_key": title_key,
    }


def show_naming_assistant(parent, ckl_path, purpose, default_server_name="", default_output_name=""):
    import tkinter as tk
    from tkinter import ttk

    suggestion = detect_naming_suggestions(ckl_path)
    if default_server_name:
        suggestion["server_name"] = default_server_name
    recommended_name = build_recommended_name(
        suggestion["zone"],
        suggestion["project_name"],
        suggestion["server_name"],
        suggestion["technology"],
        suggestion["subcategory"],
    )
    initial_name = recommended_name
    if default_output_name and default_output_name.strip():
        if default_output_name.strip().upper() == recommended_name.upper():
            initial_name = default_output_name.strip()

    dlg = tk.Toplevel(parent)
    dlg.title(purpose)
    dlg.geometry("560x410")
    dlg.resizable(False, False)
    dlg.grab_set()

    tk.Label(dlg, text=purpose, font=FONT_BOLD, pady=8).pack()
    tk.Label(dlg, text=f"Detected STIG: {suggestion['title'] or 'Unknown'}",
             font=FONT_SMALL, fg=TEXT_GREY, wraplength=520, justify="left").pack()

    form = tk.Frame(dlg, padx=14, pady=12)
    form.pack(fill="both", expand=True)
    form.columnconfigure(1, weight=1)

    zone_var = tk.StringVar(value=suggestion["zone"])
    project_var = tk.StringVar(value=suggestion["project_name"])
    server_var = tk.StringVar(value=suggestion["server_name"])
    tech_var = tk.StringVar(value=suggestion["technology"])
    subcategory_var = tk.StringVar(value=suggestion["subcategory"])
    name_var = tk.StringVar(value=initial_name)

    tk.Label(form, text="Zone:", font=FONT_MAIN).grid(row=0, column=0, sticky="e", padx=(0, 8), pady=4)
    zone_combo = ttk.Combobox(form, textvariable=zone_var, values=ZONE_OPTIONS, state="readonly", width=32)
    zone_combo.grid(row=0, column=1, sticky="ew", pady=4)

    tk.Label(form, text="Project Name:", font=FONT_MAIN).grid(row=1, column=0, sticky="e", padx=(0, 8), pady=4)
    project_entry = ttk.Entry(form, textvariable=project_var, width=34)
    project_entry.grid(row=1, column=1, sticky="ew", pady=4)

    tk.Label(form, text="Server / IP:", font=FONT_MAIN).grid(row=2, column=0, sticky="e", padx=(0, 8), pady=4)
    server_entry = ttk.Entry(form, textvariable=server_var, width=34)
    server_entry.grid(row=2, column=1, sticky="ew", pady=4)

    tech_values = list(TECH_SUBCATEGORY_OPTIONS.keys())
    tk.Label(form, text="OS / Product:", font=FONT_MAIN).grid(row=3, column=0, sticky="e", padx=(0, 8), pady=4)
    tech_combo = ttk.Combobox(form, textvariable=tech_var, values=tech_values, width=34)
    tech_combo.grid(row=3, column=1, sticky="ew", pady=4)

    tk.Label(form, text="App / Subcategory:", font=FONT_MAIN).grid(row=4, column=0, sticky="e", padx=(0, 8), pady=4)
    subcategory_combo = ttk.Combobox(form, textvariable=subcategory_var, width=34)
    subcategory_combo.grid(row=4, column=1, sticky="ew", pady=4)

    tk.Label(form, text="Recommended Name:", font=FONT_MAIN).grid(row=5, column=0, sticky="e", padx=(0, 8), pady=(10, 4))
    name_entry = ttk.Entry(form, textvariable=name_var, width=34)
    name_entry.grid(row=5, column=1, sticky="ew", pady=(10, 4))
    tk.Label(form,
             text="Recommended format: Zone_ProjectName_x.x.##.## with an optional product or app suffix. OS checklists stop at the masked IP.",
             font=FONT_SMALL, fg=TEXT_GREY, wraplength=360, justify="left").grid(row=6, column=1, sticky="w")

    manual_override = {"used": initial_name.strip().upper() != recommended_name.upper()}
    confirmed = {"ok": False}

    def refresh_subcategories(*_args):
        options = list(TECH_SUBCATEGORY_OPTIONS.get(tech_var.get().strip(), []))
        current = subcategory_var.get().strip()
        if current and current not in options:
            options.append(current)
        subcategory_combo["values"] = options
        if tech_var.get().strip() in OS_TECHNOLOGIES:
            subcategory_var.set("")
        elif not current:
            subcategory_var.set(default_subcategory_for_technology(tech_var.get().strip()))
        if not manual_override["used"]:
            name_var.set(build_recommended_name(
                zone_var.get(),
                project_var.get(),
                server_var.get(),
                tech_var.get(),
                subcategory_var.get(),
            ))

    def on_input_change(*_args):
        if not manual_override["used"]:
            name_var.set(build_recommended_name(
                zone_var.get(),
                project_var.get(),
                server_var.get(),
                tech_var.get(),
                subcategory_var.get(),
            ))

    def on_name_change(*_args):
        recommended = build_recommended_name(
            zone_var.get(),
            project_var.get(),
            server_var.get(),
            tech_var.get(),
            subcategory_var.get(),
        )
        manual_override["used"] = name_var.get().strip() != recommended

    def _confirm():
        confirmed["ok"] = True
        dlg.destroy()

    def _cancel():
        dlg.destroy()

    zone_var.trace_add("write", on_input_change)
    project_var.trace_add("write", on_input_change)
    server_var.trace_add("write", on_input_change)
    tech_var.trace_add("write", refresh_subcategories)
    subcategory_var.trace_add("write", on_input_change)
    name_var.trace_add("write", on_name_change)
    refresh_subcategories()

    btns = tk.Frame(dlg, pady=8)
    btns.pack()
    ttk.Button(btns, text="Use Name", command=_confirm, width=12).pack(side="left", padx=6)
    ttk.Button(btns, text="Cancel", command=_cancel, width=10).pack(side="left", padx=6)

    server_entry.focus_set()
    dlg.wait_window()

    if not confirmed["ok"]:
        return None

    profiles = load_naming_profiles()
    profiles["__defaults__"] = {
        "zone": zone_var.get().strip() or "Production",
        "project_name": project_var.get().strip(),
    }
    if suggestion["title_key"]:
        profiles[suggestion["title_key"]] = {
            "technology": tech_var.get().strip(),
            "subcategory": subcategory_var.get().strip(),
        }
    save_naming_profiles(profiles)

    return {
        "zone": zone_var.get().strip() or "Production",
        "project_name": project_var.get().strip(),
        "server_name": server_var.get().strip(),
        "technology": tech_var.get().strip(),
        "subcategory": subcategory_var.get().strip(),
        "category": subcategory_var.get().strip(),
        "name": name_var.get().strip() or build_recommended_name(
            zone_var.get(),
            project_var.get(),
            server_var.get(),
            tech_var.get(),
            subcategory_var.get(),
        ),
    }


# ============================================================
# Main application window
# ============================================================
def main():
    import tkinter as tk
    from tkinter import ttk

    root = tk.Tk()
    root.title("STIG Helper")
    root.geometry("700x660")
    root.minsize(680, 620)
    root.configure(bg=DOD_BLUE)

    # Container that fills the window — we swap its contents for navigation
    container = tk.Frame(root, bg=DOD_BLUE)
    container.pack(fill="both", expand=True)

    def show_frame(build_fn, *args, **kwargs):
        """Clear the container and draw a new frame."""
        for w in container.winfo_children():
            w.destroy()
        build_fn(container, show_frame, *args, **kwargs)

    show_frame(build_main_menu)
    root.mainloop()


# ============================================================
# Main menu frame
# ============================================================
def build_main_menu(parent, navigate):
    import tkinter as tk
    from tkinter import ttk

    # Header bar
    header = tk.Frame(parent, bg=MAIN_HEADER_BG, pady=24)
    header.pack(fill="x")

    tk.Label(header, text="STIG Helper", font=("Segoe UI", 22, "bold"),
             bg=MAIN_HEADER_BG, fg=MAIN_HEADER_TEXT).pack()
    tk.Label(header, text="DoD STIG Compliance Utilities",
             font=FONT_MAIN, bg=MAIN_HEADER_BG, fg=MAIN_SUBTEXT).pack()

    # Card area
    card_area = tk.Frame(parent, bg=MAIN_BG, pady=24, padx=28)
    card_area.pack(fill="both", expand=True)
    card_area.columnconfigure(0, weight=1)
    card_area.columnconfigure(1, weight=1)

    tools = [
        {
            "icon": "🔀",
            "title": "CKL Merger",
            "desc": "Combine ACAS and Evaluate-STIG checklists into one authoritative file",
            "build": build_merger_frame,
        },
        {
            "icon": "🔍",
            "title": "CKL Diff",
            "desc": "Compare before and after checklists to detect regressions and drift",
            "build": build_diff_frame,
        },
        {
            "icon": "📊",
            "title": "Create Status Report",
            "desc": "Generate HTML and Excel status summaries from any checklist file",
            "build": build_status_report_frame,
        },
        {
            "icon": "📝",
            "title": "Create Artifact Report",
            "desc": "Generate a Word artifact report with editable narratives and placeholders",
            "build": build_artifact_report_frame,
        },
        {
            "icon": "📦",
            "title": "Standardize / Export",
            "desc": "Rename, standardize, or export checklists as CKL or native CKLB",
            "build": build_export_checklist_frame,
        },
        {
            "icon": "📜",
            "title": "History",
            "desc": "View recent merge, diff, report, artifact, and export activity",
            "build": build_history_frame,
        },
    ]

    for idx, tool in enumerate(tools):
        _make_menu_card(card_area, tool, navigate, row=idx // 2, column=idx % 2)

    # Footer
    footer = tk.Frame(parent, bg=MAIN_FOOTER_BG, pady=8)
    footer.pack(fill="x", side="bottom")
    tk.Label(footer, text="v1.4.1", font=FONT_SMALL,
             bg=MAIN_FOOTER_BG, fg=MAIN_SUBTEXT).pack(side="left", padx=12)
    ttk.Button(footer, text="Exit",
               command=parent.winfo_toplevel().destroy).pack(side="right", padx=12)


def _make_menu_card(parent, tool, navigate, row=None, column=None):
    import tkinter as tk

    card = tk.Frame(parent, bg=CARD_BG, relief="flat",
                    highlightbackground=MAIN_CARD_BORDER, highlightthickness=1,
                    cursor="hand2", padx=16, pady=12)
    if row is None or column is None:
        card.pack(fill="x", pady=7)
    else:
        card.grid(row=row, column=column, sticky="nsew", padx=8, pady=8)

    left = tk.Frame(card, bg=CARD_BG)
    left.pack(side="left", fill="both", expand=True)

    title_row = tk.Frame(left, bg=CARD_BG)
    title_row.pack(fill="x")
    tk.Label(title_row, text=tool["icon"], font=("Segoe UI", 18),
             bg=CARD_BG).pack(side="left", padx=(0, 10))
    tk.Label(title_row, text=tool["title"], font=FONT_BOLD,
             bg=CARD_BG, fg=TEXT_DARK).pack(side="left")

    tk.Label(left, text=tool["desc"], font=FONT_SMALL,
             bg=CARD_BG, fg=TEXT_GREY, wraplength=240,
             justify="left").pack(fill="x", pady=(4, 0))

    arrow = tk.Label(card, text="›", font=("Segoe UI", 20),
                     bg=CARD_BG, fg=ACCENT, cursor="hand2")
    arrow.pack(side="right")

    # Hover effect
    def on_enter(e):
        for w in [card, left, title_row, arrow] + list(left.winfo_children()) + \
                 list(title_row.winfo_children()):
            try:
                w.configure(bg=MAIN_CARD_HOVER)
            except Exception:
                pass

    def on_leave(e):
        for w in [card, left, title_row, arrow] + list(left.winfo_children()) + \
                 list(title_row.winfo_children()):
            try:
                w.configure(bg=CARD_BG)
            except Exception:
                pass

    def on_click(e):
        navigate(tool["build"])

    for w in [card, left, arrow, title_row]:
        w.bind("<Enter>", on_enter)
        w.bind("<Leave>", on_leave)
        w.bind("<Button-1>", on_click)
    for child in left.winfo_children():
        child.bind("<Enter>", on_enter)
        child.bind("<Leave>", on_leave)
        child.bind("<Button-1>", on_click)


# ============================================================
# Shared back button helper
# ============================================================
def _back_button(parent, navigate, bg=DOD_BLUE):
    import tkinter as tk
    bar = tk.Frame(parent, bg=bg, pady=8, padx=12)
    bar.pack(fill="x")
    btn = tk.Button(
        bar,
        text="←  Back to Main Menu",
        command=lambda: navigate(build_main_menu),
        font=FONT_BOLD,
        bg="#F7FBFF",
        fg=MAIN_HEADER_TEXT,
        activebackground="#E2F0FF",
        activeforeground=MAIN_HEADER_TEXT,
        relief="flat",
        bd=0,
        padx=14,
        pady=8,
        cursor="hand2",
    )
    btn.pack(side="left")
    return bar


def _tool_header(parent, title, subtitle, bg=DOD_BLUE):
    import tkinter as tk
    hdr = tk.Frame(parent, bg=bg, pady=10, padx=14)
    hdr.pack(fill="x")
    tk.Label(hdr, text=title, font=FONT_TITLE, bg=bg, fg=WHITE).pack(anchor="w")
    if subtitle:
        tk.Label(hdr, text=subtitle, font=FONT_SMALL, bg=bg,
                 fg="#AACCEE").pack(anchor="w")
    return hdr


# ============================================================
# CKL Merger frame
# ============================================================
def build_merger_frame(parent, navigate):
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext

    _back_button(parent, navigate)
    _tool_header(parent, "CKL Merger",
                 "Combine an ACAS CKL and an Evaluate-STIG CKL for the same host")

    body = tk.Frame(parent, bg=LIGHT_BG, padx=16, pady=12)
    body.pack(fill="both", expand=True)
    body.columnconfigure(1, weight=1)

    acas_var = tk.StringVar()
    eval_var = tk.StringVar()
    name_var = tk.StringVar()

    # Input rows
    def _file_row(row, label, var, title_str, on_selected=None):
        tk.Label(body, text=label, font=FONT_MAIN, bg=LIGHT_BG,
                 fg=TEXT_DARK).grid(row=row, column=0, sticky="e",
                                    padx=(0, 8), pady=4)
        ttk.Entry(body, textvariable=var).grid(row=row, column=1,
                                               sticky="ew", pady=4)
        def _browse():
            p = filedialog.askopenfilename(
                title=title_str,
                initialdir=browse_initial_dir(var.get()),
                filetypes=[("CKL files", "*.ckl"), ("All files", "*.*")])
            if p:
                var.set(p)
                if on_selected:
                    on_selected(p)
        ttk.Button(body, text="Browse...", command=_browse,
                   width=10).grid(row=row, column=2, padx=(8, 0), pady=4)

    _file_row(0, "ACAS CKL:", acas_var, "Select ACAS CKL file")
    _file_row(
        1,
        "Eval-STIG CKL:",
        eval_var,
        "Select Evaluate-STIG CKL file",
        on_selected=lambda p: name_var.set(recommended_name_for_checklist(p))
        if not name_var.get().strip() else None,
    )

    tk.Label(body, text="Output name:", font=FONT_MAIN, bg=LIGHT_BG,
             fg=TEXT_DARK).grid(row=2, column=0, sticky="e",
                                padx=(0, 8), pady=(8, 4))
    ttk.Entry(body, textvariable=name_var).grid(row=2, column=1,
                                                sticky="ew", pady=(8, 4))
    tk.Label(body, text="Optional — timestamp will be appended",
             font=FONT_SMALL, bg=LIGHT_BG,
             fg=TEXT_GREY).grid(row=3, column=1, sticky="w")

    # Buttons
    btn_row = tk.Frame(body, bg=LIGHT_BG)
    btn_row.grid(row=4, column=0, columnspan=3, pady=(14, 8))

    last_out = [None]

    def _open_report():
        if not last_out[0]:
            messagebox.showinfo("No output yet", "Run a merge first.")
            return
        err = open_path(last_out[0])
        if err:
            messagebox.showerror("Error", err)

    def _open_folder_btn():
        if not last_out[0]:
            messagebox.showinfo("No output yet", "Run a merge first.")
            return
        err = open_folder(last_out[0])
        if err:
            messagebox.showerror("Error", err)

    def _clear():
        acas_var.set(""); eval_var.set(""); name_var.set("")
        log.configure(state="normal")
        log.delete("1.0", "end")
        log.insert("end", "Ready.\n")
        log.configure(state="disabled")
        last_out[0] = None

    merge_btn = ttk.Button(btn_row, text="  Merge  ", width=12)
    merge_btn.pack(side="left", padx=4)
    ttk.Button(btn_row, text="Open Output", command=_open_report,
               width=12).pack(side="left", padx=4)
    ttk.Button(btn_row, text="Open Folder", command=_open_folder_btn,
               width=12).pack(side="left", padx=4)
    ttk.Button(btn_row, text="Clear", command=_clear,
               width=8).pack(side="left", padx=4)

    # Log
    log_frame = ttk.LabelFrame(body, text=" Merge Log ", padding=4)
    log_frame.grid(row=5, column=0, columnspan=3, sticky="nsew", pady=(8, 0))
    body.rowconfigure(5, weight=1)
    log_frame.columnconfigure(0, weight=1)
    log_frame.rowconfigure(0, weight=1)
    log = scrolledtext.ScrolledText(log_frame, font=FONT_MONO, height=10,
                                    wrap="word")
    log.grid(row=0, column=0, sticky="nsew")
    log.insert("end", "Ready.\n")
    log.configure(state="disabled")

    def _run_merge():
        a = acas_var.get().strip()
        e = eval_var.get().strip()
        n = name_var.get().strip()
        if not a:
            messagebox.showerror("Missing input", "Please select an ACAS CKL.")
            return
        if not e:
            messagebox.showerror("Missing input", "Please select an Eval-STIG CKL.")
            return

        log.configure(state="normal")
        log.delete("1.0", "end")
        log.insert("end", f"Starting merge at {datetime.now().strftime('%H:%M:%S')}...\n\n")
        log.configure(state="disabled")
        parent.update_idletasks()

        buf = io.StringIO()
        try:
            m = _import_merge()
            acas_p = Path(a).expanduser().resolve()
            eval_p = Path(e).expanduser().resolve()
            if n:
                m.MERGED_DIR.mkdir(parents=True, exist_ok=True)
                safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in n)
                ts = datetime.now().strftime("%Y_%m_%d_%H%M%S")
                out_p = m.MERGED_DIR / f"{safe}_{ts}.ckl"
            else:
                naming = show_naming_assistant(parent.winfo_toplevel(), str(eval_p), "Name Merged Output")
                if not naming:
                    return
                m.MERGED_DIR.mkdir(parents=True, exist_ok=True)
                safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in naming["name"])
                ts = datetime.now().strftime("%Y_%m_%d_%H%M%S")
                out_p = m.MERGED_DIR / f"{safe}_{ts}.ckl"

            with contextlib.redirect_stdout(buf):
                m.merge_ckls(acas_p, eval_p, out_p)

            last_out[0] = str(out_p)
            log.configure(state="normal")
            merge_log = buf.getvalue()
            log.insert("end", merge_log)
            log.insert("end", "\n--- Merge complete. ---\n")
            log.see("end")
            log.configure(state="disabled")
            record_activity(
                "Merge Log",
                "Success",
                f"Merged {acas_p.name} and {eval_p.name}",
                inputs=[acas_p, eval_p],
                outputs=[out_p],
                log_text=merge_log,
                details={"output_name": out_p.name},
            )

        except Exception as ex:
            log.configure(state="normal")
            log.insert("end", f"\n[ERROR] {type(ex).__name__}: {ex}\n")
            log.configure(state="disabled")
            record_activity(
                "Merge Log",
                "Error",
                f"Merge failed for {Path(a).name if a else 'unknown'} and {Path(e).name if e else 'unknown'}",
                inputs=[a, e],
                log_text=str(ex),
                details={"error_type": type(ex).__name__},
            )
            messagebox.showerror("Merge failed", f"{type(ex).__name__}: {ex}")

    merge_btn.configure(command=_run_merge)


# ============================================================
# CKL Diff frame
# ============================================================
def build_diff_frame(parent, navigate):
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext

    diff_mod = _import_diff()

    _back_button(parent, navigate)
    _tool_header(parent, "CKL Diff",
                 "Compare two checklist files to detect what changed")

    body = tk.Frame(parent, bg=LIGHT_BG, padx=16, pady=12)
    body.pack(fill="both", expand=True)
    body.columnconfigure(1, weight=1)

    before_var = tk.StringVar()
    after_var = tk.StringVar()
    name_var = tk.StringVar()
    name_auto = [True]
    name_sync = [False]
    last_rpt = [None]

    def _set_report_name(value, auto=False):
        name_sync[0] = True
        name_var.set(value)
        name_sync[0] = False
        name_auto[0] = auto

    def _suggest_diff_report_name(candidate_path=""):
        candidate = str(candidate_path or "").strip()
        if not candidate:
            return ""
        try:
            suggested = recommended_name_for_checklist(candidate)
            return suggested or Path(candidate).stem
        except Exception:
            return Path(candidate).stem

    def _refresh_report_name(force=False):
        if not force and not name_auto[0]:
            return
        candidate = after_var.get().strip() or before_var.get().strip()
        _set_report_name(_suggest_diff_report_name(candidate), auto=True)

    def _on_name_change(*_args):
        if name_sync[0]:
            return
        name_auto[0] = not bool(name_var.get().strip())

    name_var.trace_add("write", _on_name_change)

    def _browse_file(var, title_str):
        p = filedialog.askopenfilename(
            title=title_str,
            initialdir=browse_initial_dir(var.get()),
            filetypes=[("Checklist files", "*.ckl *.cklb"), ("All files", "*.*")])
        if p:
            var.set(p)
            _refresh_report_name()

    tk.Label(body, text="Before CKL:", font=FONT_MAIN, bg=LIGHT_BG,
             fg=TEXT_DARK).grid(row=0, column=0, sticky="e", padx=(0, 8), pady=4)
    ttk.Entry(body, textvariable=before_var).grid(row=0, column=1, sticky="ew", pady=4)
    ttk.Button(body, text="Browse...", width=10,
               command=lambda: _browse_file(before_var, "Select BEFORE checklist")).grid(
                   row=0, column=2, padx=(8, 0), pady=4)

    tk.Label(body, text="After CKL:", font=FONT_MAIN, bg=LIGHT_BG,
             fg=TEXT_DARK).grid(row=1, column=0, sticky="e", padx=(0, 8), pady=4)
    ttk.Entry(body, textvariable=after_var).grid(row=1, column=1, sticky="ew", pady=4)
    ttk.Button(body, text="Browse...", width=10,
               command=lambda: _browse_file(after_var, "Select AFTER checklist")).grid(
                   row=1, column=2, padx=(8, 0), pady=4)

    tk.Label(body, text="Report name:", font=FONT_MAIN, bg=LIGHT_BG,
             fg=TEXT_DARK).grid(row=2, column=0, sticky="e", padx=(0, 8), pady=(8, 4))
    ttk.Entry(body, textvariable=name_var).grid(row=2, column=1, sticky="ew", pady=(8, 4))
    tk.Label(body, text="Optional — timestamp will be appended",
             font=FONT_SMALL, bg=LIGHT_BG, fg=TEXT_GREY).grid(row=3, column=1, sticky="w")

    btn_row = tk.Frame(body, bg=LIGHT_BG)
    btn_row.grid(row=4, column=0, columnspan=3, pady=(12, 8))

    def _open_rpt():
        if not last_rpt[0]:
            messagebox.showinfo("No report", "Run a comparison first.")
            return
        err = open_path(last_rpt[0])
        if err:
            messagebox.showerror("Error", err)

    def _open_fld():
        if not last_rpt[0]:
            messagebox.showinfo("No report", "Run a comparison first.")
            return
        err = open_folder(last_rpt[0])
        if err:
            messagebox.showerror("Error", err)

    def _clear():
        before_var.set("")
        after_var.set("")
        _set_report_name("", auto=True)
        log.configure(state="normal")
        log.delete("1.0", "end")
        log.insert("end", "Ready.\n")
        log.configure(state="disabled")
        last_rpt[0] = None

    compare_btn = ttk.Button(btn_row, text="  Compare  ", width=12)
    compare_btn.pack(side="left", padx=4)
    ttk.Button(btn_row, text="Open Report", command=_open_rpt,
               width=12).pack(side="left", padx=4)
    ttk.Button(btn_row, text="Open Folder", command=_open_fld,
               width=12).pack(side="left", padx=4)
    ttk.Button(btn_row, text="Clear", command=_clear,
               width=8).pack(side="left", padx=4)

    log_frame = ttk.LabelFrame(body, text=" Diff Results ", padding=4)
    log_frame.grid(row=5, column=0, columnspan=3, sticky="nsew", pady=(8, 0))
    body.rowconfigure(5, weight=1)
    log_frame.columnconfigure(0, weight=1)
    log_frame.rowconfigure(0, weight=1)
    log = scrolledtext.ScrolledText(log_frame, font=FONT_MONO, height=10,
                                    wrap="word")
    log.grid(row=0, column=0, sticky="nsew")
    log.insert("end", "Ready.\n")
    log.configure(state="disabled")

    def _run_compare():
        bp = before_var.get().strip()
        ap = after_var.get().strip()
        name = name_var.get().strip()
        if not bp:
            messagebox.showerror("Missing input", "Select a Before CKL.")
            return
        if not ap:
            messagebox.showerror("Missing input", "Select an After CKL.")
            return

        before_path = Path(bp).expanduser().resolve()
        after_path = Path(ap).expanduser().resolve()
        for p, lbl in [(before_path, "Before"), (after_path, "After")]:
            if not p.is_file():
                messagebox.showerror("File not found", f"{lbl} checklist not found:\n{p}")
                return

        log.configure(state="normal")
        log.delete("1.0", "end")
        log.insert("end", f"Starting comparison at {datetime.now().strftime('%H:%M:%S')}...\n\n")
        log.configure(state="disabled")
        parent.update_idletasks()

        buf = io.StringIO()
        try:
            old_snap = diff_mod.parse_ckl(before_path)
            new_snap = diff_mod.parse_ckl(after_path)
            diff_data = diff_mod.compute_diff(old_snap, new_snap)
            label = name or old_snap["asset"].get("HOST_NAME", "").strip() or "comparison"

            with contextlib.redirect_stdout(buf):
                diff_mod.print_console_diff(label, before_path, after_path, diff_data)

            diff_mod.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
            safe = diff_mod.sanitize_hostname(label)
            out_p = diff_mod.REPORTS_DIR / f"{safe}_diff_{diff_mod.timestamp_now()}.html"
            diff_mod.write_html_report(label, before_path, after_path, diff_data, out_p)

            compare_log = buf.getvalue()
            last_rpt[0] = str(out_p)
            log.configure(state="normal")
            log.insert("end", compare_log)
            log.insert("end", f"\n[OK] Report: {out_p}\n")
            log.insert("end", "\n--- Complete. ---\n")
            log.see("end")
            log.configure(state="disabled")
            record_activity(
                "Diff Log",
                "Success",
                f"Compared {before_path.name} to {after_path.name}",
                inputs=[before_path, after_path],
                outputs=[out_p],
                log_text=compare_log,
                details={"label": label},
            )
        except Exception as ex:
            log.configure(state="normal")
            log.insert("end", f"\n[ERROR] {type(ex).__name__}: {ex}\n")
            log.configure(state="disabled")
            record_activity(
                "Diff Log",
                "Error",
                f"Comparison failed for {before_path.name} and {after_path.name}",
                inputs=[before_path, after_path],
                log_text=str(ex),
                details={"error_type": type(ex).__name__},
            )
            messagebox.showerror("Compare failed", f"{type(ex).__name__}: {ex}")

    compare_btn.configure(command=_run_compare)


# ============================================================
# Status report frame
# ============================================================
def build_status_report_frame(parent, navigate):
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext

    merge_mod = _import_merge()

    _back_button(parent, navigate)
    _tool_header(parent, "Create Status Report",
                 "Generate HTML and/or Excel status summaries from a CKL file")

    body = tk.Frame(parent, bg=LIGHT_BG, padx=16, pady=12)
    body.pack(fill="both", expand=True)
    body.columnconfigure(1, weight=1)

    ckl_var = tk.StringVar()
    fmt_var = tk.StringVar(value="both")
    last_outputs = [dict()]

    tk.Label(body, text="CKL file:", font=FONT_MAIN, bg=LIGHT_BG,
             fg=TEXT_DARK).grid(row=0, column=0, sticky="e",
                                padx=(0, 8), pady=4)
    ttk.Entry(body, textvariable=ckl_var).grid(row=0, column=1,
                                               sticky="ew", pady=4)

    def _browse():
        p = filedialog.askopenfilename(
            title="Select checklist file for status report",
            initialdir=browse_initial_dir(ckl_var.get()),
            filetypes=[("Checklist files", "*.ckl *.cklb"), ("All files", "*.*")])
        if p:
            ckl_var.set(p)

    ttk.Button(body, text="Browse...", command=_browse,
               width=10).grid(row=0, column=2, padx=(8, 0), pady=4)

    fmt_row = tk.Frame(body, bg=LIGHT_BG)
    fmt_row.grid(row=1, column=0, columnspan=3, sticky="w", pady=(10, 4))
    tk.Label(fmt_row, text="Output format:", font=FONT_MAIN,
             bg=LIGHT_BG, fg=TEXT_DARK).pack(side="left", padx=(0, 8))
    ttk.Radiobutton(fmt_row, text="HTML", variable=fmt_var,
                    value="html").pack(side="left", padx=4)
    ttk.Radiobutton(fmt_row, text="Excel", variable=fmt_var,
                    value="xlsx").pack(side="left", padx=4)
    ttk.Radiobutton(fmt_row, text="Both", variable=fmt_var,
                    value="both").pack(side="left", padx=4)

    btn_row = tk.Frame(body, bg=LIGHT_BG)
    btn_row.grid(row=2, column=0, columnspan=3, pady=(12, 8))

    def _open_outputs():
        outputs = last_outputs[0]
        if not outputs:
            messagebox.showinfo("No output yet", "Create a report first.")
            return
        for path in outputs.values():
            err = open_path(str(path))
            if err:
                messagebox.showerror("Open failed", err)
                return

    def _open_folder():
        outputs = last_outputs[0]
        if not outputs:
            messagebox.showinfo("No output yet", "Create a report first.")
            return
        first_path = next(iter(outputs.values()))
        err = open_folder(str(first_path))
        if err:
            messagebox.showerror("Error", err)

    def _clear():
        ckl_var.set("")
        last_outputs[0] = {}
        log.configure(state="normal")
        log.delete("1.0", "end")
        log.insert("end", "Ready.\n")
        log.configure(state="disabled")

    ttk.Button(btn_row, text="Create Report", width=14,
               command=lambda: _run_report()).pack(side="left", padx=4)
    ttk.Button(btn_row, text="Open Output", width=12,
               command=_open_outputs).pack(side="left", padx=4)
    ttk.Button(btn_row, text="Open Folder", width=12,
               command=_open_folder).pack(side="left", padx=4)
    ttk.Button(btn_row, text="Clear", width=8,
               command=_clear).pack(side="left", padx=4)

    log_frame = ttk.LabelFrame(body, text=" Status Report Log ", padding=4)
    log_frame.grid(row=3, column=0, columnspan=3, sticky="nsew", pady=(8, 0))
    body.rowconfigure(3, weight=1)
    log_frame.columnconfigure(0, weight=1)
    log_frame.rowconfigure(0, weight=1)
    log = scrolledtext.ScrolledText(log_frame, font=FONT_MONO, height=10,
                                    wrap="word")
    log.grid(row=0, column=0, sticky="nsew")
    log.insert("end", "Ready.\n")
    log.configure(state="disabled")

    def _run_report():
        ckl_path_str = ckl_var.get().strip()
        if not ckl_path_str:
            messagebox.showerror("Missing input", "Please select a checklist file.")
            return
        ckl_path = Path(ckl_path_str).expanduser().resolve()
        if not ckl_path.is_file():
            messagebox.showerror("File not found", f"Checklist not found:\n{ckl_path}")
            return

        output_formats = {
            "html": ("html",),
            "xlsx": ("xlsx",),
            "both": ("html", "xlsx"),
        }[fmt_var.get()]

        log.configure(state="normal")
        log.delete("1.0", "end")
        log.insert("end", f"Creating status report at {datetime.now().strftime('%H:%M:%S')}...\n\n")
        log.configure(state="disabled")
        parent.update_idletasks()

        try:
            outputs = merge_mod.create_status_reports(ckl_path, output_formats=output_formats)
            last_outputs[0] = outputs
            log.configure(state="normal")
            for fmt, path in outputs.items():
                log.insert("end", f"[OK] {fmt.upper()} report: {path}\n")
            log.insert("end", "\n--- Complete. ---\n")
            log.configure(state="disabled")
            record_activity(
                "Report Generation Log",
                "Success",
                f"Created status report for {ckl_path.name}",
                inputs=[ckl_path],
                outputs=list(outputs.values()),
                log_text="\n".join(f"{fmt.upper()}: {path}" for fmt, path in outputs.items()),
                details={"formats": list(outputs.keys())},
            )
        except Exception as ex:
            log.configure(state="normal")
            log.insert("end", f"\n[ERROR] {type(ex).__name__}: {ex}\n")
            log.configure(state="disabled")
            record_activity(
                "Report Generation Log",
                "Error",
                f"Status report failed for {ckl_path.name}",
                inputs=[ckl_path],
                log_text=str(ex),
                details={"error_type": type(ex).__name__},
            )
            messagebox.showerror("Report failed", f"{type(ex).__name__}: {ex}")


# ============================================================
# Artifact report frame
# ============================================================
def build_artifact_report_frame(parent, navigate):
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext

    merge_mod = _import_merge()

    _back_button(parent, navigate)
    _tool_header(parent, "Create Artifact Report",
                 "Generate a Word artifact report with editable narratives and screenshot placeholders")

    body = tk.Frame(parent, bg=LIGHT_BG, padx=16, pady=12)
    body.pack(fill="both", expand=True)
    body.columnconfigure(1, weight=1)
    body.rowconfigure(2, weight=1)

    ckl_var = tk.StringVar()
    selected_only_var = tk.BooleanVar(value=False)
    current_output = [None]
    metadata = [None]
    artifact_rows = {}
    list_items = []
    current_vid = [None]

    tk.Label(body, text="Checklist file:", font=FONT_MAIN, bg=LIGHT_BG,
             fg=TEXT_DARK).grid(row=0, column=0, sticky="e",
                                padx=(0, 8), pady=4)
    ttk.Entry(body, textvariable=ckl_var).grid(row=0, column=1,
                                               sticky="ew", pady=4)

    def _browse():
        p = filedialog.askopenfilename(
            title="Select checklist file for artifact report",
            initialdir=browse_initial_dir(ckl_var.get()),
            filetypes=[("Checklist files", "*.ckl *.cklb"), ("All files", "*.*")])
        if p:
            ckl_var.set(p)
            _load_findings()

    ttk.Button(body, text="Browse...", command=_browse,
               width=10).grid(row=0, column=2, padx=(8, 0), pady=4)

    note = tk.Label(
        body,
        text="The artifact list only loads actionable findings. Items already marked Not a Finding or Not Applicable are skipped automatically. Turn on 'Only selected findings' if you want to export just a subset of the remaining findings.",
        font=FONT_SMALL,
        bg=LIGHT_BG,
        fg=TEXT_GREY,
        wraplength=620,
        justify="left",
    )
    note.grid(row=1, column=0, columnspan=3, sticky="w", pady=(2, 8))

    options_row = tk.Frame(body, bg=LIGHT_BG)
    options_row.grid(row=2, column=0, columnspan=3, sticky="w", pady=(0, 8))
    ttk.Checkbutton(
        options_row,
        text="Only selected findings",
        variable=selected_only_var,
    ).pack(side="left")

    work = tk.Frame(body, bg=LIGHT_BG)
    work.grid(row=3, column=0, columnspan=3, sticky="nsew")
    work.columnconfigure(0, weight=0)
    work.columnconfigure(1, weight=1)
    work.rowconfigure(0, weight=1)

    left = ttk.LabelFrame(work, text=" Findings ", padding=6)
    left.grid(row=0, column=0, sticky="nsw", padx=(0, 10))
    left.columnconfigure(0, weight=1)
    left.rowconfigure(0, weight=1)

    findings_list = tk.Listbox(left, width=36, height=18, exportselection=False,
                               selectmode="extended", font=FONT_MAIN)
    findings_list.grid(row=0, column=0, sticky="nsew")
    findings_scroll = ttk.Scrollbar(left, orient="vertical", command=findings_list.yview)
    findings_scroll.grid(row=0, column=1, sticky="ns")
    findings_list.configure(yscrollcommand=findings_scroll.set)

    right = ttk.LabelFrame(work, text=" Artifact Narrative ", padding=8)
    right.grid(row=0, column=1, sticky="nsew")
    right.columnconfigure(1, weight=1)
    right.rowconfigure(3, weight=1)

    vuln_var = tk.StringVar(value="Vuln Num:")
    status_var = tk.StringVar(value="Status:")
    title_var = tk.StringVar(value="Rule Title:")

    ttk.Label(right, textvariable=vuln_var).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 4))
    ttk.Label(right, textvariable=status_var).grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 4))
    ttk.Label(right, textvariable=title_var, wraplength=520).grid(row=2, column=0, columnspan=2, sticky="w", pady=(0, 8))

    editor = scrolledtext.ScrolledText(right, font=FONT_MAIN, wrap="word", height=16)
    editor.grid(row=3, column=0, columnspan=2, sticky="nsew")
    editor.insert("end", "Load a checklist to begin.\n")

    btn_row = tk.Frame(body, bg=LIGHT_BG)
    btn_row.grid(row=4, column=0, columnspan=3, pady=(12, 8))

    def _save_current_text():
        vid = current_vid[0]
        if vid and vid in artifact_rows:
            artifact_rows[vid]["Artifact Text"] = editor.get("1.0", "end").strip()

    def _load_editor_for_vid(vid):
        row = artifact_rows[vid]
        current_vid[0] = vid
        vuln_var.set(f"Vuln Num: {vid}")
        status_var.set(f"Status: {row['Status Label']}")
        title_var.set(f"Rule Title: {row['Rule Title']}")
        editor.delete("1.0", "end")
        editor.insert("1.0", row["Artifact Text"])

    def _on_select(_event=None):
        selection = findings_list.curselection()
        if not selection:
            return
        _save_current_text()
        idx = selection[-1]
        vid = list_items[idx]
        _load_editor_for_vid(vid)

    findings_list.bind("<<ListboxSelect>>", _on_select)

    def _load_findings():
        ckl_path_str = ckl_var.get().strip()
        if not ckl_path_str:
            return
        ckl_path = Path(ckl_path_str).expanduser().resolve()
        if not ckl_path.is_file():
            messagebox.showerror("File not found", f"Checklist not found:\n{ckl_path}")
            return

        try:
            meta, rows = merge_mod.build_artifact_report_data(ckl_path)
        except Exception as ex:
            messagebox.showerror("Load failed", f"{type(ex).__name__}: {ex}")
            return

        metadata[0] = meta
        artifact_rows.clear()
        list_items.clear()
        findings_list.delete(0, "end")
        for row in rows:
            vid = row["Vuln Num"]
            artifact_rows[vid] = dict(row)
            list_items.append(vid)
            findings_list.insert("end", f"{vid} [{row['Status Label']}]")

        editor.delete("1.0", "end")
        if list_items:
            findings_list.selection_set(0)
            findings_list.activate(0)
            _load_editor_for_vid(list_items[0])
        else:
            current_vid[0] = None
            vuln_var.set("Vuln Num:")
            status_var.set("Status:")
            title_var.set("Rule Title:")
            editor.insert("end", "No actionable findings were available in this checklist.\n")

    def _open_output():
        if not current_output[0]:
            messagebox.showinfo("No output yet", "Create an artifact report first.")
            return
        err = open_path(current_output[0])
        if err:
            messagebox.showerror("Error", err)

    def _open_folder():
        if not current_output[0]:
            messagebox.showinfo("No output yet", "Create an artifact report first.")
            return
        err = open_folder(current_output[0])
        if err:
            messagebox.showerror("Error", err)

    def _clear():
        ckl_var.set("")
        metadata[0] = None
        artifact_rows.clear()
        list_items.clear()
        current_vid[0] = None
        current_output[0] = None
        selected_only_var.set(False)
        findings_list.delete(0, "end")
        vuln_var.set("Vuln Num:")
        status_var.set("Status:")
        title_var.set("Rule Title:")
        editor.delete("1.0", "end")
        editor.insert("end", "Load a checklist to begin.\n")
        log.configure(state="normal")
        log.delete("1.0", "end")
        log.insert("end", "Ready.\n")
        log.configure(state="disabled")

    def _create_report():
        if not artifact_rows:
            _load_findings()
            if not artifact_rows:
                return

        if selected_only_var.get():
            selected = [list_items[i] for i in findings_list.curselection()]
            if not selected:
                messagebox.showerror("No findings selected", "Select one or more findings, or turn off 'Only selected findings' to export everything.")
                return
        else:
            selected = list(list_items)

        _save_current_text()

        ckl_path = Path(ckl_var.get().strip()).expanduser().resolve()
        log.configure(state="normal")
        log.delete("1.0", "end")
        log.insert("end", f"Creating artifact report at {datetime.now().strftime('%H:%M:%S')}...\n\n")
        log.configure(state="disabled")
        parent.update_idletasks()

        try:
            naming = show_naming_assistant(parent.winfo_toplevel(), str(ckl_path), "Name Artifact Report")
            if not naming:
                return
            safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in naming["name"])
            ts = datetime.now().strftime("%Y_%m_%d_%H%M%S")
            out_path = merge_mod.REPORTS_DIR / f"{safe}_artifact_{ts}.docx"
            overrides = {vid: artifact_rows[vid]["Artifact Text"] for vid in selected}
            merge_mod.create_artifact_report(
                ckl_path,
                selected_vids=selected,
                narrative_overrides=overrides,
                output_path=out_path,
            )
            current_output[0] = str(out_path)
            log.configure(state="normal")
            log.insert("end", f"[OK] DOCX artifact: {out_path}\n")
            log.insert("end", f"[OK] Findings included: {', '.join(selected)}\n")
            log.insert("end", "\n--- Complete. ---\n")
            log.configure(state="disabled")
            record_activity(
                "Artifact Report Log",
                "Success",
                f"Created artifact report for {ckl_path.name}",
                inputs=[ckl_path],
                outputs=[out_path],
                log_text=f"Included findings: {', '.join(selected)}",
                details={"findings": selected},
            )
            messagebox.showinfo(
                "Artifact report created",
                f"Created:\n{out_path}\n\nIncluded findings:\n{', '.join(selected)}"
            )
            err = open_path(str(out_path))
            if err:
                messagebox.showerror("Open failed", err)
        except Exception as ex:
            log.configure(state="normal")
            log.insert("end", f"\n[ERROR] {type(ex).__name__}: {ex}\n")
            log.configure(state="disabled")
            record_activity(
                "Artifact Report Log",
                "Error",
                f"Artifact report failed for {ckl_path.name}",
                inputs=[ckl_path],
                log_text=str(ex),
                details={"error_type": type(ex).__name__},
            )
            messagebox.showerror("Artifact report failed", f"{type(ex).__name__}: {ex}")

    ttk.Button(btn_row, text="Load Findings", width=12,
               command=_load_findings).pack(side="left", padx=4)
    ttk.Button(btn_row, text="Create DOCX", width=12,
               command=_create_report).pack(side="left", padx=4)
    ttk.Button(btn_row, text="Open Output", width=12,
               command=_open_output).pack(side="left", padx=4)
    ttk.Button(btn_row, text="Open Folder", width=12,
               command=_open_folder).pack(side="left", padx=4)
    ttk.Button(btn_row, text="Clear", width=8,
               command=_clear).pack(side="left", padx=4)

    log_frame = ttk.LabelFrame(body, text=" Artifact Report Log ", padding=4)
    log_frame.grid(row=5, column=0, columnspan=3, sticky="nsew", pady=(8, 0))
    body.rowconfigure(5, weight=0)
    log_frame.columnconfigure(0, weight=1)
    log_frame.rowconfigure(0, weight=1)
    log = scrolledtext.ScrolledText(log_frame, font=FONT_MONO, height=7,
                                    wrap="word")
    log.grid(row=0, column=0, sticky="nsew")
    log.insert("end", "Ready.\n")
    log.configure(state="disabled")


# ============================================================
# Checklist export frame
# ============================================================
def build_export_checklist_frame(parent, navigate):
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext

    _back_button(parent, navigate)
    _tool_header(parent, "Standardize / Export Checklist",
                 "Rename and standardize a checklist, or export it as CKL or native CKLB")

    body = tk.Frame(parent, bg=LIGHT_BG, padx=16, pady=12)
    body.pack(fill="both", expand=True)
    body.columnconfigure(1, weight=1)

    ckl_var = tk.StringVar()
    fmt_var = tk.StringVar(value="ckl")
    last_out = [None]

    tk.Label(body, text="Source checklist:", font=FONT_MAIN, bg=LIGHT_BG,
             fg=TEXT_DARK).grid(row=0, column=0, sticky="e",
                                padx=(0, 8), pady=4)
    ttk.Entry(body, textvariable=ckl_var).grid(row=0, column=1,
                                               sticky="ew", pady=4)

    def _browse():
        p = filedialog.askopenfilename(
            title="Select checklist to standardize or export",
            initialdir=browse_initial_dir(ckl_var.get()),
            filetypes=[("Checklist files", "*.ckl *.cklb"), ("All files", "*.*")])
        if p:
            ckl_var.set(p)

    ttk.Button(body, text="Browse...", command=_browse,
               width=10).grid(row=0, column=2, padx=(8, 0), pady=4)

    fmt_row = tk.Frame(body, bg=LIGHT_BG)
    fmt_row.grid(row=1, column=0, columnspan=3, sticky="w", pady=(10, 4))
    tk.Label(fmt_row, text="Output format:", font=FONT_MAIN,
             bg=LIGHT_BG, fg=TEXT_DARK).pack(side="left", padx=(0, 8))
    ttk.Radiobutton(fmt_row, text="CKL", variable=fmt_var,
                    value="ckl").pack(side="left", padx=4)
    ttk.Radiobutton(fmt_row, text="CKLB", variable=fmt_var,
                    value="cklb").pack(side="left", padx=4)

    tk.Label(body,
             text="CKL keeps the checklist in the same format with a clean standardized name. The renamed copy uses the checklist's original date when it can be detected. CKLB creates a native STIG Viewer 3 checklist.",
             font=FONT_SMALL, bg=LIGHT_BG, fg=TEXT_GREY,
             wraplength=560, justify="left").grid(row=2, column=0, columnspan=3,
                                                  sticky="w", pady=(2, 10))

    btn_row = tk.Frame(body, bg=LIGHT_BG)
    btn_row.grid(row=3, column=0, columnspan=3, pady=(8, 8))

    def _open_output():
        if not last_out[0]:
            messagebox.showinfo("No output yet", "Create an output checklist first.")
            return
        err = open_path(last_out[0])
        if err:
            messagebox.showerror("Error", err)

    def _open_folder_btn():
        if not last_out[0]:
            messagebox.showinfo("No output yet", "Create an output checklist first.")
            return
        err = open_folder(last_out[0])
        if err:
            messagebox.showerror("Error", err)

    def _clear():
        ckl_var.set("")
        fmt_var.set("ckl")
        last_out[0] = None
        log.configure(state="normal")
        log.delete("1.0", "end")
        log.insert("end", "Ready.\n")
        log.configure(state="disabled")

    ttk.Button(btn_row, text="Create Output", width=12,
               command=lambda: _run_export()).pack(side="left", padx=4)
    ttk.Button(btn_row, text="Open Output", width=12,
               command=_open_output).pack(side="left", padx=4)
    ttk.Button(btn_row, text="Open Folder", width=12,
               command=_open_folder_btn).pack(side="left", padx=4)
    ttk.Button(btn_row, text="Clear", width=8,
               command=_clear).pack(side="left", padx=4)

    log_frame = ttk.LabelFrame(body, text=" Export Log ", padding=4)
    log_frame.grid(row=4, column=0, columnspan=3, sticky="nsew", pady=(8, 0))
    body.rowconfigure(4, weight=1)
    log_frame.columnconfigure(0, weight=1)
    log_frame.rowconfigure(0, weight=1)
    log = scrolledtext.ScrolledText(log_frame, font=FONT_MONO, height=10,
                                    wrap="word")
    log.grid(row=0, column=0, sticky="nsew")
    log.insert("end", "Ready.\n")
    log.configure(state="disabled")

    def _run_export():
        source_str = ckl_var.get().strip()
        if not source_str:
            messagebox.showerror("Missing input", "Please select a checklist file.")
            return
        source_path = Path(source_str).expanduser().resolve()
        if not source_path.is_file():
            messagebox.showerror("File not found", f"Checklist not found:\n{source_path}")
            return

        log.configure(state="normal")
        log.delete("1.0", "end")
        log.insert("end", f"Starting export at {datetime.now().strftime('%H:%M:%S')}...\n\n")
        log.configure(state="disabled")
        parent.update_idletasks()

        try:
            merge_mod = _import_merge()
            EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
            naming = show_naming_assistant(parent.winfo_toplevel(), str(source_path), "Standardize / Export Checklist")
            if not naming:
                return
            safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in naming["name"])
            original_dt, timestamp_source = detect_checklist_timestamp(source_path)
            ts = original_dt.strftime("%Y_%m_%d_%H%M%S")
            ext = ".cklb" if fmt_var.get() == "cklb" else ".ckl"
            out_path = EXPORTS_DIR / f"{safe}_export_{ts}{ext}"
            merge_mod.export_checklist(source_path, fmt_var.get(), out_path)
            last_out[0] = str(out_path)
            log.configure(state="normal")
            action = "Standardized CKL" if fmt_var.get() == "ckl" else "Exported CKLB"
            log.insert("end", f"[OK] {action}: {out_path}\n")
            log.insert("end", f"[INFO] Using original checklist date from {timestamp_source}: "
                              f"{original_dt.strftime('%Y-%m-%d %H:%M:%S')}\n")
            log.insert("end", "\n--- Complete. ---\n")
            log.configure(state="disabled")
            record_activity(
                "Export Log",
                "Success",
                f"{action} for {source_path.name}",
                inputs=[source_path],
                outputs=[out_path],
                log_text=f"{action}: {out_path}\nTimestamp source: {timestamp_source}",
                details={"format": fmt_var.get(), "timestamp_source": timestamp_source},
            )
        except Exception as ex:
            log.configure(state="normal")
            log.insert("end", f"\n[ERROR] {type(ex).__name__}: {ex}\n")
            log.configure(state="disabled")
            record_activity(
                "Export Log",
                "Error",
                f"Export failed for {source_path.name}",
                inputs=[source_path],
                log_text=str(ex),
                details={"error_type": type(ex).__name__},
            )
            messagebox.showerror("Export failed", f"{type(ex).__name__}: {ex}")


# ============================================================
# History frame
# ============================================================
def build_history_frame(parent, navigate):
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext

    _back_button(parent, navigate)
    _tool_header(parent, "History",
                 "Recent activity across merge, diff, report, artifact, and export workflows")

    body = tk.Frame(parent, bg=LIGHT_BG, padx=12, pady=10)
    body.pack(fill="both", expand=True)
    body.columnconfigure(0, weight=1)
    body.rowconfigure(2, weight=1)

    filter_row = tk.Frame(body, bg=LIGHT_BG)
    filter_row.grid(row=0, column=0, sticky="ew", pady=(0, 8))

    type_var = tk.StringVar(value="All")
    search_var = tk.StringVar()
    status_var = tk.StringVar(value="All")

    tk.Label(filter_row, text="Type:", font=FONT_MAIN, bg=LIGHT_BG, fg=TEXT_DARK).pack(side="left")
    type_combo = ttk.Combobox(
        filter_row,
        textvariable=type_var,
        state="readonly",
        width=24,
        values=["All", "Merge Log", "Diff Log", "Report Generation Log", "Artifact Report Log", "Export Log"],
    )
    type_combo.pack(side="left", padx=(6, 12))

    tk.Label(filter_row, text="Status:", font=FONT_MAIN, bg=LIGHT_BG, fg=TEXT_DARK).pack(side="left")
    status_combo = ttk.Combobox(
        filter_row,
        textvariable=status_var,
        state="readonly",
        width=12,
        values=["All", "Success", "Error"],
    )
    status_combo.pack(side="left", padx=(6, 12))

    tk.Label(filter_row, text="Search:", font=FONT_MAIN, bg=LIGHT_BG, fg=TEXT_DARK).pack(side="left")
    search_entry = ttk.Entry(filter_row, textvariable=search_var, width=28)
    search_entry.pack(side="left", padx=(6, 8))

    cols = ("timestamp", "type", "status", "summary")
    tree = ttk.Treeview(body, columns=cols, show="headings", height=12)
    tree.grid(row=1, column=0, sticky="nsew")
    body.rowconfigure(1, weight=1)

    widths = {"timestamp": 150, "type": 150, "status": 80, "summary": 520}
    labels = {"timestamp": "Timestamp", "type": "Type", "status": "Status", "summary": "Summary"}
    for col in cols:
        tree.heading(col, text=labels[col], anchor="w")
        tree.column(col, width=widths[col], anchor="w")

    tree.tag_configure("error", foreground=RED_FLAG)
    tree.tag_configure("success", foreground=GREEN_OK)

    details_frame = ttk.LabelFrame(body, text=" Activity Details ", padding=6)
    details_frame.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
    details_frame.columnconfigure(0, weight=1)
    details_frame.rowconfigure(0, weight=1)

    details = scrolledtext.ScrolledText(details_frame, font=FONT_MONO, height=10, wrap="word")
    details.grid(row=0, column=0, sticky="nsew")
    details.insert("end", "Select an activity entry to view details.\n")
    details.configure(state="disabled")

    footer = tk.Frame(body, bg=LIGHT_BG)
    footer.grid(row=3, column=0, sticky="ew", pady=(8, 0))

    cached_entries = {"all": [], "visible": []}

    def _format_entry(entry):
        lines = [
            f"Timestamp: {entry.get('timestamp', '')}",
            f"Type: {entry.get('action_type', '')}",
            f"Status: {entry.get('status', '')}",
            f"Summary: {entry.get('summary', '')}",
        ]
        inputs = entry.get("inputs") or []
        outputs = entry.get("outputs") or []
        if inputs:
            lines.append("")
            lines.append("Inputs:")
            lines.extend(f"  - {item}" for item in inputs)
        if outputs:
            lines.append("")
            lines.append("Outputs:")
            lines.extend(f"  - {item}" for item in outputs)
        details_map = entry.get("details") or {}
        if details_map:
            lines.append("")
            lines.append("Details:")
            for key, value in details_map.items():
                lines.append(f"  - {key}: {value}")
        log_text = (entry.get("log_text") or "").strip()
        if log_text:
            lines.append("")
            lines.append("Log:")
            lines.append(log_text)
        return "\n".join(lines)

    def _show_selected(_event=None):
        selection = tree.selection()
        details.configure(state="normal")
        details.delete("1.0", "end")
        if not selection:
            details.insert("end", "Select an activity entry to view details.\n")
            details.configure(state="disabled")
            return
        idx = tree.index(selection[0])
        entry = cached_entries["visible"][idx]
        details.insert("end", _format_entry(entry))
        details.configure(state="disabled")

    def _refresh():
        entries = read_activity_entries()
        cached_entries["all"] = entries
        tree.delete(*tree.get_children())
        needle = search_var.get().strip().lower()
        selected_type = type_var.get().strip()
        selected_status = status_var.get().strip()
        visible = []
        for entry in entries:
            if selected_type != "All" and entry.get("action_type") != selected_type:
                continue
            if selected_status != "All" and entry.get("status") != selected_status:
                continue
            haystack = " ".join([
                entry.get("timestamp", ""),
                entry.get("action_type", ""),
                entry.get("status", ""),
                entry.get("summary", ""),
                entry.get("log_text", ""),
                " ".join(str(v) for v in (entry.get("inputs") or [])),
                " ".join(str(v) for v in (entry.get("outputs") or [])),
            ]).lower()
            if needle and needle not in haystack:
                continue
            visible.append(entry)
            tag = "error" if entry.get("status") == "Error" else "success"
            tree.insert(
                "",
                "end",
                values=(
                    entry.get("timestamp", ""),
                    entry.get("action_type", ""),
                    entry.get("status", ""),
                    entry.get("summary", ""),
                ),
                tags=(tag,),
            )
        cached_entries["visible"] = visible
        details.configure(state="normal")
        details.delete("1.0", "end")
        if visible:
            details.insert("end", "Select an activity entry to view details.\n")
        else:
            details.insert("end", "No matching activity entries were found.\n")
        details.configure(state="disabled")

    def _open_output():
        selection = tree.selection()
        if not selection:
            messagebox.showinfo("No selection", "Select a history entry first.")
            return
        entry = cached_entries["visible"][tree.index(selection[0])]
        outputs = entry.get("outputs") or []
        if not outputs:
            messagebox.showinfo("No output", "This activity entry does not have an output file.")
            return
        err = open_path(outputs[0])
        if err:
            messagebox.showerror("Open failed", err)

    def _open_folder():
        selection = tree.selection()
        if not selection:
            messagebox.showinfo("No selection", "Select a history entry first.")
            return
        entry = cached_entries["visible"][tree.index(selection[0])]
        outputs = entry.get("outputs") or []
        target = outputs[0] if outputs else None
        if not target:
            messagebox.showinfo("No output", "This activity entry does not have an output file.")
            return
        err = open_folder(target)
        if err:
            messagebox.showerror("Open failed", err)

    ttk.Button(footer, text="Refresh", width=10, command=_refresh).pack(side="right", padx=4)
    ttk.Button(footer, text="Open Folder", width=12, command=_open_folder).pack(side="right", padx=4)
    ttk.Button(footer, text="Open Output", width=12, command=_open_output).pack(side="right", padx=4)

    tree.bind("<<TreeviewSelect>>", _show_selected)
    type_combo.bind("<<ComboboxSelected>>", lambda _e: _refresh())
    status_combo.bind("<<ComboboxSelected>>", lambda _e: _refresh())
    search_entry.bind("<KeyRelease>", lambda _e: _refresh())

    _refresh()


# ============================================================
# Entry point
# ============================================================
if __name__ == "__main__":
    main()
