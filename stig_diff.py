#!/usr/bin/env python3
"""
STIG Diff - Track STIG compliance state changes over time.

A zero-dependency PoC tool for detecting changes between DISA STIG Checklist
(CKL) snapshots. Compares each Vuln_Num's STATUS (Open / NotAFinding /
Not_Applicable / Not_Reviewed), FINDING_DETAILS, and COMMENTS across scans.

Usage:
    python stig_diff.py add <host> <ckl_file>
    python stig_diff.py list [host]
    python stig_diff.py diff <host> [--from DATE] [--to DATE]
    python stig_diff.py report <host> [--from DATE] [--to DATE] [--output FILE]

No database. No external packages. Python 3.8+ only.
"""

import argparse
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime
from pathlib import Path

# ============================================================
# Paths
# ============================================================
BASE_DIR = Path(__file__).parent.resolve()
SNAPSHOTS_DIR = BASE_DIR / "Snapshots"
REPORTS_DIR = BASE_DIR / "Reports"
BUCKET_META_NAME = "bucket.json"
FORBIDDEN_XML_PATTERN = re.compile(rb"<!\s*(DOCTYPE|ENTITY)\b", re.IGNORECASE)
ALLOWED_CHECKLIST_SUFFIXES = {".ckl"}


def _resolve_existing_local_path(path_value):
    """Resolve a user-visible local path and require that it already exists."""
    target = Path(path_value).expanduser()
    if not target.is_absolute():
        target = (BASE_DIR / target).resolve()
    else:
        target = target.resolve()
    if not target.exists():
        raise FileNotFoundError(f"Path not found: {target}")
    return target


def _resolve_checklist_path(path_value, allowed_suffixes=None):
    """Resolve and validate a checklist input path before reading it."""
    allowed = {suffix.lower() for suffix in (allowed_suffixes or ALLOWED_CHECKLIST_SUFFIXES)}
    target = _resolve_existing_local_path(path_value)
    if not target.is_file():
        raise ValueError(f"Checklist path is not a file: {target}")
    if target.suffix.lower() not in allowed:
        allowed_text = ", ".join(sorted(allowed))
        raise ValueError(f"Unsupported checklist type: {target.name} (expected {allowed_text})")
    return target


def _open_local_path(path_value):
    """Open a validated local file or folder without invoking a shell."""
    target = _resolve_existing_local_path(path_value)
    target_str = str(target)
    if sys.platform == "win32":
        os.startfile(target_str)  # nosemgrep: validated local path, no shell
    elif sys.platform == "darwin":
        subprocess.Popen(["open", target_str])  # nosemgrep: constant command, validated local path
    else:
        subprocess.Popen(["xdg-open", target_str])  # nosemgrep: constant command, validated local path


def _open_local_folder(path_value):
    """Open the parent folder for a validated local path without invoking a shell."""
    target = _resolve_existing_local_path(path_value)
    folder = target if target.is_dir() else target.parent
    folder_str = str(folder)
    if sys.platform == "win32":
        os.startfile(folder_str)  # nosemgrep: validated local path, no shell
    elif sys.platform == "darwin":
        subprocess.Popen(["open", folder_str])  # nosemgrep: constant command, validated local path
    else:
        subprocess.Popen(["xdg-open", folder_str])  # nosemgrep: constant command, validated local path


def _ensure_xml_has_no_external_entities(xml_bytes, source_name="XML"):
    """Reject XML that declares DOCTYPE or ENTITY before parsing it."""
    if FORBIDDEN_XML_PATTERN.search(xml_bytes):
        raise ValueError(f"{source_name} contains unsupported DOCTYPE/ENTITY declarations.")


def _parse_safe_xml_file(path_value, source_name="XML"):
    xml_bytes = _resolve_existing_local_path(path_value).read_bytes()
    _ensure_xml_has_no_external_entities(xml_bytes, source_name)
    root = ET.fromstring(xml_bytes)
    return ET.ElementTree(root)


# ============================================================
# CKL Parser
# ============================================================
def parse_ckl(ckl_path):
    """Parse a CKL file into a normalized dict structure."""
    ckl_path = _resolve_checklist_path(ckl_path, allowed_suffixes={".ckl"})
    tree = _parse_safe_xml_file(ckl_path, source_name=f"CKL file {ckl_path}")
    root = tree.getroot()

    asset = {}
    asset_el = root.find("ASSET")
    if asset_el is not None:
        for child in asset_el:
            asset[child.tag] = (child.text or "").strip()

    stigs = []
    for istig in root.findall(".//iSTIG"):
        stig_info = {}
        for si_data in istig.findall("./STIG_INFO/SI_DATA"):
            name = si_data.findtext("SID_NAME", "").strip()
            data = si_data.findtext("SID_DATA", "").strip()
            if name:
                stig_info[name] = data

        vulns = {}
        for vuln in istig.findall("VULN"):
            attrs = {}
            for stig_data in vuln.findall("STIG_DATA"):
                name = stig_data.findtext("VULN_ATTRIBUTE", "").strip()
                data = stig_data.findtext("ATTRIBUTE_DATA", "").strip()
                if not name:
                    continue
                # Some attrs (CCI_REF) repeat — keep as list
                if name in attrs:
                    if isinstance(attrs[name], list):
                        attrs[name].append(data)
                    else:
                        attrs[name] = [attrs[name], data]
                else:
                    attrs[name] = data

            vuln_num = attrs.get("Vuln_Num", "")
            if not vuln_num:
                continue

            vulns[vuln_num] = {
                "vuln_num": vuln_num,
                "rule_id": attrs.get("Rule_ID", ""),
                "rule_title": attrs.get("Rule_Title", ""),
                "severity": attrs.get("Severity", ""),
                "group_title": attrs.get("Group_Title", ""),
                "status": (vuln.findtext("STATUS") or "").strip(),
                "finding_details": (vuln.findtext("FINDING_DETAILS") or "").strip(),
                "comments": (vuln.findtext("COMMENTS") or "").strip(),
                "severity_override": (vuln.findtext("SEVERITY_OVERRIDE") or "").strip(),
                "severity_justification": (vuln.findtext("SEVERITY_JUSTIFICATION") or "").strip(),
            }

        stigs.append({
            "title": stig_info.get("title", "Unknown STIG"),
            "stigid": stig_info.get("stigid", ""),
            "version": stig_info.get("version", ""),
            "release": stig_info.get("releaseinfo", ""),
            "vulns": vulns,
        })

    return {
        "asset": asset,
        "stigs": stigs,
        "source_file": Path(ckl_path).name,
        "parsed_at": datetime.now().isoformat(timespec="seconds"),
    }


def flatten_vulns(snapshot):
    """Merge all iSTIGs' vulns into one dict keyed by Vuln_Num."""
    merged = {}
    for stig in snapshot["stigs"]:
        merged.update(stig["vulns"])
    return merged


# ============================================================
# Snapshot Management
# ============================================================
def sanitize_hostname(name):
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
    return safe.strip("._") or "UNKNOWN"


def shorten_stig_title(title):
    """Derive a short tag from a full STIG title.

    Examples:
      'Microsoft Windows Server 2019 STIG' → 'WinServer2019'
      'Google Chrome STIG'                 → 'Chrome'
      'Mozilla Firefox STIG'               → 'Firefox'
      'Ubuntu 20.04 LTS STIG'              → 'Ubuntu2004'
      'Application Security and Dev STIG'  → 'ASD'
    """
    # Remove common noise words
    noise = [
        "security technical implementation guide", "stig", "benchmark",
        "microsoft", "disa", "for", "the", "and", "of", "v1", "v2", "v3",
        "release", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8",
    ]
    import re
    t = title.lower().strip()
    # Remove version suffixes like "V3R8"
    t = re.sub(r'\bv\d+r\d+\b', '', t)
    # Remove parenthesized content
    t = re.sub(r'\(.*?\)', '', t)
    # Split into words, drop noise
    words = [w for w in re.split(r'[\s_\-]+', t)
             if w and w not in noise]
    # For known long names, produce a readable short form
    joined = " ".join(words)
    short_map = {
        "windows server 2019": "WinServer2019",
        "windows server 2022": "WinServer2022",
        "windows server 2016": "WinServer2016",
        "windows 10": "Win10",
        "windows 11": "Win11",
        "rhel 7": "RHEL7",
        "rhel 8": "RHEL8",
        "rhel 9": "RHEL9",
        "red hat enterprise linux 7": "RHEL7",
        "red hat enterprise linux 8": "RHEL8",
        "red hat enterprise linux 9": "RHEL9",
        "ubuntu 20.04": "Ubuntu2004",
        "ubuntu 22.04": "Ubuntu2204",
        "google chrome": "Chrome",
        "mozilla firefox": "Firefox",
        "internet explorer": "IE",
        "iis 10.0": "IIS10",
        "iis 8.5": "IIS85",
        "oracle jre": "OracleJRE",
        "oracle database": "OracleDB",
        "sql server 2019": "MSSQL2019",
        "sql server 2017": "MSSQL2017",
        "application security": "ASD",
        "active directory": "AD",
        "windows defender": "Defender",
        "adobe acrobat": "Acrobat",
        "adobe reader": "AcrobatReader",
    }
    for pattern, replacement in short_map.items():
        if pattern in joined:
            return replacement
    # Fall back: take first 2 meaningful words, capitalize
    if words:
        return "".join(w.capitalize() for w in words[:2])
    return "STIG"


def derive_host_key(snapshot):
    """Build a reliable host+STIG folder key from parsed CKL content.

    Returns e.g. 'SERVER01-WinServer2019' or 'SERVER01-Chrome'.
    Falls back gracefully if any piece is missing.
    """
    hostname = snapshot["asset"].get("HOST_NAME", "").strip()
    if not hostname:
        hostname = "UNKNOWN"

    # Use the first STIG's title
    stig_tag = "STIG"
    if snapshot.get("stigs"):
        title = snapshot["stigs"][0].get("title", "").strip()
        if title:
            stig_tag = shorten_stig_title(title)

    raw = f"{hostname}-{stig_tag}"
    return sanitize_hostname(raw)


def timestamp_now():
    return datetime.now().strftime("%Y_%m_%d_%H%M%S")


def browse_initial_dir(current_value=""):
    """Return the best starting folder for file pickers."""
    if current_value:
        candidate = Path(current_value).expanduser()
        if candidate.is_file():
            return str(candidate.parent)
        if candidate.is_dir():
            return str(candidate)
    return str(BASE_DIR)


def bucket_metadata_path(bucket_dir):
    return Path(bucket_dir) / BUCKET_META_NAME


def load_bucket_metadata(bucket_dir):
    meta_path = bucket_metadata_path(bucket_dir)
    if not meta_path.is_file():
        return {}
    try:
        return json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def write_bucket_metadata(bucket_dir, metadata):
    meta_path = bucket_metadata_path(bucket_dir)
    meta_path.write_text(json.dumps(metadata, indent=2, sort_keys=True),
                         encoding="utf-8")


def file_sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_bucket_metadata(bucket_key, snapshot, bucket_dir, latest_snapshot=None,
                          source_hash=None):
    host_name = snapshot["asset"].get("HOST_NAME", "").strip() or "UNKNOWN"
    stig = snapshot["stigs"][0] if snapshot.get("stigs") else {}
    now_iso = datetime.now().isoformat(timespec="seconds")
    existing = load_bucket_metadata(bucket_dir)
    created_at = existing.get("created_at", now_iso)
    metadata = {
        "bucket_key": bucket_key,
        "host_name": host_name,
        "stig_title": stig.get("title", "Unknown STIG"),
        "stig_short_name": shorten_stig_title(stig.get("title", "")) if stig.get("title") else "STIG",
        "stigid": stig.get("stigid", ""),
        "created_at": created_at,
        "last_seen_at": now_iso,
        "snapshot_count": len(list(Path(bucket_dir).glob("*.ckl"))),
    }
    if latest_snapshot:
        metadata["latest_snapshot"] = Path(latest_snapshot).name
    if source_hash:
        metadata["latest_source_sha256"] = source_hash
    return metadata


def find_duplicate_snapshot(bucket_dir, source_hash):
    for existing in sorted(Path(bucket_dir).glob("*.ckl")):
        try:
            if file_sha256(existing) == source_hash:
                return existing
        except OSError:
            continue
    return None


def save_snapshot_to_history(ckl_file, bucket_key=None):
    """Save a CKL file into the snapshot history store.

    If bucket_key is omitted, derive it from CKL content using the host name
    and a shortened STIG title.

    Returns a dict with:
      bucket_key, dest_path, snapshot, vulns, saved, duplicate_of
    """
    ckl_path = Path(ckl_file).expanduser().resolve()
    if not ckl_path.is_file():
        raise FileNotFoundError(f"File not found: {ckl_path}")

    snapshot = parse_ckl(ckl_path)
    vulns = flatten_vulns(snapshot)

    if not vulns:
        print("WARNING: No VULN entries found. Is this a valid CKL?",
              file=sys.stderr)

    bucket_key = sanitize_hostname(bucket_key) if bucket_key else derive_host_key(snapshot)
    bucket_dir = SNAPSHOTS_DIR / bucket_key
    bucket_dir.mkdir(parents=True, exist_ok=True)

    source_hash = file_sha256(ckl_path)
    duplicate_of = find_duplicate_snapshot(bucket_dir, source_hash)
    if duplicate_of is not None:
        metadata = build_bucket_metadata(bucket_key, snapshot, bucket_dir,
                                         latest_snapshot=duplicate_of,
                                         source_hash=source_hash)
        write_bucket_metadata(bucket_dir, metadata)
        return {
            "bucket_key": bucket_key,
            "dest_path": duplicate_of,
            "snapshot": snapshot,
            "vulns": vulns,
            "saved": False,
            "duplicate_of": duplicate_of,
            "source_sha256": source_hash,
            "metadata_path": bucket_metadata_path(bucket_dir),
        }

    ts = timestamp_now()
    dest = bucket_dir / f"{ts}.ckl"
    shutil.copy2(ckl_path, dest)
    metadata = build_bucket_metadata(bucket_key, snapshot, bucket_dir,
                                     latest_snapshot=dest,
                                     source_hash=source_hash)
    write_bucket_metadata(bucket_dir, metadata)

    return {
        "bucket_key": bucket_key,
        "dest_path": dest,
        "snapshot": snapshot,
        "vulns": vulns,
        "saved": True,
        "duplicate_of": None,
        "source_sha256": source_hash,
        "metadata_path": bucket_metadata_path(bucket_dir),
    }


def register_ckl(ckl_file):
    """Backward-compatible alias for saving a CKL into history."""
    result = save_snapshot_to_history(ckl_file)
    return result["bucket_key"], result["dest_path"], result["snapshot"], result["vulns"]


def add_snapshot(host, ckl_file):
    """CLI wrapper for saving a snapshot into history.

    If host is 'AUTO' (or empty), derive the bucket key from CKL content.
    Otherwise, use the provided bucket name.
    """
    if not host or host.upper() == "AUTO":
        try:
            result = save_snapshot_to_history(ckl_file)
        except (FileNotFoundError, ET.ParseError) as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        try:
            result = save_snapshot_to_history(
                ckl_file, bucket_key=host)
        except (FileNotFoundError, ET.ParseError) as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
    host_key = result["bucket_key"]
    dest = result["dest_path"]
    snapshot = result["snapshot"]
    vulns = result["vulns"]

    tally = {}
    for v in vulns.values():
        tally[v["status"]] = tally.get(v["status"], 0) + 1

    if result["saved"]:
        print(f"[OK] Snapshot saved: {dest.relative_to(BASE_DIR)}")
    else:
        print(f"[OK] Duplicate snapshot detected: {dest.relative_to(BASE_DIR)}")
        print("     No new file copied; existing history entry reused.")
    print(f"     History bucket: {host_key}")
    print(f"     Host name: {snapshot['asset'].get('HOST_NAME', host_key)}")
    print(f"     STIGs: {len(snapshot['stigs'])}")
    print(f"     Vulns: {len(vulns)}")
    for status, count in sorted(tally.items()):
        print(f"       {status or '(blank)'}: {count}")


def list_snapshots(host=None):
    if not SNAPSHOTS_DIR.exists():
        print("(no snapshots yet - use 'add' to save a CKL into history)")
        return

    hosts = sorted(SNAPSHOTS_DIR.iterdir())
    if host:
        host_safe = sanitize_hostname(host)
        hosts = [h for h in hosts if h.name == host_safe]

    if not hosts:
        print("(no snapshots found)")
        return

    for host_dir in hosts:
        if not host_dir.is_dir():
            continue
        ckls = sorted(host_dir.glob("*.ckl"))
        print(f"\n{host_dir.name}  ({len(ckls)} snapshots)")
        for ckl in ckls:
            size_kb = ckl.stat().st_size / 1024
            print(f"  {ckl.stem}  ({size_kb:.1f} KB)")


def get_snapshots(host):
    host_safe = sanitize_hostname(host)
    host_dir = SNAPSHOTS_DIR / host_safe
    if not host_dir.exists():
        return []
    return sorted(host_dir.glob("*.ckl"))


def get_all_hosts():
    """Return history bucket names (folder names under Snapshots/)."""
    if not SNAPSHOTS_DIR.exists():
        return []
    return sorted(
        d.name for d in SNAPSHOTS_DIR.iterdir()
        if d.is_dir() and list(d.glob("*.ckl"))
    )


def get_host_summary(host_key):
    """Return a summary dict for a saved history bucket.

    Keys: host_key, snapshots (list of Path), snapshot_count,
          last_scan (datetime|None), latest_tally (dict status->count),
          metadata (dict).
    """
    host_dir = SNAPSHOTS_DIR / host_key
    snaps = sorted(host_dir.glob("*.ckl")) if host_dir.exists() else []
    metadata = load_bucket_metadata(host_dir) if host_dir.exists() else {}
    last_scan = snapshot_datetime(snaps[-1]) if snaps else None
    tally = {}
    if snaps:
        try:
            snap = parse_ckl(snaps[-1])
            for v in flatten_vulns(snap).values():
                s = v["status"] or "blank"
                tally[s] = tally.get(s, 0) + 1
        except Exception:
            pass
    return {
        "host_key": host_key,
        "snapshots": snaps,
        "snapshot_count": len(snaps),
        "last_scan": last_scan,
        "latest_tally": tally,
        "metadata": metadata,
    }


def _normalize_severity(severity):
    s = (severity or "").strip().lower().replace("_", "").replace(" ", "")
    if s in {"high", "cati", "cat1", "categoryi"}:
        return "cat1"
    if s in {"medium", "catii", "cat2", "categoryii"}:
        return "cat2"
    if s in {"low", "catiii", "cat3", "categoryiii"}:
        return "cat3"
    return ""


def summarize_excel_counts(snapshot):
    """Summarize the latest snapshot into Excel-report columns."""
    counts = {
        "Open CAT I": 0,
        "Not Reviewed CAT I": 0,
        "Open CAT IIs": 0,
        "Not Reviewed CAT IIs": 0,
        "Open CAT IIIs": 0,
        "Not Reviewed CAT IIIs": 0,
        "Not a Finding": 0,
        "Not Applicable": 0,
        "Total": 0,
    }
    for vuln in flatten_vulns(snapshot).values():
        status = (vuln.get("status") or "").strip()
        severity = _normalize_severity(vuln.get("severity"))
        counts["Total"] += 1
        if status == "Open":
            if severity == "cat1":
                counts["Open CAT I"] += 1
            elif severity == "cat2":
                counts["Open CAT IIs"] += 1
            elif severity == "cat3":
                counts["Open CAT IIIs"] += 1
        elif status == "Not_Reviewed":
            if severity == "cat1":
                counts["Not Reviewed CAT I"] += 1
            elif severity == "cat2":
                counts["Not Reviewed CAT IIs"] += 1
            elif severity == "cat3":
                counts["Not Reviewed CAT IIIs"] += 1
        elif status == "NotAFinding":
            counts["Not a Finding"] += 1
        elif status == "Not_Applicable":
            counts["Not Applicable"] += 1
    return counts


def build_history_excel_rows():
    """Return one export row per tracked system using its latest snapshot."""
    rows = []
    for host_key in get_all_hosts():
        summary = get_host_summary(host_key)
        snaps = summary["snapshots"]
        metadata = summary.get("metadata") or {}
        row = {
            "History Bucket": host_key,
            "Host Name": metadata.get("host_name", host_key),
            "STIG": metadata.get("stig_short_name")
                or shorten_stig_title(metadata.get("stig_title", "")),
            "Last Scan": summary["last_scan"].strftime("%Y-%m-%d %H:%M:%S")
                if summary["last_scan"] else "",
        }
        counts = {
            "Open CAT I": 0,
            "Not Reviewed CAT I": 0,
            "Open CAT IIs": 0,
            "Not Reviewed CAT IIs": 0,
            "Open CAT IIIs": 0,
            "Not Reviewed CAT IIIs": 0,
            "Not a Finding": 0,
            "Not Applicable": 0,
            "Total": 0,
        }
        if snaps:
            try:
                counts = summarize_excel_counts(parse_ckl(snaps[-1]))
            except Exception:
                pass
        row.update(counts)
        rows.append(row)
    return rows


def _excel_column_name(index):
    name = ""
    while index > 0:
        index, remainder = divmod(index - 1, 26)
        name = chr(65 + remainder) + name
    return name


def write_history_excel_report(rows, output_path):
    """Write a simple .xlsx workbook for Excel using only the stdlib."""
    columns = [
        "History Bucket",
        "Host Name",
        "STIG",
        "Last Scan",
        "Open CAT I",
        "Not Reviewed CAT I",
        "Open CAT IIs",
        "Not Reviewed CAT IIs",
        "Open CAT IIIs",
        "Not Reviewed CAT IIIs",
        "Not a Finding",
        "Not Applicable",
        "Total",
    ]
    widths = [24, 18, 14, 20, 12, 16, 12, 17, 12, 18, 14, 14, 10]

    def esc(text):
        return html.escape(str(text), quote=False)

    def cell_xml(ref, value, is_header=False):
        style_attr = ' s="1"' if is_header else ""
        if isinstance(value, int):
            return f'<c r="{ref}"{style_attr}><v>{value}</v></c>'
        return (
            f'<c r="{ref}" t="inlineStr"{style_attr}>'
            f'<is><t>{esc(value)}</t></is></c>'
        )

    all_rows = [columns]
    for row in rows:
        all_rows.append([row.get(col, "") for col in columns])

    sheet_rows = []
    for row_idx, row_values in enumerate(all_rows, start=1):
        cells = []
        for col_idx, value in enumerate(row_values, start=1):
            ref = f"{_excel_column_name(col_idx)}{row_idx}"
            cells.append(cell_xml(ref, value, is_header=(row_idx == 1)))
        sheet_rows.append(f'<row r="{row_idx}">{"".join(cells)}</row>')

    cols_xml = "".join(
        f'<col min="{i}" max="{i}" width="{width}" customWidth="1"/>'
        for i, width in enumerate(widths, start=1)
    )
    last_col = _excel_column_name(len(columns))
    last_row = len(all_rows)
    sheet_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<dimension ref="A1:{last_col}{last_row}"/>'
        '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" '
        'activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'
        '<sheetFormatPr defaultRowHeight="15"/>'
        f'<cols>{cols_xml}</cols>'
        f'<sheetData>{"".join(sheet_rows)}</sheetData>'
        '</worksheet>'
    )

    workbook_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="History Summary" sheetId="1" r:id="rId1"/></sheets>'
        '</workbook>'
    )
    workbook_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet1.xml"/>'
        '<Relationship Id="rId2" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
        '</Relationships>'
    )
    root_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>'
        '</Relationships>'
    )
    content_types_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '<Override PartName="/xl/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        '</Types>'
    )
    styles_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="2">'
        '<font><sz val="11"/><name val="Calibri"/></font>'
        '<font><b/><sz val="11"/><name val="Calibri"/></font>'
        '</fonts>'
        '<fills count="2">'
        '<fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill>'
        '</fills>'
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="2">'
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>'
        '</cellXfs>'
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        '</styleSheet>'
    )

    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types_xml)
        zf.writestr("_rels/.rels", root_rels_xml)
        zf.writestr("xl/workbook.xml", workbook_xml)
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels_xml)
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)
        zf.writestr("xl/styles.xml", styles_xml)
    return output_path


def write_history_html_report(rows, output_path):
    """Write an HTML summary report for the latest snapshot per tracked system."""
    columns = [
        "History Bucket",
        "Host Name",
        "STIG",
        "Last Scan",
        "Open CAT I",
        "Not Reviewed CAT I",
        "Open CAT IIs",
        "Not Reviewed CAT IIs",
        "Open CAT IIIs",
        "Not Reviewed CAT IIIs",
        "Not a Finding",
        "Not Applicable",
        "Total",
    ]

    def esc(text):
        return html.escape(str(text), quote=False)

    table_rows = []
    for row in rows:
        cells = "".join(
            f"<td>{esc(row.get(col, ''))}</td>"
            for col in columns
        )
        table_rows.append(f"<tr>{cells}</tr>")

    header_cells = "".join(f"<th>{esc(col)}</th>" for col in columns)
    html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>STIG History Summary</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 24px; background: #f6f8fb; color: #1f2937; }}
  h1 {{ margin-bottom: 8px; }}
  .meta {{ color: #5b6472; margin-bottom: 18px; }}
  table {{ width: 100%; border-collapse: collapse; background: #ffffff; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }}
  th, td {{ border: 1px solid #d7deea; padding: 8px 10px; font-size: 13px; text-align: left; }}
  th {{ background: #003366; color: #ffffff; position: sticky; top: 0; }}
  tr:nth-child(even) td {{ background: #f8fbff; }}
  td {{ white-space: nowrap; }}
</style>
</head>
<body>
<h1>STIG History Summary</h1>
<div class="meta">Latest snapshot per tracked system. Generated {esc(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}.</div>
<table>
  <thead><tr>{header_cells}</tr></thead>
  <tbody>{''.join(table_rows) if table_rows else '<tr><td colspan="13">No saved history found.</td></tr>'}</tbody>
</table>
</body>
</html>
"""
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_out, encoding="utf-8")
    return output_path


def parse_date_arg(s):
    if not s:
        return None
    for fmt in ("%Y_%m_%d_%H%M%S", "%Y-%m-%d_%H%M%S", "%Y_%m_%d", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(
        f"Invalid date: {s} (use YYYY-MM-DD, YYYY_MM_DD, YYYY-MM-DD_HHMMSS, or YYYY_MM_DD_HHMMSS)")


def snapshot_datetime(ckl_path):
    try:
        for fmt in ("%Y_%m_%d_%H%M%S", "%Y-%m-%d_%H%M%S"):
            try:
                return datetime.strptime(ckl_path.stem, fmt)
            except ValueError:
                pass
        raise ValueError("unsupported snapshot timestamp format")
    except ValueError:
        return datetime.fromtimestamp(ckl_path.stat().st_mtime)


def pick_snapshots(host, from_dt=None, to_dt=None):
    """Return (old, new) snapshot paths based on date filters.

    No filters: last two snapshots.
    --from only: that one vs most recent.
    --from and --to: both closest matches.
    """
    all_snaps = get_snapshots(host)
    if len(all_snaps) < 2:
        return None, None

    if from_dt is None and to_dt is None:
        return all_snaps[-2], all_snaps[-1]

    def closest(target):
        return min(all_snaps, key=lambda p: abs(snapshot_datetime(p) - target))

    if from_dt and to_dt:
        return closest(from_dt), closest(to_dt)
    if from_dt:
        return closest(from_dt), all_snaps[-1]
    return all_snaps[-2], closest(to_dt)


# ============================================================
# Diff Engine
# ============================================================
_COMPLIANT = {"NotAFinding", "Not_Applicable"}
_NONCOMPLIANT = {"Open"}


def _is_regression(old, new):
    return old in _COMPLIANT and new in _NONCOMPLIANT


def _is_improvement(old, new):
    return old in _NONCOMPLIANT and new in _COMPLIANT


def _vuln_sort_key(v):
    s = v if isinstance(v, str) else v.get("vuln_num", "")
    digits = "".join(c for c in s if c.isdigit())
    return (int(digits) if digits else 0, s)


def compute_diff(old_snap, new_snap):
    """Compute categorized diff between two snapshots."""
    old_vulns = flatten_vulns(old_snap)
    new_vulns = flatten_vulns(new_snap)

    old_ids = set(old_vulns.keys())
    new_ids = set(new_vulns.keys())

    regressions = []
    improvements = []
    status_changes = []
    metadata_changes = []

    for vid in sorted(old_ids & new_ids, key=_vuln_sort_key):
        old_v = old_vulns[vid]
        new_v = new_vulns[vid]

        entry = {
            "vuln_num": vid,
            "rule_title": new_v.get("rule_title") or old_v.get("rule_title"),
            "severity": new_v.get("severity") or old_v.get("severity"),
            "old_status": old_v["status"],
            "new_status": new_v["status"],
            "old_finding_details": old_v["finding_details"],
            "new_finding_details": new_v["finding_details"],
            "old_comments": old_v["comments"],
            "new_comments": new_v["comments"],
        }

        if old_v["status"] != new_v["status"]:
            if _is_regression(old_v["status"], new_v["status"]):
                regressions.append(entry)
            elif _is_improvement(old_v["status"], new_v["status"]):
                improvements.append(entry)
            else:
                status_changes.append(entry)
        else:
            if (old_v["finding_details"] != new_v["finding_details"]
                    or old_v["comments"] != new_v["comments"]):
                metadata_changes.append(entry)

    new_only = [new_vulns[v] for v in sorted(new_ids - old_ids, key=_vuln_sort_key)]
    removed = [old_vulns[v] for v in sorted(old_ids - new_ids, key=_vuln_sort_key)]

    return {
        "regressions": regressions,
        "improvements": improvements,
        "status_changes": status_changes,
        "metadata_changes": metadata_changes,
        "new_vulns": new_only,
        "removed_vulns": removed,
    }


# ============================================================
# Console Reporter
# ============================================================
def print_console_diff(host, old_path, new_path, diff):
    old_dt = snapshot_datetime(old_path)
    new_dt = snapshot_datetime(new_path)
    print("\n" + "=" * 72)
    print(f"STIG Diff: {host}")
    print(f"  Old: {old_path.name}  ({old_dt})")
    print(f"  New: {new_path.name}  ({new_dt})")
    print("=" * 72)

    print(f"\n[!] REGRESSIONS           ({len(diff['regressions'])})  "
          "-- compliance got worse")
    for e in diff["regressions"]:
        print(f"    {e['vuln_num']}  [{e['severity']}]  "
              f"{e['old_status']} -> {e['new_status']}")
        title = e['rule_title'][:75] + ("..." if len(e['rule_title']) > 75 else "")
        print(f"        {title}")

    print(f"\n[+] IMPROVEMENTS          ({len(diff['improvements'])})")
    for e in diff["improvements"]:
        print(f"    {e['vuln_num']}  [{e['severity']}]  "
              f"{e['old_status']} -> {e['new_status']}")

    print(f"\n[~] OTHER STATUS CHANGES  ({len(diff['status_changes'])})")
    for e in diff["status_changes"]:
        print(f"    {e['vuln_num']}  {e['old_status']} -> {e['new_status']}")

    print(f"\n[*] METADATA CHANGES      ({len(diff['metadata_changes'])})  "
          "-- status same, details/comments differ")
    for e in diff["metadata_changes"]:
        print(f"    {e['vuln_num']}  ({e['new_status']})")

    print(f"\n[N] NEW VULNS             ({len(diff['new_vulns'])})")
    for v in diff["new_vulns"][:20]:
        print(f"    {v['vuln_num']}  [{v['severity']}]  {v['status']}")
    if len(diff["new_vulns"]) > 20:
        print(f"    ... and {len(diff['new_vulns']) - 20} more")

    print(f"\n[-] REMOVED VULNS         ({len(diff['removed_vulns'])})")
    for v in diff["removed_vulns"][:20]:
        print(f"    {v['vuln_num']}  [{v['severity']}]")
    if len(diff["removed_vulns"]) > 20:
        print(f"    ... and {len(diff['removed_vulns']) - 20} more")
    print()


# ============================================================
# HTML Reporter
# ============================================================
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>STIG Diff Report - {host}</title>
<style>
  body {{ font-family: -apple-system, 'Segoe UI', Roboto, sans-serif;
          max-width: 1200px; margin: 2em auto; padding: 0 1em;
          color: #222; background: #fafafa; }}
  header {{ border-bottom: 2px solid #333; padding-bottom: 1em;
           margin-bottom: 1.5em; }}
  h1 {{ margin: 0 0 0.3em 0; }}
  .meta {{ color: #666; font-size: 0.9em; line-height: 1.6; }}
  .summary {{ display: grid; grid-template-columns: repeat(6, 1fr);
             gap: 0.8em; margin: 1.5em 0; }}
  .summary .card {{ background: #fff; padding: 0.9em; border-radius: 6px;
                   border-left: 4px solid #888; }}
  .summary .card.regression {{ border-color: #c62828; }}
  .summary .card.improvement {{ border-color: #2e7d32; }}
  .summary .card.status {{ border-color: #f9a825; }}
  .summary .card.metadata {{ border-color: #6a1b9a; }}
  .summary .card.new {{ border-color: #0277bd; }}
  .summary .card.removed {{ border-color: #555; }}
  .summary .count {{ font-size: 1.8em; font-weight: bold; display: block; }}
  .summary .label {{ font-size: 0.75em; color: #666; text-transform: uppercase;
                    letter-spacing: 0.05em; }}
  section {{ background: #fff; padding: 1.2em; border-radius: 6px;
            margin-bottom: 1.5em; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
  section h2 {{ margin-top: 0; }}
  section.regressions h2 {{ color: #c62828; }}
  section.improvements h2 {{ color: #2e7d32; }}
  section.status-changes h2 {{ color: #f57c00; }}
  section.metadata h2 {{ color: #6a1b9a; }}
  .count-badge {{ font-weight: normal; color: #999; font-size: 0.8em; }}
  table {{ width: 100%; border-collapse: collapse; }}
  td {{ padding: 0.5em; border-bottom: 1px solid #eee; vertical-align: top; }}
  td.vuln {{ font-family: monospace; font-weight: bold; width: 110px; }}
  td.sev {{ width: 75px; font-size: 0.85em; text-transform: uppercase; }}
  td.sev.sev-high {{ color: #c62828; font-weight: bold; }}
  td.sev.sev-medium {{ color: #f57c00; }}
  td.sev.sev-low {{ color: #558b2f; }}
  td.status {{ width: 230px; font-family: monospace; font-size: 0.85em; }}
  td.title {{ color: #444; }}
  td.empty {{ color: #999; text-align: center; padding: 1.5em;
             font-style: italic; }}
  details {{ margin: 0.3em 0; }}
  summary {{ cursor: pointer; color: #0277bd; font-size: 0.85em; }}
  .detail-grid {{ display: grid; grid-template-columns: 1fr 1fr;
                 gap: 1em; margin-top: 0.6em; }}
  .detail-grid h4 {{ margin: 0 0 0.3em 0; font-size: 0.8em; color: #555; }}
  .detail-grid pre {{ background: #f5f5f5; padding: 0.5em; border-radius: 3px;
                     white-space: pre-wrap; font-size: 0.8em;
                     max-height: 200px; overflow: auto; margin: 0; }}
  footer {{ text-align: center; color: #999; font-size: 0.8em; margin-top: 2em; }}
</style>
</head>
<body>
<header>
  <h1>STIG Diff Report</h1>
  <div class="meta">
    <strong>Host:</strong> {host}<br>
    <strong>Comparing:</strong> <code>{old_file}</code> ({old_dt})
    &nbsp;&rarr;&nbsp; <code>{new_file}</code> ({new_dt})<br>
    <strong>Generated:</strong> {generated}
  </div>
</header>

<div class="summary">
  <div class="card regression">
    <span class="count">{regression_count}</span>
    <span class="label">Regressions</span>
  </div>
  <div class="card improvement">
    <span class="count">{improvement_count}</span>
    <span class="label">Improvements</span>
  </div>
  <div class="card status">
    <span class="count">{status_change_count}</span>
    <span class="label">Status Changes</span>
  </div>
  <div class="card metadata">
    <span class="count">{metadata_change_count}</span>
    <span class="label">Metadata</span>
  </div>
  <div class="card new">
    <span class="count">{new_vuln_count}</span>
    <span class="label">New</span>
  </div>
  <div class="card removed">
    <span class="count">{removed_vuln_count}</span>
    <span class="label">Removed</span>
  </div>
</div>

{regression_section}
{improvement_section}
{status_change_section}
{metadata_change_section}
{new_vulns_section}
{removed_vulns_section}

<footer>STIG Diff PoC &middot; Evidence files: <code>Snapshots/{host}/</code></footer>
</body>
</html>
"""


def write_html_report(host, old_path, new_path, diff, output_path):
    old_dt = snapshot_datetime(old_path)
    new_dt = snapshot_datetime(new_path)

    def esc(s):
        return html.escape(str(s)) if s else ""

    def row_change(e):
        return f"""
        <tr>
          <td class="vuln">{esc(e['vuln_num'])}</td>
          <td class="sev sev-{esc(e['severity']).lower()}">{esc(e['severity'])}</td>
          <td class="status">{esc(e['old_status'])} &rarr; <strong>{esc(e['new_status'])}</strong></td>
          <td class="title">{esc(e['rule_title'])}
            <details>
              <summary>Details</summary>
              <div class="detail-grid">
                <div><h4>FINDING_DETAILS (old)</h4><pre>{esc(e['old_finding_details']) or '(empty)'}</pre></div>
                <div><h4>FINDING_DETAILS (new)</h4><pre>{esc(e['new_finding_details']) or '(empty)'}</pre></div>
                <div><h4>COMMENTS (old)</h4><pre>{esc(e['old_comments']) or '(empty)'}</pre></div>
                <div><h4>COMMENTS (new)</h4><pre>{esc(e['new_comments']) or '(empty)'}</pre></div>
              </div>
            </details>
          </td>
        </tr>"""

    def row_new(v):
        return f"""
        <tr>
          <td class="vuln">{esc(v['vuln_num'])}</td>
          <td class="sev sev-{esc(v['severity']).lower()}">{esc(v['severity'])}</td>
          <td class="status">{esc(v['status'])}</td>
          <td class="title">{esc(v['rule_title'])}</td>
        </tr>"""

    def section(title, entries, css_class, render_fn, empty_msg):
        if entries:
            rows = "\n".join(render_fn(e) for e in entries)
        else:
            rows = f'<tr><td colspan="4" class="empty">{empty_msg}</td></tr>'
        return (f'<section class="{css_class}">\n'
                f'  <h2>{title} <span class="count-badge">({len(entries)})</span></h2>\n'
                f'  <table>{rows}</table>\n'
                f'</section>')

    html_out = HTML_TEMPLATE.format(
        host=esc(host),
        old_file=esc(old_path.name),
        new_file=esc(new_path.name),
        old_dt=esc(old_dt.strftime("%Y-%m-%d %H:%M:%S")),
        new_dt=esc(new_dt.strftime("%Y-%m-%d %H:%M:%S")),
        generated=esc(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        regression_count=len(diff["regressions"]),
        improvement_count=len(diff["improvements"]),
        status_change_count=len(diff["status_changes"]),
        metadata_change_count=len(diff["metadata_changes"]),
        new_vuln_count=len(diff["new_vulns"]),
        removed_vuln_count=len(diff["removed_vulns"]),
        regression_section=section(
            "&#9888; Regressions", diff["regressions"], "regressions",
            row_change, "No regressions &mdash; no compliance loss detected."),
        improvement_section=section(
            "&#10003; Improvements", diff["improvements"], "improvements",
            row_change, "No improvements in this window."),
        status_change_section=section(
            "&#8635; Other Status Changes", diff["status_changes"],
            "status-changes", row_change, "No other status changes."),
        metadata_change_section=section(
            "&#128221; Metadata Changes (same status, different details)",
            diff["metadata_changes"], "metadata", row_change,
            "No metadata changes."),
        new_vulns_section=section(
            "&#10133; New Vulnerabilities", diff["new_vulns"], "new-vulns",
            row_new, "No new vulns."),
        removed_vulns_section=section(
            "&#10134; Removed Vulnerabilities", diff["removed_vulns"],
            "removed-vulns", row_new, "No removed vulns."),
    )

    output_path.write_text(html_out, encoding="utf-8")


# ============================================================
# CLI
# ============================================================
def cmd_add(args):
    add_snapshot(args.host, args.ckl_file)


def cmd_list(args):
    list_snapshots(args.host)


def cmd_diff(args):
    old_path, new_path = pick_snapshots(args.host, args.from_date, args.to_date)
    if old_path is None:
        print(f"ERROR: Need >=2 snapshots for host '{args.host}'.", file=sys.stderr)
        sys.exit(1)
    old_snap = parse_ckl(old_path)
    new_snap = parse_ckl(new_path)
    diff = compute_diff(old_snap, new_snap)
    print_console_diff(args.host, old_path, new_path, diff)


def cmd_report(args):
    old_path, new_path = pick_snapshots(args.host, args.from_date, args.to_date)
    if old_path is None:
        print(f"ERROR: Need >=2 snapshots for host '{args.host}'.", file=sys.stderr)
        sys.exit(1)
    old_snap = parse_ckl(old_path)
    new_snap = parse_ckl(new_path)
    diff = compute_diff(old_snap, new_snap)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if args.output:
        output_path = Path(args.output).resolve()
    else:
        output_path = REPORTS_DIR / f"{sanitize_hostname(args.host)}_diff_{timestamp_now()}.html"

    write_html_report(args.host, old_path, new_path, diff, output_path)
    print(f"[OK] Report written: {output_path}")
    print(f"     Regressions: {len(diff['regressions'])}")
    print(f"     Improvements: {len(diff['improvements'])}")
    print(f"     Metadata changes: {len(diff['metadata_changes'])}")


def cmd_compare(args):
    """Direct before/after CKL comparison — no registration needed.

    Used by the GUI and available on the CLI for quick ad-hoc diffs.
    Produces both a console summary and an HTML report.
    """
    before_path = Path(args.before).expanduser().resolve()
    after_path = Path(args.after).expanduser().resolve()

    if not before_path.is_file():
        print(f"ERROR: 'Before' CKL not found: {before_path}", file=sys.stderr)
        sys.exit(1)
    if not after_path.is_file():
        print(f"ERROR: 'After' CKL not found: {after_path}", file=sys.stderr)
        sys.exit(1)

    try:
        old_snap = parse_ckl(before_path)
        new_snap = parse_ckl(after_path)
    except ET.ParseError as e:
        print(f"ERROR: XML parse error: {e}", file=sys.stderr)
        sys.exit(1)

    diff = compute_diff(old_snap, new_snap)

    # Derive a label for the report title
    label = args.name or old_snap["asset"].get("HOST_NAME", "").strip() or "comparison"

    # Console summary
    print_console_diff(label, before_path, after_path, diff)

    # HTML report
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if args.output:
        output_path = Path(args.output).expanduser().resolve()
    else:
        safe = sanitize_hostname(label)
        output_path = REPORTS_DIR / f"{safe}_diff_{timestamp_now()}.html"

    write_html_report(label, before_path, after_path, diff, output_path)
    print(f"\n[OK] Report written: {output_path}")
    return output_path


def build_parser():
    p = argparse.ArgumentParser(
        prog="stig_diff",
        description="Track STIG compliance state changes across CKL snapshots.")
    p.add_argument("--gui", action="store_true",
                   help="Launch the graphical interface")
    sub = p.add_subparsers(dest="command")

    pa = sub.add_parser("add", help="Save a new CKL snapshot into history")
    pa.add_argument("host", help="History bucket name, or AUTO to derive from the CKL")
    pa.add_argument("ckl_file", help="Path to CKL file")
    pa.set_defaults(func=cmd_add)

    pl = sub.add_parser("list", help="List saved snapshots in history")
    pl.add_argument("host", nargs="?", help="Filter by host (optional)")
    pl.set_defaults(func=cmd_list)

    pd = sub.add_parser("diff", help="Show diff between two saved snapshots")
    pd.add_argument("host")
    pd.add_argument("--from", dest="from_date", type=parse_date_arg, default=None,
                    help="Compare from this date (YYYY-MM-DD)")
    pd.add_argument("--to", dest="to_date", type=parse_date_arg, default=None,
                    help="Compare to this date (YYYY-MM-DD)")
    pd.set_defaults(func=cmd_diff)

    pr = sub.add_parser("report", help="Generate HTML diff report from saved snapshots")
    pr.add_argument("host")
    pr.add_argument("--from", dest="from_date", type=parse_date_arg, default=None)
    pr.add_argument("--to", dest="to_date", type=parse_date_arg, default=None)
    pr.add_argument("--output", help="Output HTML file path")
    pr.set_defaults(func=cmd_report)

    # New: compare — direct two-file diff without registration
    pc = sub.add_parser("compare",
                        help="Compare two CKLs directly (no snapshot registration)")
    pc.add_argument("--before", required=True, help="Earlier / baseline CKL")
    pc.add_argument("--after", required=True, help="Later / current CKL")
    pc.add_argument("--name", default=None,
                    help="Custom label / report filename prefix (optional)")
    pc.add_argument("--output", default=None,
                    help="Exact output HTML path (overrides --name)")
    pc.set_defaults(func=cmd_compare)

    return p


# ============================================================
# GUI mode (tkinter)
# ============================================================

def launch_gui(on_back=None):
    """Launch the CKL Diff GUI.

    on_back: optional callback for main-menu Back button integration.
    """
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    import io, contextlib, subprocess

    win = tk.Toplevel() if on_back else tk.Tk()
    win.title("STIG Diff — CKL Comparison")
    win.geometry("820x800")
    win.minsize(700, 620)

    before_var = tk.StringVar()
    after_var = tk.StringVar()
    name_var = tk.StringVar()
    mode_var = tk.StringVar(value="browse")
    host_var = tk.StringVar()
    before_snap_var = tk.StringVar()
    after_snap_var = tk.StringVar()

    mf = ttk.Frame(win, padding="12")
    mf.pack(fill="both", expand=True)
    mf.columnconfigure(1, weight=1)

    # Header
    hdr = ttk.Frame(mf)
    hdr.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0,4))
    if on_back:
        ttk.Button(hdr, text="← Back", width=10,
                   command=lambda: _back()).pack(side="left", padx=(0,12))
    ttk.Label(hdr, text="CKL Diff — Compare STIG Snapshots",
              font=("TkDefaultFont", 12, "bold")).pack(side="left")

    ttk.Label(mf,
              text="Select Before and After CKL files to see what changed between scans.",
              foreground="#555", wraplength=780, justify="left"
              ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(0,8))

    # History library
    hf = ttk.LabelFrame(mf, text=" History Library ", padding=6)
    hf.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(0,8))
    hf.columnconfigure(0, weight=1)

    hlb_frame = ttk.Frame(hf)
    hlb_frame.pack(fill="x", expand=True)
    hlb_frame.columnconfigure(0, weight=1)
    hosts_lb = tk.Listbox(hlb_frame, height=4, selectmode="single",
                          font=("Consolas",9) if sys.platform=="win32"
                          else ("Monospace",9))
    hsb = ttk.Scrollbar(hlb_frame, orient="vertical", command=hosts_lb.yview)
    hosts_lb.configure(yscrollcommand=hsb.set)
    hosts_lb.grid(row=0, column=0, sticky="ew")
    hsb.grid(row=0, column=1, sticky="ns")

    hbr = ttk.Frame(hf)
    hbr.pack(fill="x", pady=(6,0))

    def refresh_hosts():
        hosts_lb.delete(0, "end")
        for hk in get_all_hosts():
            s = get_host_summary(hk)
            last = s["last_scan"].strftime("%Y-%m-%d") if s["last_scan"] else "never"
            n = s["snapshot_count"]
            t = s["latest_tally"]
            tag = " ⚠" if t.get("Open",0) > 0 else ""
            hosts_lb.insert("end",
                f"{hk:<32}  {n:>2} snap  last:{last}"
                f"  Open:{t.get('Open',0)} NF:{t.get('NotAFinding',0)}{tag}")
        host_combo["values"] = get_all_hosts()

    def save_to_history():
        path = filedialog.askopenfilename(
            title="Select CKL to save to history",
            initialdir=browse_initial_dir(),
            filetypes=[("CKL files","*.ckl"),("All files","*.*")])
        if not path:
            return
        try:
            result = save_snapshot_to_history(path)
            hk = result["bucket_key"]
            dest = result["dest_path"]
            vulns = result["vulns"]
            t = {}
            for v in vulns.values():
                t[v["status"]] = t.get(v["status"],0)+1
            if result["saved"]:
                title = "Saved to history"
                detail = f"Snapshot: {dest.name}"
            else:
                title = "Already in history"
                detail = f"Existing snapshot reused: {dest.name}"
            messagebox.showinfo(title,
                f"History bucket: {hk}\n"
                f"{detail}\n"
                f"V-IDs: {len(vulns)}  "
                f"Open:{t.get('Open',0)} NF:{t.get('NotAFinding',0)} "
                f"NA:{t.get('Not_Applicable',0)} NR:{t.get('Not_Reviewed',0)}")
            refresh_hosts()
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    ttk.Button(hbr, text="+ Save CKL to History", command=save_to_history, width=18).pack(side="left", padx=(0,8))
    ttk.Button(hbr, text="Refresh", command=refresh_hosts, width=10).pack(side="left")

    # Mode toggle
    mframe = ttk.LabelFrame(mf, text=" Comparison Mode ", padding=6)
    mframe.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(0,8))
    ttk.Radiobutton(mframe, text="Browse  (pick any two CKL files)",
                    variable=mode_var, value="browse",
                    command=lambda: _toggle()).pack(side="left", padx=(0,24))
    ttk.Radiobutton(mframe, text="History  (from saved snapshots)",
                    variable=mode_var, value="history",
                    command=lambda: _toggle()).pack(side="left")

    # Browse widgets
    bf = ttk.Frame(mf)
    bf.columnconfigure(1, weight=1)

    ttk.Label(bf, text="Before CKL:").grid(row=0, column=0, sticky="e", padx=(0,8), pady=4)
    ttk.Entry(bf, textvariable=before_var).grid(row=0, column=1, sticky="ew", pady=4)
    def bb():
        p = filedialog.askopenfilename(title="BEFORE CKL",
            initialdir=browse_initial_dir(before_var.get()),
            filetypes=[("CKL files","*.ckl"),("All files","*.*")])
        if p: before_var.set(p)
    ttk.Button(bf, text="Browse...", command=bb, width=12).grid(row=0, column=2, padx=(8,0), pady=4)
    ttk.Label(bf, text="earlier scan / known-good baseline",
              foreground="#777", font=("TkDefaultFont",8)).grid(row=1,column=1,sticky="w")

    ttk.Label(bf, text="After CKL:").grid(row=2, column=0, sticky="e", padx=(0,8), pady=(8,4))
    ttk.Entry(bf, textvariable=after_var).grid(row=2, column=1, sticky="ew", pady=(8,4))
    def ba():
        p = filedialog.askopenfilename(title="AFTER CKL",
            initialdir=browse_initial_dir(after_var.get()),
            filetypes=[("CKL files","*.ckl"),("All files","*.*")])
        if p: after_var.set(p)
    ttk.Button(bf, text="Browse...", command=ba, width=12).grid(row=2, column=2, padx=(8,0), pady=(8,4))
    ttk.Label(bf, text="later scan / current state",
              foreground="#777", font=("TkDefaultFont",8)).grid(row=3,column=1,sticky="w")

    # History widgets
    histf = ttk.Frame(mf)
    histf.columnconfigure(1, weight=1)

    ttk.Label(histf, text="Host:").grid(row=0,column=0,sticky="e",padx=(0,8),pady=4)
    host_combo = ttk.Combobox(histf, textvariable=host_var,
                               state="readonly", values=get_all_hosts())
    host_combo.grid(row=0,column=1,sticky="ew",pady=4,columnspan=2)

    ttk.Label(histf, text="Before:").grid(row=1,column=0,sticky="e",padx=(0,8),pady=4)
    before_snap_combo = ttk.Combobox(histf, textvariable=before_snap_var, state="readonly")
    before_snap_combo.grid(row=1,column=1,sticky="ew",pady=4,columnspan=2)

    ttk.Label(histf, text="After:").grid(row=2,column=0,sticky="e",padx=(0,8),pady=4)
    after_snap_combo = ttk.Combobox(histf, textvariable=after_snap_var, state="readonly")
    after_snap_combo.grid(row=2,column=1,sticky="ew",pady=4,columnspan=2)

    def update_combos(*args):
        hk = host_var.get()
        if not hk: return
        snaps = get_snapshots(hk)
        labels = [f"{snapshot_datetime(p).strftime('%Y-%m-%d %H:%M:%S')} ({p.stat().st_size//1024} KB)"
                  for p in snaps]
        before_snap_combo["values"] = labels
        after_snap_combo["values"] = labels
        if len(labels)>=2:
            before_snap_var.set(labels[-2]); after_snap_var.set(labels[-1])
        elif labels:
            before_snap_var.set(labels[0]); after_snap_var.set(labels[0])
        win._snap_paths = snaps
        win._snap_labels = labels

    host_combo.bind("<<ComboboxSelected>>", update_combos)

    def _toggle():
        if mode_var.get()=="browse":
            histf.grid_remove(); bf.grid(row=4,column=0,columnspan=3,sticky="ew")
        else:
            bf.grid_remove(); histf.grid(row=4,column=0,columnspan=3,sticky="ew")

    # Report name
    nf = ttk.Frame(mf)
    nf.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(8,0))
    nf.columnconfigure(1, weight=1)
    ttk.Label(nf, text="Report name:").grid(row=0,column=0,sticky="e",padx=(0,8),pady=4)
    ttk.Entry(nf, textvariable=name_var).grid(row=0,column=1,sticky="ew",pady=4)
    ttk.Label(nf, text="Optional. Timestamp will be appended.",
              foreground="#777", font=("TkDefaultFont",8)).grid(row=1,column=1,sticky="w")

    # Buttons
    brow = ttk.Frame(mf)
    brow.grid(row=6, column=0, columnspan=3, pady=(14,6))

    compare_btn = ttk.Button(brow, text="  Compare  ", width=14)
    compare_btn.pack(side="left", padx=4)

    last_rpt = [None]

    def open_rpt():
        p = last_rpt[0]
        if not p: messagebox.showinfo("No report yet","Run a comparison first."); return
        try:
            _open_local_path(p)
        except Exception as e: messagebox.showerror("Error",str(e))

    ttk.Button(brow, text="Open Report", command=open_rpt, width=14).pack(side="left",padx=4)

    def open_fld():
        p = last_rpt[0]
        if not p: messagebox.showinfo("No report yet","Run a comparison first."); return
        try:
            _open_local_folder(p)
        except Exception as e: messagebox.showerror("Error",str(e))

    ttk.Button(brow, text="Open Folder", command=open_fld, width=14).pack(side="left",padx=4)

    def clear_all():
        for v in [before_var,after_var,name_var,host_var,before_snap_var,after_snap_var]:
            v.set("")
        log.configure(state="normal"); log.delete("1.0","end")
        log.insert("end","Ready.\n"); log.configure(state="disabled")
        last_rpt[0] = None

    ttk.Button(brow, text="Clear", command=clear_all, width=10).pack(side="left",padx=4)

    def _back():
        win.destroy()
        if on_back: on_back()

    if not on_back:
        ttk.Button(brow, text="Exit", command=win.destroy, width=10).pack(side="left",padx=4)

    # Log
    lf = ttk.LabelFrame(mf, text=" Diff Results ", padding=6)
    lf.grid(row=7, column=0, columnspan=3, sticky="nsew", pady=(8,0))
    mf.rowconfigure(7, weight=1)
    lf.columnconfigure(0, weight=1); lf.rowconfigure(0, weight=1)
    log = scrolledtext.ScrolledText(lf, wrap="word", height=14,
        font=("Consolas",9) if sys.platform=="win32" else ("Monospace",9))
    log.grid(row=0, column=0, sticky="nsew")
    log.insert("end","Ready.\n"); log.configure(state="disabled")

    def run_compare():
        name = name_var.get().strip()
        if mode_var.get()=="browse":
            bs = before_var.get().strip(); as_ = after_var.get().strip()
            if not bs: messagebox.showerror("Missing","Select a BEFORE CKL."); return
            if not as_: messagebox.showerror("Missing","Select an AFTER CKL."); return
            bp = Path(bs).expanduser().resolve()
            ap = Path(as_).expanduser().resolve()
        else:
            hk = host_var.get()
            if not hk: messagebox.showerror("Missing","Select a host."); return
            bl = before_snap_var.get(); al = after_snap_var.get()
            if not bl or not al:
                messagebox.showerror("Missing","Select Before and After snapshots."); return
            try:
                labs = getattr(win,"_snap_labels",[])
                paths = getattr(win,"_snap_paths",[])
                bp = paths[labs.index(bl)]
                ap = paths[labs.index(al)]
            except (ValueError,IndexError):
                messagebox.showerror("Error","Could not resolve snapshots. Refresh first."); return
            if not name: name = hk

        if not bp.is_file(): messagebox.showerror("Not found",f"{bp}"); return
        if not ap.is_file(): messagebox.showerror("Not found",f"{ap}"); return
        if bp==ap: messagebox.showwarning("Same file","Before and After are the same."); return

        log.configure(state="normal"); log.delete("1.0","end")
        log.insert("end",f"Starting at {datetime.now().strftime('%H:%M:%S')}...\n\n")
        log.configure(state="disabled"); win.update_idletasks()

        buf = io.StringIO()
        try:
            os_ = parse_ckl(bp); ns = parse_ckl(ap)
            diff = compute_diff(os_, ns)
            label = name or os_["asset"].get("HOST_NAME","").strip() or "comparison"
            with contextlib.redirect_stdout(buf):
                print_console_diff(label, bp, ap, diff)
            REPORTS_DIR.mkdir(parents=True, exist_ok=True)
            op = REPORTS_DIR / f"{sanitize_hostname(label)}_diff_{timestamp_now()}.html"
            write_html_report(label, bp, ap, diff, op)
            log.configure(state="normal")
            log.insert("end", buf.getvalue())
            log.insert("end", f"\n[OK] Report written:\n  {op}\n--- Done. ---\n")
            log.see("end"); log.configure(state="disabled")
            last_rpt[0] = str(op)
        except ET.ParseError as e:
            log.configure(state="normal"); log.insert("end",f"\n[ERROR] {e}\n")
            log.configure(state="disabled"); messagebox.showerror("Parse error",str(e))
        except Exception as e:
            log.configure(state="normal"); log.insert("end",f"\n[ERROR] {e}\n")
            log.configure(state="disabled"); messagebox.showerror("Failed",str(e))

    compare_btn.configure(command=run_compare)

    ttk.Label(mf,
              text="Tip: 'Save CKL to History' tracks scan history by host and STIG. Reports go in the 'Reports' folder.",
              foreground="#777", font=("TkDefaultFont",8)
              ).grid(row=8, column=0, columnspan=3, sticky="w", pady=(8,0))

    _toggle(); refresh_hosts()
    if not on_back: win.mainloop()


def main():
    # No args at all → launch GUI
    if len(sys.argv) == 1:
        launch_gui()
        return

    parser = build_parser()
    args = parser.parse_args()

    if args.gui:
        launch_gui()
        return

    if not getattr(args, "command", None):
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
