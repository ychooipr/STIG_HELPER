#!/usr/bin/env python3
"""
combine_stig.py - Merge ACAS + Evaluate-STIG CKLs for the same host.

Produces a single merged CKL that combines:
  * Metadata (HOST_NAME, HOST_IP, HOST_FQDN, ROLE, etc.) from Evaluate-STIG
    (ACAS typically leaves these blank)
  * Per-V-ID status using "compliance wins" logic:
      Priority: Not_Applicable > NotAFinding > Open > Not_Reviewed
      Whichever scanner reports the higher-priority status wins.
      If both agree, ACAS (the base) wins.
  * Finding_Details and Comments merged with [ACAS] / [Eval-STIG] prefixes.
  * Material disagreements (Open vs NF/NA) annotated with [MERGE NOTE] for audit.
  * Detects and warns on benchmark version mismatch between scanners.

Usage:
    python3 combine_stig.py --acas ACAS.ckl --eval EVAL.ckl --output MERGED.ckl
    python3 combine_stig.py ACAS.ckl EVAL.ckl            (auto-named output)
    python3 combine_stig.py --help

Zero dependencies. Python 3.8+ stdlib only.
"""

import argparse
import copy
import html
import io
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
import uuid

BASE_DIR = Path(__file__).parent.resolve()
REPORTS_DIR = BASE_DIR / "Reports"
MERGED_DIR = BASE_DIR / "Merged"
DEFAULT_ARTIFACT_TEMPLATE_CANDIDATES = [
    BASE_DIR / "artifact_template.docx",
]
W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
W_TAG = f"{{{W_NS}}}"
W_VAL = f"{{{W_NS}}}val"
FORBIDDEN_XML_PATTERN = re.compile(rb"<!\s*(DOCTYPE|ENTITY)\b", re.IGNORECASE)
ALLOWED_CHECKLIST_SUFFIXES = {".ckl", ".cklb"}
XML_ROOT_PATTERN = re.compile(rb"<\?xml[^>]*\?>\s*<([A-Za-z_][\w:.-]*)\b|^\s*<([A-Za-z_][\w:.-]*)\b", re.DOTALL)


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


def _open_local_folder(path_value):
    """Open the parent folder for a validated local path without using a shell."""
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


def _ensure_allowed_xml_root(xml_bytes, allowed_roots, source_name="XML"):
    """Reject XML whose root element is not one of the expected names."""
    match = XML_ROOT_PATTERN.search(xml_bytes)
    if not match:
        raise ValueError(f"{source_name} does not contain a recognizable XML root element.")
    root_name = (match.group(1) or match.group(2) or b"").decode("utf-8", "replace")
    if root_name not in allowed_roots:
        allowed_text = ", ".join(sorted(allowed_roots))
        raise ValueError(f"{source_name} root element {root_name!r} is not allowed (expected {allowed_text}).")


def _parse_safe_xml_file(path_value, source_name="XML", allowed_roots=("CHECKLIST",)):
    xml_bytes = _resolve_existing_local_path(path_value).read_bytes()
    _ensure_xml_has_no_external_entities(xml_bytes, source_name)
    _ensure_allowed_xml_root(xml_bytes, allowed_roots, source_name)
    root = ET.fromstring(xml_bytes)  # nosemgrep: input is validated local XML with blocked DOCTYPE/ENTITY and allowed roots
    return ET.ElementTree(root)


def _parse_safe_xml_bytes(xml_bytes, source_name="XML", allowed_roots=("document", "w:document")):
    _ensure_xml_has_no_external_entities(xml_bytes, source_name)
    _ensure_allowed_xml_root(xml_bytes, allowed_roots, source_name)
    return ET.fromstring(xml_bytes)  # nosemgrep: input is prevalidated XML content with blocked DOCTYPE/ENTITY and allowed roots


# ============================================================
# Status priority (higher wins)
# ============================================================
STATUS_PRIORITY = {
    "Not_Applicable": 4,  # strongest — no check needed
    "NotAFinding":    3,  # compliant
    "Open":           2,  # non-compliant
    "Not_Reviewed":   1,  # unknown
    "":               0,  # blank / missing
}


def status_priority(s):
    return STATUS_PRIORITY.get((s or "").strip(), 0)


# ============================================================
# CKL parsing helpers
# ============================================================
def parse_ckl(ckl_path):
    """Parse a CKL and return (tree, root, asset_dict, vulns_by_id, istigs,
                               stig_info_dict_for_first_istig)."""
    ckl_path = _resolve_checklist_path(ckl_path, allowed_suffixes={".ckl"})
    tree = _parse_safe_xml_file(ckl_path, source_name=f"CKL file {ckl_path}", allowed_roots=("CHECKLIST",))
    root = tree.getroot()

    asset = {}
    asset_el = root.find("ASSET")
    if asset_el is not None:
        for child in asset_el:
            # Collect text content robustly. Some CKLs have whitespace-only text or
            # unusual child structure; use itertext() to be safe and then strip.
            raw = "".join(child.itertext()) if len(child) > 0 else (child.text or "")
            value = raw.strip()
            # If the same tag appears multiple times, prefer the first non-empty value
            if child.tag not in asset or (not asset[child.tag] and value):
                asset[child.tag] = value

    vulns_by_id = {}
    istigs = root.findall(".//iSTIG")
    for istig in istigs:
        for vuln in istig.findall("VULN"):
            vnum = ""
            for sd in vuln.findall("STIG_DATA"):
                attr = sd.findtext("VULN_ATTRIBUTE", "").strip()
                data = sd.findtext("ATTRIBUTE_DATA", "").strip()
                if attr == "Vuln_Num":
                    vnum = data
                    break
            if vnum:
                vulns_by_id[vnum] = vuln

    # Pull STIG_INFO from the first iSTIG for version reporting
    stig_info = {}
    if istigs:
        for si in istigs[0].findall("./STIG_INFO/SI_DATA"):
            name = si.findtext("SID_NAME", "").strip()
            data = si.findtext("SID_DATA", "").strip()
            if name:
                stig_info[name] = data

    return tree, root, asset, vulns_by_id, istigs, stig_info


def parse_cklb(cklb_path):
    """Parse a CKLB JSON file into a CKL-like XML structure."""
    cklb_path = _resolve_checklist_path(cklb_path, allowed_suffixes={".cklb"})
    doc = json.loads(Path(cklb_path).read_text(encoding="utf-8"))

    root = ET.Element("CHECKLIST")
    asset_el = ET.SubElement(root, "ASSET")
    target_data = doc.get("target_data", {}) or {}
    asset_map = {
        "ROLE": target_data.get("role", ""),
        "ASSET_TYPE": target_data.get("target_type", ""),
        "HOST_NAME": target_data.get("host_name", ""),
        "HOST_IP": target_data.get("ip_address", ""),
        "HOST_MAC": target_data.get("mac_address", ""),
        "HOST_FQDN": target_data.get("fqdn", ""),
        "TARGET_COMMENT": target_data.get("comments", ""),
        "TECH_AREA": target_data.get("technology_area", ""),
        "TARGET_KEY": "",
        "WEB_OR_DATABASE": "true" if target_data.get("is_web_database") else "false",
        "WEB_DB_SITE": target_data.get("web_db_site", ""),
        "WEB_DB_INSTANCE": target_data.get("web_db_instance", ""),
    }
    for tag, value in asset_map.items():
        el = ET.SubElement(asset_el, tag)
        el.text = str(value or "")

    stigs_root = ET.SubElement(root, "STIGS")
    vulns_by_id = {}
    istigs = []
    first_stig_info = {}

    for stig_doc in doc.get("stigs", []) or []:
        istig = ET.SubElement(stigs_root, "iSTIG")
        istigs.append(istig)
        stig_info_el = ET.SubElement(istig, "STIG_INFO")
        stig_info = {
            "title": stig_doc.get("stig_name", ""),
            "version": stig_doc.get("version", ""),
            "releaseinfo": stig_doc.get("release_info", ""),
            "stigid": stig_doc.get("stig_id", ""),
        }
        if not first_stig_info:
            first_stig_info = dict(stig_info)
        for key, value in stig_info.items():
            si = ET.SubElement(stig_info_el, "SI_DATA")
            ET.SubElement(si, "SID_NAME").text = key
            ET.SubElement(si, "SID_DATA").text = str(value or "")

        for rule in stig_doc.get("rules", []) or []:
            vuln = ET.SubElement(istig, "VULN")
            attrs = [
                ("Vuln_Num", rule.get("group_id", "")),
                ("Severity", rule.get("severity", "")),
                ("Rule_ID", rule.get("rule_id_src", "") or f"{rule.get('rule_id', '')}_rule"),
                ("Rule_Ver", rule.get("rule_version", "")),
                ("Rule_Title", rule.get("rule_title", "")),
                ("Group_Title", rule.get("group_title", "")),
                ("Vuln_Discuss", rule.get("discussion", "")),
                ("Check_Content", rule.get("check_content", "")),
                ("Fix_Text", rule.get("fix_text", "")),
                ("Weight", rule.get("weight", "10.0")),
                ("Class", rule.get("classification", "")),
                ("IA_Controls", rule.get("ia_controls", "")),
            ]
            for cci in rule.get("ccis", []) or []:
                attrs.append(("CCI_REF", cci))
            for legacy_id in rule.get("legacy_ids", []) or []:
                attrs.append(("Legacy_ID", legacy_id))
            for attr_name, attr_value in attrs:
                sd = ET.SubElement(vuln, "STIG_DATA")
                ET.SubElement(sd, "VULN_ATTRIBUTE").text = attr_name
                ET.SubElement(sd, "ATTRIBUTE_DATA").text = str(attr_value or "")

            ET.SubElement(vuln, "STATUS").text = {
                "open": "Open",
                "not_a_finding": "NotAFinding",
                "not_applicable": "Not_Applicable",
                "not_reviewed": "Not_Reviewed",
            }.get((rule.get("status") or "").strip(), "Not_Reviewed")
            ET.SubElement(vuln, "FINDING_DETAILS").text = rule.get("finding_details", "")
            ET.SubElement(vuln, "COMMENTS").text = rule.get("comments", "")
            overrides = rule.get("overrides", {}) or {}
            ET.SubElement(vuln, "SEVERITY_OVERRIDE").text = overrides.get("severity_override", "")
            ET.SubElement(vuln, "SEVERITY_JUSTIFICATION").text = overrides.get("severity_justification", "")

            vid = rule.get("group_id", "")
            if vid:
                vulns_by_id[vid] = vuln

    tree = ET.ElementTree(root)
    return tree, root, asset_map, vulns_by_id, istigs, first_stig_info


def parse_any_checklist(path):
    path = _resolve_checklist_path(path)
    if path.suffix.lower() == ".cklb":
        return parse_cklb(path)
    return parse_ckl(path)


def get_field(vuln_el, tag):
    el = vuln_el.find(tag)
    return (el.text or "").strip() if el is not None else ""


def set_field(vuln_el, tag, text):
    el = vuln_el.find(tag)
    if el is None:
        el = ET.SubElement(vuln_el, tag)
    el.text = text


def get_rule_title(vuln_el):
    for sd in vuln_el.findall("STIG_DATA"):
        attr = sd.findtext("VULN_ATTRIBUTE", "").strip()
        data = sd.findtext("ATTRIBUTE_DATA", "").strip()
        if attr == "Rule_Title":
            return data
    return ""


def get_vuln_attribute(vuln_el, attr_name):
    for sd in vuln_el.findall("STIG_DATA"):
        attr = sd.findtext("VULN_ATTRIBUTE", "").strip()
        data = sd.findtext("ATTRIBUTE_DATA", "").strip()
        if attr == attr_name:
            return data
    return ""


def get_all_vuln_attributes(vuln_el):
    attrs = {}
    for sd in vuln_el.findall("STIG_DATA"):
        attr = sd.findtext("VULN_ATTRIBUTE", "").strip()
        data = sd.findtext("ATTRIBUTE_DATA", "").strip()
        if not attr:
            continue
        if attr in attrs:
            if isinstance(attrs[attr], list):
                attrs[attr].append(data)
            else:
                attrs[attr] = [attrs[attr], data]
        else:
            attrs[attr] = data
    return attrs


def vuln_sort_key(vid):
    digits = "".join(c for c in vid if c.isdigit())
    return (int(digits) if digits else 0, vid)


def _normalize_severity(severity):
    s = (severity or "").strip().lower().replace("_", "").replace(" ", "")
    if s in {"high", "cati", "cat1", "categoryi"}:
        return "cat1"
    if s in {"medium", "catii", "cat2", "categoryii"}:
        return "cat2"
    if s in {"low", "catiii", "cat3", "categoryiii"}:
        return "cat3"
    return ""


def _cklb_severity(severity):
    s = (severity or "").strip().lower()
    if s in {"cat i", "cat ii", "cat iii"}:
        return s.replace(" ", "")
    if s in {"high", "medium", "low"}:
        return s
    if s == "cat1":
        return "high"
    if s == "cat2":
        return "medium"
    if s == "cat3":
        return "low"
    return s or "medium"


def _cklb_status(status):
    mapping = {
        "Open": "open",
        "NotAFinding": "not_a_finding",
        "Not_Applicable": "not_applicable",
        "Not_Reviewed": "not_reviewed",
    }
    return mapping.get((status or "").strip(), "not_reviewed")


def _split_rule_id(rule_id_src):
    raw = (rule_id_src or "").strip()
    if raw.endswith("_rule"):
        return raw, raw[:-5]
    return raw, raw


def _ensure_list(value):
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    return [value]


def _display_name_from_title(title):
    name = (title or "").replace("Security Technical Implementation Guide", "")
    name = name.replace("STIG", "").strip(" -")
    return name or (title or "STIG")


def summarize_vulns(vulns_by_id):
    summary = {
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
    for vuln_el in vulns_by_id.values():
        status = get_field(vuln_el, "STATUS")
        severity = _normalize_severity(get_vuln_attribute(vuln_el, "Severity"))
        summary["Total"] += 1
        if status == "Open":
            if severity == "cat1":
                summary["Open CAT I"] += 1
            elif severity == "cat2":
                summary["Open CAT IIs"] += 1
            elif severity == "cat3":
                summary["Open CAT IIIs"] += 1
        elif status == "Not_Reviewed":
            if severity == "cat1":
                summary["Not Reviewed CAT I"] += 1
            elif severity == "cat2":
                summary["Not Reviewed CAT IIs"] += 1
            elif severity == "cat3":
                summary["Not Reviewed CAT IIIs"] += 1
        elif status == "NotAFinding":
            summary["Not a Finding"] += 1
        elif status == "Not_Applicable":
            summary["Not Applicable"] += 1
    return summary


def _excel_column_name(index):
    name = ""
    while index > 0:
        index, remainder = divmod(index - 1, 26)
        name = chr(65 + remainder) + name
    return name


def build_detail_rows(vulns_by_id):
    rows = []
    for vid in sorted(vulns_by_id.keys(), key=vuln_sort_key):
        vuln_el = vulns_by_id[vid]
        rows.append({
            "Vuln Num": vid,
            "Rule Title": get_rule_title(vuln_el),
            "Severity": get_vuln_attribute(vuln_el, "Severity"),
            "Status": get_field(vuln_el, "STATUS"),
            "Finding Details": get_field(vuln_el, "FINDING_DETAILS"),
            "Comments": get_field(vuln_el, "COMMENTS"),
        })
    return rows


def write_summary_html(summary_row, output_path, detail_rows=None, title="CKL Status Summary"):
    columns = list(summary_row.keys())
    detail_columns = ["Vuln Num", "Rule Title", "Severity", "Status", "Finding Details", "Comments"]

    def esc(text):
        return html.escape(str(text), quote=False)

    header_cells = "".join(f"<th>{esc(col)}</th>" for col in columns)
    value_cells = "".join(f"<td>{esc(summary_row[col])}</td>" for col in columns)
    detail_section = ""
    if detail_rows:
        detail_header = "".join(f"<th>{esc(col)}</th>" for col in detail_columns)
        detail_body = []
        for row in detail_rows:
            cells = "".join(f"<td>{esc(row.get(col, ''))}</td>" for col in detail_columns)
            detail_body.append(f"<tr>{cells}</tr>")
        detail_section = f"""
<h2>Details</h2>
<table>
  <thead><tr>{detail_header}</tr></thead>
  <tbody>{''.join(detail_body)}</tbody>
</table>
"""
    html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{esc(title)}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 24px; background: #f6f8fb; color: #1f2937; }}
  h1 {{ margin-bottom: 8px; }}
  h2 {{ margin-top: 24px; }}
  .meta {{ color: #5b6472; margin-bottom: 18px; }}
  table {{ width: 100%; border-collapse: collapse; background: #ffffff; box-shadow: 0 1px 4px rgba(0,0,0,0.08); margin-bottom: 16px; }}
  th, td {{ border: 1px solid #d7deea; padding: 8px 10px; font-size: 13px; text-align: left; vertical-align: top; }}
  th {{ background: #003366; color: #ffffff; }}
  td {{ white-space: pre-wrap; }}
</style>
</head>
<body>
<h1>{esc(title)}</h1>
<div class="meta">Generated {esc(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}</div>
<table>
  <thead><tr>{header_cells}</tr></thead>
  <tbody><tr>{value_cells}</tr></tbody>
</table>
{detail_section}
</body>
</html>
"""
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_out, encoding="utf-8")
    return output_path


def write_summary_excel(summary_row, output_path, detail_rows=None):
    summary_columns = list(summary_row.keys())
    summary_widths = [26, 18, 20, 12, 16, 12, 17, 12, 18, 14, 14, 10]
    detail_columns = ["Vuln Num", "Rule Title", "Severity", "Status", "Finding Details", "Comments"]
    detail_widths = [14, 42, 12, 16, 48, 48]

    def esc(text):
        return html.escape(str(text), quote=False)

    def cell_xml(ref, value, is_header=False):
        style_attr = ' s="1"' if is_header else ""
        if isinstance(value, int):
            return f'<c r="{ref}"{style_attr}><v>{value}</v></c>'
        return (
            f'<c r="{ref}" t="inlineStr"{style_attr}>'
            f'<is><t>{esc(value)}</t></is>'
            f'</c>'
        )

    def build_sheet(rows, widths):
        sheet_rows = []
        for row_idx, row_values in enumerate(rows, start=1):
            cells = []
            for col_idx, value in enumerate(row_values, start=1):
                ref = f"{_excel_column_name(col_idx)}{row_idx}"
                cells.append(cell_xml(ref, value, is_header=(row_idx == 1)))
            sheet_rows.append(f'<row r="{row_idx}">{"".join(cells)}</row>')
        cols_xml = "".join(
            f'<col min="{i}" max="{i}" width="{width}" customWidth="1"/>'
            for i, width in enumerate(widths, start=1)
        )
        last_col = _excel_column_name(len(rows[0]))
        last_row = len(rows)
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            f'<dimension ref="A1:{last_col}{last_row}"/>'
            '<sheetViews><sheetView workbookViewId="0"/></sheetViews>'
            '<sheetFormatPr defaultRowHeight="15"/>'
            f'<cols>{cols_xml}</cols>'
            f'<sheetData>{"".join(sheet_rows)}</sheetData>'
            '</worksheet>'
        )

    summary_rows = [summary_columns, [summary_row.get(col, "") for col in summary_columns]]
    detail_rows = detail_rows or []
    detail_sheet_rows = [detail_columns] + [
        [row.get(col, "") for col in detail_columns] for row in detail_rows
    ]

    workbook_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets>'
        '<sheet name="Summary" sheetId="1" r:id="rId1"/>'
        '<sheet name="Details" sheetId="2" r:id="rId2"/>'
        '</sheets>'
        '</workbook>'
    )
    workbook_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>'
        '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
        '</Relationships>'
    )
    root_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        '</Relationships>'
    )
    content_types_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '<Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        '</Types>'
    )
    styles_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
        '<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>'
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
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
        zf.writestr("xl/worksheets/sheet1.xml", build_sheet(summary_rows, summary_widths))
        zf.writestr("xl/worksheets/sheet2.xml", build_sheet(detail_sheet_rows, detail_widths))
        zf.writestr("xl/styles.xml", styles_xml)
    return output_path


def build_status_report_data(ckl_path):
    ckl_path = Path(ckl_path).resolve()
    _, _, asset, vulns_by_id, _, stig_info = parse_any_checklist(ckl_path)
    host_name = (asset.get("HOST_NAME") or "").strip() or ckl_path.stem
    summary_row = {
        "Checklist File": ckl_path.name,
        "Host Name": host_name,
        "Generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    summary_row.update(summarize_vulns(vulns_by_id))
    metadata = {
        "host_name": host_name,
        "checklist_file": ckl_path.name,
        "checklist_path": ckl_path,
        "stig_title": stig_info.get("title", ""),
        "stig_display_name": _display_name_from_title(stig_info.get("title", "")),
        "stig_version": stig_info.get("version", ""),
        "stig_releaseinfo": stig_info.get("releaseinfo", ""),
        "generated": summary_row["Generated"],
    }
    return summary_row, build_detail_rows(vulns_by_id), metadata


def _report_base_name(ckl_path, host_name):
    stem = Path(ckl_path).stem.strip()
    cleaned = stem
    for pattern in (
        r"[_-]\d{4}_\d{2}_\d{2}_\d{6}$",
        r"[_-]\d{4}-\d{2}-\d{2}_\d{6}$",
        r"[_-]\d{4}_\d{2}_\d{2}$",
        r"[_-]\d{4}-\d{2}-\d{2}$",
    ):
        cleaned = re.sub(pattern, "", cleaned)
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in cleaned)
    if safe:
        return safe
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in host_name) or "STATUS"


def create_status_reports(ckl_path, output_formats=("html", "xlsx")):
    """Create status summary reports for a CKL. Returns dict of created paths."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ckl_path = Path(ckl_path).resolve()
    summary_row, detail_rows, _ = build_status_report_data(ckl_path)
    host_name = summary_row["Host Name"]
    safe = _report_base_name(ckl_path, host_name)
    ts = datetime.now().strftime("%Y_%m_%d_%H%M%S")
    created = {}
    for fmt in output_formats:
        key = fmt.lower()
        if key == "html":
            path = REPORTS_DIR / f"{safe}_status_summary_{ts}.html"
            write_summary_html(summary_row, path, detail_rows=detail_rows, title="CKL Status Summary")
            created["html"] = path
        elif key in {"xlsx", "excel"}:
            path = REPORTS_DIR / f"{safe}_status_summary_{ts}.xlsx"
            write_summary_excel(summary_row, path, detail_rows=detail_rows)
            created["xlsx"] = path
    return created


def _artifact_status_label(status):
    mapping = {
        "NotAFinding": "Not a Finding",
        "Not_Applicable": "Not Applicable",
        "Open": "Open",
        "Not_Reviewed": "Not Reviewed",
    }
    return mapping.get((status or "").strip(), (status or "").strip() or "Unknown")


def _artifact_lead(status):
    mapping = {
        "NotAFinding": "Not a finding.",
        "Not_Applicable": "Not Applicable.",
        "Open": "Open finding.",
        "Not_Reviewed": "Not Reviewed.",
    }
    return mapping.get((status or "").strip(), "Artifact narrative pending.")


def _clean_artifact_text(status, comments, finding_details):
    parts = []
    for text in (comments, finding_details):
        text = (text or "").strip()
        if text and text not in parts:
            parts.append(text)

    if not parts:
        return _artifact_lead(status)

    body = "\n\n".join(parts)
    lowered = body.lower()
    lead = _artifact_lead(status)

    if status == "NotAFinding" and "not a finding" in lowered:
        return body
    if status == "Not_Applicable" and "not applicable" in lowered:
        return body
    if status == "Open" and lowered.startswith("open"):
        return body
    if status == "Not_Reviewed" and "not reviewed" in lowered:
        return body
    return f"{lead} {body}".strip()


def _artifact_placeholder(status):
    status = (status or "").strip()
    if status == "NotAFinding":
        return "[Screenshot Placeholder]"
    if status == "Open":
        return "[Remediation / Evidence Placeholder]"
    if status == "Not_Applicable":
        return "[Justification Placeholder]"
    if status == "Not_Reviewed":
        return "[Assessment Needed]"
    return "[Evidence Placeholder]"


def _artifact_template_display_name(metadata):
    display_name = (metadata.get("stig_display_name") or metadata.get("stig_title") or "STIG").strip()
    version = (metadata.get("stig_version") or "").strip()
    releaseinfo = (metadata.get("stig_releaseinfo") or "").strip()
    parts = [display_name]
    if version:
        parts.append(f"Version {version}")
    if releaseinfo:
        parts.append(releaseinfo)
    return " ".join(parts).strip()


def _is_artifact_addressed(row):
    haystack = "\n".join([
        str(row.get("Comments", "") or ""),
        str(row.get("Finding Details", "") or ""),
        str(row.get("Artifact Text", "") or ""),
    ]).lower()
    phrases = [
        "evaluate-stig found this to be not a finding",
        "evaluate-stig found this to be not applicable",
        "nessus marks as not a finding",
        "nessus marks as not applicable",
    ]
    return any(phrase in haystack for phrase in phrases)


def build_artifact_report_data(ckl_path):
    ckl_path = Path(ckl_path).resolve()
    summary_row, detail_rows, metadata = build_status_report_data(ckl_path)
    artifact_rows = []
    for row in detail_rows:
        if row["Status"] in {"NotAFinding", "Not_Applicable"}:
            continue
        artifact_rows.append({
            "Vuln Num": row["Vuln Num"],
            "Rule Title": row["Rule Title"],
            "Severity": row["Severity"],
            "Status": row["Status"],
            "Status Label": _artifact_status_label(row["Status"]),
            "Comments": row["Comments"],
            "Finding Details": row["Finding Details"],
            "Artifact Text": _clean_artifact_text(
                row["Status"], row["Comments"], row["Finding Details"]),
        })
    metadata["summary"] = summary_row
    return metadata, artifact_rows


def _docx_escape(text):
    return html.escape(_xml_safe_text(text), quote=False)


def _xml_safe_text(text):
    text = str(text or "")
    cleaned = []
    for ch in text:
        code = ord(ch)
        if code in (0x9, 0xA, 0xD) or 0x20 <= code <= 0xD7FF or 0xE000 <= code <= 0xFFFD or 0x10000 <= code <= 0x10FFFF:
            cleaned.append(ch)
    return "".join(cleaned)


def build_artifact_report_title(metadata):
    host_name = (metadata.get("host_name") or "System").strip() or "System"
    display_name = (metadata.get("stig_display_name") or metadata.get("stig_title") or "").strip()
    version = (metadata.get("stig_version") or "").strip()
    releaseinfo = (metadata.get("stig_releaseinfo") or "").strip()

    parts = [host_name]
    if display_name:
        parts.append(display_name)

    benchmark_bits = []
    if version:
        benchmark_bits.append(f"Version {version}")
    if releaseinfo:
        benchmark_bits.append(releaseinfo)

    title = " ".join(parts).strip() or "System"
    if benchmark_bits:
        title = f"{title} ({' '.join(benchmark_bits)})"
    return f"{title} Artifact Report"


def write_artifact_docx(metadata, artifact_rows, output_path):
    def run_xml(text, bold=False, size=None):
        props = []
        if bold:
            props.append("<w:b/>")
        if size:
            props.append(f'<w:sz w:val="{size}"/>')
        props_xml = f"<w:rPr>{''.join(props)}</w:rPr>" if props else ""
        text = _xml_safe_text(text)
        preserve = ' xml:space="preserve"' if text[:1].isspace() or text[-1:].isspace() else ""
        return f"<w:r>{props_xml}<w:t{preserve}>{_docx_escape(text)}</w:t></w:r>"

    def paragraph_xml(runs, align=None):
        ppr = []
        if align:
            ppr.append(f'<w:jc w:val="{align}"/>')
        ppr_xml = f"<w:pPr>{''.join(ppr)}</w:pPr>" if ppr else ""
        return f"<w:p>{ppr_xml}{''.join(runs)}</w:p>"

    body = []
    title = build_artifact_report_title(metadata)
    body.append(paragraph_xml([run_xml(title, bold=True, size=32)], align="center"))
    body.append(paragraph_xml([run_xml(f"Checklist: {metadata.get('checklist_file', '')}", bold=True)]))
    stig_title = metadata.get("stig_title", "")
    if stig_title:
        body.append(paragraph_xml([run_xml(f"STIG: {stig_title}", bold=True)]))
    included_vids = metadata.get("included_vids", []) or []
    if included_vids:
        body.append(paragraph_xml([run_xml(f"Included Findings: {', '.join(included_vids)}", bold=True)]))
    body.append(paragraph_xml([run_xml(f"Generated: {metadata.get('generated', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}")]))
    body.append("<w:p/>")

    for row in artifact_rows:
        body.append(paragraph_xml([run_xml(row["Vuln Num"], bold=True, size=28)]))
        if row.get("Rule Title"):
            body.append(paragraph_xml([
                run_xml("Rule Title: ", bold=True),
                run_xml(row["Rule Title"]),
            ]))
        body.append(paragraph_xml([
            run_xml("Status: ", bold=True),
            run_xml(row.get("Status Label", row.get("Status", ""))),
        ]))

        narrative = (row.get("Artifact Text") or "").strip() or _artifact_lead(row.get("Status"))
        for para in [part.strip() for part in narrative.split("\n\n") if part.strip()]:
            body.append(paragraph_xml([run_xml(para)]))

        body.append(paragraph_xml([run_xml(_artifact_placeholder(row.get("Status")), bold=True)]))
        body.append("<w:p/>")

    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas" '
        'xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" '
        'xmlns:o="urn:schemas-microsoft-com:office:office" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math" '
        'xmlns:v="urn:schemas-microsoft-com:vml" '
        'xmlns:wp14="http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing" '
        'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
        'xmlns:w10="urn:schemas-microsoft-com:office:word" '
        'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" '
        'xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup" '
        'xmlns:wpi="http://schemas.microsoft.com/office/word/2010/wordprocessingInk" '
        'xmlns:wne="http://schemas.microsoft.com/office/word/2006/wordml" '
        'xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape" '
        'mc:Ignorable="w14 wp14">'
        f'<w:body>{"".join(body)}'
        '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="708" w:footer="708" w:gutter="0"/></w:sectPr>'
        '</w:body></w:document>'
    )

    content_types_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
        '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
        '</Types>'
    )
    root_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
        '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
        '</Relationships>'
    )
    doc_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>'
    )
    now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    core_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" '
        'xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:dcmitype="http://purl.org/dc/dcmitype/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f'<dc:title>{_docx_escape(title)}</dc:title>'
        '<dc:creator>STIG Helper</dc:creator>'
        '<cp:lastModifiedBy>STIG Helper</cp:lastModifiedBy>'
        f'<dcterms:created xsi:type="dcterms:W3CDTF">{now_iso}</dcterms:created>'
        f'<dcterms:modified xsi:type="dcterms:W3CDTF">{now_iso}</dcterms:modified>'
        '</cp:coreProperties>'
    )
    app_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" '
        'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
        '<Application>STIG Helper</Application>'
        '</Properties>'
    )

    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types_xml)
        zf.writestr("_rels/.rels", root_rels_xml)
        zf.writestr("word/document.xml", document_xml)
        zf.writestr("word/_rels/document.xml.rels", doc_rels_xml)
        zf.writestr("docProps/core.xml", core_xml)
        zf.writestr("docProps/app.xml", app_xml)
    return output_path


def _find_existing_template():
    for path in DEFAULT_ARTIFACT_TEMPLATE_CANDIDATES:
        if Path(path).is_file():
            return Path(path)
    return None


def _paragraph_text(paragraph):
    return "".join((node.text or "") for node in paragraph.findall(f".//{W_TAG}t"))


def _register_document_namespaces(document_xml):
    seen = set()
    root_text = re.search(r"<[^>]+document\b[^>]*>", document_xml.decode("utf-8", "replace"))
    if not root_text:
        return
    namespace_pairs = [("", uri) for uri in re.findall(r'\sxmlns="([^"]+)"', root_text.group(0))]
    namespace_pairs.extend(re.findall(r'\sxmlns:([A-Za-z0-9_]+)="([^"]+)"', root_text.group(0)))
    for prefix, uri in namespace_pairs:
        if (prefix, uri) in seen:
            continue
        seen.add((prefix, uri))
        ET.register_namespace(prefix or "", uri)
        try:
            ET._namespace_map[uri] = prefix or ""
        except Exception:
            pass


def _preserve_template_root(original_xml, updated_xml):
    original_text = original_xml.decode("utf-8", "replace")
    updated_text = updated_xml.decode("utf-8", "replace")

    original_root = re.search(r"<[^>]+document\b[^>]*>", original_text)
    updated_root = re.search(r"<[^>]+document\b[^>]*>", updated_text)
    if not original_root or not updated_root:
        return updated_xml

    original_prefixes = {uri: prefix for prefix, uri in re.findall(r'xmlns:([A-Za-z0-9]+)="([^"]+)"', original_root.group(0))}
    updated_prefixes = {uri: prefix for prefix, uri in re.findall(r'xmlns:([A-Za-z0-9]+)="([^"]+)"', updated_root.group(0))}

    for uri, desired_prefix in original_prefixes.items():
        actual_prefix = updated_prefixes.get(uri)
        if actual_prefix and actual_prefix != desired_prefix:
            updated_text = re.sub(rf"\b{re.escape(actual_prefix)}:", f"{desired_prefix}:", updated_text)

    updated_root = re.search(r"<[^>]+document\b[^>]*>", updated_text)
    if updated_root:
        merged_root = original_root.group(0)[:-1]
        original_declared_uris = set(original_prefixes.keys())
        extra_decls = []
        for prefix, uri in re.findall(r'xmlns:([A-Za-z0-9]+)="([^"]+)"', updated_root.group(0)):
            if uri not in original_declared_uris:
                extra_decls.append(f' xmlns:{prefix}="{uri}"')
                original_declared_uris.add(uri)
        if extra_decls:
            merged_root += "".join(extra_decls)
        merged_root += ">"
        updated_text = updated_text.replace(updated_root.group(0), merged_root, 1)

    original_decl = re.match(r"<\?xml[^>]+\?>", original_text)
    updated_decl = re.match(r"<\?xml[^>]+\?>", updated_text)
    if original_decl and updated_decl:
        updated_text = updated_text.replace(updated_decl.group(0), original_decl.group(0), 1)

    return updated_text.encode("utf-8")


def _clear_paragraph_runs(paragraph):
    for child in list(paragraph):
        if child.tag != f"{W_TAG}pPr":
            paragraph.remove(child)


def _append_run(paragraph, text):
    run = ET.SubElement(paragraph, f"{W_TAG}r")
    t = ET.SubElement(run, f"{W_TAG}t")
    safe_text = _xml_safe_text(text)
    if safe_text.startswith(" ") or safe_text.endswith(" "):
        t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
    t.text = safe_text


def _make_styled_paragraph(text, style, bold=False):
    p = ET.Element(f"{W_TAG}p")
    pPr = ET.SubElement(p, f"{W_TAG}pPr")
    pStyle = ET.SubElement(pPr, f"{W_TAG}pStyle")
    pStyle.set(W_VAL, style)
    run = ET.SubElement(p, f"{W_TAG}r")
    rPr = ET.SubElement(run, f"{W_TAG}rPr")
    if bold:
        ET.SubElement(rPr, f"{W_TAG}b")
    t = ET.SubElement(run, f"{W_TAG}t")
    t.text = _xml_safe_text(text)
    return p


def write_artifact_docx_from_template(template_path, metadata, artifact_rows, output_path):
    template_path = Path(template_path).resolve()
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(template_path, "r") as zin:
        entries = {info.filename: zin.read(info.filename) for info in zin.infolist()}

    document_xml = entries.get("word/document.xml")
    if not document_xml:
        raise ValueError("Template is missing word/document.xml")

    _register_document_namespaces(document_xml)
    root = _parse_safe_xml_bytes(document_xml, source_name="Word document.xml", allowed_roots=("document", "w:document"))
    body = root.find(f"{W_TAG}body")
    if body is None:
        raise ValueError("Template document body is missing")

    host_name = (metadata.get("host_name") or "System").strip() or "System"
    display_name = _artifact_template_display_name(metadata)
    cover_title = f"STIG ARTIFACTS FOR {host_name}"
    cover_subtitle = f"{host_name} STIG ARTIFACT"
    cover_body = f"This document contains the STIG artifacts for {host_name}"

    for paragraph in body.findall(f"{W_TAG}p"):
        text = _paragraph_text(paragraph).strip()
        if text == "STIG ARTIFACTS FOR SUNET CCB-XXX":
            _clear_paragraph_runs(paragraph)
            _append_run(paragraph, cover_title)
        elif text == "CCB-XXX STIG ARTIFACT":
            _clear_paragraph_runs(paragraph)
            _append_run(paragraph, cover_subtitle)
        elif text == "SUNet":
            _clear_paragraph_runs(paragraph)
            _append_run(paragraph, display_name)
        elif text == "This document contains the STIG artifacts for CCB-XXX":
            _clear_paragraph_runs(paragraph)
            _append_run(paragraph, cover_body)

    children = list(body)
    content_start = None
    for idx, child in enumerate(children):
        if child.tag == f"{W_TAG}p" and _paragraph_text(child).strip() == "CCB ARTIFACTS":
            content_start = idx
            break

    sect_pr = body.find(f"{W_TAG}sectPr")
    if sect_pr is None:
        raise ValueError("Template section properties are missing")

    if content_start is not None:
        removable = []
        for child in list(body)[content_start:]:
            if child is not sect_pr:
                removable.append(child)
        for child in removable:
            body.remove(child)

    body.insert(len(body) - 1, _make_styled_paragraph("CCB ARTIFACTS", "SUNetInfHeading1"))
    body.insert(len(body) - 1, _make_styled_paragraph(display_name, "SUNetInfHeading2"))

    for row in artifact_rows:
        body.insert(len(body) - 1, _make_styled_paragraph(row["Vuln Num"], "SUNetInfHeading3"))
        body.insert(len(body) - 1, _make_styled_paragraph(f"Status: {row.get('Status Label', row.get('Status', ''))}", "SUNetInfBodyText", bold=True))
        narrative = (row.get("Artifact Text") or "").strip() or _artifact_lead(row.get("Status"))
        for para in [part.strip() for part in narrative.split("\n\n") if part.strip()]:
            body.insert(len(body) - 1, _make_styled_paragraph(para, "SUNetInfBodyText"))
        body.insert(len(body) - 1, _make_styled_paragraph(_artifact_placeholder(row.get("Status")), "SUNetInfBodyText", bold=True))
        body.insert(len(body) - 1, ET.Element(f"{W_TAG}p"))

    updated_document_xml = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    updated_document_xml = _preserve_template_root(document_xml, updated_document_xml)

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for name, content in entries.items():
            if name == "word/document.xml":
                zout.writestr(name, updated_document_xml)
            else:
                zout.writestr(name, content)
    return output_path


def create_artifact_report(ckl_path, selected_vids=None, narrative_overrides=None, output_path=None):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    metadata, artifact_rows = build_artifact_report_data(ckl_path)
    selected = set(selected_vids or [])
    if selected:
        artifact_rows = [row for row in artifact_rows if row["Vuln Num"] in selected]
    if not artifact_rows:
        raise ValueError("No actionable artifact findings were selected.")

    overrides = narrative_overrides or {}
    for row in artifact_rows:
        override = overrides.get(row["Vuln Num"])
        if override is not None:
            row["Artifact Text"] = str(override).strip() or row["Artifact Text"]

    template_path = _find_existing_template()
    if template_path:
        artifact_rows = [row for row in artifact_rows if not _is_artifact_addressed(row)]
        if not artifact_rows:
            raise ValueError("All selected findings were already addressed by the default not-a-finding/not-applicable statements.")

    metadata["included_vids"] = [row["Vuln Num"] for row in artifact_rows]

    if output_path is None:
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in metadata["host_name"]) or "ARTIFACT"
        ts = datetime.now().strftime("%Y_%m_%d_%H%M%S")
        output_path = REPORTS_DIR / f"{safe}_artifact_{ts}.docx"

    if template_path:
        return write_artifact_docx_from_template(template_path, metadata, artifact_rows, output_path)
    return write_artifact_docx(metadata, artifact_rows, output_path)


def build_cklb_document(ckl_path, title=None):
    ckl_path = _resolve_checklist_path(ckl_path)
    _, root, asset, _, istigs, _ = parse_any_checklist(ckl_path)

    stig_docs = []
    for istig in istigs:
        stig_info = {}
        for si in istig.findall("./STIG_INFO/SI_DATA"):
            name = si.findtext("SID_NAME", "").strip()
            data = si.findtext("SID_DATA", "").strip()
            if name:
                stig_info[name] = data

        stig_uuid = str(uuid.uuid4())
        rules = []
        for vuln_el in istig.findall("VULN"):
            attrs = get_all_vuln_attributes(vuln_el)
            vuln_num = attrs.get("Vuln_Num", "")
            rule_id_src, rule_id = _split_rule_id(attrs.get("Rule_ID", ""))
            overrides = {}
            severity_override = get_field(vuln_el, "SEVERITY_OVERRIDE")
            severity_justification = get_field(vuln_el, "SEVERITY_JUSTIFICATION")
            if severity_override:
                overrides["severity_override"] = severity_override
            if severity_justification:
                overrides["severity_justification"] = severity_justification

            rules.append({
                "group_id": vuln_num,
                "group_id_src": vuln_num,
                "severity": _cklb_severity(attrs.get("Severity", "")),
                "group_title": attrs.get("Group_Title", ""),
                "rule_id_src": rule_id_src,
                "rule_id": rule_id,
                "rule_version": attrs.get("Rule_Ver", ""),
                "rule_title": attrs.get("Rule_Title", ""),
                "discussion": attrs.get("Vuln_Discuss", ""),
                "ia_controls": attrs.get("IA_Controls", ""),
                "check_content": attrs.get("Check_Content", ""),
                "fix_text": attrs.get("Fix_Text", ""),
                "false_positives": attrs.get("False_Positives", ""),
                "false_negatives": attrs.get("False_Negatives", ""),
                "documentable": attrs.get("Documentable", "false").lower() or "false",
                "mitigations": attrs.get("Mitigations", ""),
                "potential_impacts": attrs.get("Potential_Impact", ""),
                "third_party_tools": attrs.get("Third_Party_Tools", ""),
                "mitigation_control": attrs.get("Mitigation_Control", ""),
                "responsibility": attrs.get("Responsibility", ""),
                "security_override_guidance": attrs.get("Security_Override_Guidance", ""),
                "check_content_ref": {"name": attrs.get("Check_Content_REF", "M"), "href": ""},
                "weight": attrs.get("Weight", "10.0"),
                "classification": attrs.get("Class", "Unclass"),
                "legacy_ids": _ensure_list(attrs.get("Legacy_ID")),
                "ccis": _ensure_list(attrs.get("CCI_REF")),
                "stig_ref": f"{stig_info.get('title', 'STIG')} :: Version {stig_info.get('version', '')}, {stig_info.get('releaseinfo', '')}".strip(),
                "target_key": asset.get("TARGET_KEY", ""),
                "stig_uuid": stig_uuid,
                "uuid": str(uuid.uuid4()),
                "comments": get_field(vuln_el, "COMMENTS"),
                "finding_details": get_field(vuln_el, "FINDING_DETAILS"),
                "group_tree": [],
                "status": _cklb_status(get_field(vuln_el, "STATUS")),
                "overrides": overrides,
            })

        stig_docs.append({
            "stig_name": stig_info.get("title", "Unknown STIG"),
            "display_name": _display_name_from_title(stig_info.get("title", "")),
            "version": stig_info.get("version", ""),
            "stig_id": stig_info.get("stigid", ""),
            "release_info": stig_info.get("releaseinfo", ""),
            "uuid": stig_uuid,
            "size": len(rules),
            "rules": rules,
        })

    return {
        "stigs": stig_docs,
        "title": title or ckl_path.stem,
        "id": str(uuid.uuid4()),
        "active": True,
        "mode": 2,
        "has_path": False,
        "target_data": {
            "target_type": asset.get("ASSET_TYPE", ""),
            "host_name": asset.get("HOST_NAME", ""),
            "ip_address": asset.get("HOST_IP", ""),
            "mac_address": asset.get("HOST_MAC", ""),
            "fqdn": asset.get("HOST_FQDN", ""),
            "comments": asset.get("TARGET_COMMENT", ""),
            "role": asset.get("ROLE", "None") or "None",
            "is_web_database": (asset.get("WEB_OR_DATABASE", "").strip().lower() == "true"),
            "technology_area": asset.get("TECH_AREA", ""),
            "web_db_site": asset.get("WEB_DB_SITE", ""),
            "web_db_instance": asset.get("WEB_DB_INSTANCE", ""),
        },
        "cklb_version": "1.0",
    }


def export_checklist(source_path, export_format, output_path):
    source_path = Path(source_path).resolve()
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fmt = export_format.lower()
    if fmt == "ckl":
        if source_path.suffix.lower() == ".ckl":
            shutil.copy2(source_path, output_path)
        else:
            tree, _, _, _, _, _ = parse_any_checklist(source_path)
            tree.write(output_path, encoding="UTF-8", xml_declaration=True)
        return output_path
    if fmt == "cklb":
        if source_path.suffix.lower() == ".cklb":
            shutil.copy2(source_path, output_path)
        else:
            doc = build_cklb_document(source_path, title=output_path.stem)
            output_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        return output_path
    raise ValueError(f"Unsupported export format: {export_format}")


# ============================================================
# Merge logic
# ============================================================
def decide_status(acas_status, eval_status):
    """Return (source, winning_status). source in {'acas','eval','tie'}."""
    ap = status_priority(acas_status)
    ep = status_priority(eval_status)
    if ap == ep:
        return "tie", acas_status
    if ap > ep:
        return "acas", acas_status
    return "eval", eval_status


def merge_finding_details(acas_details, eval_details):
    parts = []
    if acas_details:
        parts.append(f"[ACAS] {acas_details}")
    if eval_details and eval_details != acas_details:
        parts.append(f"[Eval-STIG] {eval_details}")
    return "\n\n".join(parts)


def merge_comments(acas_comment, eval_comment, acas_status, eval_status,
                   winning_status, disagreement):
    parts = []
    if acas_comment:
        parts.append(f"[ACAS] {acas_comment}")
    if eval_comment and eval_comment != acas_comment:
        parts.append(f"[Eval-STIG] {eval_comment}")
    if disagreement:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        note = (
            f"[MERGE NOTE {ts}] Scanner disagreement: "
            f"ACAS reported '{acas_status or 'blank'}', "
            f"Eval-STIG reported '{eval_status or 'blank'}'. "
            f"Merged result took '{winning_status}' per compliance-priority policy. "
            "Review if audit-critical."
        )
        parts.append(note)
    return "\n\n".join(parts)


# ============================================================
# Asset merge — explicit fields including ROLE
# ============================================================
# ROLE is REQUIRED in this list. Member Server, Workstation, Domain Controller,
# None, etc. ACAS typically leaves ROLE blank; Eval-STIG populates it.
# Full list of fields the merged output should take from Eval-STIG when Eval has a value.
OVERWRITE_FIELDS = [
    "ROLE",
    "ASSET_TYPE",
    "HOST_NAME",
    "HOST_IP",
    "HOST_MAC",
    "HOST_FQDN",
    "TARGET_COMMENT",
    "TECH_AREA",
    "TARGET_KEY",
    "WEB_OR_DATABASE",
    "WEB_DB_SITE",
    "WEB_DB_INSTANCE",
    "MARKING",
]


def _extract_asset_value(asset_dict, field):
    """Pull a field's value from a parsed asset dict, tolerating None / whitespace."""
    raw = asset_dict.get(field)
    if raw is None:
        return ""
    return str(raw).strip()


def merge_asset(acas_root, eval_asset):
    """Overwrite ACAS asset fields with Eval-STIG values where Eval has content.

    Strategy: locate or create the ASSET element in the ACAS tree, then for each
    managed field (a) remove any existing element with that tag, and (b) create a
    fresh element with the Eval value. This bypasses any quirks from partially-
    populated, attribute-laden, or malformed ACAS ASSET entries.

    Returns a list of (field, old_value, new_value) tuples for reporting.
    """
    asset_el = acas_root.find("ASSET")
    if asset_el is None:
        asset_el = ET.SubElement(acas_root, "ASSET")
        # Put ASSET as the first child for schema cleanliness
        acas_root.remove(asset_el)
        acas_root.insert(0, asset_el)

    changed = []
    for field in OVERWRITE_FIELDS:
        eval_val = _extract_asset_value(eval_asset, field)
        if not eval_val:
            continue  # Eval didn't have a meaningful value — leave ACAS's field alone

        # Find the current value (for reporting) BEFORE we rewrite
        existing = asset_el.find(field)
        old_val = ""
        if existing is not None:
            old_val = (existing.text or "").strip()
            # Remove ALL existing elements with this tag (in case of duplicates)
            for dup in list(asset_el.findall(field)):
                asset_el.remove(dup)

        # Create a fresh element with clean text
        new_el = ET.SubElement(asset_el, field)
        new_el.text = eval_val

        if old_val != eval_val:
            changed.append((field, old_val, eval_val))

    return changed


# ============================================================
# Benchmark version comparison
# ============================================================
MONTH_MAP = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "sept": 9, "oct": 10, "nov": 11, "dec": 12,
}


def parse_release_info(releaseinfo):
    """Parse DISA's release info string into (release_num, year, month, day).

    Format is typically "Release: N Benchmark Date: DD MMM YYYY"
    but tolerates casing / extra whitespace. Any field that can't be
    parsed becomes 0, so missing parts still sort correctly (lower).
    """
    import re
    s = (releaseinfo or "").strip()

    release_num = 0
    m = re.search(r"release\s*:\s*(\d+)", s, re.IGNORECASE)
    if m:
        release_num = int(m.group(1))

    year = month = day = 0
    # Try "DD MMM YYYY" first (DISA's standard)
    m = re.search(r"(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})", s)
    if m:
        day = int(m.group(1))
        month = MONTH_MAP.get(m.group(2).lower()[:4], 0) or \
                MONTH_MAP.get(m.group(2).lower()[:3], 0)
        year = int(m.group(3))
    else:
        # Try ISO "YYYY-MM-DD" as a fallback
        m = re.search(r"(\d{4})-(\d{1,2})-(\d{1,2})", s)
        if m:
            year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))

    return (release_num, year, month, day)


def benchmark_rank(stig_info):
    """Return a comparable tuple (version, release_num, year, month, day).

    Higher tuple = newer benchmark. Used to decide which scanner's
    STIG_INFO block to use as the label on the merged CKL.
    """
    try:
        version_num = int(stig_info.get("version", "0") or 0)
    except ValueError:
        version_num = 0
    release_num, year, month, day = parse_release_info(
        stig_info.get("releaseinfo", ""))
    return (version_num, release_num, year, month, day)


def describe_benchmark(stig_info):
    """Human-readable benchmark label from STIG_INFO dict."""
    title = stig_info.get("title", "Unknown STIG")
    version = stig_info.get("version", "?")
    release = stig_info.get("releaseinfo", "") or "(release info unavailable)"
    return f"{title}  V{version}  {release}"


def benchmark_versions_differ(acas_info, eval_info):
    """Return True if the two benchmarks are for the same STIG but different versions."""
    same_stigid = (acas_info.get("stigid", "") == eval_info.get("stigid", "")
                   and acas_info.get("stigid"))
    if not same_stigid:
        return False  # Either different STIGs entirely, or no stigid info
    return (acas_info.get("version", "") != eval_info.get("version", "")
            or acas_info.get("releaseinfo", "") != eval_info.get("releaseinfo", ""))


# ============================================================
# Main merge
# ============================================================
def merge_ckls(acas_path, eval_path, output_path):
    print(f"Reading ACAS:      {acas_path}")
    acas_tree, acas_root, acas_asset, acas_vulns, acas_istigs, acas_stiginfo = \
        parse_ckl(acas_path)

    print(f"Reading Eval-STIG: {eval_path}")
    eval_tree, _, eval_asset, eval_vulns, eval_istigs, eval_stiginfo = \
        parse_ckl(eval_path)

    # Benchmark version check and ranking
    version_mismatch = benchmark_versions_differ(acas_stiginfo, eval_stiginfo)
    acas_rank = benchmark_rank(acas_stiginfo)
    eval_rank = benchmark_rank(eval_stiginfo)
    if eval_rank > acas_rank:
        newer_source = "eval"
        newer_label = describe_benchmark(eval_stiginfo)
        older_label = describe_benchmark(acas_stiginfo)
    elif acas_rank > eval_rank:
        newer_source = "acas"
        newer_label = describe_benchmark(acas_stiginfo)
        older_label = describe_benchmark(eval_stiginfo)
    else:
        newer_source = "tie"
        newer_label = describe_benchmark(acas_stiginfo)
        older_label = newer_label

    # If Eval-STIG has the newer benchmark, swap its STIG_INFO block into
    # the merged tree so the output carries the newer version label.
    if newer_source == "eval" and acas_istigs and eval_istigs:
        acas_istig_info = acas_istigs[0].find("STIG_INFO")
        eval_istig_info = eval_istigs[0].find("STIG_INFO")
        if acas_istig_info is not None and eval_istig_info is not None:
            acas_istigs[0].remove(acas_istig_info)
            new_stig_info = copy.deepcopy(eval_istig_info)
            acas_istigs[0].insert(0, new_stig_info)

    acas_ids = set(acas_vulns.keys())
    eval_ids = set(eval_vulns.keys())
    common = acas_ids & eval_ids
    only_acas = acas_ids - eval_ids
    only_eval = eval_ids - acas_ids

    # Merge asset metadata (Eval-STIG wins where populated)
    asset_changes = merge_asset(acas_root, eval_asset)

    stats = {
        "total": len(acas_ids | eval_ids),
        "common": len(common),
        "only_acas": len(only_acas),
        "only_eval_count": len(only_eval),
        "status_from_acas": 0,
        "status_from_eval": 0,
        "status_tied": 0,
        "disagreements": [],
        "newer_source": newer_source,
        "newer_label": newer_label,
        "older_label": older_label,
        "version_mismatch": version_mismatch,
    }

    # Merge common V-IDs (apply directly to ACAS tree)
    for vid in sorted(common, key=vuln_sort_key):
        acas_v = acas_vulns[vid]
        eval_v = eval_vulns[vid]

        a_status = get_field(acas_v, "STATUS")
        e_status = get_field(eval_v, "STATUS")
        a_det = get_field(acas_v, "FINDING_DETAILS")
        e_det = get_field(eval_v, "FINDING_DETAILS")
        a_com = get_field(acas_v, "COMMENTS")
        e_com = get_field(eval_v, "COMMENTS")

        source, winner = decide_status(a_status, e_status)
        if source == "acas":
            stats["status_from_acas"] += 1
        elif source == "eval":
            stats["status_from_eval"] += 1
        else:
            stats["status_tied"] += 1

        # Material disagreement = one says Open while the other says NF/NA
        disagreement = (
            a_status != e_status
            and "Open" in (a_status, e_status)
            and any(s in ("NotAFinding", "Not_Applicable") for s in (a_status, e_status))
        )
        if disagreement:
            stats["disagreements"].append({
                "vid": vid,
                "acas": a_status,
                "eval": e_status,
                "winner": winner,
                "title": get_rule_title(acas_v),
            })

        set_field(acas_v, "STATUS", winner)
        set_field(acas_v, "FINDING_DETAILS", merge_finding_details(a_det, e_det))
        set_field(acas_v, "COMMENTS",
                  merge_comments(a_com, e_com, a_status, e_status, winner, disagreement))

    # Append V-IDs that exist only in Eval-STIG
    eval_only_added = []
    if only_eval and acas_istigs:
        target_istig = acas_istigs[0]
        for vid in sorted(only_eval, key=vuln_sort_key):
            cloned = copy.deepcopy(eval_vulns[vid])
            existing = get_field(cloned, "COMMENTS")
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            note = (f"[MERGE NOTE {ts}] This V-ID was present in Eval-STIG only "
                    "(not in ACAS scan). Added to merged output from Eval-STIG.")
            set_field(cloned, "COMMENTS",
                      f"{existing}\n\n{note}" if existing else note)
            target_istig.append(cloned)
            eval_only_added.append({
                "vid": vid,
                "status": get_field(cloned, "STATUS"),
                "title": get_rule_title(cloned),
            })

    # Write merged CKL
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    acas_tree.write(output_path, encoding="UTF-8", xml_declaration=True)

    # ----------------- Report -----------------
    print()
    print("=" * 72)
    print("MERGE SUMMARY")
    print("=" * 72)
    print(f"Output file:     {output_path}")
    print()
    print("Benchmark info:")
    print(f"  ACAS:       {describe_benchmark(acas_stiginfo)}")
    print(f"  Eval-STIG:  {describe_benchmark(eval_stiginfo)}")
    if newer_source == "acas":
        print(f"  -> Merged CKL labeled with ACAS benchmark (newer).")
    elif newer_source == "eval":
        print(f"  -> Merged CKL labeled with Eval-STIG benchmark (newer).")
    else:
        print(f"  -> Both benchmarks match (or couldn't be ranked). Using ACAS as-is.")

    if version_mismatch:
        print()
        print("[!] BENCHMARK VERSION MISMATCH")
        print("    The two scanners used different versions of the same STIG.")
        if newer_source == "eval":
            print("    Merged CKL is labeled with the NEWER Eval-STIG benchmark.")
            print("    Caveats to be aware of:")
            print("      * The ACAS data (older benchmark) was merged in under the")
            print("        newer label. Most V-IDs carry across cleanly, but:")
            print("      * V-IDs added in the newer benchmark that ACAS never scanned")
            print("        will carry only Eval-STIG's data (that's fine).")
            print("      * V-IDs removed between versions may still appear if ACAS")
            print("        reported them. Review the V-ID list if strict conformance")
            print("        to the newer benchmark matters.")
        elif newer_source == "acas":
            print("    Merged CKL is labeled with the NEWER ACAS benchmark.")
            print("    Caveats to be aware of:")
            print("      * The Eval-STIG data (older benchmark) was merged in under")
            print("        the newer label. Consider updating Evaluate-STIG to match.")
            print("      * V-IDs added in the newer benchmark that Eval-STIG never")
            print("        scanned will carry only ACAS's data (that's fine).")

    print()
    print(f"V-ID coverage:")
    print(f"  Total unique V-IDs:     {stats['total']}")
    print(f"  In both scanners:       {stats['common']}")
    print(f"  ACAS only:              {stats['only_acas']}")
    print(f"  Eval-STIG only (added): {stats['only_eval_count']}")

    print()
    print(f"Asset metadata fields updated from Eval-STIG: {len(asset_changes)}")
    for field, old, new in asset_changes:
        old_show = old if old else "(blank)"
        print(f"  {field:<18} '{old_show}' -> '{new}'")

    # Report fields that were expected but still blank
    missing = []
    asset_el = acas_root.find("ASSET")
    for field in ["HOST_NAME", "HOST_IP", "HOST_FQDN", "ROLE"]:
        el = asset_el.find(field) if asset_el is not None else None
        val = (el.text or "").strip() if el is not None else ""
        if not val:
            missing.append(field)
    if missing:
        print(f"  [!] Still blank after merge: {', '.join(missing)}")
        print(f"      (Eval-STIG didn't provide values for these either.)")

    print()
    print("Status decisions on common V-IDs:")
    print(f"  Taken from ACAS:        {stats['status_from_acas']}")
    print(f"  Taken from Eval-STIG:   {stats['status_from_eval']}")
    print(f"  Both agreed (ACAS):     {stats['status_tied']}")

    n_dis = len(stats["disagreements"])
    print()
    if n_dis:
        print(f"[!] MATERIAL DISAGREEMENTS FLAGGED: {n_dis}")
        print("    (One scanner said Open, the other said NF/NA.")
        print("     Merged CKL took the compliance-favorable status per your policy.")
        print("     Each is annotated with a [MERGE NOTE] in the Comments field.)")
        print()
        for d in stats["disagreements"]:
            title = d["title"]
            short = (title[:60] + "...") if len(title) > 60 else title
            print(f"    {d['vid']}  ACAS={d['acas']:<15} Eval={d['eval']:<15} -> took '{d['winner']}'")
            if short:
                print(f"          {short}")
    else:
        print("[OK] No material disagreements (no Open-vs-NF/NA conflicts).")

    if eval_only_added:
        print()
        print(f"V-IDs added from Eval-STIG only: {len(eval_only_added)}")
        for item in eval_only_added[:10]:
            print(f"  {item['vid']}  [{item['status']}]")
        if len(eval_only_added) > 10:
            print(f"  ... and {len(eval_only_added) - 10} more")

    print()
    print(f"[OK] Merged CKL written: {output_path}")


# ============================================================
# CLI
# ============================================================
def build_parser():
    p = argparse.ArgumentParser(
        prog="combine_stig",
        description="Merge an ACAS CKL and an Evaluate-STIG CKL for the same host.",
        epilog=(
            "Examples:\n"
            "  python3 combine_stig.py --acas ACAS.ckl --eval EVAL.ckl --output OUT.ckl\n"
            "  python3 combine_stig.py --acas ACAS.ckl --eval EVAL.ckl --name Server01\n"
            "  python3 combine_stig.py ACAS.ckl EVAL.ckl           (auto-named output)\n"
            "\n"
            "Filename precedence (highest wins):\n"
            "  --output FILE       : exact filename (you control everything)\n"
            "  --name PREFIX       : Merged\\PREFIX_YYYY_MM_DD_HHMMSS.ckl\n"
            "  (neither)           : Merged\\<EvalHostname>_merged_YYYY_MM_DD_HHMMSS.ckl"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("positional", nargs="*",
                   help="Positional form: ACAS_FILE EVAL_FILE [OUTPUT_FILE]")
    p.add_argument("--acas", help="ACAS CKL file path")
    p.add_argument("--eval", dest="eval_file", help="Evaluate-STIG CKL file path")
    p.add_argument("--output", "-o",
                   help="Exact output filename (overrides --name)")
    p.add_argument("--name", "-n",
                   help="Custom filename prefix (e.g. 'Server01'); "
                        "timestamp and .ckl extension are appended automatically")
    return p


def resolve_args(args):
    if args.acas and args.eval_file:
        acas, evalf = args.acas, args.eval_file
        output = args.output
    elif len(args.positional) == 2:
        acas, evalf = args.positional
        output = args.output
    elif len(args.positional) == 3:
        acas, evalf, output = args.positional
        output = args.output or output
    else:
        print("ERROR: Provide both ACAS and Eval-STIG CKLs.", file=sys.stderr)
        print("  --acas ACAS.ckl --eval EVAL.ckl [--output OUT.ckl | --name PREFIX]",
              file=sys.stderr)
        print("  OR", file=sys.stderr)
        print("  ACAS.ckl EVAL.ckl [OUT.ckl]", file=sys.stderr)
        sys.exit(2)

    acas_path = Path(acas).expanduser().resolve()
    eval_path = Path(evalf).expanduser().resolve()

    if not acas_path.is_file():
        print(f"ERROR: ACAS file not found: {acas_path}", file=sys.stderr)
        sys.exit(1)
    if not eval_path.is_file():
        print(f"ERROR: Eval-STIG file not found: {eval_path}", file=sys.stderr)
        sys.exit(1)

    if output:
        # User gave an explicit full output filename — use it as-is
        output_path = Path(output).expanduser().resolve()
    elif getattr(args, "name", None):
        # User gave a name prefix — append timestamp + .ckl
        MERGED_DIR.mkdir(parents=True, exist_ok=True)
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in args.name)
        ts = datetime.now().strftime("%Y_%m_%d_%H%M%S")
        output_path = MERGED_DIR / f"{safe}_{ts}.ckl"
    else:
        # Fall back to auto-naming from Eval-STIG hostname
        try:
            _, _, ea, _, _, _ = parse_ckl(eval_path)
            hostname = ea.get("HOST_NAME", "").strip() or "MERGED"
        except Exception:
            hostname = "MERGED"
        MERGED_DIR.mkdir(parents=True, exist_ok=True)
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in hostname)
        ts = datetime.now().strftime("%Y_%m_%d_%H%M%S")
        output_path = MERGED_DIR / f"{safe}_merged_{ts}.ckl"

    return acas_path, eval_path, output_path


def browse_initial_dir(current_value=""):
    """Return the best starting folder for file pickers."""
    if current_value:
        candidate = Path(current_value).expanduser()
        if candidate.is_file():
            return str(candidate.parent)
        if candidate.is_dir():
            return str(candidate)
    return str(BASE_DIR)


# ============================================================
# GUI mode (tkinter)
# ============================================================
def launch_gui():
    """Launch an interactive tkinter GUI. All merging logic reuses the CLI functions."""
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    import io
    import contextlib

    root = tk.Tk()
    root.title("STIG CKL Merger")
    root.geometry("720x620")
    root.minsize(640, 520)

    # --- Variables ---
    acas_var = tk.StringVar()
    eval_var = tk.StringVar()
    name_var = tk.StringVar()

    # --- Layout frame ---
    main_frame = ttk.Frame(root, padding="12")
    main_frame.pack(fill="both", expand=True)
    main_frame.columnconfigure(1, weight=1)

    # --- Header ---
    header = ttk.Label(
        main_frame,
        text="Merge ACAS + Evaluate-STIG CKLs",
        font=("TkDefaultFont", 12, "bold"),
    )
    header.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 4))

    subheader = ttk.Label(
        main_frame,
        text=("Pick the two CKL files for the same host. "
              "The merged output combines their best data."),
        foreground="#555",
    )
    subheader.grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 12))

    # --- ACAS file row ---
    ttk.Label(main_frame, text="ACAS CKL:").grid(
        row=2, column=0, sticky="e", padx=(0, 8), pady=4)
    acas_entry = ttk.Entry(main_frame, textvariable=acas_var)
    acas_entry.grid(row=2, column=1, sticky="ew", pady=4)

    def browse_acas():
        path = filedialog.askopenfilename(
            title="Select ACAS CKL file",
            initialdir=browse_initial_dir(acas_var.get()),
            filetypes=[("CKL files", "*.ckl"), ("All files", "*.*")],
        )
        if path:
            acas_var.set(path)

    ttk.Button(main_frame, text="Browse...", command=browse_acas, width=12).grid(
        row=2, column=2, padx=(8, 0), pady=4)

    # --- Eval file row ---
    ttk.Label(main_frame, text="Eval-STIG CKL:").grid(
        row=3, column=0, sticky="e", padx=(0, 8), pady=4)
    eval_entry = ttk.Entry(main_frame, textvariable=eval_var)
    eval_entry.grid(row=3, column=1, sticky="ew", pady=4)

    def browse_eval():
        path = filedialog.askopenfilename(
            title="Select Evaluate-STIG CKL file",
            initialdir=browse_initial_dir(eval_var.get()),
            filetypes=[("CKL files", "*.ckl"), ("All files", "*.*")],
        )
        if path:
            eval_var.set(path)

    ttk.Button(main_frame, text="Browse...", command=browse_eval, width=12).grid(
        row=3, column=2, padx=(8, 0), pady=4)

    # --- Output name row ---
    ttk.Label(main_frame, text="Output name:").grid(
        row=4, column=0, sticky="e", padx=(0, 8), pady=4)
    name_entry = ttk.Entry(main_frame, textvariable=name_var)
    name_entry.grid(row=4, column=1, sticky="ew", pady=4)

    name_hint = ttk.Label(
        main_frame,
        text="Optional. Timestamp + .ckl will be appended automatically.",
        foreground="#777", font=("TkDefaultFont", 8),
    )
    name_hint.grid(row=5, column=1, sticky="w")

    # --- Merge button ---
    button_row = ttk.Frame(main_frame)
    button_row.grid(row=6, column=0, columnspan=3, pady=(16, 8))

    merge_btn = ttk.Button(button_row, text="  Merge  ", width=14)
    merge_btn.pack(side="left", padx=4)

    # State for "Open Output Folder" button
    last_output_path = [None]  # mutable closure

    def open_output_folder():
        path = last_output_path[0]
        if not path:
            messagebox.showinfo("No output yet",
                                "Run a merge first, then this button will open the folder.")
            return
        try:
            _open_local_folder(path)
        except Exception as e:
            messagebox.showerror("Could not open folder", str(e))

    open_folder_btn = ttk.Button(button_row, text="Open Output Folder",
                                 command=open_output_folder, width=20)
    open_folder_btn.pack(side="left", padx=4)

    def clear_fields():
        acas_var.set("")
        eval_var.set("")
        name_var.set("")
        log_area.configure(state="normal")
        log_area.delete("1.0", "end")
        log_area.insert("end", "Ready.\n")
        log_area.configure(state="disabled")
        last_output_path[0] = None

    ttk.Button(button_row, text="Clear", command=clear_fields, width=10).pack(
        side="left", padx=4)

    ttk.Button(button_row, text="Exit", command=root.destroy, width=10).pack(
        side="left", padx=4)

    # --- Log area ---
    log_frame = ttk.LabelFrame(main_frame, text=" Merge Log ", padding=6)
    log_frame.grid(row=7, column=0, columnspan=3, sticky="nsew", pady=(8, 0))
    main_frame.rowconfigure(7, weight=1)
    log_frame.columnconfigure(0, weight=1)
    log_frame.rowconfigure(0, weight=1)

    log_area = scrolledtext.ScrolledText(
        log_frame, wrap="word", height=14,
        font=("Consolas", 9) if sys.platform == "win32" else ("Monospace", 9),
    )
    log_area.grid(row=0, column=0, sticky="nsew")
    log_area.insert("end", "Ready.\n")
    log_area.configure(state="disabled")

    # --- Merge action ---
    def run_merge():
        acas_path_str = acas_var.get().strip()
        eval_path_str = eval_var.get().strip()
        name = name_var.get().strip()

        # Validate inputs
        if not acas_path_str:
            messagebox.showerror("Missing input", "Please select an ACAS CKL file.")
            return
        if not eval_path_str:
            messagebox.showerror("Missing input", "Please select an Eval-STIG CKL file.")
            return

        acas_path = Path(acas_path_str).expanduser().resolve()
        eval_path = Path(eval_path_str).expanduser().resolve()

        if not acas_path.is_file():
            messagebox.showerror("File not found", f"ACAS CKL not found:\n{acas_path}")
            return
        if not eval_path.is_file():
            messagebox.showerror("File not found", f"Eval-STIG CKL not found:\n{eval_path}")
            return

        # Compute output path
        if name:
            MERGED_DIR.mkdir(parents=True, exist_ok=True)
            safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
            ts = datetime.now().strftime("%Y_%m_%d_%H%M%S")
            output_path = MERGED_DIR / f"{safe}_{ts}.ckl"
        else:
            try:
                _, _, ea, _, _, _ = parse_ckl(eval_path)
                hostname = ea.get("HOST_NAME", "").strip() or "MERGED"
            except Exception:
                hostname = "MERGED"
            MERGED_DIR.mkdir(parents=True, exist_ok=True)
            safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in hostname)
            ts = datetime.now().strftime("%Y_%m_%d_%H%M%S")
            output_path = MERGED_DIR / f"{safe}_merged_{ts}.ckl"

        # Run the merge — capture stdout into the log
        log_area.configure(state="normal")
        log_area.delete("1.0", "end")
        log_area.insert("end", f"Starting merge at {datetime.now().strftime('%H:%M:%S')}...\n\n")
        log_area.configure(state="disabled")
        root.update_idletasks()

        buffer = io.StringIO()
        try:
            with contextlib.redirect_stdout(buffer):
                merge_ckls(acas_path, eval_path, output_path)
            output_text = buffer.getvalue()

            log_area.configure(state="normal")
            log_area.insert("end", output_text)
            log_area.insert("end", "\n--- Merge complete. ---\n")
            log_area.see("end")
            log_area.configure(state="disabled")

            last_output_path[0] = str(output_path)

        except ET.ParseError as e:
            log_area.configure(state="normal")
            log_area.insert("end", f"\n[ERROR] XML parse error: {e}\n")
            log_area.insert("end", "One of the CKL files is not valid XML.\n")
            log_area.configure(state="disabled")
            messagebox.showerror(
                "XML parse error",
                f"One of the CKL files could not be parsed as XML:\n\n{e}"
            )
        except Exception as e:
            log_area.configure(state="normal")
            log_area.insert("end", f"\n[ERROR] {type(e).__name__}: {e}\n")
            log_area.configure(state="disabled")
            messagebox.showerror("Merge failed", f"{type(e).__name__}: {e}")

    merge_btn.configure(command=run_merge)

    # --- Bottom status bar ---
    status = ttk.Label(
        main_frame,
        text="Tip: use 'Browse...' to select CKL files. The merged file "
             "is saved in the 'Merged' folder.",
        foreground="#777", font=("TkDefaultFont", 8),
    )
    status.grid(row=8, column=0, columnspan=3, sticky="w", pady=(8, 0))

    root.mainloop()


# ============================================================
# Main entry point
# ============================================================
def main():
    # If no arguments at all, launch the GUI
    if len(sys.argv) == 1:
        launch_gui()
        return

    parser = build_parser()
    # Allow --gui flag to launch GUI explicitly
    parser.add_argument("--gui", action="store_true",
                        help="Launch the graphical interface")
    args = parser.parse_args()

    if args.gui:
        launch_gui()
        return

    acas_path, eval_path, output_path = resolve_args(args)
    try:
        merge_ckls(acas_path, eval_path, output_path)
    except ET.ParseError as e:
        print(f"ERROR: XML parse error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
