#!/usr/bin/env python3
"""
Generate realistic sample CKL files for testing STIG Helper workflows.

This script creates paired "old" and "new" synthetic checklists with richer
asset metadata, fuller STIG_DATA coverage, and meaningful status drift so the
merge, diff, status-report, export, and artifact features can be exercised
without using production STIG files.

Usage:
    python generate_sample_ckls.py
    python generate_sample_ckls.py --profile edge --host RAPP01
    python generate_sample_ckls.py --out-dir C:\\Temp\\samples
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from pathlib import Path
from xml.sax.saxutils import escape

DEFAULT_OUT_DIR = Path(__file__).parent


def xml_text(value):
    return escape(str(value or ""), {'"': "&quot;"})


def make_stig_data(attrs):
    lines = []
    for key, value in attrs:
        values = value if isinstance(value, list) else [value]
        for item in values:
            lines.append(
                "    <STIG_DATA>\n"
                f"      <VULN_ATTRIBUTE>{xml_text(key)}</VULN_ATTRIBUTE>\n"
                f"      <ATTRIBUTE_DATA>{xml_text(item)}</ATTRIBUTE_DATA>\n"
                "    </STIG_DATA>"
            )
    return "\n".join(lines)


def make_vuln(
    vuln_num,
    rule_title,
    severity,
    status,
    *,
    group_title,
    rule_ver,
    discussion,
    check_content,
    fix_text,
    finding_details="",
    comments="",
    ccis=None,
    ia_controls="",
    mitigations="",
    false_positives="",
    check_ref="",
    weight="10.0",
    classification="Unclass",
):
    attrs = [
        ("Vuln_Num", vuln_num),
        ("Severity", severity),
        ("Group_Title", group_title),
        ("Rule_ID", f"SV-{vuln_num[2:]}r1_rule"),
        ("Rule_Ver", rule_ver),
        ("Rule_Title", rule_title),
        ("Vuln_Discuss", discussion),
        ("Check_Content", check_content),
        ("Fix_Text", fix_text),
        ("Weight", weight),
        ("Class", classification),
        ("IA_Controls", ia_controls),
        ("False_Positives", false_positives),
        ("False_Negatives", ""),
        ("Documentable", "true"),
        ("Mitigations", mitigations),
        ("Potential_Impact", "Compromise of confidentiality, integrity, or availability."),
        ("Third_Party_Tools", ""),
        ("Mitigation_Control", ""),
        ("Responsibility", "AO / ISSO / System Administrator"),
        ("Security_Override_Guidance", ""),
        ("Check_Content_Ref", check_ref),
        ("STIGRef", ""),
        ("CCI_REF", ccis or []),
    ]
    return f"""  <VULN>
{make_stig_data(attrs)}
    <STATUS>{xml_text(status)}</STATUS>
    <FINDING_DETAILS>{xml_text(finding_details)}</FINDING_DETAILS>
    <COMMENTS>{xml_text(comments)}</COMMENTS>
    <SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>
    <SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>
  </VULN>"""


def build_ckl(asset, stig_info, vulns):
    stig_info_xml = "\n".join(
        "    <SI_DATA>\n"
        f"      <SID_NAME>{xml_text(name)}</SID_NAME>\n"
        f"      <SID_DATA>{xml_text(value)}</SID_DATA>\n"
        "    </SI_DATA>"
        for name, value in stig_info.items()
    )
    asset_xml = "\n".join(
        f"  <{tag}>{xml_text(value)}</{tag}>"
        for tag, value in asset.items()
    )
    vuln_blocks = "\n".join(vulns)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<CHECKLIST>
<ASSET>
{asset_xml}
</ASSET>
<STIGS>
<iSTIG>
  <STIG_INFO>
{stig_info_xml}
  </STIG_INFO>
{vuln_blocks}
</iSTIG>
</STIGS>
</CHECKLIST>
"""


def default_asset(host_name, target_comment="", tech_area=""):
    return {
        "ROLE": "Member Server",
        "ASSET_TYPE": "Computing",
        "MARKING": "UNCLASSIFIED",
        "HOST_NAME": host_name,
        "HOST_IP": "10.20.30.40",
        "HOST_MAC": "00-15-5D-20-30-40",
        "HOST_FQDN": f"{host_name.lower()}.example.mil",
        "TARGET_COMMENT": target_comment,
        "TECH_AREA": tech_area,
        "TARGET_KEY": "2350",
        "WEB_OR_DATABASE": "false",
        "WEB_DB_SITE": "",
        "WEB_DB_INSTANCE": "",
    }


def default_windows_stig_info():
    return {
        "version": "1",
        "classification": "UNCLASSIFIED",
        "customname": "",
        "stigid": "Windows_Server_2022_STIG",
        "description": "Synthetic Windows Server 2022 checklist for STIG Helper testing.",
        "filename": "U_MS_Windows_Server_2022_STIG_V1R2_Manual-xccdf.xml",
        "releaseinfo": "Release: 2 Benchmark Date: 07 Feb 2026",
        "title": "Microsoft Windows Server 2022 Security Technical Implementation Guide",
        "uuid": "00000000-0000-0000-0000-000000000001",
        "notice": "For internal testing only.",
        "source": "Synthetic generator",
    }


def default_edge_stig_info():
    return {
        "version": "2",
        "classification": "UNCLASSIFIED",
        "customname": "",
        "stigid": "Microsoft_Edge_STIG",
        "description": "Synthetic Microsoft Edge checklist for STIG Helper testing.",
        "filename": "U_MS_Edge_STIG_V2R5_Manual-xccdf.xml",
        "releaseinfo": "Release: 5 Benchmark Date: 01 Apr 2026",
        "title": "Microsoft Edge Security Technical Implementation Guide",
        "uuid": "00000000-0000-0000-0000-000000000002",
        "notice": "For internal testing only.",
        "source": "Synthetic generator",
    }


WINDOWS_BASELINE = [
    {
        "vuln_num": "V-254238",
        "rule_title": "Windows Server 2022 must be configured to audit process creation.",
        "severity": "medium",
        "group_title": "SRG-OS-000042-GPOS-00020",
        "rule_ver": "WN22-00-000010",
        "discussion": "Capturing process creation events improves accountability and supports incident response.",
        "check_content": "Verify audit policy for Process Creation is enabled for Success events.",
        "fix_text": "Configure Advanced Audit Policy to enable Success for Process Creation.",
        "ia_controls": "AU-3, AU-12",
        "ccis": ["CCI-000172", "CCI-001875"],
        "check_ref": "https://public.cyber.mil/stigs/",
    },
    {
        "vuln_num": "V-254239",
        "rule_title": "Windows Server 2022 must have the built-in guest account disabled.",
        "severity": "medium",
        "group_title": "SRG-OS-000104-GPOS-00051",
        "rule_ver": "WN22-00-000020",
        "discussion": "The guest account provides anonymous local access and must remain disabled.",
        "check_content": "Review Local Users and Groups and verify the Guest account is disabled.",
        "fix_text": "Disable the Guest account and verify it remains disabled after imaging or patch cycles.",
        "ia_controls": "AC-2, AC-6",
        "ccis": ["CCI-000764"],
    },
    {
        "vuln_num": "V-254240",
        "rule_title": "Windows Server 2022 password history must be configured to 24 passwords remembered.",
        "severity": "medium",
        "group_title": "SRG-OS-000077-GPOS-00045",
        "rule_ver": "WN22-00-000030",
        "discussion": "Password history reduces the risk of users cycling through weak or reused passwords.",
        "check_content": "Verify Enforce password history is set to 24 or more passwords remembered.",
        "fix_text": "Configure the domain or local password policy to remember at least 24 passwords.",
        "ia_controls": "IA-5(1)",
        "ccis": ["CCI-000199"],
    },
    {
        "vuln_num": "V-254241",
        "rule_title": "Windows Server 2022 maximum password age must be configured to 60 days or less.",
        "severity": "medium",
        "group_title": "SRG-OS-000076-GPOS-00044",
        "rule_ver": "WN22-00-000040",
        "discussion": "Limiting password lifetime reduces exposure from stolen credentials.",
        "check_content": "Verify Maximum password age is set to 60 days or less.",
        "fix_text": "Set Maximum password age to 60 days or less through GPO.",
        "ia_controls": "IA-5(1)",
        "ccis": ["CCI-000198"],
    },
    {
        "vuln_num": "V-254242",
        "rule_title": "Windows Server 2022 minimum password age must be configured to at least 1 day.",
        "severity": "medium",
        "group_title": "SRG-OS-000075-GPOS-00043",
        "rule_ver": "WN22-00-000050",
        "discussion": "Minimum password age prevents rapid password cycling to bypass history controls.",
        "check_content": "Verify Minimum password age is set to 1 day or more.",
        "fix_text": "Configure Minimum password age to at least 1 day.",
        "ia_controls": "IA-5(1)",
        "ccis": ["CCI-000197"],
    },
    {
        "vuln_num": "V-254243",
        "rule_title": "Windows Server 2022 must enforce password complexity.",
        "severity": "medium",
        "group_title": "SRG-OS-000078-GPOS-00046",
        "rule_ver": "WN22-00-000060",
        "discussion": "Complex passwords are harder to brute force and reduce dictionary attack risk.",
        "check_content": "Verify Password must meet complexity requirements is Enabled.",
        "fix_text": "Enable password complexity in the applicable password policy.",
        "ia_controls": "IA-5(1)",
        "ccis": ["CCI-000192"],
    },
    {
        "vuln_num": "V-254244",
        "rule_title": "Windows Server 2022 Remote Desktop Services must always prompt for password upon connection.",
        "severity": "medium",
        "group_title": "SRG-OS-000373-GPOS-00157",
        "rule_ver": "WN22-CC-000070",
        "discussion": "Prompting for credentials reduces unauthorized reuse of cached sessions.",
        "check_content": "Verify the RDS setting Always prompt for password upon connection is Enabled.",
        "fix_text": "Enable Always prompt for password upon connection for Remote Desktop Services.",
        "ia_controls": "IA-2, IA-11",
        "ccis": ["CCI-000765"],
    },
    {
        "vuln_num": "V-254245",
        "rule_title": "Windows Server 2022 must prevent the display of the last username on the logon screen.",
        "severity": "low",
        "group_title": "SRG-OS-000480-GPOS-00227",
        "rule_ver": "WN22-CC-000080",
        "discussion": "Hiding the last username reduces information disclosure to unauthorized users.",
        "check_content": "Verify Interactive logon: Do not display last user name is Enabled.",
        "fix_text": "Enable the policy to prevent displaying the last user name.",
        "ia_controls": "AC-3",
        "ccis": ["CCI-001084"],
    },
    {
        "vuln_num": "V-254246",
        "rule_title": "Windows Server 2022 LAN Manager authentication level must be configured to send NTLMv2 response only.",
        "severity": "high",
        "group_title": "SRG-OS-000480-GPOS-00232",
        "rule_ver": "WN22-CC-000090",
        "discussion": "NTLMv2 provides stronger authentication and better protection against credential replay.",
        "check_content": "Verify LAN Manager authentication level is set to Send NTLMv2 response only. Refuse LM and NTLM.",
        "fix_text": "Set Network security: LAN Manager authentication level to the required NTLMv2-only value.",
        "ia_controls": "IA-5, SC-8",
        "ccis": ["CCI-000803", "CCI-002418"],
    },
    {
        "vuln_num": "V-254247",
        "rule_title": "Windows Server 2022 SMBv1 protocol must be disabled.",
        "severity": "high",
        "group_title": "SRG-OS-000095-GPOS-00049",
        "rule_ver": "WN22-00-000100",
        "discussion": "SMBv1 is deprecated and vulnerable to widely exploited attacks.",
        "check_content": "Verify the SMBv1 protocol is removed or disabled on the host.",
        "fix_text": "Disable or remove SMBv1 and confirm server and client SMBv1 are disabled.",
        "ia_controls": "CM-6, SI-2",
        "ccis": ["CCI-000381"],
    },
    {
        "vuln_num": "V-254248",
        "rule_title": "Windows Server 2022 must have the Windows Firewall enabled on all profiles.",
        "severity": "medium",
        "group_title": "SRG-OS-000480-GPOS-00227",
        "rule_ver": "WN22-CC-000110",
        "discussion": "Host firewalls reduce exposure from unnecessary inbound access and lateral movement.",
        "check_content": "Verify Domain, Private, and Public firewall profiles are enabled.",
        "fix_text": "Enable Windows Defender Firewall on all network profiles.",
        "ia_controls": "SC-7",
        "ccis": ["CCI-002314"],
    },
    {
        "vuln_num": "V-254249",
        "rule_title": "Windows Server 2022 must audit logon events.",
        "severity": "medium",
        "group_title": "SRG-OS-000470-GPOS-00214",
        "rule_ver": "WN22-00-000120",
        "discussion": "Auditing logon activity supports incident detection and account misuse investigations.",
        "check_content": "Verify Success and Failure auditing are enabled for Logon events.",
        "fix_text": "Enable Success and Failure for Logon under Advanced Audit Policy.",
        "ia_controls": "AU-2, AU-12",
        "ccis": ["CCI-000130"],
    },
    {
        "vuln_num": "V-254250",
        "rule_title": "Windows Server 2022 must disable the TLS RC4 cipher suites.",
        "severity": "high",
        "group_title": "SRG-OS-000120-GPOS-00061",
        "rule_ver": "WN22-00-000130",
        "discussion": "RC4 is cryptographically weak and must not be available for secure communications.",
        "check_content": "Verify RC4 cipher suites are disabled in Schannel or equivalent policy.",
        "fix_text": "Disable RC4 cipher suites in the approved TLS configuration baseline.",
        "ia_controls": "SC-13",
        "ccis": ["CCI-002450"],
    },
]


EDGE_BASELINE = [
    {
        "vuln_num": "V-204709",
        "rule_title": "The browser must use FIPS-compliant algorithms when required.",
        "severity": "medium",
        "group_title": "SRG-APP-000014-BRWSR-000001",
        "rule_ver": "EDGE-00-000010",
        "discussion": "Use of FIPS-validated cryptography protects management and application traffic.",
        "check_content": "Verify Edge inherits the host FIPS configuration and uses approved TLS settings.",
        "fix_text": "Enable the required host/browser cryptographic settings and validate TLS policy.",
        "ia_controls": "SC-13",
        "ccis": ["CCI-002450"],
    },
    {
        "vuln_num": "V-204715",
        "rule_title": "The web server must present a valid certificate.",
        "severity": "medium",
        "group_title": "SRG-APP-000015-BRWSR-000002",
        "rule_ver": "EDGE-00-000020",
        "discussion": "Certificates support trust, confidentiality, and non-repudiation for secured sessions.",
        "check_content": "Verify the accessed site presents a valid certificate signed by a trusted authority.",
        "fix_text": "Deploy a valid certificate and configure the site to require HTTPS.",
        "ia_controls": "SC-8, SC-23",
        "ccis": ["CCI-001184"],
    },
    {
        "vuln_num": "V-204754",
        "rule_title": "The browser must enforce certificate validation for secure sessions.",
        "severity": "medium",
        "group_title": "SRG-APP-000015-BRWSR-000003",
        "rule_ver": "EDGE-00-000030",
        "discussion": "Certificate validation prevents users from accepting invalid secure connections.",
        "check_content": "Verify invalid certificates are blocked or clearly rejected in browser policy.",
        "fix_text": "Enable certificate validation enforcement in the browser policy baseline.",
        "ia_controls": "SC-23",
        "ccis": ["CCI-001185"],
    },
    {
        "vuln_num": "V-204760",
        "rule_title": "The browser must prevent execution of unauthorized mobile code.",
        "severity": "medium",
        "group_title": "SRG-APP-000141-BRWSR-000010",
        "rule_ver": "EDGE-00-000040",
        "discussion": "Unauthorized mobile code can introduce harmful functionality or malware.",
        "check_content": "Verify unapproved plug-ins, add-ons, and mobile code pathways are disabled.",
        "fix_text": "Restrict plug-ins and mobile code to approved sources and configurations.",
        "ia_controls": "SI-3",
        "ccis": ["CCI-001499"],
    },
    {
        "vuln_num": "V-204761",
        "rule_title": "The browser must enforce approved home page and startup behavior.",
        "severity": "low",
        "group_title": "SRG-APP-000516-BRWSR-000200",
        "rule_ver": "EDGE-00-000050",
        "discussion": "Controlling startup behavior reduces exposure to phishing or untrusted sites.",
        "check_content": "Verify the home page and startup pages are managed through enterprise policy.",
        "fix_text": "Set startup pages and home page configuration through approved policy objects.",
        "ia_controls": "CM-7",
        "ccis": ["CCI-000366"],
    },
]


def build_windows_pair(host_name):
    old_vulns = [
        make_vuln(
            item["vuln_num"], item["rule_title"], item["severity"], status,
            group_title=item["group_title"],
            rule_ver=item["rule_ver"],
            discussion=item["discussion"],
            check_content=item["check_content"],
            fix_text=item["fix_text"],
            ia_controls=item["ia_controls"],
            ccis=item["ccis"],
            check_ref=item.get("check_ref", ""),
            finding_details=finding_details,
            comments=comments,
            mitigations=mitigations,
        )
        for item, status, finding_details, comments, mitigations in [
            (WINDOWS_BASELINE[0], "NotAFinding",
             "AuditPolicy verified via auditpol /get /subcategory:\"Process Creation\". Success enabled.",
             "Baseline GPO GP-SEC-001 applied 2026-01-15.",
             ""),
            (WINDOWS_BASELINE[1], "NotAFinding",
             "Guest account disabled via Local Users and Groups.",
             "Disabled per baseline.",
             ""),
            (WINDOWS_BASELINE[2], "NotAFinding",
             "PasswordHistorySize = 24. Confirmed via net accounts.",
             "Configured by GPO.",
             ""),
            (WINDOWS_BASELINE[3], "NotAFinding",
             "MaxPasswordAge = 60.",
             "",
             ""),
            (WINDOWS_BASELINE[4], "Open",
             "MinPasswordAge = 0. Fails check.",
             "Pending GPO update ticket CHG-2026-0142.",
             ""),
            (WINDOWS_BASELINE[5], "NotAFinding",
             "ComplexityEnabled = 1.",
             "",
             ""),
            (WINDOWS_BASELINE[6], "NotAFinding",
             "fPromptForPassword = 1 in registry.",
             "",
             ""),
            (WINDOWS_BASELINE[7], "NotAFinding",
             "DontDisplayLastUserName = 1.",
             "",
             ""),
            (WINDOWS_BASELINE[8], "NotAFinding",
             "LmCompatibilityLevel = 5.",
             "Critical setting verified by ISSO.",
             ""),
            (WINDOWS_BASELINE[9], "NotAFinding",
             "SMB1 feature removed via DISM. Get-SmbServerConfiguration shows EnableSMB1Protocol = False.",
             "Removed per baseline hardening.",
             ""),
            (WINDOWS_BASELINE[10], "NotAFinding",
             "Domain, Private, Public profiles all Enabled.",
             "",
             ""),
            (WINDOWS_BASELINE[11], "Not_Applicable",
             "Host is a jump box with centralized logging; local audit disabled per waiver.",
             "Waiver WV-2025-088 approved by ISSM.",
             "Enterprise SIEM provides compensating coverage."),
        ]
    ]

    new_vulns = deepcopy(old_vulns)
    new_vulns[1] = make_vuln(
        WINDOWS_BASELINE[1]["vuln_num"], WINDOWS_BASELINE[1]["rule_title"], WINDOWS_BASELINE[1]["severity"], "Open",
        group_title=WINDOWS_BASELINE[1]["group_title"],
        rule_ver=WINDOWS_BASELINE[1]["rule_ver"],
        discussion=WINDOWS_BASELINE[1]["discussion"],
        check_content=WINDOWS_BASELINE[1]["check_content"],
        fix_text=WINDOWS_BASELINE[1]["fix_text"],
        ia_controls=WINDOWS_BASELINE[1]["ia_controls"],
        ccis=WINDOWS_BASELINE[1]["ccis"],
        finding_details="Guest account is ENABLED. Unexpected state change detected.",
        comments="REGRESSION DETECTED — investigate vendor imaging or local reset activity.",
    )
    new_vulns[3] = make_vuln(
        WINDOWS_BASELINE[3]["vuln_num"], WINDOWS_BASELINE[3]["rule_title"], WINDOWS_BASELINE[3]["severity"], "NotAFinding",
        group_title=WINDOWS_BASELINE[3]["group_title"],
        rule_ver=WINDOWS_BASELINE[3]["rule_ver"],
        discussion=WINDOWS_BASELINE[3]["discussion"],
        check_content=WINDOWS_BASELINE[3]["check_content"],
        fix_text=WINDOWS_BASELINE[3]["fix_text"],
        ia_controls=WINDOWS_BASELINE[3]["ia_controls"],
        ccis=WINDOWS_BASELINE[3]["ccis"],
        finding_details="MaxPasswordAge = 60.",
        comments="Re-verified 2026-04-20 after quarterly review.",
    )
    new_vulns[4] = make_vuln(
        WINDOWS_BASELINE[4]["vuln_num"], WINDOWS_BASELINE[4]["rule_title"], WINDOWS_BASELINE[4]["severity"], "NotAFinding",
        group_title=WINDOWS_BASELINE[4]["group_title"],
        rule_ver=WINDOWS_BASELINE[4]["rule_ver"],
        discussion=WINDOWS_BASELINE[4]["discussion"],
        check_content=WINDOWS_BASELINE[4]["check_content"],
        fix_text=WINDOWS_BASELINE[4]["fix_text"],
        ia_controls=WINDOWS_BASELINE[4]["ia_controls"],
        ccis=WINDOWS_BASELINE[4]["ccis"],
        finding_details="MinPasswordAge = 1. GPO updated per CHG-2026-0142.",
        comments="Remediated 2026-04-18.",
    )
    new_vulns[8] = make_vuln(
        WINDOWS_BASELINE[8]["vuln_num"], WINDOWS_BASELINE[8]["rule_title"], WINDOWS_BASELINE[8]["severity"], "Open",
        group_title=WINDOWS_BASELINE[8]["group_title"],
        rule_ver=WINDOWS_BASELINE[8]["rule_ver"],
        discussion=WINDOWS_BASELINE[8]["discussion"],
        check_content=WINDOWS_BASELINE[8]["check_content"],
        fix_text=WINDOWS_BASELINE[8]["fix_text"],
        ia_controls=WINDOWS_BASELINE[8]["ia_controls"],
        ccis=WINDOWS_BASELINE[8]["ccis"],
        finding_details="LmCompatibilityLevel = 3. Downgraded from required value 5.",
        comments="URGENT — likely overridden by third-party policy or agent.",
    )
    new_vulns.append(make_vuln(
        WINDOWS_BASELINE[12]["vuln_num"], WINDOWS_BASELINE[12]["rule_title"], WINDOWS_BASELINE[12]["severity"], "Not_Reviewed",
        group_title=WINDOWS_BASELINE[12]["group_title"],
        rule_ver=WINDOWS_BASELINE[12]["rule_ver"],
        discussion=WINDOWS_BASELINE[12]["discussion"],
        check_content=WINDOWS_BASELINE[12]["check_content"],
        fix_text=WINDOWS_BASELINE[12]["fix_text"],
        ia_controls=WINDOWS_BASELINE[12]["ia_controls"],
        ccis=WINDOWS_BASELINE[12]["ccis"],
        comments="New control added in STIG R2.",
    ))

    asset = default_asset(host_name, target_comment="Synthetic Windows server sample for testing.")
    stig_info = default_windows_stig_info()
    return (
        build_ckl(asset, stig_info, old_vulns),
        build_ckl(asset, stig_info, new_vulns),
    )


def build_edge_pair(host_name):
    asset = default_asset(
        host_name,
        target_comment="Synthetic browser checklist for testing.",
        tech_area="Browser",
    )
    asset["ROLE"] = "Workstation"
    asset["WEB_OR_DATABASE"] = "false"
    stig_info = default_edge_stig_info()

    old_vulns = [
        make_vuln(
            EDGE_BASELINE[0]["vuln_num"], EDGE_BASELINE[0]["rule_title"], EDGE_BASELINE[0]["severity"], "NotAFinding",
            group_title=EDGE_BASELINE[0]["group_title"],
            rule_ver=EDGE_BASELINE[0]["rule_ver"],
            discussion=EDGE_BASELINE[0]["discussion"],
            check_content=EDGE_BASELINE[0]["check_content"],
            fix_text=EDGE_BASELINE[0]["fix_text"],
            ia_controls=EDGE_BASELINE[0]["ia_controls"],
            ccis=EDGE_BASELINE[0]["ccis"],
            finding_details="The application server is FIPS enabled and management sessions use HTTPS.",
            comments="Reviewed during secure browser validation.",
        ),
        make_vuln(
            EDGE_BASELINE[1]["vuln_num"], EDGE_BASELINE[1]["rule_title"], EDGE_BASELINE[1]["severity"], "NotAFinding",
            group_title=EDGE_BASELINE[1]["group_title"],
            rule_ver=EDGE_BASELINE[1]["rule_ver"],
            discussion=EDGE_BASELINE[1]["discussion"],
            check_content=EDGE_BASELINE[1]["check_content"],
            fix_text=EDGE_BASELINE[1]["fix_text"],
            ia_controls=EDGE_BASELINE[1]["ia_controls"],
            ccis=EDGE_BASELINE[1]["ccis"],
            finding_details="The web server presents a valid certificate issued by a trusted CA.",
            comments="Non-repudiation in place.",
        ),
        make_vuln(
            EDGE_BASELINE[2]["vuln_num"], EDGE_BASELINE[2]["rule_title"], EDGE_BASELINE[2]["severity"], "NotAFinding",
            group_title=EDGE_BASELINE[2]["group_title"],
            rule_ver=EDGE_BASELINE[2]["rule_ver"],
            discussion=EDGE_BASELINE[2]["discussion"],
            check_content=EDGE_BASELINE[2]["check_content"],
            fix_text=EDGE_BASELINE[2]["fix_text"],
            ia_controls=EDGE_BASELINE[2]["ia_controls"],
            ccis=EDGE_BASELINE[2]["ccis"],
            finding_details="Browser policy blocks invalid certificate acceptance by users.",
            comments="Certificate validation confirmed.",
        ),
        make_vuln(
            EDGE_BASELINE[3]["vuln_num"], EDGE_BASELINE[3]["rule_title"], EDGE_BASELINE[3]["severity"], "Not_Applicable",
            group_title=EDGE_BASELINE[3]["group_title"],
            rule_ver=EDGE_BASELINE[3]["rule_ver"],
            discussion=EDGE_BASELINE[3]["discussion"],
            check_content=EDGE_BASELINE[3]["check_content"],
            fix_text=EDGE_BASELINE[3]["fix_text"],
            ia_controls=EDGE_BASELINE[3]["ia_controls"],
            ccis=EDGE_BASELINE[3]["ccis"],
            finding_details="Mobile code is not installed.",
            comments="Only approved administrators can install software. ESS provides malware protection.",
        ),
        make_vuln(
            EDGE_BASELINE[4]["vuln_num"], EDGE_BASELINE[4]["rule_title"], EDGE_BASELINE[4]["severity"], "NotAFinding",
            group_title=EDGE_BASELINE[4]["group_title"],
            rule_ver=EDGE_BASELINE[4]["rule_ver"],
            discussion=EDGE_BASELINE[4]["discussion"],
            check_content=EDGE_BASELINE[4]["check_content"],
            fix_text=EDGE_BASELINE[4]["fix_text"],
            ia_controls=EDGE_BASELINE[4]["ia_controls"],
            ccis=EDGE_BASELINE[4]["ccis"],
            finding_details="Startup page policy enforced through enterprise management.",
            comments="",
        ),
    ]

    new_vulns = deepcopy(old_vulns)
    new_vulns[2] = make_vuln(
        EDGE_BASELINE[2]["vuln_num"], EDGE_BASELINE[2]["rule_title"], EDGE_BASELINE[2]["severity"], "Open",
        group_title=EDGE_BASELINE[2]["group_title"],
        rule_ver=EDGE_BASELINE[2]["rule_ver"],
        discussion=EDGE_BASELINE[2]["discussion"],
        check_content=EDGE_BASELINE[2]["check_content"],
        fix_text=EDGE_BASELINE[2]["fix_text"],
        ia_controls=EDGE_BASELINE[2]["ia_controls"],
        ccis=EDGE_BASELINE[2]["ccis"],
        finding_details="Browser warning bypass is allowed for invalid certificates.",
        comments="Policy drift detected after browser update.",
    )
    new_vulns[4] = make_vuln(
        EDGE_BASELINE[4]["vuln_num"], EDGE_BASELINE[4]["rule_title"], EDGE_BASELINE[4]["severity"], "Not_Reviewed",
        group_title=EDGE_BASELINE[4]["group_title"],
        rule_ver=EDGE_BASELINE[4]["rule_ver"],
        discussion=EDGE_BASELINE[4]["discussion"],
        check_content=EDGE_BASELINE[4]["check_content"],
        fix_text=EDGE_BASELINE[4]["fix_text"],
        ia_controls=EDGE_BASELINE[4]["ia_controls"],
        ccis=EDGE_BASELINE[4]["ccis"],
        comments="Pending validation after policy refresh.",
    )

    return (
        build_ckl(asset, stig_info, old_vulns),
        build_ckl(asset, stig_info, new_vulns),
    )


PROFILES = {
    "windows": build_windows_pair,
    "edge": build_edge_pair,
}


def parse_args():
    parser = argparse.ArgumentParser(description="Generate realistic sample CKL files for testing.")
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES.keys()),
        default="windows",
        help="Sample profile to generate.",
    )
    parser.add_argument(
        "--host",
        default="SERVER01",
        help="Host name to embed in the generated CKLs.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=DEFAULT_OUT_DIR,
        help="Directory where sample files should be written.",
    )
    parser.add_argument(
        "--prefix",
        default="sample",
        help="Filename prefix for generated outputs.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    old_ckl, new_ckl = PROFILES[args.profile](args.host)
    old_path = out_dir / f"{args.prefix}_{args.profile}_old.ckl"
    new_path = out_dir / f"{args.prefix}_{args.profile}_new.ckl"
    old_path.write_text(old_ckl, encoding="utf-8")
    new_path.write_text(new_ckl, encoding="utf-8")

    print(f"[OK] Wrote {old_path.name} and {new_path.name}")
    print(f"     Profile: {args.profile}")
    print(f"     Host:    {args.host}")
    print(f"     Output:  {out_dir}")
    print()
    print("Suggested next steps:")
    print(f"  python stig_diff.py add {args.host} {old_path.name}")
    print(f"  python stig_diff.py add {args.host} {new_path.name}")
    print(f"  python stig_diff.py diff {args.host}")
    print(f"  python stig_diff.py report {args.host}")


if __name__ == "__main__":
    main()
