import json
import subprocess
from typing import List


def run_bandit(project_path: str) -> List[dict]:
    try:
        result = subprocess.run(
            ["bandit", "-r", project_path, "-f", "json", "-q"],
            capture_output=True, text=True, timeout=300,
        )
        if not result.stdout:
            return []
        data = json.loads(result.stdout)
        return [_parse_result(r) for r in data.get("results", [])]
    except Exception as exc:
        print(f"[bandit] {exc}")
        return []


def _parse_result(r: dict) -> dict:
    test_id = r.get("test_id", "")
    owasp, cwe = _bandit_owasp_cwe(test_id)
    return {
        "vulnerability": r.get("test_name", "").replace("_", " ").title(),
        "severity":      r.get("issue_severity", "MEDIUM").lower(),
        "confidence":    _conf(r.get("issue_confidence", "MEDIUM")),
        "location":      r.get("filename", ""),
        "line":          r.get("line_number", 0),
        "code_snippet":  r.get("code", "")[:400],
        "tool":          "bandit",
        "team":          "blue",
        "category":      test_id,
        "owasp":         owasp,
        "cwe":           cwe,
        "root_cause":    r.get("issue_text", ""),
    }


# ── Complete Bandit B-code → OWASP + CWE table ──────────────────────
# Source: https://bandit.readthedocs.io/en/latest/plugins/index.html
_BANDIT_MAP = {
    # B1xx — Injection
    "B101": ("A05:2021-Security Misconfiguration",               "CWE-703"),  # assert_used
    "B102": ("A05:2021-Security Misconfiguration",               "CWE-78"),   # exec_used
    "B103": ("A05:2021-Security Misconfiguration",               "CWE-732"),  # set_bad_file_permissions
    "B104": ("A05:2021-Security Misconfiguration",               "CWE-605"),  # hardcoded_bind_all_interfaces
    "B105": ("A02:2021-Cryptographic Failures",                  "CWE-259"),  # hardcoded_password_string
    "B106": ("A02:2021-Cryptographic Failures",                  "CWE-259"),  # hardcoded_password_funcarg
    "B107": ("A02:2021-Cryptographic Failures",                  "CWE-259"),  # hardcoded_password_default
    "B108": ("A01:2021-Broken Access Control",                   "CWE-377"),  # hardcoded_tmp_directory
    "B110": ("A05:2021-Security Misconfiguration",               "CWE-391"),  # try_except_pass
    "B112": ("A05:2021-Security Misconfiguration",               "CWE-391"),  # try_except_continue

    # B2xx — Crypto
    "B201": ("A05:2021-Security Misconfiguration",               "CWE-94"),   # flask_debug_true
    "B202": ("A05:2021-Security Misconfiguration",               "CWE-94"),   # tarfile_unsafe_members
    "B301": ("A08:2021-Software and Data Integrity Failures",    "CWE-502"),  # pickle
    "B302": ("A08:2021-Software and Data Integrity Failures",    "CWE-502"),  # marshal
    "B303": ("A02:2021-Cryptographic Failures",                  "CWE-327"),  # md5/sha1
    "B304": ("A02:2021-Cryptographic Failures",                  "CWE-327"),  # ciphers
    "B305": ("A02:2021-Cryptographic Failures",                  "CWE-327"),  # cipher modes
    "B306": ("A02:2021-Cryptographic Failures",                  "CWE-330"),  # mktemp_q
    "B307": ("A03:2021-Injection",                               "CWE-78"),   # eval
    "B308": ("A03:2021-Injection",                               "CWE-78"),   # mark_safe
    "B310": ("A10:2021-Server-Side Request Forgery",             "CWE-918"),  # urllib_urlopen
    "B311": ("A02:2021-Cryptographic Failures",                  "CWE-330"),  # random
    "B312": ("A03:2021-Injection",                               "CWE-78"),   # telnet
    "B313": ("A03:2021-Injection",                               "CWE-611"),  # xml sax
    "B314": ("A03:2021-Injection",                               "CWE-611"),  # xml minidom
    "B315": ("A03:2021-Injection",                               "CWE-611"),  # xml pulldom
    "B316": ("A03:2021-Injection",                               "CWE-611"),  # xml expat
    "B317": ("A03:2021-Injection",                               "CWE-611"),  # xml lxml
    "B318": ("A03:2021-Injection",                               "CWE-611"),  # xml etree
    "B319": ("A03:2021-Injection",                               "CWE-611"),  # xml xmlrpc
    "B320": ("A03:2021-Injection",                               "CWE-611"),  # xml lxml etree
    "B321": ("A02:2021-Cryptographic Failures",                  "CWE-319"),  # ftp
    "B322": ("A03:2021-Injection",                               "CWE-78"),   # input
    "B323": ("A02:2021-Cryptographic Failures",                  "CWE-295"),  # unverified_context
    "B324": ("A02:2021-Cryptographic Failures",                  "CWE-327"),  # hashlib
    "B325": ("A02:2021-Cryptographic Failures",                  "CWE-330"),  # mktemp

    # B4xx — Blacklist calls
    "B401": ("A03:2021-Injection",                               "CWE-78"),   # import telnet
    "B402": ("A03:2021-Injection",                               "CWE-78"),   # import ftplib
    "B403": ("A08:2021-Software and Data Integrity Failures",    "CWE-502"),  # import pickle
    "B404": ("A03:2021-Injection",                               "CWE-78"),   # import subprocess
    "B405": ("A03:2021-Injection",                               "CWE-611"),  # import xml.etree
    "B406": ("A03:2021-Injection",                               "CWE-611"),  # import xml.sax
    "B407": ("A03:2021-Injection",                               "CWE-611"),  # import xml.expat
    "B408": ("A03:2021-Injection",                               "CWE-611"),  # import xml.minidom
    "B409": ("A03:2021-Injection",                               "CWE-611"),  # import xml.pulldom
    "B410": ("A03:2021-Injection",                               "CWE-611"),  # import lxml
    "B411": ("A03:2021-Injection",                               "CWE-78"),   # import xmlrpclib
    "B412": ("A03:2021-Injection",                               "CWE-78"),   # import httpoxy
    "B413": ("A02:2021-Cryptographic Failures",                  "CWE-327"),  # import pycrypto
    "B415": ("A03:2021-Injection",                               "CWE-78"),   # import pyghmi

    # B5xx — Crypto / TLS
    "B501": ("A02:2021-Cryptographic Failures",                  "CWE-295"),  # request_with_no_cert_validation
    "B502": ("A02:2021-Cryptographic Failures",                  "CWE-326"),  # ssl_with_bad_version
    "B503": ("A02:2021-Cryptographic Failures",                  "CWE-326"),  # ssl_with_bad_defaults
    "B504": ("A02:2021-Cryptographic Failures",                  "CWE-326"),  # ssl_with_no_version
    "B505": ("A02:2021-Cryptographic Failures",                  "CWE-326"),  # weak_cryptographic_key
    "B506": ("A08:2021-Software and Data Integrity Failures",    "CWE-502"),  # yaml_load
    "B507": ("A02:2021-Cryptographic Failures",                  "CWE-295"),  # ssh_no_host_key_verify
    "B508": ("A02:2021-Cryptographic Failures",                  "CWE-319"),  # snmp_insecure_version
    "B509": ("A02:2021-Cryptographic Failures",                  "CWE-319"),  # snmp_weak_cryptography

    # B6xx — Injection
    "B601": ("A03:2021-Injection",                               "CWE-78"),   # paramiko_calls
    "B602": ("A03:2021-Injection",                               "CWE-78"),   # subprocess_popen_with_shell_equals_true
    "B603": ("A03:2021-Injection",                               "CWE-78"),   # subprocess_without_shell_equals_true
    "B604": ("A03:2021-Injection",                               "CWE-78"),   # any_other_function_with_shell_equals_true
    "B605": ("A03:2021-Injection",                               "CWE-78"),   # start_process_with_a_shell
    "B606": ("A03:2021-Injection",                               "CWE-78"),   # start_process_with_no_shell
    "B607": ("A03:2021-Injection",                               "CWE-78"),   # start_process_with_partial_path
    "B608": ("A03:2021-Injection",                               "CWE-89"),   # hardcoded_sql_expressions
    "B609": ("A03:2021-Injection",                               "CWE-78"),   # linux_commands_wildcard_injection
    "B610": ("A03:2021-Injection",                               "CWE-89"),   # django_extra_used
    "B611": ("A03:2021-Injection",                               "CWE-89"),   # django_rawsql_used

    # B7xx — XML / XPath
    "B701": ("A03:2021-Injection",                               "CWE-94"),   # jinja2_autoescape_false
    "B702": ("A03:2021-Injection",                               "CWE-79"),   # use_of_mako_templates
    "B703": ("A03:2021-Injection",                               "CWE-79"),   # django_mark_safe
}


def _bandit_owasp_cwe(test_id: str):
    entry = _BANDIT_MAP.get(test_id.upper())
    if entry:
        return entry
    # Prefix fallback
    tid = test_id.upper()
    if tid.startswith("B3") or tid.startswith("B5"):
        return "A02:2021-Cryptographic Failures", ""
    if tid.startswith("B6") or tid.startswith("B7"):
        return "A03:2021-Injection", ""
    if tid.startswith("B4"):
        return "A08:2021-Software and Data Integrity Failures", ""
    return "", ""


def _conf(c: str) -> float:
    return {"HIGH": 0.90, "MEDIUM": 0.72, "LOW": 0.52}.get(c.upper(), 0.72)
