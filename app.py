import json
import boto3
import os
import re
from datetime import datetime, timezone
from pathlib import Path
import imaplib
import email
import urllib.request
import urllib.parse
from email.header import decode_header
from dotenv import load_dotenv

load_dotenv()

from flask import Flask, request, render_template_string, render_template, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.getenv("FLASK_SECRET_KEY") or "local-development-only-change-me"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
)

# AWS clients
lambda_client = boto3.client("lambda", region_name="us-east-1")
s3_client = boto3.client("s3", region_name="us-east-1")
logs_client = boto3.client("logs", region_name="us-east-1")

# AWS S3 configuration
S3_BUCKET = "cti-threat-data-sk-2026"
S3_KEY = "threats.json"

FAILED_ATTEMPTS = 0
USERS_FILE = "users.json"
VULNERABILITY_LOG_FILE = "vulnerability_monitor.log"

# ============================================================
# SCENARIO 5: AWS AUTOMATIC CRITICAL-THREAT PROCESSING
# Merged from the Scenario 5 Lambda source.
# The lambda_handler remains deployable as an AWS Lambda entry point.
# ============================================================

# ============================================================
# SCENARIO 5: AWS Automatic Critical-Threat Processing
# API Gateway + Lambda — CTI Data Request & Processing
#
# This Lambda function:
# 1. Receives a CTI data request from the CTI website via API Gateway
# 2. Fetches real CVE data from NVD API (or uses demo data)
# 3. Processes and classifies threats by severity
# 4. Logs every request to CloudWatch automatically
# 5. Returns structured results back to the website
# ============================================================

# CloudWatch logging is automatic — every print() goes to CloudWatch Logs
# No extra setup needed

def lambda_handler(event, context):
    print("=" * 60)
    print("CTI Data Processing Request Received")
    print(f"Timestamp: {datetime.now(timezone.utc).replace(microsecond=0).isoformat()}")
    print("=" * 60)

    try:
        # ── Handle CORS preflight ───────────────────────────
        method = event.get("httpMethod") or event.get("requestContext", {}).get("http", {}).get("method")
        if method == "OPTIONS":
            return {
                "statusCode": 204,
                "headers": {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Headers": "Content-Type",
                    "Access-Control-Allow-Methods": "POST,OPTIONS"
                },
                "body": ""
            }

        # ── Parse request body ──────────────────────────────
        body = event.get("body", {}) or {}
        if isinstance(body, str):
            body = json.loads(body) if body.strip() else {}
        if not isinstance(body, dict):
            raise ValueError("Request body must be a JSON object.")

        query_type = str(body.get("query_type", "latest")).lower()
        severity_filter = str(body.get("severity", "ALL")).upper()
        if severity_filter not in {"ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}:
            raise ValueError("Invalid severity filter.")
        try:
            limit = max(1, min(int(body.get("limit", 5)), 50))
        except (TypeError, ValueError):
            raise ValueError("limit must be an integer between 1 and 50.")

        print(f"Query Type   : {query_type}")
        print(f"Severity     : {severity_filter}")
        print(f"Limit        : {limit}")

        # ── Fetch CTI Data ───────────────────────────────────
        # Try NVD API first; fall back to demo data for reliable demo
        cve_data = fetch_cve_data(severity_filter, limit)

        # ── Process & Classify Threats ───────────────────────
        processed = process_threats(cve_data, severity_filter)

        # ── Summary stats ────────────────────────────────────
        summary = build_summary(processed)

        print(f"Threats processed  : {len(processed)}")
        print(f"Critical found     : {summary['critical_count']}")
        print(f"High found         : {summary['high_count']}")
        print(f"Processing complete: SUCCESS")

        # ── Return response to website ───────────────────────
        return {
            'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Methods': 'POST,OPTIONS'
            },
            'body': json.dumps({
                'status': 'success',
                'message': 'CTI data processed successfully by AWS Lambda',
                'query_type': query_type,
                'severity_filter': severity_filter,
                'processed_at': datetime.now(timezone.utc).replace(microsecond=0).isoformat() + 'Z',
                'processed_by': 'AWS Lambda (CTI-Data-Processor)',
                'summary': summary,
                'threats': processed
            })
        }

    except Exception as e:
        print(f"ERROR: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Methods': 'POST,OPTIONS'
            },
            'body': json.dumps({
                'status': 'error',
                'message': str(e)
            })
        }


def fetch_cve_data(severity_filter, limit):
    """
    Fetch CVE data from NVD API.
    Falls back to demo data if NVD is unavailable (for demo reliability).
    """
    print("Fetching CVE data from NVD API...")
    try:
        params = {"resultsPerPage": max(1, min(int(limit), 50)), "startIndex": 0}
        if severity_filter in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            params["cvssV3Severity"] = severity_filter
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={'User-Agent': 'CTI-Platform/1.0'})
        with urllib.request.urlopen(req, timeout=8) as response:
            data = json.loads(response.read())
            vulnerabilities = data.get('vulnerabilities', [])
            print(f"NVD API returned {len(vulnerabilities)} records")
            return vulnerabilities
    except Exception as e:
        print(f"NVD API unavailable ({e}) — using demo data for reliable testing")
        return get_demo_data()


def get_demo_data():
    """
    Realistic demo CVE data for reliable presentation demos.
    These mirror real NVD API response structure.
    """
    return [
        {
            'cve': {
                'id': 'CVE-2026-1001',
                'descriptions': [{'lang': 'en', 'value': 'Remote code execution vulnerability in OpenSSL allowing unauthenticated attackers to execute arbitrary code via crafted TLS packets.'}],
                'published': '2026-09-10T08:00:00.000',
                'metrics': {'cvssMetricV31': [{'cvssData': {'baseScore': 9.8, 'baseSeverity': 'CRITICAL'}}]}
            }
        },
        {
            'cve': {
                'id': 'CVE-2026-1002',
                'descriptions': [{'lang': 'en', 'value': 'SQL injection vulnerability in popular web framework allows privilege escalation and data exfiltration via crafted HTTP requests.'}],
                'published': '2026-09-09T12:00:00.000',
                'metrics': {'cvssMetricV31': [{'cvssData': {'baseScore': 8.6, 'baseSeverity': 'HIGH'}}]}
            }
        },
        {
            'cve': {
                'id': 'CVE-2026-1003',
                'descriptions': [{'lang': 'en', 'value': 'Cross-site scripting (XSS) in authentication module enables session hijacking and credential theft by injecting malicious scripts.'}],
                'published': '2026-09-08T09:30:00.000',
                'metrics': {'cvssMetricV31': [{'cvssData': {'baseScore': 7.2, 'baseSeverity': 'HIGH'}}]}
            }
        },
        {
            'cve': {
                'id': 'CVE-2026-1004',
                'descriptions': [{'lang': 'en', 'value': 'Improper input validation in Linux kernel network stack allows local privilege escalation.'}],
                'published': '2026-09-07T15:00:00.000',
                'metrics': {'cvssMetricV31': [{'cvssData': {'baseScore': 6.5, 'baseSeverity': 'MEDIUM'}}]}
            }
        },
        {
            'cve': {
                'id': 'CVE-2026-1005',
                'descriptions': [{'lang': 'en', 'value': 'Information disclosure in cloud storage API leaks sensitive metadata to authenticated users with read-only permissions.'}],
                'published': '2026-09-06T11:00:00.000',
                'metrics': {'cvssMetricV31': [{'cvssData': {'baseScore': 4.3, 'baseSeverity': 'MEDIUM'}}]}
            }
        }
    ]


def process_threats(vulnerabilities, severity_filter):
    """
    Process raw CVE data: extract fields, classify, filter by severity.
    This is the core 'automatic critical-threat processing' that Lambda performs.
    """
    processed = []

    for item in vulnerabilities:
        cve = item.get('cve', {})

        # Extract CVE ID
        cve_id = cve.get('id', 'UNKNOWN')

        # Extract description
        descriptions = cve.get('descriptions', [])
        description = next(
            (d['value'] for d in descriptions if d.get('lang') == 'en'),
            'No description available'
        )

        # Extract CVSS score and severity
        cvss_score = 0.0
        severity = 'UNKNOWN'
        metrics = cve.get('metrics', {})

        if metrics.get('cvssMetricV40'):
            cvss_data = metrics['cvssMetricV40'][0]['cvssData']
            cvss_score = cvss_data.get('baseScore', 0.0)
            severity = cvss_data.get('baseSeverity', 'UNKNOWN')
        elif metrics.get('cvssMetricV31'):
            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
            cvss_score = cvss_data.get('baseScore', 0.0)
            severity = cvss_data.get('baseSeverity', 'UNKNOWN')
        elif metrics.get('cvssMetricV30'):
            cvss_data = metrics['cvssMetricV30'][0]['cvssData']
            cvss_score = cvss_data.get('baseScore', 0.0)
            severity = cvss_data.get('baseSeverity', 'UNKNOWN')
        elif metrics.get('cvssMetricV2'):
            cvss_data = metrics['cvssMetricV2'][0]['cvssData']
            cvss_score = cvss_data.get('baseScore', 0.0)
            # Convert V2 score to severity label
            severity = classify_severity(cvss_score)

        severity = severity.upper()

        # Log each threat
        print(f"  CVE: {cve_id} | Severity: {severity} | CVSS: {cvss_score}")

        # Apply severity filter
        if severity_filter != 'ALL' and severity != severity_filter.upper():
            continue

        processed.append({
            'cve_id': cve_id,
            'severity': severity,
            'cvss_score': cvss_score,
            'description': description[:200] + '...' if len(description) > 200 else description,
            'published': cve.get('published', 'N/A')[:10],
            'risk_level': get_risk_level(severity),
            'action_required': get_action(severity)
        })

    return processed


def classify_severity(score):
    """Convert CVSS score to severity label."""
    if score >= 9.0:
        return 'CRITICAL'
    elif score >= 7.0:
        return 'HIGH'
    elif score >= 4.0:
        return 'MEDIUM'
    elif score > 0:
        return 'LOW'
    return 'UNKNOWN'


def get_risk_level(severity):
    return {
        'CRITICAL': 'IMMEDIATE ACTION REQUIRED',
        'HIGH': 'Action Required Within 24 Hours',
        'MEDIUM': 'Review Within 7 Days',
        'LOW': 'Monitor and Patch at Next Cycle'
    }.get(severity, 'Assess Manually')


def get_action(severity):
    return {
        'CRITICAL': 'Isolate affected systems immediately and apply emergency patch',
        'HIGH': 'Prioritise patching and review affected assets',
        'MEDIUM': 'Schedule patch in next maintenance window',
        'LOW': 'Log and include in next patch cycle'
    }.get(severity, 'Manual review required')


def build_summary(threats):
    """Build a stats summary for the dashboard."""
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
    for t in threats:
        sev = t.get('severity', 'UNKNOWN')
        counts[sev] = counts.get(sev, 0) + 1

    return {
        'total_threats': len(threats),
        'critical_count': counts['CRITICAL'],
        'high_count': counts['HIGH'],
        'medium_count': counts['MEDIUM'],
        'low_count': counts['LOW'],
        'highest_cvss': max((t['cvss_score'] for t in threats), default=0),
        'requires_immediate_action': counts['CRITICAL'] > 0
    }

# ---------------- DEMO CVE REMEDIATION ----------------
# Safe demo: this simulates remediation for one CVE without changing
# a real WordPress installation.
DEMO_CVE_ID = "CVE-2026-32558"
DEMO_PLUGIN = "Affiliate Pro - Affiliate Program for WooCommerce"
DEMO_AFFECTED_VERSION = "<= 8.9.1"
DEMO_FIXED_VERSION = "9.0.0 (demo target)"

# ---------------- GMAIL CVE INTAKE + NVD ENRICHMENT ----------------
CVE_RESULTS_FILE = "cve_results.json"
REMEDIATION_PLANS_FILE = "remediation_plans.json"
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Project-supplied advisory reference for the demonstrated CVE.
# This is a local mapping, not a live WPScan API integration.
ADVISORY_OVERRIDES = {
    "CVE-2026-14182": {
        "product": "Customer Email Verification for WooCommerce",
        "affected_version": "< 3.2.6",
        "fixed_version": "3.2.6",
        "advisory_url": (
            "https://wpscan.com/vulnerability/"
            "ef4e95a3-6f90-4423-9551-9ac28f7b6291/"
        ),
        "advisory_source": "Project-supplied WPScan advisory reference"
    }
}


def load_cve_results():
    try:
        with open(CVE_RESULTS_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
            return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def save_cve_results(records):
    with open(CVE_RESULTS_FILE, "w", encoding="utf-8") as file:
        json.dump(records, file, indent=2, ensure_ascii=False)


def decode_mime_header(value):
    if not value:
        return ""
    parts = decode_header(value)
    return "".join(
        part.decode(encoding or "utf-8", errors="replace")
        if isinstance(part, bytes) else part
        for part, encoding in parts
    )


def scan_gmail_cves():
    """Read CVE alert emails from Gmail without modifying their read status."""

    address = os.getenv("GMAIL_ADDRESS")
    app_password = os.getenv("GMAIL_APP_PASSWORD")

    print("GMAIL_ADDRESS loaded:", bool(address))
    print("GMAIL_APP_PASSWORD loaded:", bool(app_password))

    if not address or not app_password:
        raise RuntimeError(
            "Gmail environment variables are missing on the server."
        )

    found = {}

    found = {}

    with imaplib.IMAP4_SSL("imap.gmail.com", 993) as mailbox:
        mailbox.login(address, app_password)
        mailbox.select("INBOX", readonly=True)

        status, data = mailbox.search(
            None, '(OR SUBJECT "CVE" BODY "CVE-")'
        )
        if status != "OK":
            raise RuntimeError("Gmail search failed.")

        for message_id in data[0].split():
            status, message_data = mailbox.fetch(message_id, "(RFC822)")
            if status != "OK":
                continue

            raw_message = next(
                (
                    item[1] for item in message_data
                    if isinstance(item, tuple)
                ),
                None
            )
            if not raw_message:
                continue

            message = email.message_from_bytes(raw_message)
            subject = decode_mime_header(message.get("Subject", ""))
            body_parts = [subject]

            if message.is_multipart():
                for part in message.walk():
                    if (
                        part.get_content_type() == "text/plain"
                        and not part.get_filename()
                    ):
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_parts.append(
                                payload.decode(
                                    part.get_content_charset() or "utf-8",
                                    errors="replace"
                                )
                            )
            else:
                payload = message.get_payload(decode=True)
                if payload:
                    body_parts.append(
                        payload.decode(
                            message.get_content_charset() or "utf-8",
                            errors="replace"
                        )
                    )

            full_text = "\n".join(body_parts)
            for cve_id in set(
                item.upper() for item in CVE_PATTERN.findall(full_text)
            ):
                found.setdefault(cve_id, {
                    "cve_id": cve_id,
                    "email_subject": subject,
                    "email_sender": decode_mime_header(
                        message.get("From", "")
                    )
                })

        mailbox.logout()

    return list(found.values())


def lookup_nvd_cve(cve_id):
    """Retrieve CVE details from the public NVD API."""
    query = urllib.parse.urlencode({"cveId": cve_id})
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0?"
        + query
    )
    request_obj = urllib.request.Request(
        url,
        headers={"User-Agent": "CTI-Platform-CVE-Portal/1.0"}
    )

    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        request_obj.add_header("apiKey", api_key)

    with urllib.request.urlopen(request_obj, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))

    items = payload.get("vulnerabilities", [])
    if not items:
        return {
            "cve_id": cve_id,
            "severity": "UNKNOWN",
            "assessment": "NVD record not found."
        }

    cve = items[0].get("cve", {})
    description = next(
        (
            item.get("value", "")
            for item in cve.get("descriptions", [])
            if item.get("lang") == "en"
        ),
        ""
    )

    score = None
    severity = "UNKNOWN"
    metrics = cve.get("metrics", {})
    for metric_name in (
        "cvssMetricV40", "cvssMetricV31",
        "cvssMetricV30", "cvssMetricV2"
    ):
        metric_items = metrics.get(metric_name, [])
        if metric_items:
            metric = metric_items[0]
            cvss = metric.get("cvssData", {})
            score = cvss.get("baseScore")
            severity = (
                cvss.get("baseSeverity")
                or metric.get("baseSeverity")
                or severity
            )
            break

    return {
        "cve_id": cve_id,
        "description": description,
        "severity": str(severity).upper(),
        "cvss_score": score,
        "published": cve.get("published", ""),
        "references": [
            item.get("url")
            for item in cve.get("references", [])
            if item.get("url")
        ],
        "assessment": (
            "NVD details retrieved. Verify the affected product and "
            "version against the vendor advisory."
        )
    }


def process_gmail_cves():
    """Deduplicate CVE IDs, enrich records, and persist them for the portal."""
    previous = {
        record.get("cve_id"): record
        for record in load_cve_results()
        if record.get("cve_id")
    }
    records = []

    for email_record in scan_gmail_cves():
        cve_id = email_record["cve_id"]
        try:
            record = lookup_nvd_cve(cve_id)
        except Exception as error:
            record = {
                "cve_id": cve_id,
                "severity": "UNKNOWN",
                "assessment": "NVD lookup failed: " + str(error)
            }

        record.update(email_record)
        advisory = ADVISORY_OVERRIDES.get(cve_id)

        if advisory:
            record.update(advisory)
            record["assessment"] = (
                "Project-supplied advisory matched. Confirm the installed "
                "plugin and version before applying the update."
            )
            record["recommended_action"] = (
                "Back up and test compatibility, then update to "
                + advisory["fixed_version"] + " or later."
            )
        else:
            record.setdefault("product", "Not identified")
            record.setdefault("affected_version", "Not confirmed")
            record.setdefault("fixed_version", "Not confirmed")
            record["recommended_action"] = (
                "Review the vendor advisory and verify the affected "
                "product/version before applying a fix."
            )

        record["remediation_status"] = previous.get(
            cve_id, {}
        ).get("remediation_status", "REVIEW REQUIRED")
        record["last_seen_utc"] = datetime.now(
            timezone.utc
        ).isoformat()
        records.append(record)

    save_cve_results(records)
    return records


#Admin reference
ADMIN_REFERENCE = os.environ.get("ADMIN_REFERENCE")


# ---------------- USERS ----------------

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_users(users):
    with open(USERS_FILE, "w") as file:
        json.dump(users, file, indent=4)

def write_vulnerability_log(message):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(
        VULNERABILITY_LOG_FILE,
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            f"{timestamp} | {message}\n"
        )


# ---------------- AWS S3 THREAT DATA ----------------

def load_threats_from_s3():
    print("Trying to load threats from S3...")
    try:
        response = s3_client.get_object(
            Bucket=S3_BUCKET,
            Key=S3_KEY
        )

        content = response["Body"].read().decode("utf-8")
        print("S3 load successful")
        return json.loads(content)

    except Exception as error:
        print("S3 error:", error)
        return []


# ---------------- LOGIN PAGE ----------------

LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>CTI Platform Login</title>
</head>

<body>

    <h1>Cyber Threat Intelligence Platform</h1>
    <h2>Secure Login</h2>

    <form method="POST" action="/login">

        <input
            type="text"
            name="username"
            placeholder="Username"
            required
        >

        <br><br>

        <input
            type="password"
            name="password"
            placeholder="Password"
            required
        >

        <br><br>

        <button type="submit">Login</button>

    </form>

    <p>{{ message }}</p>

    <p>
        Don't have an account?
        <a href="/register">Register</a>
    </p>

</body>
</html>
"""


# ---------------- REGISTER PAGE ----------------

REGISTER_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Register - CTI Platform</title>
</head>

<body>

    <h1>Create CTI Account</h1>

    <form method="POST" action="/register">

        <input
            type="text"
            name="username"
            placeholder="Username"
            required
        >

        <br><br>

        <input
            type="password"
            name="password"
            placeholder="Password"
            required
        >

        <br><br>

        <label>Account Type:</label>

        <select name="role" id="role" required>
            <option value="client">Client</option>
            <option value="admin">Administrator</option>
        </select>

        <br><br>

        <div id="adminReferenceSection" style="display:none;">
          
             <label for="admin_reference">Enter Admin Reference:</label>

             <input
                type="password"
                name="admin_reference"
                id="admin_reference"
             >
             <br><br>
        </div>



        <button type="submit">Register</button>

    </form>

    <p>{{ message }}</p>

    <a href="/">Back to Login</a>

    <script>
        const roleSelect = document.getElementById("role");
        const adminReferenceSection =
             document.getElementById("adminReferenceSection");

        roleSelect.addEventListener("change", function () {
            if (this.value === "admin") {
                adminReferenceSection.style.display = "block";
            } else{
                 adminReferenceSection.style.display = "none";
            }

        });
    </script>

</body>
</html>
"""


# ---------------- PB-14 ADMIN PORTAL ----------------

ADMIN_HTML = """
<!DOCTYPE html>
<html>

<head>
    <title>Administrator Portal</title>
</head>

<body>

    <h1>CTI Administrator Portal</h1>

    <h2>Welcome, {{ username }}</h2>

    <p>Administrator login successful.</p>

    <hr>

    <h3>Platform Management</h3>

    <p>System Status: Online</p>
    <p>Threat Intelligence Service: Active</p>
    <p>Security Monitoring: Active</p>

    <hr>

    <h3>Critical CVE Detection</h3>

    <p>
        Scan the National Vulnerability Database for
        critical cybersecurity vulnerabilities.
    </p>

    <form method="POST" action="/scan-cves">

        <input
            type="hidden"
            name="username"
            value="{{ username }}"
        >

        <button type="submit">
            Run Critical CVE Scan
        </button>

    </form>

    {% if scan_message %}

        <p>
            <strong>{{ scan_message }}</strong>
        </p>

    {% endif %}

    {% if scan_results %}

        <hr>

        <h3>CVE Scan Results</h3>

        <p>
            <strong>Total CVEs Checked:</strong>
            {{ scan_results.total_checked }}
        </p>

        <p>
            <strong>New Critical Alerts Sent:</strong>
            {{ scan_results.new_alerts_sent }}
        </p>

        <p>
            <strong>Duplicate Alerts Skipped:</strong>
            {{ scan_results.duplicate_alerts_skipped }}
        </p>

    {% endif %}

<br><br>
    <hr>

    {% if cve_records %}
    <hr>
    <h3>Gmail CVE Alert Details</h3>
    <p>Unique CVEs found in Gmail alerts and enriched with NVD details.
       Recommendations require verification; this portal does not patch software.</p>
    {% for cve in cve_records %}
    <div style="border:1px solid #aaa;padding:12px;margin:12px 0;">
        <h4>{{ cve.cve_id }} — {{ cve.severity or 'UNKNOWN' }}
            (CVSS {{ cve.cvss_score if cve.cvss_score is not none else 'N/A' }})</h4>
        <p><strong>Product:</strong> {{ cve.product or 'Not identified' }}</p>
        <p><strong>Affected version:</strong> {{ cve.affected_version or 'Not confirmed' }}</p>
        <p><strong>Fixed version:</strong> {{ cve.fixed_version or 'Not confirmed' }}</p>
        <p><strong>Description:</strong> {{ cve.description or 'Unavailable' }}</p>
        <p><strong>Recommendation:</strong> {{ cve.recommended_action or 'Review vendor advisory.' }}</p>
        <p><strong>Assessment:</strong> {{ cve.assessment }}</p>
        <p><strong>Remediation status:</strong> {{ cve.remediation_status }}</p>
        {% if cve.advisory_url %}
        <p><a href="{{ cve.advisory_url }}" target="_blank" rel="noopener">View vendor advisory</a></p>
        {% endif %}
        {% if cve.references %}
        <p><strong>NVD references:</strong>
        {% for ref in cve.references[:3] %}
            <a href="{{ ref }}" target="_blank" rel="noopener">Reference {{ loop.index }}</a>{% if not loop.last %} | {% endif %}
        {% endfor %}
        </p>
        {% endif %}
        <form method="POST" action="/remediate-cve">
            <input type="hidden" name="username" value="{{ username }}">
            <input type="hidden" name="cve_id" value="{{ cve.cve_id }}">
            <button type="submit">Record remediation plan</button>
        </form>
    </div>
    {% endfor %}
    {% endif %}

    <h3>Automatic CVE Remediation (Demo)</h3>

    <p>
        This demo handles one critical CVE:
        <strong>{{ demo_cve_id }}</strong>
    </p>

    <p>
        <strong>Plugin:</strong> {{ demo_plugin }}
    </p>

    <p>
        <strong>Affected version:</strong> {{ demo_affected_version }}
    </p>

    <form method="POST" action="/remediate-cve">
        <input type="hidden" name="username" value="{{ username }}">
        <button type="submit">Run Automatic Remediation</button>
    </form>

    {% if remediation_message %}
        <p><strong>{{ remediation_message }}</strong></p>
    {% endif %}

    {% if remediation_result %}
        <hr>
        <h4>Remediation Result</h4>
        <p><strong>CVE:</strong> {{ remediation_result.cve_id }}</p>
        <p><strong>Plugin:</strong> {{ remediation_result.plugin }}</p>
        <p><strong>Action:</strong> {{ remediation_result.action }}</p>
        <p><strong>Status:</strong> {{ remediation_result.status }}</p>
        <p><strong>Target version:</strong> {{ remediation_result.target_version }}</p>
    {% endif %}

<br><br>

<hr>

<h3>Automated Vulnerability Monitoring</h3>

<p>
    Monitor newly published cybersecurity vulnerabilities
    from the National Vulnerability Database (NVD).
</p>

<form action="/vulnerability-monitor" method="get">
    <button type="submit">Open Vulnerability Monitor</button>
</form>

<br><br>

<hr>

<h3>Security Log Watch</h3>

<p>
    Central security monitoring for all CTI platform scenarios.
</p>

<form action="/log-watch" method="get">
    <button type="submit">Open Security Log Watch</button>
</form>

<br><br>

<a href="/">Logout</a>

</body>
</html>
"""


VULNERABILITY_MONITOR_HTML = """
<!DOCTYPE html>
<html>

<head>
    <title>Automated Vulnerability Monitoring</title>
</head>

<body>

    <h1>Automated Vulnerability Monitoring</h1>

    <h2>Welcome, {{ username }}</h2>

    <p>
        This function retrieves newly published cybersecurity
        vulnerabilities from the National Vulnerability Database (NVD).
    </p>

<br><br>

    <form action="/run-vulnerability-scan" method="get">
        <button type="submit">Run Vulnerability Scan</button>
    </form>

    <br><br>

    <a href="/admin">
        Back to Administrator Portal
    </a>

</body>

</html>
"""

VULNERABILITY_RESULT_HTML = """
<!DOCTYPE html>
<html>

<head>
    <title>Vulnerability Scan Result</title>
</head>

<body>

    <h1>Vulnerability Scan Result</h1>

    <p>
        <strong>Scan Time:</strong>
        {{ scan_time }}
    </p>

    <p>
        <strong>New Vulnerabilities Found:</strong>
        {{ total_vulnerabilities }}
    </p>

    <hr>

    <h3>Latest Vulnerabilities</h3>

    {% if vulnerabilities %}

        <table border="1" cellpadding="8">

            <tr>
                <th>CVE ID</th>
                <th>Published</th>
                <th>Description</th>
            </tr>

            {% for vulnerability in vulnerabilities %}

                <tr>
                    <td>{{ vulnerability.cve_id }}</td>
                    <td>{{ vulnerability.published }}</td>
                    <td>{{ vulnerability.description }}</td>
                </tr>

            {% endfor %}

        </table>

        <p>Showing the first 20 vulnerabilities.</p>

    {% else %}

        <p>No new vulnerabilities found.</p>

    {% endif %}

    <br><br>

        <form action="/run-vulnerability-scan" method="get">
            <button type="submit">Run Again</button>
        </form>

        <br>

        <form action="/admin" method="get">
            <button type="submit">Back to Administrator Portal</button>
        </form>

</body>

</html>
"""

# ---------------- PB-15 CLIENT PORTAL ----------------

CLIENT_HTML = """
<!DOCTYPE html>
<html>

<head>
    <title>Client Threat Portal</title>
</head>

<body>

    <h1>CTI Client Portal</h1>

    <h2>Welcome, {{ username }}</h2>

    <p>Client login successful.</p>

    <hr>

    <h3>Threat Intelligence Processing</h3>

    <p>
        Retrieve and process cybersecurity threat intelligence
        using AWS Lambda and the National Vulnerability Database (NVD).
    </p>

    <form action="/cti-dashboard" method="get">
        <button type="submit">
            Open Threat Intelligence Dashboard
        </button>
    </form>

    <br><br>

    <hr>

    <h3>Support Request</h3>

    <p>
        Submit a support request for cybersecurity assistance.
    </p>

    <form action="/support" method="get">
        <button type="submit">
            Open Support Request
        </button>
    </form>

    <br><br>

    <a href="/">Logout</a>

</body>
</html>
"""




# ---------------- SCENARIO 5 WEB DASHBOARD ----------------
# Embedded from the standalone Scenario 5 dashboard HTML.
CTI_DASHBOARD_HTML = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n<title>CTI Platform — Threat Intelligence</title>\n<style>\n  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }\n\n  body {\n    font-family: 'Segoe UI', system-ui, sans-serif;\n    background: #0b1120;\n    color: #c8d1dc;\n    min-height: 100vh;\n  }\n\n  /* ── Subtle grid bg ─── */\n  body::before {\n    content: '';\n    position: fixed;\n    inset: 0;\n    background:\n      linear-gradient(rgba(59,130,246,.03) 1px, transparent 1px),\n      linear-gradient(90deg, rgba(59,130,246,.03) 1px, transparent 1px);\n    background-size: 44px 44px;\n    pointer-events: none;\n    z-index: 0;\n  }\n\n  .page { position: relative; z-index: 1; max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem; }\n\n  /* ── Header ─── */\n  .header {\n    display: flex;\n    align-items: center;\n    gap: 1rem;\n    margin-bottom: 2rem;\n    padding-bottom: 1.25rem;\n    border-bottom: 1px solid #1e293b;\n  }\n  .logo {\n    background: rgba(59,130,246,.12);\n    border: 1px solid rgba(59,130,246,.25);\n    border-radius: 10px;\n    padding: .6rem .9rem;\n    font-size: .75rem;\n    font-weight: 700;\n    letter-spacing: .08em;\n    color: #3b82f6;\n    text-transform: uppercase;\n  }\n  .header h1 { font-size: 1.1rem; font-weight: 700; color: #e2e8f0; }\n  .header p  { font-size: .72rem; color: #64748b; }\n  .badge {\n    margin-left: auto;\n    background: rgba(34,197,94,.08);\n    border: 1px solid rgba(34,197,94,.2);\n    border-radius: 20px;\n    padding: .25rem .8rem;\n    font-size: .7rem;\n    color: #4ade80;\n    font-weight: 600;\n  }\n\n  /* ── Query panel ─── */\n  .query-panel {\n    background: #111827;\n    border: 1px solid #1e293b;\n    border-radius: 12px;\n    padding: 1.5rem;\n    margin-bottom: 1.5rem;\n  }\n  .query-panel h2 {\n    font-size: .8rem;\n    font-weight: 600;\n    text-transform: uppercase;\n    letter-spacing: .08em;\n    color: #64748b;\n    margin-bottom: 1rem;\n  }\n\n  .controls {\n    display: flex;\n    gap: 1rem;\n    flex-wrap: wrap;\n    align-items: flex-end;\n  }\n\n  .control-group { display: flex; flex-direction: column; gap: .3rem; }\n  .control-group label { font-size: .68rem; text-transform: uppercase; letter-spacing: .06em; color: #64748b; }\n\n  select {\n    padding: .55rem .8rem;\n    font-family: inherit;\n    font-size: .82rem;\n    color: #e2e8f0;\n    background: #0b1120;\n    border: 1px solid #1e293b;\n    border-radius: 6px;\n    outline: none;\n    cursor: pointer;\n    min-width: 160px;\n  }\n  select:focus { border-color: #3b82f6; }\n\n  .btn-fetch {\n    padding: .6rem 1.6rem;\n    font-family: inherit;\n    font-size: .82rem;\n    font-weight: 600;\n    color: #fff;\n    background: #3b82f6;\n    border: none;\n    border-radius: 6px;\n    cursor: pointer;\n    transition: background .2s, transform .1s;\n    white-space: nowrap;\n  }\n  .btn-fetch:hover { background: #2563eb; }\n  .btn-fetch:active { transform: scale(.97); }\n  .btn-fetch:disabled { background: #374151; color: #6b7280; cursor: not-allowed; transform: none; }\n\n  /* ── AWS flow indicator ─── */\n  .flow-bar {\n    display: flex;\n    align-items: center;\n    gap: .5rem;\n    flex-wrap: wrap;\n    margin-top: 1rem;\n    padding: .6rem .8rem;\n    background: rgba(59,130,246,.04);\n    border: 1px solid #1e293b;\n    border-radius: 6px;\n    font-size: .7rem;\n    color: #64748b;\n  }\n  .flow-step {\n    padding: .2rem .55rem;\n    border-radius: 4px;\n    font-weight: 600;\n    font-size: .68rem;\n  }\n  .flow-step.website { background: rgba(59,130,246,.12); color: #93c5fd; }\n  .flow-step.api     { background: rgba(124,58,237,.12); color: #c4b5fd; }\n  .flow-step.lambda  { background: rgba(234,88,12,.12);  color: #fdba74; }\n  .flow-step.result  { background: rgba(34,197,94,.12);  color: #4ade80; }\n  .flow-arrow { color: #374151; }\n\n  /* ── Status strip ─── */\n  #statusBar {\n    margin-top: 1rem;\n    padding: .6rem .8rem;\n    border-radius: 6px;\n    font-size: .75rem;\n    display: none;\n  }\n  #statusBar.loading { display: block; background: rgba(234,88,12,.06); border: 1px solid rgba(234,88,12,.2); color: #fdba74; }\n  #statusBar.success { display: block; background: rgba(34,197,94,.06); border: 1px solid rgba(34,197,94,.2); color: #4ade80; }\n  #statusBar.error   { display: block; background: rgba(239,68,68,.06); border: 1px solid rgba(239,68,68,.2); color: #fca5a5; }\n\n  /* ── Summary cards ─── */\n  .summary-grid {\n    display: grid;\n    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));\n    gap: 1rem;\n    margin-bottom: 1.5rem;\n  }\n  .summary-card {\n    background: #111827;\n    border: 1px solid #1e293b;\n    border-radius: 10px;\n    padding: 1rem;\n    text-align: center;\n  }\n  .summary-card .num {\n    font-size: 2rem;\n    font-weight: 700;\n    line-height: 1;\n    margin-bottom: .3rem;\n  }\n  .summary-card .lbl { font-size: .68rem; text-transform: uppercase; letter-spacing: .06em; color: #64748b; }\n  .summary-card.critical .num { color: #ef4444; }\n  .summary-card.high     .num { color: #f97316; }\n  .summary-card.medium   .num { color: #eab308; }\n  .summary-card.total    .num { color: #3b82f6; }\n\n  /* ── Threat cards ─── */\n  .threats-panel { display: flex; flex-direction: column; gap: .85rem; }\n  .threat-card {\n    background: #111827;\n    border: 1px solid #1e293b;\n    border-radius: 10px;\n    padding: 1.1rem 1.2rem;\n    display: grid;\n    grid-template-columns: auto 1fr auto;\n    gap: 1rem;\n    align-items: start;\n  }\n  .threat-card:hover { border-color: #334155; }\n\n  .sev-badge {\n    padding: .25rem .6rem;\n    border-radius: 5px;\n    font-size: .68rem;\n    font-weight: 700;\n    letter-spacing: .05em;\n    text-transform: uppercase;\n    white-space: nowrap;\n    margin-top: .15rem;\n  }\n  .sev-CRITICAL { background: rgba(239,68,68,.12);  color: #ef4444; border: 1px solid rgba(239,68,68,.2); }\n  .sev-HIGH     { background: rgba(249,115,22,.12); color: #f97316; border: 1px solid rgba(249,115,22,.2); }\n  .sev-MEDIUM   { background: rgba(234,179,8,.12);  color: #eab308; border: 1px solid rgba(234,179,8,.2); }\n  .sev-LOW      { background: rgba(34,197,94,.12);  color: #22c55e; border: 1px solid rgba(34,197,94,.2); }\n  .sev-UNKNOWN  { background: rgba(100,116,139,.12);color: #64748b; border: 1px solid #334155; }\n\n  .threat-body .cve-id { font-size: .85rem; font-weight: 700; color: #e2e8f0; margin-bottom: .3rem; }\n  .threat-body .desc   { font-size: .75rem; color: #94a3b8; line-height: 1.5; margin-bottom: .5rem; }\n  .threat-body .action { font-size: .7rem; color: #60a5fa; }\n\n  .threat-meta { text-align: right; }\n  .cvss-score {\n    font-size: 1.5rem;\n    font-weight: 700;\n    line-height: 1;\n  }\n  .cvss-label { font-size: .62rem; color: #64748b; text-transform: uppercase; letter-spacing: .05em; }\n  .pub-date   { font-size: .65rem; color: #475569; margin-top: .4rem; }\n\n  /* ── CloudWatch log strip ─── */\n  .log-panel {\n    background: #0d1117;\n    border: 1px solid #1e293b;\n    border-radius: 10px;\n    padding: 1rem;\n    margin-top: 1.5rem;\n    font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;\n  }\n  .log-panel h3 {\n    font-size: .65rem;\n    text-transform: uppercase;\n    letter-spacing: .08em;\n    color: #4b5563;\n    margin-bottom: .6rem;\n    font-family: 'Segoe UI', sans-serif;\n  }\n  .log-line {\n    font-size: .68rem;\n    padding: .18rem 0;\n    color: #4ade80;\n    border-bottom: 1px solid #111827;\n  }\n  .log-line .ts  { color: #374151; margin-right: .5rem; }\n  .log-line.warn { color: #fbbf24; }\n  .log-line.info { color: #60a5fa; }\n\n  /* ── Footer ─── */\n  .footer {\n    margin-top: 2rem;\n    padding-top: 1rem;\n    border-top: 1px solid #1e293b;\n    text-align: center;\n    font-size: .65rem;\n    color: #374151;\n  }\n\n  @media (max-width: 600px) {\n    .threat-card { grid-template-columns: 1fr; }\n    .threat-meta { text-align: left; }\n  }\n</style>\n</head>\n<body>\n<div class=\"page\">\n\n  <!-- ── Header ──────────────────────────────── -->\n  <div class=\"header\">\n    <div class=\"logo\">CTI</div>\n    <div>\n      <h1>Threat Intelligence Dashboard</h1>\n      <p>Cloud-Based CTI Platform &mdash; Scenario 5: AWS API Gateway + Lambda Processing</p>\n    </div>\n    <div class=\"badge\">&#x25CF; AWS Connected</div>\n  </div>\n\n  <!-- ── Query Panel ─────────────────────────── -->\n  <div class=\"query-panel\">\n    <h2>Query CTI Data via AWS</h2>\n\n    <div class=\"controls\">\n      <div class=\"control-group\">\n        <label>Severity Filter</label>\n        <select id=\"severityFilter\">\n          <option value=\"ALL\">All Severities</option>\n          <option value=\"CRITICAL\">Critical Only</option>\n          <option value=\"HIGH\">High Only</option>\n          <option value=\"MEDIUM\">Medium Only</option>\n          <option value=\"LOW\">Low Only</option>\n        </select>\n      </div>\n      <div class=\"control-group\">\n        <label>Results Limit</label>\n        <select id=\"limitSelect\">\n          <option value=\"5\">5 threats</option>\n          <option value=\"10\">10 threats</option>\n          <option value=\"3\">3 threats</option>\n        </select>\n      </div>\n      <button class=\"btn-fetch\" id=\"fetchBtn\" onclick=\"fetchCTIData()\">\n        &#x2601; Fetch &amp; Process CTI Data\n      </button>\n    </div>\n\n    <!-- AWS flow diagram -->\n    <div class=\"flow-bar\">\n      <span>Data Flow:</span>\n      <span class=\"flow-step website\">CTI Website</span>\n      <span class=\"flow-arrow\">&#x2192;</span>\n      <span class=\"flow-step api\">API Gateway</span>\n      <span class=\"flow-arrow\">&#x2192;</span>\n      <span class=\"flow-step lambda\">&#x03BB; Lambda</span>\n      <span class=\"flow-arrow\">&#x2192;</span>\n      <span class=\"flow-step result\">Results Returned</span>\n    </div>\n\n    <div id=\"statusBar\"></div>\n  </div>\n\n  <!-- ── Summary Cards ───────────────────────── -->\n  <div class=\"summary-grid\" id=\"summaryGrid\" style=\"display:none;\">\n    <div class=\"summary-card total\">\n      <div class=\"num\" id=\"sumTotal\">0</div>\n      <div class=\"lbl\">Total Threats</div>\n    </div>\n    <div class=\"summary-card critical\">\n      <div class=\"num\" id=\"sumCritical\">0</div>\n      <div class=\"lbl\">Critical</div>\n    </div>\n    <div class=\"summary-card high\">\n      <div class=\"num\" id=\"sumHigh\">0</div>\n      <div class=\"lbl\">High</div>\n    </div>\n    <div class=\"summary-card medium\">\n      <div class=\"num\" id=\"sumMedium\">0</div>\n      <div class=\"lbl\">Medium</div>\n    </div>\n  </div>\n\n  <!-- ── Threat Results ──────────────────────── -->\n  <div class=\"threats-panel\" id=\"threatsPanel\"></div>\n\n  <!-- ── Lambda Log Viewer ───────────────────── -->\n  <div class=\"log-panel\" id=\"logPanel\" style=\"display:none;\">\n    <h3>&#x1F4CA; Lambda Execution Log (CloudWatch)</h3>\n    <div id=\"logLines\"></div>\n  </div>\n\n  <div class=\"footer\">\n    BIT303 Capstone Project &mdash; CTI Platform &mdash; Scenario 5: AWS API Gateway + Lambda &mdash; 2026\n  </div>\n</div>\n\n<script>\n// ============================================================\n//  UPDATE THIS WITH YOUR API GATEWAY INVOKE URL\n// ============================================================\nconst API_ENDPOINT = '{{ api_endpoint }}';\n// ============================================================\n\nconst statusBar    = document.getElementById('statusBar');\nconst fetchBtn     = document.getElementById('fetchBtn');\nconst summaryGrid  = document.getElementById('summaryGrid');\nconst threatsPanel = document.getElementById('threatsPanel');\nconst logPanel     = document.getElementById('logPanel');\nconst logLines     = document.getElementById('logLines');\n\nfunction ts() {\n  return new Date().toLocaleTimeString('en-AU', { hour12: false });\n}\n\nfunction addLog(msg, type = '') {\n  const line = document.createElement('div');\n  line.className = 'log-line ' + type;\n  line.innerHTML = `<span class=\"ts\">[${ts()}]</span>${msg}`;\n  logLines.appendChild(line);\n  logPanel.style.display = 'block';\n}\n\nfunction setStatus(msg, type) {\n  statusBar.textContent = msg;\n  statusBar.className = type;\n}\n\nfunction cvssColor(score) {\n  if (score >= 9) return '#ef4444';\n  if (score >= 7) return '#f97316';\n  if (score >= 4) return '#eab308';\n  return '#22c55e';\n}\n\nasync function fetchCTIData() {\n  const severity = document.getElementById('severityFilter').value;\n  const limit    = document.getElementById('limitSelect').value;\n\n  // Reset UI\n  threatsPanel.innerHTML = '';\n  logLines.innerHTML = '';\n  summaryGrid.style.display = 'none';\n  logPanel.style.display = 'none';\n  fetchBtn.disabled = true;\n  fetchBtn.textContent = 'Processing...';\n\n  setStatus('Sending request to AWS API Gateway...', 'loading');\n  addLog('CTI data request initiated by Security Analyst', 'info');\n  addLog(`Query: severity=${severity}, limit=${limit}`, 'info');\n  addLog('POST request sent to Amazon API Gateway...', '');\n\n  try {\n    const response = await fetch(API_ENDPOINT, {\n      method: 'POST',\n      headers: { 'Content-Type': 'application/json' },\n      body: JSON.stringify({ query_type: 'latest', severity: severity, limit: parseInt(limit) })\n    });\n\n    const data = await response.json();\n\n    if (!response.ok) throw new Error(data.message || 'Lambda returned error');\n\n    addLog('API Gateway forwarded request to AWS Lambda', '');\n    addLog('Lambda function CTI-Data-Processor executing...', '');\n    addLog(`Lambda fetched ${data.threats.length} CVE records`, '');\n    addLog(`Severity processing complete — Critical: ${data.summary.critical_count}, High: ${data.summary.high_count}`, data.summary.critical_count > 0 ? 'warn' : '');\n    addLog('Results returned to CTI website via API Gateway ✔', 'info');\n\n    setStatus(`✅ AWS Lambda processed ${data.summary.total_threats} threats — returned to website via API Gateway`, 'success');\n\n    renderSummary(data.summary);\n    renderThreats(data.threats);\n\n  } catch (err) {\n    setStatus('❌ Error: ' + err.message, 'error');\n    addLog('ERROR: ' + err.message, 'warn');\n    console.error(err);\n  } finally {\n    fetchBtn.disabled = false;\n    fetchBtn.textContent = '☁ Fetch & Process CTI Data';\n  }\n}\n\nfunction renderSummary(s) {\n  document.getElementById('sumTotal').textContent    = s.total_threats;\n  document.getElementById('sumCritical').textContent = s.critical_count;\n  document.getElementById('sumHigh').textContent     = s.high_count;\n  document.getElementById('sumMedium').textContent   = s.medium_count;\n  summaryGrid.style.display = 'grid';\n}\n\nfunction renderThreats(threats) {\n  if (threats.length === 0) {\n    threatsPanel.innerHTML = `<div style=\"text-align:center;color:#64748b;padding:2rem;\">No threats matched the selected filter.</div>`;\n    return;\n  }\n\n  threats.forEach(t => {\n    const card = document.createElement('div');\n    card.className = 'threat-card';\n    card.innerHTML = `\n      <div>\n        <div class=\"sev-badge sev-${t.severity}\">${t.severity}</div>\n      </div>\n      <div class=\"threat-body\">\n        <div class=\"cve-id\">${t.cve_id}</div>\n        <div class=\"desc\">${t.description}</div>\n        <div class=\"action\">&#x26A0; ${t.action_required}</div>\n      </div>\n      <div class=\"threat-meta\">\n        <div class=\"cvss-score\" style=\"color:${cvssColor(t.cvss_score)}\">${t.cvss_score.toFixed(1)}</div>\n        <div class=\"cvss-label\">CVSS Score</div>\n        <div class=\"pub-date\">Published<br>${t.published}</div>\n      </div>\n    `;\n    threatsPanel.appendChild(card);\n  });\n}\n</script>\n</body>\n</html>\n"

@app.route("/cti-dashboard")
def cti_dashboard():
    if session.get("role") not in {"admin", "client"}:
        return redirect(url_for("home"))
    return render_template_string(CTI_DASHBOARD_HTML, api_endpoint=url_for("cti_api"))

@app.route("/api/cti", methods=["POST", "OPTIONS"])
def cti_api():
    """Local bridge: the dashboard calls the merged Lambda handler."""
    event = {
        "httpMethod": request.method,
        "body": request.get_data(as_text=True) if request.method == "POST" else "",
        "headers": dict(request.headers),
    }
    result = lambda_handler(event, None)
    response = app.response_class(
        response=result.get("body", ""),
        status=result.get("statusCode", 500),
        mimetype="application/json"
    )
    for key, value in result.get("headers", {}).items():
        response.headers[key] = value
    return response

# ---------------- HOME ----------------

@app.route("/")
def home():
    return render_template_string(
        LOGIN_HTML,
        message=""
    )


# ---------------- CLIENT PORTAL ----------------

@app.route("/client")
def client_portal():

    if session.get("role") != "client":
        return redirect(url_for("home"))

    return render_template_string(
        CLIENT_HTML,
        username=session["username"],
    )

# ---------------- ADMIN PORTAL ----------------

@app.route("/admin")
def admin_portal():

    if "role" not in session:
        return redirect(url_for("home"))

    if session.get("role") != "admin":

        import urllib.request
        import urllib.parse

        try:
            params = urllib.parse.urlencode({
            "role": session.get("role", "unknown"),
            "requested_page": "admin"
            })

            alert_url = (
                "https://ym8icbwmok.execute-api.us-east-1.amazonaws.com/"
                "default/UnauthorizedAccessCheck?"
                +params
            )

            urllib.request.urlopen(alert_url, timeout=10)

        except Exception as error:
             print("Unauthorized access alert error:", error)

             
        return "Unauthorized access.", 403

    return render_template_string(
    ADMIN_HTML,
    username=session["username"],
    scan_message="",
    scan_results=None,
    cve_records=load_cve_results(),
    demo_cve_id=DEMO_CVE_ID,
    demo_plugin=DEMO_PLUGIN,
    demo_affected_version=DEMO_AFFECTED_VERSION,
    remediation_message="",
    remediation_result=None
)

# ---------------- AUTOMATED VULNERABILITY MONITOR ----------------

@app.route("/vulnerability-monitor")
def vulnerability_monitor():

    if session.get("role") != "admin":
        return redirect(url_for("home"))

    return render_template_string(
        VULNERABILITY_MONITOR_HTML
    )

@app.route("/run-vulnerability-scan")
def run_vulnerability_scan():

    if session.get("role") != "admin":
        return redirect(url_for("home"))

    try:
        import urllib.request

        api_url = "https://5jnc268wm1.execute-api.us-east-1.amazonaws.com/default/Daily-Vulunerability-Monitor"

        with urllib.request.urlopen(
            api_url,
            timeout=30
        ) as response:

            response_data = json.loads(
                response.read().decode("utf-8")
            )

        if "body" in response_data:
            body = response_data["body"]

            if isinstance(body, str):
                body = json.loads(body)

        else:
            body = response_data


        total_vulnerabilities = body.get(
            "new_vulnerabilities",
            0
        )

        scan_time = body.get(
            "scan_time",
            "Unknown"
        )


        write_vulnerability_log(
            f"Automated vulnerability monitoring completed | "
            f"Source: NVD | "
            f"New vulnerabilities: {total_vulnerabilities}"
        )


        vulnerabilities = body.get(
            "vulnerabilities",
            []
        )

        vulnerabilities = vulnerabilities[:20]


        return render_template_string(
            VULNERABILITY_RESULT_HTML,
            total_vulnerabilities=total_vulnerabilities,
            scan_time=scan_time,
            vulnerabilities=vulnerabilities
        )


    except Exception as error:

        return f"Error: {error}"


# ---------------- SECURITY LOG WATCH ----------------
@app.route("/log-watch")
def log_watch():
    if session.get("role") != "admin":
        return redirect(url_for("home"))

    log_events = []
    log_error = None
    scenario2_events = []
    scenario2_error = None
    scenario3_events = []
    scenario3_error = None

    try:
        streams_response = logs_client.describe_log_streams(
            logGroupName="/aws/lambda/CTI-Failed-Login-Alert",
            orderBy="LastEventTime",
            descending=True,
            limit=1
        )
        streams = streams_response.get("logStreams", [])
        if streams:
            latest_stream = streams[0]["logStreamName"]
            response = logs_client.get_log_events(
                logGroupName="/aws/lambda/CTI-Failed-Login-Alert",
                logStreamName=latest_stream,
                startFromHead=True
            )
            for event in response.get("events", []):
                timestamp_ms = event.get("timestamp", 0)
                readable_time = datetime.fromtimestamp(timestamp_ms / 1000).strftime("%Y-%m-%d %H:%M:%S")
                message = event.get("message", "").strip()
                if any(marker in message for marker in (
                    "CTI SECURITY LOG", "Timestamp:", "Scenario:", "Username:",
                    "Failed Attempts:", "Severity:", "Event:", "Action:",
                    "SNS Status:", "Log Status:"
                )):
                    log_events.append({"timestamp": readable_time, "message": message})
    except Exception as error:
        log_error = str(error)
        print("CloudWatch Log Watch error:", error)

    try:
        if os.path.exists(VULNERABILITY_LOG_FILE):
            with open(VULNERABILITY_LOG_FILE, "r", encoding="utf-8") as file:
                lines = file.readlines()
            for line in reversed(lines[-20:]):
                line = line.strip()
                if " | " in line:
                    timestamp, message = line.split(" | ", 1)
                    scenario2_events.append({"timestamp": timestamp, "message": message})
    except Exception as error:
        scenario2_error = str(error)
        print("Scenario 2 Log File Error:", error)

    LOG_WATCH_HTML = """
<!DOCTYPE html>
<html>
<head><title>CTI Security Log Watch</title></head>
<body>
<h1>CTI Security Log Watch</h1>
<h2>Central Security Monitoring</h2>
<p>This dashboard monitors security events generated by the CTI platform scenarios.</p>
<hr>
<h3>Scenario 1 - Failed Login Detection</h3>
<p><strong>Status:</strong> Active</p>
<p><strong>Severity:</strong> High</p>
<p><strong>Detection:</strong> Multiple failed login attempts</p>
<p><strong>Action:</strong> SNS security alert triggered</p>
<p><strong>CloudWatch Logging:</strong> Active</p>
<h3>Live CloudWatch Security Logs</h3>
{% if log_error %}<p><strong>CloudWatch Error:</strong> {{ log_error }}</p>
{% elif log_events %}<table border="1" cellpadding="8"><tr><th>Time</th><th>Security Event</th></tr>{% for log in log_events %}<tr><td>{{ log.timestamp }}</td><td>{{ log.message }}</td></tr>{% endfor %}</table>
{% else %}<p>No Scenario 1 security logs found.</p>{% endif %}
<hr>
<h3>Scenario 2 - Automated Vulnerability Monitoring</h3>
<p><strong>Status:</strong> Active</p>
<p><strong>Data Source:</strong> National Vulnerability Database (NVD)</p>
<p><strong>Monitoring:</strong> Newly published vulnerabilities</p>
<p><strong>CloudWatch Logging:</strong> Active</p>
<h3>Vulnerability Monitor Logs</h3>
{% if scenario2_error %}<p><strong>Log Error:</strong> {{ scenario2_error }}</p>
{% elif scenario2_events %}<table border="1" cellpadding="8"><tr><th>Time</th><th>Event</th></tr>{% for log in scenario2_events %}<tr><td>{{ log.timestamp }}</td><td>{{ log.message }}</td></tr>{% endfor %}</table>
{% else %}<p>No Scenario 2 logs found.</p>{% endif %}
<hr>
<h3>Scenario 3 - Critical CVE Detection</h3>
<p><strong>Status:</strong> Active</p>
<p><strong>Severity:</strong> Critical</p>
<p><strong>Data Source:</strong> National Vulnerability Database (NVD)</p>
<p><strong>Detection:</strong> Critical CVEs detected</p>
<p><strong>CloudWatch Logging:</strong> Active</p>
<h3>Critical CVE Detection Logs</h3>
{% if scenario3_error %}<p><strong>Log Error:</strong> {{ scenario3_error }}</p>
{% elif scenario3_events %}<table border="1" cellpadding="8"><tr><th>Time</th><th>Event</th></tr>{% for log in scenario3_events %}<tr><td>{{ log.timestamp }}</td><td>{{ log.message }}</td></tr>{% endfor %}</table>
{% else %}<p>No Scenario 3 Critical CVE logs found.</p>{% endif %}
<hr>
<h3>Scenario 4</h3><p><strong>Status:</strong> Pending Log Watch connection</p>
<hr>
<h3>Scenario 5 - CTI Threat Processing</h3><p><strong>Status:</strong> AWS Lambda CTI processor included in this application.</p>
<hr>
<p><strong>Overall Monitoring Status:</strong> Active</p>
<br><a href="/admin">Back to Administrator Portal</a>
</body>
</html>
"""

    return render_template_string(
        LOG_WATCH_HTML,
        log_events=log_events,
        log_error=log_error,
        scenario2_events=scenario2_events,
        scenario2_error=scenario2_error,
        scenario3_events=scenario3_events,
        scenario3_error=scenario3_error
    )
# ---------------- REGISTER ROUTE ----------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "GET":
        return render_template_string(
            REGISTER_HTML,
            message=""
        )

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "client").strip().lower()

    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,50}", username):
        return render_template_string(REGISTER_HTML, message="Username must be 3-50 characters and use letters, numbers, dots, underscores or hyphens.")
    if len(password) < 8:
        return render_template_string(REGISTER_HTML, message="Password must be at least 8 characters.")
    if role not in {"client", "admin"}:
        return render_template_string(REGISTER_HTML, message="Invalid account type.")

    if role == "admin":
         admin_reference = request.form.get("admin_reference", "")



         if not ADMIN_REFERENCE or admin_reference != ADMIN_REFERENCE:
             return render_template_string(
                 REGISTER_HTML,
                 message="Invalid Admin Reference."
             )

    users = load_users()

    if username in users:
        return render_template_string(
            REGISTER_HTML,
            message="Username already exists."
        )

    hashed_password = generate_password_hash(password)

    users[username] = {
        "password": hashed_password,
        "role": role
    }

    save_users(users)

    return redirect(url_for("home"))


# ---------------- LOGIN ROUTE ----------------

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    users = load_users()

    user = users.get(username)
    if user and check_password_hash(user.get("password", ""), password):
        session.clear()
        session["username"] = username
        session["role"] = user.get("role", "client")
        session["failed_attempts"] = 0
        return redirect(url_for("admin_portal" if session["role"] == "admin" else "client_portal"))

    attempts = int(session.get("failed_attempts", 0)) + 1
    session["failed_attempts"] = attempts
    if attempts >= 3:
        payload = {"username": username or "unknown", "failed_attempts": attempts, "severity": "High"}
        try:
            lambda_client.invoke(FunctionName="CTI-Failed-Login-Alert", InvocationType="Event", Payload=json.dumps(payload).encode("utf-8"))
        except Exception as error:
            print("AWS Lambda error:", error)
        session["failed_attempts"] = 0
        return render_template_string(LOGIN_HTML, message="Security Alert: Multiple failed login attempts detected!")

    return render_template_string(LOGIN_HTML, message=f"Invalid login. Failed attempt {attempts}/3")


# ---------------- SUPPORT REQUEST ----------------

@app.route("/support")
def support():
    try:
        return render_template("support.html")
    except Exception:
        return "<h1>Support</h1><p>Support page template is not installed.</p>"


# ---------------- SCENARIO 3: CRITICAL CVE SCAN ----------------

@app.route("/scan-cves", methods=["POST"])
def scan_cves():
    if session.get("role") != "admin":
        return redirect(url_for("home"))
    username = session.get("username", "Administrator")

    try:
        # Keep the existing Lambda scan, SNS notification and DynamoDB deduplication.
        lambda_url = (
            "https://kvuo36cwp7v7jpn2jn5u2c4ao40ysvlm."
            "lambda-url.us-east-1.on.aws/"
        )
        with urllib.request.urlopen(lambda_url, timeout=60) as response:
            response_payload = json.loads(
                response.read().decode("utf-8")
            )

        if "statusCode" in response_payload:
            if response_payload["statusCode"] != 200:
                raise RuntimeError("AWS Lambda CVE scan returned an error.")
            scan_results = response_payload.get("body", {})
            if isinstance(scan_results, str):
                scan_results = json.loads(scan_results)
        else:
            scan_results = response_payload

        if "total_checked" not in scan_results:
            scan_results["total_checked"] = len(
                scan_results.get("vulnerabilities", [])
            )

        # Additionally scan Gmail alert emails, deduplicate, enrich via NVD,
        # and persist records for display on the admin portal.
        cve_records = process_gmail_cves()

        return render_template_string(
            ADMIN_HTML,
            username=username,
            scan_message=(
                f"Scan completed. {len(cve_records)} unique CVEs "
                "processed from Gmail alert emails."
            ),
            scan_results=scan_results,
            cve_records=cve_records,
            demo_cve_id=DEMO_CVE_ID,
            demo_plugin=DEMO_PLUGIN,
            demo_affected_version=DEMO_AFFECTED_VERSION,
            remediation_message="",
            remediation_result=None
        )

    except Exception as error:
        print("CVE scan error:", error)
        return render_template_string(
            ADMIN_HTML,
            username=username,
            scan_message="CVE Scan Error: " + str(error),
            scan_results=None,
            cve_records=load_cve_results(),
            demo_cve_id=DEMO_CVE_ID,
            demo_plugin=DEMO_PLUGIN,
            demo_affected_version=DEMO_AFFECTED_VERSION,
            remediation_message="",
            remediation_result=None
        )


# ---------------- DEMO: AUTOMATIC CVE REMEDIATION ----------------

@app.route("/remediate-cve", methods=["POST"])
def remediate_cve():
    """Persist a remediation plan; this route does not patch software."""
    if session.get("role") != "admin":
        return redirect(url_for("home"))
    username = session.get("username", "Administrator")
    cve_id = request.form.get("cve_id", DEMO_CVE_ID).strip().upper()
    records = load_cve_results()
    record = next((item for item in records if item.get("cve_id", "").upper() == cve_id), None)

    if record is None:
        message = "CVE not found in saved Gmail scan results. Run the Critical CVE Scan first."
        remediation_result = None
    else:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        plan = {
            "plan_id": f"{cve_id}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
            "cve_id": cve_id,
            "product": record.get("product") or "Unknown — verify affected asset",
            "affected_version": record.get("affected_version") or "Unknown — verify installed version",
            "fixed_version": record.get("fixed_version") or "Not confirmed — review vendor advisory",
            "action": record.get("recommended_action") or "Review vendor advisory and verify applicability before patching.",
            "status": "PLAN RECORDED — MANUAL REVIEW / PATCH REQUIRED",
            "created_at": now,
            "created_by": username,
            "execution": "PLAN ONLY — no software was changed"
        }

        # Keep a durable, separate history of remediation plans.
        try:
            plans = json.loads(Path(REMEDIATION_PLANS_FILE).read_text(encoding="utf-8")) if Path(REMEDIATION_PLANS_FILE).exists() else []
            if not isinstance(plans, list):
                plans = []
        except (OSError, json.JSONDecodeError):
            plans = []
        plans.append(plan)
        Path(REMEDIATION_PLANS_FILE).write_text(json.dumps(plans, indent=2, ensure_ascii=False), encoding="utf-8")

        # Also update the CVE result shown in the dashboard.
        record["remediation_status"] = plan["status"]
        record["remediation_action"] = plan["action"]
        record["remediation_plan_created_at"] = now
        record["remediation_plan_file"] = REMEDIATION_PLANS_FILE
        save_cve_results(records)

        message = f"Remediation plan saved to {REMEDIATION_PLANS_FILE}. No software was changed; manual review and patching are still required."
        remediation_result = {
            "cve_id": cve_id,
            "plugin": plan["product"],
            "action": plan["action"],
            "status": plan["status"],
            "target_version": plan["fixed_version"]
        }

    return render_template_string(
        ADMIN_HTML,
        username=username,
        scan_message="",
        scan_results=None,
        cve_records=records,
        demo_cve_id=DEMO_CVE_ID,
        demo_plugin=DEMO_PLUGIN,
        demo_affected_version=DEMO_AFFECTED_VERSION,
        remediation_message=message,
        remediation_result=remediation_result
    )


# ---------------- RUN APP ----------------

if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")), debug=False)
