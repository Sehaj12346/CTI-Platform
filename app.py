import boto3
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
import imaplib
import email
import urllib.request
import urllib.parse
from email.header import decode_header
from dotenv import load_dotenvimport boto3
import json
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

from flask import Flask, request, render_template_string, render_template,redirect, url_for,session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'local-demo-change-me')
app.secret_key = os.environ.get("SECRET_KEY")

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

    if not address or not app_password:

load_dotenv()

from flask import Flask, request, render_template_string, render_template,redirect, url_for,session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'local-demo-change-me')
app.secret_key = os.environ.get("SECRET_KEY")

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

    if not address or not app_password:
        raise RuntimeError(
            "Set GMAIL_ADDRESS and GMAIL_APP_PASSWORD in your local .env file."
        )

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

    with open(USERS_FILE, "r") as file:
        return json.load(file)


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

    <h1>Cybersecurity Threat Intelligence</h1>

    <h2>Welcome, {{ username }}</h2>

    <p>Latest published cybersecurity threats from AWS S3:</p>

    <hr>

    {% if threats %}

        {% for threat in threats %}

            <h3>{{ loop.index }}. {{ threat.title }}</h3>

            <p>
                <strong>Severity:</strong>
                {{ threat.severity }}
            </p>

            <p>{{ threat.description }}</p>

            <hr>

        {% endfor %}

    {% else %}

        <p>No threat data is currently available.</p>

    {% endif %}

    <p>
        PB-15: Clients can view published cybersecurity threats
        and stay informed about current risks.
    </p>

    <br>

    <br><br>

    <a href="/support">Support Request</a>

<br><br>
    

    <a href="/">Logout</a>

</body>
</html>
"""


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

    threats = load_threats_from_s3()

    return render_template_string(
        CLIENT_HTML,
        username=session["username"],
        threats=threats
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

            events = response.get("events", [])

            for event in events:
                timestamp_ms = event.get("timestamp", 0)

                readable_time = datetime.fromtimestamp(
                    timestamp_ms / 1000
                ).strftime("%Y-%m-%d %H:%M:%S")

                message = event.get("message", "").strip()

                if (
                    "CTI SECURITY LOG" in message
                    or "Timestamp:" in message
                    or "Scenario:" in message
                    or "Username:" in message
                    or "Failed Attempts:" in message
                    or "Severity:" in message
                    or "Event:" in message
                    or "Action:" in message
                    or "SNS Status:" in message
                    or "Log Status:" in message
                ):
                    log_events.append({
                        "timestamp": readable_time,
                        "message": message
                    })

    except Exception as error:
        log_error = str(error)
        print("CloudWatch Log Watch error:", error)




    # ---------------- SCENARIO 2: VULNERABILITY MONITOR LOGS ----------------

    try:

        if os.path.exists(VULNERABILITY_LOG_FILE):

            with open(
                VULNERABILITY_LOG_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                lines = file.readlines()

            # Show the latest 20 log records
            for line in reversed(lines[-20:]):
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
    username = request.form.get("username", "Administrator")
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
    app.run(debug=True)


                line = line.strip()

                if " | " in line:

                    timestamp, message = line.split(
                        " | ",
                        1
                    )

                    scenario2_events.append({
                        "timestamp": timestamp,
                        "message": message
                    })

    except Exception as error:

        scenario2_error = str(error)

        print(
            "Scenario 2 Log File Error:",
            error
        )

    LOG_WATCH_HTML = """

    <!DOCTYPE html>
    <html>

        <head>
            <title>CTI Security Log Watch</title>
        </head>

        <body>

            <h1>CTI Security Log Watch</h1>

            <h2>Central Security Monitoring</h2>

            <p>
                This dashboard monitors security events generated
                by the CTI platform scenarios.
            </p>

            <hr>

            <h3>Scenario 1 - Failed Login Detection</h3>

            <p><strong>Status:</strong> Active</p>
            <p><strong>Severity:</strong> High</p>
            <p><strong>Detection:</strong> Multiple failed login attempts</p>
            <p><strong>Action:</strong> SNS security alert triggered</p>
            <p><strong>CloudWatch Logging:</strong> Active</p>

            <h3>Live CloudWatch Security Logs</h3>

            {% if log_error %}

                <p>
                    <strong>CloudWatch Error:</strong>
                    {{ log_error }}
                </p>

            {% elif log_events %}

                <table border="1" cellpadding="8">

                    <tr>
                        <th>Time</th>
                        <th>Security Event</th>
                    </tr>

                    {% for log in log_events %}

                        <tr>
                            <td>{{ log.timestamp }}</td>
                            <td>{{ log.message }}</td>
                        </tr>

                    {% endfor %}

                </table>

            {% else %}

                <p>No Scenario 1 security logs found.</p>

            {% endif %}

            <hr>
            <h3>Scenario 2 - Automated Vulnerability Monitoring</h3>

            <p><strong>Status:</strong> Active</p>
            <p><strong>Data Source:</strong> National Vulnerability Database (NVD)</p>
            <p><strong>Monitoring:</strong> Newly published vulnerabilities</p>
            <p><strong>CloudWatch Logging:</strong> Active</p>

            <h3>Vulnerability Monitor Logs</h3>

            {% if scenario2_error %}

                <p>
                <strong>CloudWatch Error:</strong>
                {{ scenario2_error }}
                </p>

            {% elif scenario2_events %}

                <table border="1" cellpadding="8">

                    <tr>
                        <th>Time</th>
                        <th>Event</th>
                    </tr>

                    {% for log in scenario2_events %}

                        <tr>
                            <td>{{ log.timestamp }}</td>
                            <td>{{ log.message }}</td>
                        </tr>

                    {% endfor %}

                </table>

            {% else %}

            <p>No Scenario 2 logs found.</p>

            {% endif %}

            <hr>
<h3>Scenario 3 - Critical CVE Detection</h3>

<p><strong>Status:</strong> Active</p>
<p><strong>Severity:</strong> Critical</p>
<p><strong>Data Source:</strong> National Vulnerability Database (NVD)</p>
<p><strong>Detection:</strong> Critical CVEs detected</p>
<p><strong>CloudWatch Logging:</strong> Active</p>

<h3>Critical CVE Detection Logs</h3>

{% if scenario3_error %}

    <p>
        <strong>CloudWatch Error:</strong>
        {{ scenario3_error }}
    </p>

{% elif scenario3_events %}

    <table border="1" cellpadding="8">

        <tr>
            <th>Time</th>
            <th>Event</th>
        </tr>

        {% for log in scenario3_events %}

        <tr>
            <td>{{ log.timestamp }}</td>
            <td>{{ log.message }}</td>
        </tr>

        {% endfor %}

    </table>

{% else %}

    <p>No Scenario 3 Critical CVE logs found.</p>

{% endif %}
     

            <hr>

            <h3>Scenario 4</h3>
            <p><strong>Status:</strong> Pending Log Watch connection</p>

            <hr>

            <h3>Scenario 5 - CTI Threat Processing</h3>
            <p><strong>Status:</strong> Pending Log Watch connection</p>

            <hr>

            <p>
                <strong>Overall Monitoring Status:</strong>
                Active
            </p>

            <br>

            <a href="/admin">
                Back to Administrator Portal
            </a>

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

    username = request.form["username"]
    password = request.form["password"]
    role = request.form["role"]

    if role == "admin":
         admin_reference = request.form.get("admin_reference", "")



         if admin_reference != ADMIN_REFERENCE:
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

    global FAILED_ATTEMPTS

    username = request.form["username"]
    password = request.form["password"]

    users = load_users()

    if username in users:

        stored_password = users[username]["password"]

        if check_password_hash(stored_password, password):

            FAILED_ATTEMPTS = 0

            role = users[username].get("role", "client")
            session["username"] = username
            session["role"] = role

            # PB-14 Administrator
            if role == "admin":
                return redirect(url_for("admin_portal"))

            # PB-15 Client
            else:
                 return redirect(url_for("client_portal"))


    # ---------------- FAILED LOGIN ----------------

    FAILED_ATTEMPTS += 1

    if FAILED_ATTEMPTS >= 3:

        payload = {
            "username": username,
            "failed_attempts": FAILED_ATTEMPTS,
            "severity": "High"
        }

        try:

            lambda_client.invoke(
                FunctionName="CTI-Failed-Login-Alert",
                InvocationType="Event",
                Payload=json.dumps(payload).encode("utf-8")
            )

            print("AWS Lambda security alert invoked successfully.")

        except Exception as error:

            print("AWS Lambda error:", error)

        FAILED_ATTEMPTS = 0

        return render_template_string(
            LOGIN_HTML,
            message=(
                "Security Alert: Multiple failed login "
                "attempts detected!"
            )
        )

    return render_template_string(
        LOGIN_HTML,
        message=f"Invalid login. Failed attempt {FAILED_ATTEMPTS}/3"
    )


# ---------------- SUPPORT REQUEST ----------------

@app.route("/support")
def support():
    return render_template("support.html")


# ---------------- SCENARIO 3: CRITICAL CVE SCAN ----------------

@app.route("/scan-cves", methods=["POST"])
def scan_cves():
    username = request.form.get("username", "Administrator")

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
    username = request.form.get("username", "Administrator")
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
    app.run(debug=True)

