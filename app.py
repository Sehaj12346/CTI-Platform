import boto3
import json
import os
from flask import Flask, request, render_template_string, render_template,redirect, url_for,session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
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

    <hr>

   <p>
    PB-14: Secure administrator access to the CTI platform.
</p>

<hr>

<h3>Security Log Watch</h3>

<p>
    Central security monitoring for all CTI platform scenarios.
</p>

<a href="/log-watch">Open Security Log Watch</a>

<br><br>

<a href="/">Logout</a>

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

    <a href="/threat-search">Search Threats</a>

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
        scan_results=None
    )
# ---------------- SECURITY LOG WATCH ----------------

# ---------------- SECURITY LOG WATCH ----------------

@app.route("/log-watch")
def log_watch():

    if session.get("role") != "admin":
        return redirect(url_for("home"))

    log_events = []
    log_error = None

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

        <h3>Scenario 2</h3>
        <p><strong>Status:</strong> Pending Log Watch connection</p>

        <hr>

        <h3>Scenario 3 - Critical CVE Detection</h3>
        <p><strong>Status:</strong> Pending Log Watch connection</p>

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
        log_error=log_error
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



# ---------------- THREAT SEARCH ----------------

@app.route("/threat-search")
def threat_search():
    return render_template("threat-search.html")


# ---------------- SUPPORT REQUEST ----------------

@app.route("/support")
def support():
    return render_template("support.html")


# ---------------- SCENARIO 3: CRITICAL CVE SCAN ----------------

@app.route("/scan-cves", methods=["POST"])
def scan_cves():

    username = request.form.get("username", "Administrator")

    try:
        import urllib.request

        lambda_url = "https://kvuo36cwp7v7jpn2jn5u2c4ao40ysvlm.lambda-url.us-east-1.on.aws/"

        with urllib.request.urlopen(
            lambda_url,
            timeout=30
        ) as response:

            response_payload = json.loads(
                response.read().decode("utf-8")
            )

        print("CVE Lambda response:", response_payload)

        # Function URL may return Lambda body directly
        if "statusCode" in response_payload:

            if response_payload["statusCode"] != 200:
                return render_template_string(
                    ADMIN_HTML,
                    username=username,
                    scan_message="CVE scan returned an error.",
                    scan_results=None
                )

            scan_results = response_payload.get("body", {})

            if isinstance(scan_results, str):
                scan_results = json.loads(scan_results)

        else:
            # Direct response from Lambda Function URL
            scan_results = response_payload

        # Calculate total if it is not included
        if "total_checked" not in scan_results:
            scan_results["total_checked"] = len(
                scan_results.get("vulnerabilities", [])
            )

        return render_template_string(
            ADMIN_HTML,
            username=username,
            scan_message="Critical CVE scan completed successfully.",
            scan_results=scan_results
        )

    except Exception as error:

        print("CVE Lambda error:", error)

        return render_template_string(
            ADMIN_HTML,
            username=username,
            scan_message="CVE Scan Error: " + str(error),
            scan_results=None
        )
# ---------------- RUN APP ----------------

if __name__ == "__main__":
    app.run(debug=True)
