import boto3
import json
import os
from flask import Flask, request, render_template_string, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(_name_)

lambda_client = boto3.client("lambda", region_name="us-east-1")

FAILED_ATTEMPTS = 0
USERS_FILE = "users.json"


# ---------------- USERS ----------------

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}

    with open(USERS_FILE, "r") as file:
        return json.load(file)


def save_users(users):
    with open(USERS_FILE, "w") as file:
        json.dump(users, file, indent=4)


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


# ---------------- REGISTER ----------------

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

        <select name="role" required>
            <option value="client">Client</option>
            <option value="admin">Administrator</option>
        </select>

        <br><br>

        <button type="submit">Register</button>

    </form>

    <p>{{ message }}</p>

    <a href="/">Back to Login</a>

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

    <p>
        PB-14: Secure administrator access to the CTI platform.
    </p>

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

    <p>Latest published cybersecurity threats:</p>

    <hr>

    <h3>1. Phishing Campaign</h3>

    <p><strong>Severity:</strong> High</p>

    <p>
        Fraudulent emails may attempt to steal usernames,
        passwords and other sensitive information.
    </p>

    <hr>

    <h3>2. Ransomware Threat</h3>

    <p><strong>Severity:</strong> Critical</p>

    <p>
        Ransomware may encrypt organisational files
        and demand payment for recovery.
    </p>

    <hr>

    <h3>3. Credential Attack</h3>

    <p><strong>Severity:</strong> Medium</p>

    <p>
        Multiple failed authentication attempts may
        indicate an attempted account compromise.
    </p>

    <hr>

    <p>
        PB-15: Clients can view published cybersecurity threats
        and stay informed about current risks.
    </p>

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

            # PB-14 Administrator
            if role == "admin":

                return render_template_string(
                    ADMIN_HTML,
                    username=username
                )

            # PB-15 Client
            else:

                return render_template_string(
                    CLIENT_HTML,
                    username=username
                )

    # Failed login
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

            message = (
                "Security Alert: Multiple failed login "
                "attempts detected!"
            )

        except Exception as error:

            print("AWS Lambda error:", error)

            message = (
                "Security Alert: Multiple failed login "
                "attempts detected!"
            )

        FAILED_ATTEMPTS = 0

        return render_template_string(
            LOGIN_HTML,
            message=message
        )

    return render_template_string(
        LOGIN_HTML,
        message=f"Invalid login. Failed attempt {FAILED_ATTEMPTS}/3"
    )


# ---------------- RUN APP ----------------

if _name_ == "_main_":
    app.run(debug=True)
