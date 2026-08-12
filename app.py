import boto3
import json
import os
from flask import Flask, request, render_template_string, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__)
lambda_client = boto3.client("lambda", region_name="us-east-1")
FAILED_ATTEMPTS = 0
USERS_FILE = "users.json"

def load_users():
   if not os.path.exists(USERS_FILE):
       return {}
   with open(USERS_FILE, "r") as file:
       return json.load(file)

def save_users(users):
   with open(USERS_FILE, "w") as file:
       json.dump(users, file, indent=4)

LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>CTI Platform Login</title>
</head>
<body>
<h1>CTI Platform Login</h1>
<form method="POST" action="/login">
<input
           type="text"
           name="username"
           placeholder="Username"
           required
>
<input
           type="password"
           name="password"
           placeholder="Password"
           required
>
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

REGISTER_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Register - CTI Platform</title>
</head>
<body>
<h1>Create CTI User</h1>
<form method="POST" action="/register">
<input
           type="text"
           name="username"
           placeholder="Username"
           required
>
<input
           type="password"
           name="password"
           placeholder="Password"
           required
>
<button type="submit">Register</button>
</form>
<p>{{ message }}</p>
<p>
<a href="/">Back to Login</a>
</p>
</body>
</html>
"""

@app.route("/")
def home():
   return render_template_string(
       LOGIN_HTML,
       message=""
   )

@app.route("/register", methods=["GET", "POST"])
def register():
   if request.method == "GET":
       return render_template_string(
           REGISTER_HTML,
           message=""
       )
   username = request.form["username"]
   password = request.form["password"]
   users = load_users()
   if username in users:
       return render_template_string(
           REGISTER_HTML,
           message="Username already exists."
       )
   hashed_password = generate_password_hash(password)
   users[username] = {
       "password": hashed_password
   }
   save_users(users)
   return redirect(url_for("home"))

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
           return render_template_string(
               LOGIN_HTML,
               message="Login successful"
           )
   FAILED_ATTEMPTS += 1
   if FAILED_ATTEMPTS >= 3:
       payload = {
           "username": username,
           "failed_attempts": FAILED_ATTEMPTS,
           "severity": "High"
       }
       lambda_client.invoke(
           FunctionName="CTI-Failed-Login-Alert",
           InvocationType="Event",
           Payload=json.dumps(payload).encode("utf-8")
       )
       FAILED_ATTEMPTS = 0
       return render_template_string(
           LOGIN_HTML,
           message="Security Alert: Multiple failed login attempts detected!"
       )
   return render_template_string(
       LOGIN_HTML,
       message=f"Invalid login. Failed attempt {FAILED_ATTEMPTS}/3"
   )

if __name__ == "__main__":
   app.run(debug=True)
