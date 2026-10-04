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
