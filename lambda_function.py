import json
import boto3
import datetime
import urllib.request

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
    print(f"Timestamp: {datetime.datetime.utcnow().isoformat()}")
    print("=" * 60)

    try:
        # ── Parse request body ──────────────────────────────
        body = {}
        if event.get('body'):
            body = json.loads(event['body'])

        query_type = body.get('query_type', 'latest')   # 'latest' or 'severity'
        severity_filter = body.get('severity', 'ALL')   # ALL / CRITICAL / HIGH / MEDIUM / LOW
        limit = int(body.get('limit', 5))

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
                'processed_at': datetime.datetime.utcnow().isoformat() + 'Z',
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
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage={limit}&startIndex=0"
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

        if metrics.get('cvssMetricV31'):
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
