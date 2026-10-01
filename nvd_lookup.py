
"""
NVD CVE Lookup
Fetches CVE details from the National Vulnerability Database.

Usage:
    py nvd_lookup.py CVE-2026-14182
    py nvd_lookup.py CVE-2026-14182 --json

Optional environment variable:
    NVD_API_KEY
"""

import argparse
import json
import os
import urllib.error
import urllib.parse
import urllib.request


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_description(cve):
    """Return the English CVE description."""
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            return item.get("value", "No description available")

    return "No English description available"


def get_cvss(cve):
    """Extract the available CVSS score and severity."""
    metrics = cve.get("metrics", {})

    metric_types = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2"
    ]

    for metric_type in metric_types:
        entries = metrics.get(metric_type, [])

        if entries:
            metric = entries[0]
            cvss_data = metric.get("cvssData", {})

            return {
                "version": cvss_data.get("version"),
                "score": cvss_data.get("baseScore"),
                "severity": (
                    cvss_data.get("baseSeverity")
                    or metric.get("baseSeverity")
                    or "Not Available"
                )
            }

    return {
        "version": None,
        "score": None,
        "severity": "Not Available"
    }


def extract_cpe_matches(nodes, results):
    """Recursively extract affected CPE version information."""
    for node in nodes or []:
        for match in node.get("cpeMatch", []):
            results.append({
                "criteria": match.get("criteria"),
                "vulnerable": match.get("vulnerable"),
                "versionStartIncluding": match.get(
                    "versionStartIncluding"
                ),
                "versionStartExcluding": match.get(
                    "versionStartExcluding"
                ),
                "versionEndIncluding": match.get(
                    "versionEndIncluding"
                ),
                "versionEndExcluding": match.get(
                    "versionEndExcluding"
                )
            })

        extract_cpe_matches(
            node.get("children", []),
            results
        )


def lookup_cve(cve_id, api_key=None, timeout=25):
    """Query NVD and return structured vulnerability information."""
    cve_id = cve_id.strip().upper()

    if not cve_id.startswith("CVE-"):
        raise ValueError(
            "Invalid CVE ID. Example: CVE-2026-14182"
        )

    params = urllib.parse.urlencode({
        "cveId": cve_id
    })

    url = NVD_API + "?" + params

    headers = {
        "User-Agent": "CTI-Platform-CVE-Lookup/1.0"
    }

    if api_key:
        headers["apiKey"] = api_key

    request = urllib.request.Request(
        url,
        headers=headers
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout
        ) as response:
            data = json.loads(
                response.read().decode("utf-8")
            )

    except urllib.error.HTTPError as error:
        raise RuntimeError(
            f"NVD HTTP error {error.code}: {error.reason}"
        ) from error

    except urllib.error.URLError as error:
        raise RuntimeError(
            f"Could not connect to NVD: {error.reason}"
        ) from error

    vulnerabilities = data.get("vulnerabilities", [])

    if not vulnerabilities:
        return {
            "cve_id": cve_id,
            "found": False,
            "message": "CVE not found in NVD."
        }

    cve = vulnerabilities[0].get("cve", {})

    cpe_matches = []

    for configuration in cve.get("configurations", []):
        extract_cpe_matches(
            configuration.get("nodes", []),
            cpe_matches
        )

    cvss = get_cvss(cve)

    return {
        "cve_id": cve.get("id", cve_id),
        "found": True,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "description": get_description(cve),
        "cvss": cvss,
        "affected_cpe_matches": cpe_matches,
        "references": [
            reference.get("url")
            for reference in cve.get("references", [])
            if reference.get("url")
        ],
        "source": "National Vulnerability Database (NVD)"
    }


def main():
    parser = argparse.ArgumentParser(
        description="Look up CVE information from NVD."
    )

    parser.add_argument(
        "cve_id",
        help="CVE identifier, e.g. CVE-2026-14182"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Display the complete JSON response"
    )

    args = parser.parse_args()

    api_key = os.getenv("NVD_API_KEY")

    try:
        result = lookup_cve(
            args.cve_id,
            api_key=api_key
        )

        if args.json:
            print(json.dumps(result, indent=2))
            return

        if not result.get("found"):
            print(result["message"])
            return

        cvss = result["cvss"]

        print("\n===== NVD CVE LOOKUP =====")
        print("CVE ID:", result["cve_id"])
        print("Published:", result["published"])
        print("Last Modified:", result["last_modified"])
        print("CVSS Version:", cvss["version"])
        print("CVSS Score:", cvss["score"])
        print("Severity:", cvss["severity"])
        print("\nDescription:")
        print(result["description"])

        print("\nAffected Version Information:")

        if result["affected_cpe_matches"]:
            for match in result["affected_cpe_matches"]:
                if match.get("vulnerable"):
                    print(json.dumps(match, indent=2))
        else:
            print(
                "NVD did not provide affected CPE version "
                "information for this record."
            )

        print("\nReferences:")

        for reference in result["references"][:10]:
            print("-", reference)

    except (ValueError, RuntimeError) as error:
        print("Lookup failed:", error)


if __name__ == "__main__":
    main()