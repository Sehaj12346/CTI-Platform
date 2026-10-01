
"""
CVE Remediation Assessment
Checks a supplied software version against NVD affected-version data.
Provides recommendations and an optional safe simulation.
Does NOT install patches or modify software.

Usage:
    py remediation_check.py CVE-2026-14182
    py remediation_check.py CVE-2026-14182 --product "Example Plugin" --installed-version 1.0
    py remediation_check.py CVE-2026-14182 --product "Example Plugin" --installed-version 1.0 --simulate --target-version 1.2 --json
"""

import argparse
import json
import re

from nvd_lookup import lookup_cve


def version_parts(version):
    """Convert a numeric version string into comparable parts."""
    if not version:
        return None

    parts = re.findall(r"\d+", str(version))

    if not parts:
        return None

    return tuple(int(part) for part in parts)


def compare_versions(version_a, version_b):
    """Compare numeric software versions.

    Returns:
        -1 if a < b
         0 if a == b
         1 if a > b
        None if comparison is not possible
    """
    a = version_parts(version_a)
    b = version_parts(version_b)

    if a is None or b is None:
        return None

    length = max(len(a), len(b))

    a += (0,) * (length - len(a))
    b += (0,) * (length - len(b))

    if a < b:
        return -1

    if a > b:
        return 1

    return 0


def product_matches(criteria, product):
    """Check whether the supplied product resembles the CPE vendor/product."""
    if not product:
        return True

    parts = (criteria or "").lower().split(":")

    # CPE 2.3: cpe:2.3:part:vendor:product:version:...
    if len(parts) < 6:
        return False

    vendor = parts[3].replace("_", " ")
    cpe_product = parts[4].replace("_", " ")
    search = product.lower().strip()

    searchable = f"{vendor} {cpe_product}"

    return (
        search in searchable
        or all(
            word in searchable
            for word in search.split()
            if len(word) > 2
        )
    )


def is_version_affected(installed_version, match):
    """Check whether an installed version is inside an NVD range.

    Returns True, False, or None if the data is insufficient.
    """
    if not version_parts(installed_version):
        return None

    start_including = match.get("versionStartIncluding")
    start_excluding = match.get("versionStartExcluding")
    end_including = match.get("versionEndIncluding")
    end_excluding = match.get("versionEndExcluding")

    has_bounds = any([
        start_including,
        start_excluding,
        end_including,
        end_excluding
    ])

    if has_bounds:
        if start_including:
            result = compare_versions(
                installed_version,
                start_including
            )
            if result is None:
                return None
            if result < 0:
                return False

        if start_excluding:
            result = compare_versions(
                installed_version,
                start_excluding
            )
            if result is None:
                return None
            if result <= 0:
                return False

        if end_including:
            result = compare_versions(
                installed_version,
                end_including
            )
            if result is None:
                return None
            if result > 0:
                return False

        if end_excluding:
            result = compare_versions(
                installed_version,
                end_excluding
            )
            if result is None:
                return None
            if result >= 0:
                return False

        return True

    # If NVD specifies an exact CPE version, compare against it.
    criteria_parts = (match.get("criteria") or "").split(":")

    if len(criteria_parts) > 5:
        cpe_version = criteria_parts[5]

        if cpe_version not in ("*", "-", ""):
            result = compare_versions(
                installed_version,
                cpe_version
            )
            return result == 0 if result is not None else None

    # Wildcard CPE with no version bounds is inconclusive.
    return None


def assess_remediation(
    cve_id,
    product="",
    installed_version=""
):
    """Retrieve NVD information and assess remediation requirements."""
    record = lookup_cve(cve_id)

    if not record.get("found"):
        return {
            "cve_id": cve_id.upper(),
            "assessment": "Not assessed",
            "recommendation": (
                "CVE was not found in NVD. Verify the CVE identifier."
            )
        }

    matches = [
        match
        for match in record.get("affected_cpe_matches", [])
        if match.get("vulnerable")
        and product_matches(
            match.get("criteria"),
            product
        )
    ]

    if not matches:
        assessment = "Insufficient product/version data"
        recommendation = (
            "No matching affected-product CPE record was found. "
            "Verify the product, installed version and vendor advisory."
        )
        possible_fixed_versions = []

    else:
        evaluations = [
            is_version_affected(installed_version, match)
            for match in matches
        ]

        # NVD versionEndExcluding is a range boundary, not
        # necessarily a vendor-confirmed fixed release.
        possible_fixed_versions = sorted({
            match["versionEndExcluding"]
            for match in matches
            if match.get("versionEndExcluding")
        })

        if not installed_version:
            assessment = "Installed version required"
            recommendation = (
                "Provide the installed software version before "
                "determining whether it falls within an affected range."
            )

        elif any(result is True for result in evaluations):
            assessment = "Potentially affected"
            recommendation = (
                "The supplied version falls within an NVD affected "
                "range. Check the vendor advisory for a confirmed fix, "
                "then plan and test an update."
            )

        elif all(result is False for result in evaluations):
            assessment = "Outside listed affected range"
            recommendation = (
                "The supplied version is outside the matching NVD "
                "affected ranges. Verify the result against the "
                "vendor advisory and other applicable configurations."
            )

        else:
            assessment = "Inconclusive"
            recommendation = (
                "NVD version information is insufficient for a reliable "
                "comparison. Verify the affected range and fixed release "
                "with the software vendor."
            )

    cvss = record.get("cvss", {})

    return {
        "cve_id": record["cve_id"],
        "product_entered": product or "Not specified",
        "installed_version": installed_version or "Not specified",
        "severity": cvss.get("severity"),
        "cvss_score": cvss.get("score"),
        "assessment": assessment,
        "possible_fixed_version_boundaries": (
            possible_fixed_versions
        ),
        "recommendation": recommendation,
        "references": record.get("references", [])[:10],
        "remediation_mode": (
            "Assessment only - no software changes performed"
        )
    }


def simulate_remediation(
    assessment,
    target_version=""
):
    """Create a demo result without changing real software."""
    return {
        "cve_id": assessment.get("cve_id"),
        "status": "SIMULATED ONLY",
        "target_version": target_version or "Not specified",
        "action": (
            "Demo update recorded. No actual package, plugin, "
            "host or production system was modified."
        ),
        "note": (
            "Verify the vendor's fix, test compatibility, "
            "and obtain approval before performing a real update."
        )
    }


def main():
    parser = argparse.ArgumentParser(
        description="Assess CVE remediation using NVD data."
    )

    parser.add_argument(
        "cve_id",
        help="CVE identifier, e.g. CVE-2026-14182"
    )

    parser.add_argument(
        "--product",
        default="",
        help="Product name to match against NVD CPE data"
    )

    parser.add_argument(
        "--installed-version",
        default="",
        help="Installed software version"
    )

    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Generate a safe, simulated remediation result"
    )

    parser.add_argument(
        "--target-version",
        default="",
        help="Proposed version for the simulation only"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the complete assessment as JSON"
    )

    args = parser.parse_args()

    try:
        result = assess_remediation(
            args.cve_id,
            product=args.product,
            installed_version=args.installed_version
        )

        if args.simulate:
            result["simulation"] = simulate_remediation(
                result,
                target_version=args.target_version
            )

        if args.json:
            print(json.dumps(result, indent=2))
            return

        print("\n===== CVE REMEDIATION ASSESSMENT =====")
        print("CVE ID:", result.get("cve_id"))
        print("Product:", result.get("product_entered"))
        print("Installed Version:", result.get("installed_version"))
        print("Severity:", result.get("severity"))
        print("CVSS Score:", result.get("cvss_score"))
        print("Assessment:", result.get("assessment"))

        print(
            "Possible Fixed Version Boundaries:",
            result.get("possible_fixed_version_boundaries")
        )

        print("\nRecommendation:")
        print(result.get("recommendation"))

        print("\nMode:")
        print(result.get("remediation_mode"))

        if args.simulate:
            print("\n===== SIMULATED REMEDIATION =====")
            print(
                json.dumps(
                    result["simulation"],
                    indent=2
                )
            )

    except (ValueError, RuntimeError) as error:
        print("Remediation assessment failed:", error)


if __name__ == "__main__":
    main()