import json
import re
import requests
import subprocess


# --------------------------------------------------
# 1. Load installed packages
# --------------------------------------------------

try:
    with open("installed_packages.json", "r", encoding="utf-16") as file:
        packages = json.load(file)
except UnicodeError:
    with open("installed_packages.json", "r", encoding="utf-8-sig") as file:
        packages = json.load(file)

installed = {
    package["name"].lower(): package["version"]
    for package in packages
}

print("INSTALLED PACKAGES")
print("------------------------------")

for name, version in installed.items():
    print(f"{name:<20} {version}")

print("------------------------------")
print(f"Total packages: {len(installed)}")


# --------------------------------------------------
# 2. Get CVEs from Gmail scanner
# --------------------------------------------------

print("\nSCANNING GMAIL FOR CVEs")
print("------------------------------")

result = subprocess.run(
    ["py", "cve_email_scanner.py"],
    capture_output=True,
    text=True
)

scanner_output = result.stdout

cve_ids = sorted(set(
    re.findall(
        r"CVE-\d{4}-\d{4,7}",
        scanner_output,
        re.IGNORECASE
    )
))

if not cve_ids:
    print("No CVE IDs found.")
    raise SystemExit

print(f"CVE IDs found: {len(cve_ids)}")

for cve in cve_ids:
    print("-", cve.upper())


# --------------------------------------------------
# 3. Query NVD
# --------------------------------------------------

print("\nCHECKING CVEs AGAINST INSTALLED SOFTWARE")
print("----------------------------------------")

for cve in cve_ids:

    cve = cve.upper()

    print(f"\nChecking {cve}...")

    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?cveId={cve}"
    )

    try:
        response = requests.get(url, timeout=20)

        if response.status_code != 200:
            print("NVD lookup failed:", response.status_code)
            continue

        data = response.json()

    except Exception as error:
        print("Error contacting NVD:", error)
        continue

    vulnerabilities = data.get("vulnerabilities", [])

    if not vulnerabilities:
        print("No NVD information found.")
        continue

    cve_data = vulnerabilities[0].get("cve", {})

    # --------------------------------------------------
    # 4. Description
    # --------------------------------------------------

    description = ""

    for item in cve_data.get("descriptions", []):
        if item.get("lang") == "en":
            description = item.get("value", "")
            break

    print("Description:")
    print(description)

    # --------------------------------------------------
    # 5. Check NVD affected CPE/product information
    # --------------------------------------------------

    configurations = cve_data.get("configurations", [])

    affected_products = []

    def process_nodes(nodes):
        for node in nodes:

            for match in node.get("cpeMatch", []):

                criteria = match.get("criteria", "")

                vulnerable = match.get("vulnerable", True)

                if vulnerable:
                    affected_products.append(criteria)

            process_nodes(node.get("children", []))

    for configuration in configurations:
        process_nodes(configuration.get("nodes", []))

    if affected_products:

        print("\nNVD AFFECTED PRODUCTS:")

        for product in affected_products:
            print("-", product)

        # --------------------------------------------------
        # 6. Compare package names
        # --------------------------------------------------

        possible_matches = []

        for package_name, installed_version in installed.items():

            package_clean = package_name.lower().replace("-", "_")

            for product in affected_products:

                product_lower = product.lower()

                if (
                    package_clean in product_lower
                    or package_name.lower() in product_lower
                ):
                    possible_matches.append(
                        (package_name, installed_version, product)
                    )

        if possible_matches:

            print("\nPOSSIBLE PACKAGE MATCH:")

            for package_name, version, product in possible_matches:
                print(
                    f"- Package: {package_name}"
                )
                print(
                    f"  Installed version: {version}"
                )
                print(
                    f"  NVD product: {product}"
                )

            print(
                "\nVERSION CHECK REQUIRED "
                "BEFORE REMEDIATION."
            )

        else:
            print("\nNo installed package matched NVD products.")

    else:
        print("\nNVD did not provide affected CPE information.")

print("\nCVE package matching completed.")