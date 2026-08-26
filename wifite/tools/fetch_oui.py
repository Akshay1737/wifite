#!/usr/bin/env python3
import argparse
import csv
import requests
import sys
import os
from datetime import datetime

# IEEE registry URLs
IEEE_REG_URLS = {
    "OUI":   "https://standards-oui.ieee.org/oui/oui.csv",
    "MAM":   "https://standards-oui.ieee.org/oui28/mam.csv",
    "OUI36": "https://standards-oui.ieee.org/oui36/oui36.csv",
    "IAB":   "https://standards-oui.ieee.org/iab/iab.csv",
}

DEFAULT_FILENAME = "ieee-oui.txt"


def fetch_csv(url, verbose=False):
    """Download CSV content from a URL."""
    headers = {"User-Agent": "Mozilla/5.0 (compatible; FetchOUI/1.0; +https://github.com/kimocoder/wifite2)"}
    if verbose:
        print(f"→ Fetching {url}")
    response = requests.get(url, headers=headers, timeout=30)
    if not response.ok:
        raise RuntimeError(f"Failed to fetch {url}: {response.status_code} {response.reason}")
    if len(response.content) == 0:
        raise RuntimeError(f"Empty response from {url}")
    if verbose:
        print(f"  Downloaded {len(response.content)} bytes")
    return response.text


def parse_and_write_csv(csv_content, outfile, key, verbose=False):
    """Parse CSV content and write MAC/Vendor to file."""
    reader = csv.DictReader(csv_content.splitlines())
    outfile.write(f"\n#\n# Start of IEEE {key} registry data\n#\n")
    count = 0

    for row in reader:
        # Columns differ slightly between registries, so we handle gracefully
        mac = row.get("Assignment") or row.get("Registry") or ""
        vendor = row.get("Organization Name") or row.get("Organization") or ""
        vendor = vendor.strip()
        if mac and vendor:
            outfile.write(f"{mac}\t{vendor}\n")
            count += 1

    outfile.write(f"#\n# End of IEEE {key} registry data. {count} entries.\n#\n")
    if verbose:
        print(f"  Wrote {count} entries for {key}")
    return count


def main():
    parser = argparse.ArgumentParser(
        description="Fetch the IEEE OUI (manufacturer) registries and write MAC/vendor mappings to a text file."
    )
    parser.add_argument("-f", metavar="FILE", default=DEFAULT_FILENAME,
                        help=f"Output filename (default: {DEFAULT_FILENAME})")
    parser.add_argument("-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    filename = args.f
    verbose = args.v

    # Delete old file if exists
    if os.path.exists(filename):
        if verbose:
            print(f"Deleting existing {filename}")
        os.remove(filename)

    # Open new output file
    if verbose:
        print(f"Opening {filename} for output")

    with open(filename, "w", encoding="utf-8") as outfile:
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        outfile.write(f"# IEEE OUI Vendor List\n# Generated {date_str}\n")

        total_entries = 0
        for key, url in sorted(IEEE_REG_URLS.items()):
            if verbose:
                print(f"\nProcessing IEEE {key} registry data from {url}")
            try:
                content = fetch_csv(url, verbose)
                total_entries += parse_and_write_csv(content, outfile, key, verbose)
            except Exception as e:
                print(f"Error processing {key}: {e}", file=sys.stderr)

    print(f"\nTotal of {total_entries} MAC/Vendor mappings written to {filename}")


if __name__ == "__main__":
    main()
