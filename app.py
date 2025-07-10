from flask import Flask, render_template, redirect, url_for, flash
import requests
import gzip
import json
import csv
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Needed for flashing messages

# Constants
NVD_FEED_URL = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz'
OUTPUT_FILE = 'critical_cves.csv'
CVSS_THRESHOLD = 9.0
TIMESTAMP_FILE = 'last_updated.txt'


# ======================== CVE Tracker Logic ========================

def download_feed(url):
    """Download and decompress the NVD CVE feed (JSON.gz)."""
    response = requests.get(url)
    if response.status_code != 200:
        raise Exception(f"Failed to download NVD feed: {response.status_code}")
    return gzip.decompress(response.content)

def parse_feed(json_data):
    all_cves = []
    data = json.loads(json_data)
    for item in data.get("CVE_Items", []):
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        description = item["cve"]["description"]["description_data"][0]["value"]
        published_date = item["publishedDate"]

        impact = item.get("impact", {}).get("baseMetricV3")
        score = impact.get("cvssV3", {}).get("baseScore", "N/A") if impact else "N/A"

        all_cves.append([cve_id, description, published_date, score])
    return all_cves


def save_to_csv(new_data, filename):
    existing_ids = set()

    # Load existing CVE IDs
    if os.path.exists(filename):
        with open(filename, newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader, None)  # Skip header
            for row in reader:
                existing_ids.add(row[0])  # CVE ID

    # Filter out already existing CVEs
    unique_data = [row for row in new_data if row[0] not in existing_ids]

    # Append only new CVEs
    write_header = not os.path.exists(filename)
    with open(filename, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(["CVE ID", "Description", "Published Date", "CVSS v3.1 Score"])
        writer.writerows(unique_data)

    return len(unique_data)


def load_csv(filename):
    """Load CSV data to display in UI."""
    if not os.path.exists(filename):
        return []
    with open(filename, newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader, None)  # Skip header
        return list(reader)

def save_last_updated():
    """Save the timestamp of the last CVE fetch."""
    with open(TIMESTAMP_FILE, 'w') as f:
        f.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

def load_last_updated():
    """Load the last updated timestamp if available."""
    if os.path.exists(TIMESTAMP_FILE):
        with open(TIMESTAMP_FILE, 'r') as f:
            return f.read().strip()
    return "Never"

def run_tracker():
    try:
        raw = download_feed(NVD_FEED_URL)
        results = parse_feed(raw)
        new_count = save_to_csv(results, OUTPUT_FILE)
        save_last_updated()
        return f"✅ {new_count} new CVEs added."
    except Exception as e:
        return f"❌ Error: {e}"


# ======================== Flask Routes ========================

from flask import request  # Add this import at the top

@app.route('/', methods=['GET'])
def index():
    query = request.args.get('q', '').lower()
    year_filter = request.args.get('year', '')
    page = int(request.args.get('page', 1))
    per_page = 100

    sort_by = request.args.get('sort', 'date')
    sort_order = request.args.get('order', 'desc')

    all_cves = load_csv(OUTPUT_FILE)
    last_updated = load_last_updated()

    if query:
        all_cves = [row for row in all_cves if query in row[1].lower()]

    if year_filter:
        all_cves = [row for row in all_cves if row[2][:4] == year_filter]

    def get_score_bucket(score):
        try:
            s = float(score)
            if s <= 2: return 0
            elif s <= 3: return 1
            elif s <= 4: return 2
            elif s <= 5: return 3
            elif s <= 6: return 4
            elif s <= 7: return 5
            elif s <= 8: return 6
            elif s <= 9: return 7
            elif s <= 10: return 8
        except:
            return 9

    if sort_by == 'score':
        all_cves.sort(key=lambda x: get_score_bucket(x[3]), reverse=(sort_order == 'desc'))
    else:
        all_cves.sort(key=lambda x: x[2], reverse=(sort_order == 'desc'))

    total = len(all_cves)
    start = (page - 1) * per_page
    paginated_cves = all_cves[start:start + per_page]
    total_pages = (total + per_page - 1) // per_page

    return render_template(
        "index.html",
        cves=paginated_cves,
        last_updated=last_updated,
        query=query,
        page=page,
        total_pages=total_pages,
        sort_by=sort_by,
        sort_order=sort_order,
        year_filter=year_filter
    )

@app.route('/refresh')
def refresh():
    message = run_tracker()
    flash(message)
    return redirect(url_for('index'))


# ======================== Run Server ========================

if __name__ == "__main__":
    app.run(debug=True)
