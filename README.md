# 🛡️ VulnaBoard: Your CVE Command Center

A Python-Flask-based vulnerability tracking dashboard that fetches, stores, and displays CVEs from the National Vulnerability Database (NVD). This release (RR2) enhances user interactivity, data persistence, and visualization to support cybersecurity monitoring workflows.

---

## 🚀 Features

- **📡 Live CVE Feed Integration**  
  Pulls latest CVEs from NVD’s JSON feed (`nvdcve-1.1-modified.json.gz`).

- **📚 Persistent Storage**  
  Stores all unique CVEs in `critical_cves.csv` — avoids duplication and preserves history.

- **🔍 Search by Keyword**  
  Search CVEs by description keywords like `openssl`, `apache`, `router`, etc.

- **📅 Year Filtering**  
  Easily filter CVEs by year of publication (e.g., `2023`, `2024`).

- **🔢 Score Bucket Sorting**  
  Sort vulnerabilities based on CVSS v3.1 score bucket (0–10 scale).

- **📊 Pagination**  
  Displays CVEs 100 per page with navigation controls.

- **📋 Collapsible Descriptions**  
  Clean UI with “Show More / Show Less” toggles for long CVE descriptions.

- **🔄 Refresh Button**  
  One-click to fetch latest CVEs with flash-based feedback.

---

