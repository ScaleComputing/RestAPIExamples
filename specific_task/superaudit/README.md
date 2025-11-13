# SuperAudit v8.0

**Professional VM Inventory, Compliance Reporting, Capacity Planning, and Historical Monitoring for Scale Computing HyperCore**

A comprehensive Python-based auditing tool that provides detailed inventory, health monitoring, compliance reporting, and capacity planning for Scale Computing HyperCore clusters via REST API. **Now with continuous monitoring, web dashboard, and historical trend analysis!**

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-8.0-green.svg)]()

---

## 🚀 **What's New in v8.0 - Historical Data & Monitoring**

### **v8.0 (Latest) - Continuous Monitoring & Dashboard** 🎉
SuperAudit v8.0 introduces **continuous monitoring** and **historical data tracking**, transforming it from a point-in-time audit tool into a comprehensive monitoring solution.

#### **🤖 Daemon Mode - Continuous Collection**
- Run SuperAudit as a background service with scheduled collection
- Configurable collection intervals (default: 15 minutes)
- Automatic data storage in SQLite or PostgreSQL
- Silent operation - no file generation, just database logging
- Perfect for long-term monitoring and trend analysis

```bash
# Start daemon to collect data every 15 minutes
./SuperAudit_API.py -n cluster.local -u admin --daemon --database /var/lib/superaudit/audit.db --interval 15
```

#### **📊 Web Dashboard - Real-Time Visualization**
- Beautiful web-based dashboard for visualizing historical data
- Real-time cluster status overview
- Historical trend charts for compliance, capacity, and VM counts
- Individual VM history tracking
- Warning analysis and capacity forecasting
- Accessible from any browser on your network

```bash
# Start web dashboard (after collecting data with daemon mode)
./SuperAudit_API.py --dashboard --database /var/lib/superaudit/audit.db --dashboard-port 8080
# Open browser to http://localhost:8080
```

#### **💾 Database Storage - Historical Tracking**
- Timestamped audit snapshots
- VM history tracking over time
- Capacity trend analysis
- Compliance scoring trends
- Data retention policies
- Supports SQLite (built-in) and PostgreSQL

#### **Key Benefits:**
- 📈 **Trend Analysis** - Track changes over days, weeks, or months
- 🚨 **Early Warning** - Detect capacity issues before they become critical
- 📊 **Reporting** - Generate historical reports for compliance and planning
- 🔍 **VM Lifecycle** - Track individual VM changes over time
- 💡 **Capacity Forecasting** - Predict when you'll need to add resources

---

## 🚀 **Previous Releases (v7.x Series)**

### **v7.4 - UX & Testing**
- ✨ **Test Connection Mode** - Validate credentials and connectivity before running audits
- ✨ **Dry Run Mode** - Test filters and see what would be collected without generating files
- ✨ **Enhanced CLI** - Better organized help with grouped options

### **v7.3 - Filtering & Export**
- ✨ **VM Filtering** - Filter by state, type, tags, name, or node
- ✨ **JSON Export** - Full data export for automation and integrations
- ✨ **Summary Export** - Concise JSON for dashboards and monitoring

### **v7.2 - Compliance & Capacity**
- ✨ **3 New Excel Sheets** - Warnings & Recommendations, Compliance Report, Capacity Planning
- ✨ **Compliance Scoring** - 0-100 score with PASS/FAIL categories
- ✨ **Categorized Warnings** - CRITICAL/WARNING/INFO severity levels
- ✨ **Capacity Planning** - Storage metrics and expansion recommendations

### **v7.1 - Enhanced Data**
- ✨ **9 New VM Fields** - Boot order, machine type, OS, HA policy, MAC addresses, adapter types, connection status, cache mode, disk snapshots
- ✨ **Smart VM Detection** - Auto-categorize Production, Dev, Test VMs

### **v7.0 - Excel Foundation**
- ✨ **Excel by Default** - Professional 8-sheet workbooks
- ✨ **Conditional Formatting** - Color-coded status indicators
- ✨ **Summary Dashboard** - Executive overview with statistics

---

## 📊 **Excel Workbook Structure (8 Worksheets)**

SuperAudit generates a professional Excel workbook with:

| # | Worksheet | Contents |
|---|-----------|----------|
| 1 | **Summary Dashboard** | Executive summary, statistics, compliance score, warnings |
| 2 | **VM Inventory** | Complete VM audit with 30 data fields and conditional formatting |
| 3 | **Node Hardware** | Node specifications, CPU/memory usage, storage metrics |
| 4 | **Drive Health** | Individual drive health, temperature, SMART status |
| 5 | **ISO Library** | ISO catalog with sizes, paths, mount status |
| 6 | **Warnings & Recommendations** | Categorized issues (CRITICAL/WARNING/INFO) with actionable recommendations |
| 7 | **Compliance Report** | Compliance categories with PASS/FAIL status and overall score |
| 8 | **Capacity Planning** | Storage/memory capacity with expansion recommendations |

**Features:**
- ✅ Freeze panes and auto-filters on all sheets
- ✅ Conditional formatting (green/yellow/red status indicators)
- ✅ Auto-sized columns for readability
- ✅ Professional styling with colored headers
- ✅ Color-coded warnings by severity

---

## 🎯 **Key Features**

### **Data Collection (30 Fields per VM)**
- VM metadata: UUID, name, description, tags, state, CPUs, memory
- Boot configuration: Boot order, machine type (BIOS/UEFI), operating system
- High availability: HA policy (STRICT/PREFERRED)
- Network: IP addresses, VLANs, MAC addresses, adapter types, connection status
- Storage: Drive type, size, usage, SSD tier, cache mode, snapshot status
- Snapshots: Count, schedules, snapshot protection status
- Replication: Replication partners and configuration
- Node placement: Current node, node CPU load

### **Compliance & Analysis**
- **Compliance Scoring:** 0-100 overall score with 5 categories
- **Categorized Warnings:** CRITICAL, WARNING, INFO severity levels
- **Smart Recommendations:** Context-aware actionable advice
- **VM Type Detection:** Auto-categorize Production, Dev, Test, Template VMs
- **Capacity Planning:** Storage projections and expansion alerts

### **Filtering & Export**
- **Filter VMs by:** State (RUNNING/STOPPED), Type, Tags, Name, Node
- **Export Formats:** Excel (.xlsx), CSV (.csv), JSON (.json)
- **Summary Export:** JSON for dashboards and monitoring systems
- **Multiple Filters:** Combine filters for targeted audits

### **Testing & Validation**
- **Test Connection:** Validate credentials without running full audit
- **Dry Run:** Preview what would be collected with current filters
- **Enhanced Errors:** Clear troubleshooting hints

### **Continuous Monitoring & Dashboard (v8.0)**
- **Daemon Mode:** Background service with scheduled collection (configurable intervals)
- **Historical Database:** SQLite or PostgreSQL storage for audit snapshots
- **Web Dashboard:** Real-time visualization with trend charts and capacity forecasting
- **VM History Tracking:** Track individual VM changes over time
- **Capacity Forecasting:** Predict resource needs based on historical trends

---

## 🔧 **Requirements**

### **Core Requirements**
- **Python:** 3.6 or later
- **openpyxl:** For Excel output (`pip install openpyxl`)
- **Network Access:** HTTPS connectivity to HyperCore cluster
- **Credentials:** Valid cluster credentials

### **Additional Requirements for v8.0 Features**
- **flask:** For web dashboard (`pip install flask`)
- **werkzeug:** Flask dependency (`pip install werkzeug`)
- **apscheduler:** For daemon scheduling (`pip install apscheduler`)
- **SQLite:** Built-in with Python (no installation needed)

**Quick Install:**
```bash
pip install -r requirements.txt
```

---

## 🚀 **Quick Start**

### **One-Time Audit (Traditional Mode)**
```bash
# Install dependencies
pip install -r requirements.txt

# Test connection
./SuperAudit_API.py -n 10.205.109.101 --test-connection

# Run full audit (generates Excel with 8 sheets)
./SuperAudit_API.py -n 10.205.109.101 -u admin
# Output: superaudit_clustername.xlsx
```

### **Continuous Monitoring (v8.0)**
```bash
# Install all dependencies including dashboard
pip install -r requirements.txt

# Start daemon for continuous collection every 15 minutes
./SuperAudit_API.py -n cluster.local -u admin --daemon --database /var/lib/superaudit/audit.db --interval 15

# In another terminal, start the web dashboard
./SuperAudit_API.py --dashboard --database /var/lib/superaudit/audit.db --dashboard-port 8080

# Open browser to http://localhost:8080
```

---

## 📖 **Usage Examples**

### **Basic Audit**
```bash
# Interactive (secure - prompts for password)
./SuperAudit_API.py -n cluster.local -u admin
# Output: superaudit_clustername.xlsx (8 sheets)

# Using .netrc file (secure)
./SuperAudit_API.py -n cluster.local
```

### **Testing & Validation**
```bash
# Test connection before running audit
./SuperAudit_API.py -n cluster.local --test-connection

# Dry run to preview results
./SuperAudit_API.py -n cluster.local --filter-state RUNNING --dry-run
```

### **Filtering**
```bash
# Only running VMs
./SuperAudit_API.py -n cluster.local --filter-state RUNNING

# Production VMs only
./SuperAudit_API.py -n cluster.local --filter-type "PRODUCTION VM"

# VMs with specific tag
./SuperAudit_API.py -n cluster.local --filter-tag backup

# VMs on specific node
./SuperAudit_API.py -n cluster.local --filter-node 10.205.109.101

# Combine multiple filters
./SuperAudit_API.py -n cluster.local --filter-state RUNNING --filter-type "PRODUCTION VM"
```

### **Export Options**
```bash
# Excel + JSON export
./SuperAudit_API.py -n cluster.local -o audit.xlsx --export-json data.json

# Summary for dashboards
./SuperAudit_API.py -n cluster.local --export-summary summary.json

# Legacy CSV format
./SuperAudit_API.py -n cluster.local --format csv
```

### **Quick Health Check**
```bash
# Summary only (no files)
./SuperAudit_API.py -n cluster.local --summary-only

# Warnings only (for monitoring)
./SuperAudit_API.py -n cluster.local --warnings
```

### **Daemon Mode (v8.0) - Continuous Monitoring**
```bash
# Start daemon with default 15-minute interval
./SuperAudit_API.py -n cluster.local -u admin --daemon --database /var/lib/superaudit/audit.db

# Start daemon with custom interval (collect every 5 minutes)
./SuperAudit_API.py -n cluster.local -u admin --daemon --database /var/lib/superaudit/audit.db --interval 5

# One-time database logging (without continuous daemon)
./SuperAudit_API.py -n cluster.local -u admin --log-to-db --database /var/lib/superaudit/audit.db

# Using environment variables for automation
export SCALE_USER=admin
export SCALE_PASSWORD=yourpassword
./SuperAudit_API.py -n cluster.local --daemon --database /var/lib/superaudit/audit.db --interval 15
```

### **Web Dashboard (v8.0) - Historical Visualization**
```bash
# Start dashboard on default port 8080
./SuperAudit_API.py --dashboard --database /var/lib/superaudit/audit.db

# Start dashboard on custom port and host
./SuperAudit_API.py --dashboard --database /var/lib/superaudit/audit.db --dashboard-port 3000 --dashboard-host 0.0.0.0

# Access dashboard
# Open browser to http://localhost:8080
# Or from another machine: http://your-server-ip:8080
```

**Dashboard Features:**
- Real-time cluster status (VMs, nodes, storage, warnings)
- Historical trend charts (compliance scores, capacity, VM counts)
- Individual VM history tracking
- Warning analysis with severity breakdown
- Capacity forecasting and projections

---

## 🔒 **Security - Credential Methods**

SuperAudit supports **4 authentication methods** (in order of security):

### **1. Interactive Prompt (Most Secure) ✅**
```bash
./SuperAudit_API.py -n cluster.local -u admin
# Password: [hidden]
```

### **2. .netrc File (Secure) ✅**
```bash
# Create ~/.netrc with permissions 0600
cat > ~/.netrc << 'EOF'
machine cluster.local
login admin
password yourpassword
EOF
chmod 600 ~/.netrc

./SuperAudit_API.py -n cluster.local
```

### **3. Environment Variables (Secure) ✅**
```bash
export SCALE_USER=admin
export SCALE_PASSWORD=yourpassword
./SuperAudit_API.py -n cluster.local
```

### **4. Command-Line (INSECURE - Testing Only) ⚠️**
```bash
./SuperAudit_API.py -n cluster.local -u admin -p password
# WARNING: Visible in process list and shell history!
```

---

## 🔐 **SSL/TLS Certificates**

For self-signed certificates (most HyperCore clusters):

### **Recommended: Use --ca-bundle (SECURE) ✅**
```bash
# Download server certificate
echo | openssl s_client -connect cluster.local:443 -showcerts 2>/dev/null | \
  openssl x509 -outform PEM > scale_cert.pem

# Use with SuperAudit
./SuperAudit_API.py -n cluster.local -u admin --ca-bundle scale_cert.pem
```

### **Alternative: --no-verify-ssl (NOT RECOMMENDED) ⚠️**
```bash
./SuperAudit_API.py -n cluster.local -u admin --no-verify-ssl
```

---

## 🎛️ **Command-Line Options**

### **Connection**
```
-n, --node HOST           Cluster node hostname or IP
-u, --user USERNAME       Username
-p, --password PASS       Password (insecure)
--no-verify-ssl          Disable SSL verification
--ca-bundle PATH         CA certificate bundle
```

### **Output & Format**
```
--format {xlsx,csv}      Output format (default: xlsx)
-q, --quiet              Quiet mode
--summary-only           Show summary only (no files)
--warnings               Show warnings only
```

### **Filtering (v7.3+)**
```
--filter-state {RUNNING,STOPPED,PAUSED}
--filter-type TYPE       VM type filter
--filter-tag TAG         Tag filter (partial match)
--filter-name NAME       Name filter (partial match)
--filter-node NODE       Node IP filter
```

### **Export (v7.3+)**
```
--export-json FILE       Export to JSON
--export-summary FILE    Export summary JSON
```

### **Testing (v7.4+)**
```
--test-connection        Test connection and exit
--dry-run                Preview results without generating files
```

---

## 📈 **Compliance Reporting**

The **Compliance Report** sheet includes:

| Category | Target | Status |
|----------|--------|--------|
| VMs with Snapshots (Running) | 80% | PASS/FAIL |
| Production VMs with HA Policy | 70% | PASS/FAIL |
| Production VMs with Replication | 50% | PASS/FAIL |
| Disks with Adequate Space | 90% | PASS/FAIL |
| Nodes with Normal CPU | 80% | PASS/FAIL |
| **Overall Compliance Score** | **0-100** | **Score** |

**Warnings categorized by severity:**
- 🔴 **CRITICAL:** Immediate action required (e.g., production VM without snapshots, disk >95%)
- 🟡 **WARNING:** Should be addressed soon (e.g., high CPU, disk >85%)
- 🔵 **INFO:** For awareness (e.g., production VM without replication)

---

## 📊 **Sample Output**

### **Test Connection**
```
✓ CONNECTION TEST SUCCESSFUL

Host:           cluster.local
SSL Verify:     Enabled
CA Bundle:      System default
Username:       admin
Authentication: Valid
Cluster Name:   Production Cluster
ICOS Version:   9.4.33
Nodes:          5
Virtual Machines: 43

Test connection completed successfully.
```

### **Dry Run**
```
DRY RUN MODE - No files will be generated

Data Collection Summary:
- VMs collected:     28 (from 43 total)
- Nodes scanned:     5
- VM types found:    3
- Warnings generated: 12

Would generate files:
- Main output:       superaudit_production_cluster.xlsx

Applied filters:
- State:             RUNNING

Dry run completed successfully.
```

### **Audit Summary**
```
╔═══════════════════════════════════════════════════════════════════╗
║                      AUDIT SUMMARY                                ║
╠═══════════════════════════════════════════════════════════════════╣
║ VMs Processed:         43                                         ║
║   Running:             18 ( 41.9%)                                ║
║   Stopped:             25 ( 58.1%)                                ║
║                                                                   ║
║ Storage Allocated:    12.5 TB                                     ║
║ Storage Used:          3.2 TB ( 25.6%)                            ║
║                                                                   ║
║ Memory Allocated:    256.0 GB                                     ║
║                                                                   ║
║ VMs with Snapshots:    35 ( 81.4%)                                ║
║                                                                   ║
║ Execution Time:           2s                                      ║
║ Processing Speed:      498.7 VMs/s                                ║
║                                                                   ║
║ Output File:        superaudit_production_cluster.xlsx            ║
║                                                                   ║
║ ⚠  WARNINGS:                                                      ║
║   • WebServer01: No snapshots configured (Running VM)             ║
║   • DataVM: Disk 0 is 92% full                                   ║
║   • Node 10.205.109.101: High CPU usage (85.3%)                   ║
╚═══════════════════════════════════════════════════════════════════╝
```

---

## 🎯 **Use Cases**

### **1. Compliance Auditing**
```bash
# Generate compliance report
./SuperAudit_API.py -n cluster.local -o compliance_report.xlsx

# Check Compliance sheet for:
# - Overall compliance score
# - PASS/FAIL by category
# - Warnings & Recommendations sheet for remediation
```

### **2. Capacity Planning**
```bash
# Generate capacity planning data
./SuperAudit_API.py -n cluster.local -o capacity.xlsx

# Check Capacity Planning sheet for:
# - Storage usage and available capacity
# - Expansion recommendations
# - Growth projections
```

### **3. Production VM Audits**
```bash
# Filter only production VMs
./SuperAudit_API.py -n cluster.local \
  --filter-type "PRODUCTION VM" \
  --export-json production_vms.json
```

### **4. Daily Monitoring**
```bash
# Cron job for daily reports
0 2 * * * /path/to/SuperAudit_API.py -n cluster.local \
  --export-summary /var/www/dashboard/cluster-status.json -q
```

### **5. Problem Investigation**
```bash
# Check warnings only
./SuperAudit_API.py -n cluster.local --warnings

# Filter VMs on problematic node
./SuperAudit_API.py -n cluster.local --filter-node 10.205.109.101
```

---

## 🛠️ **Troubleshooting**

### **Connection Test**
```bash
# Always test connection first
./SuperAudit_API.py -n cluster.local --test-connection
```

### **SSL Certificate Errors**
```
Error: certificate verify failed: self signed certificate
```
**Solution:** Use `--ca-bundle` with your server's certificate
```bash
echo | openssl s_client -connect cluster.local:443 -showcerts 2>/dev/null | \
  openssl x509 -outform PEM > scale_cert.pem
./SuperAudit_API.py -n cluster.local --ca-bundle scale_cert.pem
```

### **Authentication Failures**
```
Error: Login failed: HTTP 401
```
**Solution:** Test credentials manually
```bash
curl -k -u admin:password https://cluster.local/rest/v1/Node
```

---

## 📝 **Changelog**

### **v7.4 (2025-11-07) - UX & Testing**
- ✨ Test connection mode (`--test-connection`)
- ✨ Dry run mode (`--dry-run`)
- ✨ Enhanced CLI organization with grouped options

### **v7.3 (2025-11-07) - Filtering & Export**
- ✨ VM filtering (state, type, tags, name, node)
- ✨ JSON export format (`--export-json`)
- ✨ Summary statistics export (`--export-summary`)

### **v7.2 (2025-11-07) - Compliance & Capacity**
- ✨ 3 new Excel sheets (Warnings, Compliance, Capacity Planning)
- ✨ Compliance scoring (0-100)
- ✨ Categorized warnings (CRITICAL/WARNING/INFO)
- ✨ Capacity planning with recommendations

### **v7.1 (2025-11-07) - Enhanced Data**
- ✨ 9 new VM data fields (boot order, machine type, HA, network details, cache mode)
- ✨ Intelligent VM type detection
- ✨ Enhanced network and disk data

### **v7.0 (2025-11-07) - Excel Foundation**
- ✨ Excel output as default with 5 sheets
- ✨ Summary Dashboard with statistics
- ✨ Conditional formatting
- ✨ Bug fixes and session handling

---

## 📚 **Quick Reference**

```bash
# MOST COMMON COMMANDS

# Test connection
./SuperAudit_API.py -n <HOST> --test-connection

# Basic audit (interactive)
./SuperAudit_API.py -n <HOST> -u admin

# With self-signed certificate
./SuperAudit_API.py -n <HOST> -u admin --ca-bundle scale_cert.pem

# Filter production VMs
./SuperAudit_API.py -n <HOST> --filter-type "PRODUCTION VM"

# Export JSON
./SuperAudit_API.py -n <HOST> --export-json data.json

# Dry run test
./SuperAudit_API.py -n <HOST> --filter-state RUNNING --dry-run

# Health check
./SuperAudit_API.py -n <HOST> --summary-only

# Monitoring mode
./SuperAudit_API.py -n <HOST> --warnings
```

---

## 🎓 **Additional Resources**

- **In-Script Documentation:** Run `./SuperAudit_API.py --help` for full option list
- **Examples:** See script docstring for detailed usage examples
- **Security:** Review SECURITY section in script for authentication best practices

---

**Made with ❤️ for the Scale Computing Community**
