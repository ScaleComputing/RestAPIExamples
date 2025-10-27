# Scale Computing HyperCore Monitoring Template

This Zabbix template is designed to monitor a Scale Computing HyperCore cluster by directly querying its REST API (v1). It utilizes the **HTTP Agent** and **Low-Level Discovery (LLD)** to automatically monitor nodes, virtual machines (VMs), and physical drives, including real-time performance metrics and disposition status.

This template has been validated on **Zabbix 7.0** and is engineered to handle complex JSON data and array parsing errors common in API integrations.

---

## 🚀 Usage and Setup

### 1. Prerequisites

1.  **Zabbix Version:** Zabbix 5.4 or newer (optimized for 7.0).

2.  **API Access:** A valid Scale Computing HyperCore user account with read-only API access.

### 2. Import Template

1.  Go to **Data collection** -> **Templates** in the Zabbix frontend.

2.  Click **Import** (top right corner).

3.  Select the YAML template file (e.g., `template_scale_api_final.yaml`).

4.  Click **Import**.

### 3. Configure Host and Macros

The template requires three mandatory host macros to successfully authenticate and connect to the HyperCore API.

1.  Go to **Data collection** -> **Hosts**.

2.  Select the host representing your Scale Computing cluster (or create a new one).

3.  Go to the **Templates** tab and link the `Scale Computing HyperCore by HTTP` template.

4.  Go to the **Macros** tab and set the following values:

| Macro | Type | Example Value | Description |
| :---- | :---- | :---- | :---- |
| **{$API_URL}** | Text | https://172.16.0.241 | The base URL of the HyperCore API (must include http:// or https://). **Do not include /rest/v1.** |
| **{$API_USER}** | Text | api_reader | Username for Basic Authentication. |
| **{$API_PASS}** | **Secret text** | P@$$w0rdS3curE! | Password for Basic Authentication. (Must be stored as Secret text). |

5.  Click **Update**. The master items should turn green within one minute, and discovery should begin shortly thereafter.

---

## 📊 Monitored Metrics (LLD)

The template utilizes four master HTTP Agent items to retrieve data and three Low-Level Discovery rules to dynamically create items for each unique resource found.

### 1. Node Discovery (Cluster Members)

| LLD Macro | Item Prototype | Unit | Description |
| :-------- | :------------- | :--- | :---------- |
| {##NODE_NAME} | **CPU Usage** | % | Current CPU utilization of the node. |
| | **Memory Usage** | % | Current total memory utilization of the node. |
| | **Network Status** | Char | Network connectivity status (ONLINE, OFFLINE). |
| | **Disposition** | Char | Node status regarding cluster participation (IN, EVACUATED, OUT). |

### 2. VM Discovery (Virtual Machines)

| LLD Macro | Item Prototype | Unit | Description |
| :-------- | :------------- | :--- | :---------- |
| {##VM_NAME} | **State** | Char | Current power state of the VM (RUNNING, SHUTOFF, etc.). |
| | **Guest Agent Status** | Char | Status of the Scale Guest Agent (AVAILABLE, UNAVAILABLE). |
| | **CPU Usage** | % | Current CPU utilization by the VM. |
| | **Network RX Rate** | bps | Incoming network traffic rate. |
| | **Network TX Rate** | bps | Outgoing network traffic rate. |
| | **Total Disk Capacity** | B | Logical capacity reserved for the VM (sum of all virtual disks). |
| | **Disk Used Allocation** | B | Actual disk space used (allocated) by the VM on shared storage. |

### 3. Physical Drive Discovery

| LLD Macro | Item Prototype | Unit | Description |
| :-------- | :------------- | :--- | :---------- |
| {##DRIVE_SN} | **Health Status** | Float | Drive health status (0=Unhealthy, 1=Healthy). Uses "Zabbix boolean" Value Map. |
| | **Temperature** | C | Current reported drive temperature. |
| | **Error Count** | errors | Total count of drive errors (reallocated sectors, etc.). |

### 🚨 Trigger Thresholds

* **Node Offline:** High priority if **Network Status is not ONLINE**.

* **Node Disposition:** Warning if **Disposition is not IN**.

* **Utilization:** Warning if Node CPU or Memory Usage average exceeds **90%** over 5 minutes.

* **Drive Health:** High priority if **Health Status is False (0)**.

* **Guest Agent:** Warning if **Guest Agent Status is not AVAILABLE** while the VM is running.