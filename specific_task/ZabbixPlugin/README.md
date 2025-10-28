# Scale Computing HyperCore by HTTP Monitoring for Zabbix

This Zabbix monitoring solution uses the Scale Computing HyperCore REST API to automatically discover and monitor your cluster's Nodes, VMs, and Physical Drives.

It uses a "host-per-object" model, meaning Zabbix will create an individual host for each discovered Node and VM, giving you a clean, organized view of your infrastructure.

## Features

This solution consists of three templates:

* **`Template Scale Computing HyperCore API` (Main Template):**
    * This is the *only* template you link to your main cluster host.
    * It performs Low-Level Discovery (LLD) to find all Nodes and VMs.
    * It creates a new Zabbix host for each Node, linking it to the `Template Scale Computing Node`.
    * It creates a new Zabbix host for each VM, linking it to the `Template Scale Computing VM`.

* **`Template Scale Computing Node` (Node Template):**
    * Monitors a single SCNode host (CPU Usage, Memory Usage, Network Status, Disposition).
    * Contains triggers for Node status (Offline, CPU, Memory).
    * Contains a *nested* LLD rule to discover all physical drives associated with *that specific node*.
    * Creates items and triggers for each drive (Health, Temperature, Error Count).

* **`Template Scale Computing VM` (VM Template):**
    * Monitors a single VM host (CPU Usage, VM State, Guest Agent Status, Disk Allocation).
    * Contains triggers for VM status (Not Running, Agent Unavailable, CPU).

## Setup Instructions

1.  **Import Templates:** Import the final YAML file (`Scale_Computing_Hypercore_Zabbix.yaml`) into your Zabbix instance. This will add all three templates and the required host groups (`HyperCore Nodes`, `Virtual machines`).

2.  **Create Cluster Host:**
    * Create a single new host in Zabbix. This host will represent your entire Scale Computing cluster (e.g., `sc-cluster.yourdomain.com`).
    * **Agent interface:** This host does not need an agent. You can remove all interfaces.
    * **Templates Tab:** Link *only* the `Template Scale Computing HyperCore API` to this host.

3.  **Configure Macros:**
    * On the **Macros** tab for your new cluster host, set the following three "Inherited and host macros":
        * `{$API_URL}`: The base URL of your cluster (e.g., `https://172.16.0.241`)
        * `{$API_USER}`: The API username (e.g., `zabbix`)
        * `{$API_PASS}`: The API user's password.

4.  **Run Discovery:**
    * Wait for the discovery rules to run (default is 5 minutes), or force them by:
        * Going to your cluster host's **Items** list.
        * Clicking **Execute now** for `HyperCore API: Get All Nodes (for LLD)`.
        * Clicking **Execute now** for `HyperCore API: Get All VMs (for LLD)`.

Within a few minutes, Zabbix will automatically create new hosts for all your VMs (e.g., `VM MyWebServer`) and Nodes (e.g., `SCNode 172.16.0.20`). These new hosts will automatically inherit the API credentials and start polling for data.

## What is Monitored

Here is a breakdown of the items that will be created on your discovered hosts.

### On Each `SCNode` Host

* **Node CPU Usage:** The total CPU utilization of the physical node, as a percentage.
* **Node Memory Usage (%)**: The total RAM utilization of the physical node, as a percentage.
* **Node Network Status:** The health of the node's network connection to the cluster. `ONLINE` is healthy.
* **Node Disposition:** The operational state of the node. `IN` is the normal, healthy state. Other states like `OUT` or `EVACUATING` will trigger an alert.
* **Discovered Drives (for each drive):**
    * **Health Status:** A boolean (True/False) reported by the drive's S.M.A.R.T. diagnostics.
    * **Temperature:** The drive's internal temperature in Celsius.
    * **Error Count:** A counter of read/write or other hardware errors.

### On Each `VM` Host

* **VM State:** The power state of the virtual machine. `RUNNING` is the normal state. Triggers on any other state (e.g., `STOPPED`, `PAUSED`).
* **Guest Agent Status:** The status of the Scale Guest Tools inside the VM's operating system. `AVAILABLE` is healthy.
* **CPU Usage:** The CPU utilization of *this specific VM*, as a percentage.
* **Disk Used Allocation (Bytes):** The total physical storage (in bytes) that the VM's virtual disks are currently consuming on the cluster.
* **Disk Allocation Growth Rate (Bps):** A calculated rate (in bytes per second) showing how fast the VM's disk allocation is growing. Useful for spotting runaway logs or backups.