# Scale Computing HyperCore - Automated VM Load Balancer

## Disclaimer ⚠️

**THIS SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.** Use this script **at your own risk**. The author and Scale Computing are not responsible for any issues that may arise from its use. **Thoroughly test** this script in **`DRY_RUN = True`** mode before enabling live migrations.

---

## Usage Instructions

1.  **Save the Script:** Save the Python code as a `.py` file (e.g., `hypercore_balancer.py`).
2.  **Install Dependencies:** Ensure you have Python 3.6+ installed. Install the `requests` library if you don't have it:
    ```bash
    pip install requests
    ```
    *(Note: On Windows, you might need to use `py -m pip install requests`)*
3.  **Configure:** Review the `# --- Configuration (Defaults) ---` section in the script. You can either:
    * **Edit the `DEFAULT_` variables** directly in the script (especially `DEFAULT_BASE_URL`, `DEFAULT_USERNAME`, `DEFAULT_PASSWORD` if not using environment variables).
    * **Set Environment Variables:** For any setting, you can set a corresponding environment variable starting with `SC_` (e.g., `SC_HOST`, `SC_DRY_RUN`, `SC_EXCLUDE_NODE_IPS`). Environment variables **override** the defaults set in the script. See the "Configuration" section below for details.
    * **Set `DRY_RUN`:** **Leave this as `True` initially!** This prevents the script from making any changes.
4.  **Run (Dry Run Mode):** Execute the script from your terminal:
    ```bash
    python hypercore_balancer.py
    ```
    The script will print the configuration settings it's using (and whether they came from ENV or Defaults).
5.  **Monitor:** Observe the script's output. It will log its actions, including data collection, analysis, cooldowns, and *potential* migration decisions (prefixed with `*** DRY RUN:`). Let it run for a sufficient period (hours or even a day) to see how it behaves with your typical workloads and ensure it respects exclusions and affinity rules.
6.  **Enable Live Migrations (Use Caution!):** Once you are confident in its logic:
    * Stop the script (`Ctrl+C`).
    * Set the `DRY_RUN` configuration to `False` (either by editing the script's `DEFAULT_DRY_RUN` or by setting the `SC_DRY_RUN` environment variable to `False`, `0`, or `No`).
    * Save the file (if edited).
    * Restart the script: `python hypercore_balancer.py`. Migrations prefixed with `!!! EXECUTING MIGRATION:` will now be attempted.
7.  **Run Continuously:** For ongoing balancing, run the script in the background using tools like `nohup` (Linux/macOS) or as a scheduled task/service. Remember to manage environment variables appropriately if using them in a background process.
    ```bash
    # Example using nohup on Linux/macOS
    nohup python hypercore_balancer.py > balancer.log 2>&1 &
    ```
8.  **Stop:** Press `Ctrl+C` in the terminal where it's running (or use process management tools if running in the background). It will attempt to log out gracefully.

---

## Purpose

This script automatically balances the workload (primarily based on CPU usage) across the nodes in a Scale Computing HyperCore cluster. It monitors node and VM performance via the REST API and initiates live migrations to prevent individual nodes from becoming overloaded, while respecting administrator-defined rules like RAM limits, node exclusions, and affinity/anti-affinity tags. It is designed to be resilient to temporary node unreachability for status checks.

---

## Features ✨

* **CPU Load Balancing:** Migrates VMs from high-CPU nodes to lower-CPU nodes based on a configurable time-averaged load.
* **RAM Constraint Management:** Will not move a VM to a node if doing so would cause that node's RAM usage to exceed a configurable threshold.
* **Node Affinity (`node_` tag):** Pins specific VMs to designated nodes (by IP suffix). Enforces this with highest priority, attempting eviction of other non-pinned VMs if needed to make RAM space.
* **Anti-Affinity (`anti_` tag):** Prevents specified pairs of VMs from running on the same node. Enforced with second-highest priority. Migration logic also prevents moves that would violate these rules.
* **Node Exclusion:** Allows specific nodes (by IP) to be completely excluded from all balancing actions (no migrations *to* or *from*).
* **Witness/Non-Virtualization Node Handling:** Automatically detects and excludes nodes that don't support running VMs (e.g., witness nodes) from being migration targets.
* **Configurable Cooldowns:** Includes global (cluster), per-VM, and post-recovery cooldowns to prevent excessive migrations and allow the cluster to stabilize.
* **Update Check:** Checks if a cluster update or preparation is in progress via `/update/update_status.json` and pauses operations if active. Includes failover logic to check other nodes if the primary is unresponsive.
* **Node Failure Handling:** Pauses operations if any node is `OFFLINE`. Enters a recovery cooldown when all nodes come back online. Uses last known node list for update/offline checks if current data fetch fails. Logs warnings for affinity violations during downtime.
* **Task Monitoring:** Tracks live migration tasks via the API and waits for completion.
* **Automatic Re-login:** Attempts to re-authenticate automatically if an API session expires (receives a 401 Unauthorized error).
* **Environment Variable Overrides:** All configuration settings can be overridden using environment variables (`SC_...`).
* **Dry Run Mode:** Allows safe testing by simulating actions without executing migrations.

---

## Understanding Tags

You can control the balancer's behavior using specific VM tags in the HyperCore UI:

* **`node_XXX`**: (Node Affinity) Assigns a VM **permanently** to the node whose LAN IP address ends in `.XXX`. `XXX` must be numeric.
    * *Example:* `node_101` pins the VM to the node with IP `192.168.1.101` (or similar).
    * This script prioritizes moving this VM *to* its designated node if it's running elsewhere and the node is available and usable (not excluded).
    * It will *prevent* this VM from being moved *off* its designated node for load balancing.
* **`anti_VM-Name`**: (Anti-Affinity) Prevents this VM from running on the same node as the VM named `VM-Name`. This requires a **reciprocal tag** on the other VM.
    * *Example:* VM `SQL-A` has tag `anti_SQL-B`, and VM `SQL-B` has tag `anti_SQL-A`.
    * The script prioritizes separating these VMs if they are found on the same node (unless blocked by `node_` tags on both).
    * It prevents migrations that would place these VMs together.

---

## How it Works (Priorities)

The script operates in a continuous loop, prioritizing actions in this order:

1.  **Check Active Migration:** Waits for any ongoing migration task to finish.
2.  **Check Recovery Cooldown:** Waits if the cluster recently recovered from a node failure.
3.  **Check Cluster Migration Cooldown:** Waits if a migration just finished.
4.  **Collect Data:** Attempts to fetch fresh Nodes, VMs, and Stats data. Stores the node list if successful. If fetching fails, uses the last known node list *only* for status checks (steps 5 & 6) but skips subsequent actions in this cycle.
5.  **Check Cluster Update Status:** Queries `/update/update_status.json` (with failover) using the available node list. Pauses if an update/prepare is active or status is unknown.
6.  **Check Node Status:** Checks the node list for any `OFFLINE` nodes. Pauses if any are found, logs affinity warnings, and sets the `cluster_was_unstable` flag. Clears the flag and starts the recovery cooldown if nodes were previously offline but are now all online.
7.  **Update Performance History:** Adds fresh CPU data to history buffers (only if data collection in step 4 was successful).
8.  **Analyze Cluster State:** Processes fresh node/VM data to determine current load, RAM usage, and node usability (only if data collection was successful).
9.  **Fix Node Affinity Violations (P1):** Moves VMs tagged `node_XXX` to their correct, usable node if they are running elsewhere. May initiate eviction of another VM if needed to free RAM (only if data collection was successful).
10. **Fix Anti-Affinity Violations (P2):** Separates VMs violating `anti_` rules, attempting to move the non-node-pinned VM first (only if data collection was successful).
11. **Check History Buffer:** Proceeds only if enough performance history data has been collected.
12. **CPU/RAM Load Balance (P3):** If history is full and no higher-priority actions were taken:
    * Identifies CPU imbalance between the busiest and coolest *usable* nodes.
    * Selects the busiest eligible VM on the busiest node (respecting `node_` tags and VM cooldown).
    * Finds the coolest eligible *usable* target node (checking RAM, `anti_` tags).
    * Initiates migration if a valid move is found.
13. **Wait:** Pauses for the configured `SAMPLE_INTERVAL_SECONDS` before starting the next cycle.

---

## Prerequisites

* Python 3.6 or newer
* `requests` Python library (`pip install requests`)

---

## Configuration

Settings can be configured in two ways:

1.  **Environment Variables (Highest Priority):** Set environment variables starting with `SC_`. These override script defaults.
2.  **Script Defaults:** Edit the `DEFAULT_` variables near the top of the Python script.

The script will print the final effective configuration and its source (`(ENV)` or `(Default)`) when it starts.

| Script Variable                       | Environment Variable                 | Type    | Description                                                                 |
| :------------------------------------ | :----------------------------------- | :------ | :-------------------------------------------------------------------------- |
| `DEFAULT_BASE_URL`                    | `SC_HOST`                            | string  | Cluster API URL (e.g., `https://1.2.3.4` or `https://mycluster.local`)        |
| `DEFAULT_USERNAME`                    | `SC_USERNAME`                        | string  | API Username                                                                |
| `DEFAULT_PASSWORD`                    | `SC_PASSWORD`                        | string  | API Password                                                                |
| `DEFAULT_VERIFY_SSL`                  | `SC_VERIFY_SSL`                      | boolean | `True`/`False`. Verify cluster SSL certificate?                             |
| `DEFAULT_DRY_RUN`                     | `SC_DRY_RUN`                         | boolean | `True`/`False`. If True, only log actions; if False, execute migrations.  |
| `DEFAULT_AVG_WINDOW_MINUTES`          | `SC_AVG_WINDOW_MINUTES`              | integer | Minutes of history to average for CPU decisions.                            |
| `DEFAULT_SAMPLE_INTERVAL_SECONDS`     | `SC_SAMPLE_INTERVAL_SECONDS`         | integer | Seconds between data collection cycles.                                     |
| `DEFAULT_RAM_LIMIT_PERCENT`           | `SC_RAM_LIMIT_PERCENT`               | float   | Max RAM % allowed on a target node after migration (0-100).               |
| `DEFAULT_CPU_UPPER_THRESHOLD_PERCENT` | `SC_CPU_UPPER_THRESHOLD_PERCENT`     | float   | Avg CPU % above which a node is considered a migration source (0-100).    |
| `DEFAULT_CPU_LOWER_THRESHOLD_PERCENT` | `SC_CPU_LOWER_THRESHOLD_PERCENT`     | float   | Avg CPU % below which a node is considered a migration target (0-100).    |
| `DEFAULT_MIGRATION_COOLDOWN_MINUTES`  | `SC_MIGRATION_COOLDOWN_MINUTES`      | integer | Minutes to wait after *any* migration before starting another.            |
| `DEFAULT_VM_MOVE_COOLDOWN_MINUTES`    | `SC_VM_MOVE_COOLDOWN_MINUTES`        | integer | Minutes to wait before the *same VM* can be moved again.                  |
| `DEFAULT_RECOVERY_COOLDOWN_MINUTES`   | `SC_RECOVERY_COOLDOWN_MINUTES`       | integer | Minutes to wait after cluster recovers from an offline node.                |
| `DEFAULT_EXCLUDE_NODE_IPS`            | `SC_EXCLUDE_NODE_IPS`                | list    | Comma-separated list of node LAN IPs to exclude entirely (e.g., `"1.1.1.1,2.2.2.2"`) |

**Boolean ENV VARS:** Use `True`, `1`, `Yes`, `Y` or `False`, `0`, `No`, `N` (case-insensitive).
**List ENV VARS:** Use comma-separated strings.

---

## Running the Script

See Usage Instructions at the top. Remember to start in Dry Run mode!