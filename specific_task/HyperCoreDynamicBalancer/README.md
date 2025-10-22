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
3.  **Configure:** Open the script file and edit the variables within the `# --- Configuration ---` section:
    * **`BASE_URL`**: Set this to the full API URL of your HyperCore cluster (e.g., `"https://192.168.1.10/rest/v1"`).
    * **`USERNAME`**: Enter a HyperCore username with administrative privileges.
    * **`PASSWORD`**: Enter the password for that user.
    * **`VERIFY_SSL`**: Set to `False` if your cluster uses a self-signed certificate (most common). Set to `True` if you have a valid, trusted certificate installed.
    * **`DRY_RUN`**: **Leave this as `True` initially!** This prevents the script from making any changes.
    * *(Optional)* Adjust other tunable parameters like cooldowns, thresholds, and the averaging window as needed.
4.  **Run (Dry Run Mode):** Execute the script from your terminal:
    ```bash
    python hypercore_balancer.py
    ```
5.  **Monitor:** Observe the script's output. It will log its actions, including data collection, analysis, and *potential* migration decisions (prefixed with `*** DRY RUN:`). Let it run for a while (hours or even a day) to see how it behaves with your typical workloads.
6.  **Enable Live Migrations (Use Caution!):** Once you are confident the script is making sensible decisions:
    * Stop the script (`Ctrl+C`).
    * Edit the script and change **`DRY_RUN = True`** to **`DRY_RUN = False`**.
    * Save the file.
    * Restart the script: `python hypercore_balancer.py`. Migrations prefixed with `!!! EXECUTING MIGRATION:` will now be attempted.
7.  **Run Continuously:** For ongoing balancing, run the script in the background using tools like `nohup` (Linux/macOS) or as a scheduled task/service.
    ```bash
    # Example using nohup on Linux/macOS
    nohup python hypercore_balancer.py > balancer.log 2>&1 &
    ```
8.  **Stop:** Press `Ctrl+C` in the terminal where it's running (or use process management tools if running in the background).

---

## Purpose

This script automatically balances the workload (primarily based on CPU usage) across the nodes in a Scale Computing HyperCore cluster. It monitors node and VM performance via the REST API and initiates live migrations to prevent individual nodes from becoming overloaded, while respecting administrator-defined rules like RAM limits and affinity/anti-affinity.

---

## Features ✨

* **CPU Load Balancing:** Moves VMs from high-CPU nodes to lower-CPU nodes based on a configurable time-averaged load.
* **RAM Constraint:** Prevents migrations to nodes that would exceed a defined RAM usage percentage.
* **Node Affinity (`node_` tag):** Pins specific VMs to designated nodes (identified by the last octet of the node's IP address). Enforces this rule with the highest priority, even attempting to evict other VMs if necessary (and safe) to make space.
* **Anti-Affinity (`anti_` tag):** Prevents specified pairs of VMs from running on the same node. Enforces this rule with the second-highest priority.
* **Cooldown Timers:** Includes global (cluster), per-VM, and post-recovery cooldowns to prevent excessive migrations and allow the cluster to stabilize.
* **Node Failure Handling:** Pauses operations if a node goes offline and enters a recovery cooldown when it comes back online. Logs warnings for affinity violations caused during downtime.
* **Task Monitoring:** Tracks live migration tasks via the API and waits for completion.
* **Affinity Clearing:** Automatically removes system-set `preferredNodeUUID` and `backupNodeUUID` after a successful script-initiated migration, preventing conflicts.
* **Dry Run Mode:** Allows safe testing by simulating actions without executing migrations.

---

## Understanding Tags

You can control the balancer's behavior using specific VM tags in the HyperCore UI:

* **`node_XXX`**: (Node Affinity) Assigns a VM **permanently** to the node whose LAN IP address ends in `.XXX`.
    * *Example:* `node_101` pins the VM to the node with IP `192.168.1.101` (or similar).
    * This script will prioritize moving this VM *to* its designated node if it's running elsewhere and the node is available.
    * It will *prevent* this VM from being moved *off* its designated node for load balancing.
* **`anti_VM-Name`**: (Anti-Affinity) Prevents this VM from running on the same node as the VM named `VM-Name`. This requires a **reciprocal tag** on the other VM.
    * *Example:* VM `SQL-A` has tag `anti_SQL-B`, and VM `SQL-B` has tag `anti_SQL-A`.
    * The script will prioritize separating these VMs if they are found on the same node.
    * It will prevent migrations that would place these VMs together.

---

## How it Works (Priorities)

The script operates in a continuous loop, prioritizing actions in this order:

1.  **Monitor Active Migration:** Waits for any ongoing migration task to finish.
2.  **Check Cooldowns:** Waits for Cluster Recovery or standard Cluster Migration cooldowns.
3.  **Check Node Status:** Pauses if any node is `OFFLINE`. Initiates recovery cooldown when nodes come back online.
4.  **Fix Node Affinity Violations:** Moves VMs tagged with `node_XXX` to their correct node (highest priority action, may involve evicting other VMs).
5.  **Fix Anti-Affinity Violations:** Separates VMs tagged with `anti_` found on the same node (second priority action).
6.  **CPU/RAM Load Balance:** If the cluster is stable, cooldowns are over, no affinity rules were violated/fixed, *and* enough performance history exists:
    * Identifies CPU imbalance.
    * Selects the busiest eligible VM on the busiest node (respecting `node_` tags).
    * Finds the coolest eligible target node (checking RAM, `anti_` tags, and VM cooldown).
    * Initiates migration if a valid move is found.

---

## Dependencies

* Python 3.6 or newer
* `requests` library (`pip install requests`)