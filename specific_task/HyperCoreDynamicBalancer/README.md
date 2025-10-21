HyperCore Automated Load Balancer Script Documentation
1. Overview
This Python script is an automated resource balancer for a Scale Computing HyperCore cluster. Its primary goal is to ensure that no single node in the cluster is consistently overloaded, thereby maintaining a healthy and performant environment for all virtual machines.

It operates by connecting to the HyperCore REST API, continuously monitoring resource utilization (CPU and RAM), and automatically live-migrating virtual machines based on a predefined set of rules and priorities. The script is designed to be run continuously as a background service.

2. Key Features
CPU Load Balancing: Migrates VMs from nodes with high average CPU load to nodes with lower CPU load.

RAM Constraint Management: Will not move a VM to a node if doing so would cause that node's RAM usage to exceed a configurable threshold (e.g., 70%).

Anti-Affinity Rules:

Violation Fixing (High Priority): If it finds two VMs running on the same node that shouldn't be (based on anti_ tags), it will immediately try to migrate one of them. This rule takes precedence over all other balancing logic.

Migration Veto: Prevents a load-balancing migration from occurring if it would place a VM on a node with an anti-affinity partner.

Configurable Cooldowns:

Cluster Cooldown: A global waiting period after any migration to allow the cluster to stabilize.

VM Cooldown: A VM-specific waiting period to prevent the same VM from being moved back and forth ("flapping").

Task Monitoring: After initiating a migration, it monitors the API task status and waits for completion before starting the cooldown timer.

Dry Run Mode: A safety feature (enabled by default) that allows you to see what actions the script would take without actually performing any live migrations.

3. How It Works: The Decision Logic
The script runs in an infinite loop, with each cycle following a strict order of operations:

Check for Active Migration: If a migration was started in a previous cycle, the script will pause and do nothing else but check the API task status until that migration is COMPLETE or has ERRORed.

Check Cluster Cooldown: If a migration has recently finished, the script will wait for the MIGRATION_COOLDOWN_MINUTES period to pass before proceeding.

Collect & Update Data: It fetches the latest data for all nodes, VMs, and their performance stats from the API. This new data is added to a historical data queue (a deque).

Anti-Affinity Violation Check (Highest Priority Action):

The script immediately checks if any running VMs violate the anti_ tag rule (e.g., VM-A has tag anti_VM-B and both are on the same node).

If a violation is found, it will immediately try to find a new node for one of the VMs that respects RAM limits.

If it initiates a migration to fix a violation, the script's main loop restarts. It will not proceed to CPU load balancing in that cycle.

Check History Buffer: The script checks if it has collected enough historical data samples (defined by AVG_WINDOW_MINUTES). If not, it waits for the next cycle. This prevents it from making decisions based on short, temporary spikes.

CPU/RAM Load Balancing (Normal Operation): If the history buffer is full and no anti-affinity violation was fixed, the script proceeds with its main balancing logic:

a. Identify Imbalance: It calculates the average CPU usage for all nodes over the time window. It identifies the most-loaded ("busiest") and least-loaded ("coolest") nodes. A potential imbalance exists if the busiest node is above CPU_UPPER_THRESHOLD_PERCENT and the coolest is below CPU_LOWER_THRESHOLD_PERCENT.

b. Select Candidate VM: It looks at the busiest VM (by average CPU) on the busiest node.

c. Find a Target Node: It iterates through all other nodes, starting from the coolest one. For each potential target node, it performs the following checks in order:

VM Cooldown Check: Has this specific VM been moved within the VM_MOVE_COOLDOWN_MINUTES? If yes, this VM is skipped, and the script evaluates the next busiest VM on the hot node.

RAM Limit Check: Would moving this VM to the target node cause the target's RAM to exceed RAM_LIMIT_PERCENT? If yes, this target node is skipped, and the script checks the next coolest node.

Anti-Affinity Veto Check: Would moving this VM to the target node create an anti-affinity violation? If yes, this target node is skipped, and the script checks the next coolest node.

d. Initiate Migration: If a VM passes all checks for a valid target node, the script initiates the live migration and the main loop restarts.

4. Prerequisites
Python 3.6+

The requests Python library. Install it via pip:

Bash

pip install requests
5. Configuration
All user-configurable parameters are located at the top of the script.

Required Settings (Must be changed):

BASE_URL: The full API endpoint for your HyperCore cluster. Example: "https://192.168.10.20/rest/v1"

USERNAME: A username with administrative privileges on the HyperCore cluster.

PASSWORD: The password for the specified user.

VERIFY_SSL: Set to False if your cluster uses a self-signed SSL certificate (common). Set to True if you have a valid, trusted certificate installed.

Tuning & Behavior Settings:

DRY_RUN: IMPORTANT! When True (default), the script will only print the actions it would take. When False, it will execute live migrations. Always run in DRY_RUN mode first to validate its behavior.

AVG_WINDOW_MINUTES: The number of minutes of historical data to average for making CPU-based decisions. A longer window makes the script less sensitive to brief spikes.

SAMPLE_INTERVAL_SECONDS: How often the script polls the API for new data.

RAM_LIMIT_PERCENT: The maximum percentage of RAM a target node can be using after a VM is migrated to it. A value of 70.0 leaves 30% headroom.

CPU_UPPER_THRESHOLD_PERCENT: A node's average CPU must be above this percentage to be considered "hot" and a source for migrations.

CPU_LOWER_THRESHOLD_PERCENT: A potential target node's average CPU must be below this percentage. The gap between the upper and lower thresholds prevents constant migrations.

MIGRATION_COOLDOWN_MINUTES: The global waiting period after a migration task completes before the script will consider initiating another one.

VM_MOVE_COOLDOWN_MINUTES: The "no-fly" period for a specific VM after it has been moved, to prevent flapping.

6. Running the Script
Save the script as a Python file (e.g., hypercore_balancer.py).

Open the file and edit the Configuration section with your cluster's details.

Start with DRY_RUN = True.

Run the script from your terminal:

Bash

python hypercore_balancer.py
Observe the log output for several hours to ensure it makes sensible decisions for your workload patterns.

When you are confident in its logic, stop the script (Ctrl+C), change DRY_RUN = False, and restart it.

To stop the script permanently, press Ctrl+C. It will attempt to log out of its API session gracefully.

7. Understanding the Log Output
The script provides verbose output so you can follow its logic.

Collecting cluster data...: The script is polling the API.

Collecting data... history 5/10 samples.: The script is filling its history buffer before making load-balancing decisions.

Checking for anti-affinity violations...: The high-priority check is running.

VIOLATION FOUND...: It has detected two VMs on the same node that violate an anti_ tag rule and will attempt to fix it.

Imbalance detected...: The CPU load on the nodes is outside the defined thresholds.

Evaluating candidate VM...: The script is looking at a specific VM on the hot node.

Checking target node...: The script is checking if the VM can be moved to one of the cooler nodes.

RAM Check: OK/FAILED: Shows the result of the RAM limit check.

Anti-Affinity Check: OK/FAILED: Shows the result of the anti-affinity veto check.

DRY RUN / EXECUTING MIGRATION: The final decision for a migration.

Waiting for active migration (Task XXX)...: The script has initiated a move and is now polling the task's status.