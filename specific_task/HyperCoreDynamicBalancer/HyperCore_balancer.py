#!/usr/bin/env python3

"""

Script to demonstrate load balancing virtual machines accross nodes in a Scale Computing Hypercore cluster.

make sure to read the README on github.com/scalecomputing for info on using this script.

THIS SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND
feel free to use without attribution in any way as seen fit, at your own risc.

Usage: Set the variables in the Configuration section and run this script as a service.

William David van Collenburg
Scale Computing

dependencies: on Windows systems 'requests' must be installed manually (pip install requests)

"""


import requests
import time
import json
import warnings
import sys
from collections import deque
from statistics import mean

# --- Configuration ---

# Cluster Connection
BASE_URL = "https://your_hypercore_address/rest/v1"  # !! CHANGE THIS
USERNAME = "admin"                             # !! CHANGE THIS
PASSWORD = "admin"                             # !! CHANGE THIS
VERIFY_SSL = False                                     # Set to True if you have valid SSL certs

# Load Balancer Tunables
DRY_RUN = True  # !! SET TO False TO ENABLE LIVE MIGRATIONS !!

# How long to average data for decisions
AVG_WINDOW_MINUTES = 5

# How often to collect new data
SAMPLE_INTERVAL_SECONDS = 30

# RAM constraint: Do not move a VM to a host if it would exceed this limit
RAM_LIMIT_PERCENT = 70.0

# CPU thresholds for balancing
CPU_UPPER_THRESHOLD_PERCENT = 70.0  # A node's avg CPU must be *above* this to be a source
CPU_LOWER_THRESHOLD_PERCENT = 60.0  # A node's avg CPU must be *below* this to be a target

# How long to wait *after* a migration task completes before attempting another
MIGRATION_COOLDOWN_MINUTES = 5

# How long to wait before a *specific VM* can be moved again
VM_MOVE_COOLDOWN_MINUTES = 30

# --- End of Configuration ---

# !!! You should not have to change anything below this point !!!


# Suppress InsecureRequestWarning if VERIFY_SSL is False
if not VERIFY_SSL:
    from urllib3.exceptions import InsecureRequestWarning
    warnings.simplefilter('ignore', InsecureRequestWarning)


class HyperCoreApiClient:
    """A simple client for the Scale Computing HyperCore API."""
    
    def __init__(self, base_url, verify_ssl=True):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.verify = verify_ssl

    def login(self, username, password):
        """Logs in to the API and stores the session cookie."""
        login_url = f"{self.base_url}/login"
        credentials = {"username": username, "password": password}
        try:
            response = self.session.post(login_url, json=credentials)
            response.raise_for_status()
            print("Successfully logged in.")
            return True
        except requests.exceptions.RequestException as e:
            print(f"Login failed: {e}")
            return False

    def logout(self):
        """Logs out of the current session."""
        try:
            self.session.post(f"{self.base_url}/logout")
            print("Successfully logged out.")
        except requests.exceptions.RequestException as e:
            print(f"Logout failed: {e}")

    def _get(self, endpoint):
        """Helper function for GET requests."""
        response = self.session.get(f"{self.base_url}{endpoint}")
        response.raise_for_status()
        return response.json()

    def _post(self, endpoint, data):
        """Helper function for POST requests."""
        response = self.session.post(f"{self.base_url}{endpoint}", json=data)
        response.raise_for_status()
        return response.json()

    def get_nodes(self):
        """Fetches all Node objects."""
        return self._get("/Node")

    def get_vms(self):
        """Fetches all VirDomain objects."""
        return self._get("/VirDomain")

    def get_vm_stats(self):
        """Fetches all VirDomainStats objects."""
        return self._get("/VirDomainStats")

    def migrate_vm(self, vm_uuid, target_node_uuid):
        """Initiates a live migration for a VM."""
        action = [
            {
                "virDomainUUID": vm_uuid,
                "actionType": "LIVEMIGRATE",
                "nodeUUID": target_node_uuid
            }
        ]
        return self._post("/VirDomain/action", action)

    def get_task_status(self, task_tag):
        """Fetches the status of a specific task tag."""
        try:
            # The API returns a list, even for a single task tag
            status_list = self._get(f"/TaskTag/{task_tag}")
            if status_list:
                # Return the state string, e.g., "RUNNING", "COMPLETE"
                return status_list[0]['state']
        except requests.exceptions.RequestException as e:
            print(f"  - Warning: Could not get status for task {task_tag}. {e}")
            
        return "UNKNOWN" # Task not found or error


class LoadBalancer:
    """Manages the data collection and load balancing logic."""

    def __init__(self, client, config):
        self.client = client
        self.config = config
        
        # Calculate max history size based on window and interval
        self.max_history_size = int(
            (config['AVG_WINDOW_MINUTES'] * 60) / config['SAMPLE_INTERVAL_SECONDS']
        )
        if self.max_history_size < 1:
            print(f"Error: AVG_WINDOW_MINUTES must be >= SAMPLE_INTERVAL_SECONDS.")
            sys.exit(1)
            
        print(f"Data history will be {self.max_history_size} samples (for {config['AVG_WINDOW_MINUTES']} min).")

        # Data stores for averaging
        self.node_cpu_history = {}  # {node_uuid: deque([cpu1, cpu2, ...])}
        self.vm_cpu_history = {}    # {vm_uuid: deque([cpu1, cpu2, ...])}
        
        self.last_migration_time = 0
        # Tracks the current migration: {"taskTag": "123", "vm_uuid": "abc-def"}
        self.active_migration_task = None 
        # Tracks when a VM was last moved: {vm_uuid: timestamp}
        self.vm_last_moved_times = {}

    def collect_data(self):
        """Fetches all required data from the API."""
        try:
            nodes = self.client.get_nodes()
            vms = self.client.get_vms()
            vm_stats = self.client.get_vm_stats()
            return nodes, vms, vm_stats
        except requests.exceptions.RequestException as e:
            print(f"Error collecting data: {e}")
            return None, None, None

    def update_history(self, nodes, vms, vm_stats):
        """Updates the CPU history deques with new data."""
        
        # Update node history
        for node in nodes:
            if node['uuid'] not in self.node_cpu_history:
                self.node_cpu_history[node['uuid']] = deque(maxlen=self.max_history_size)
            # 'cpuUsage' is a property on the Node object itself
            self.node_cpu_history[node['uuid']].append(node.get('cpuUsage', 0.0))
            
        # Update VM history
        for stat in vm_stats:
            if stat['uuid'] not in self.vm_cpu_history:
                self.vm_cpu_history[stat['uuid']] = deque(maxlen=self.max_history_size)
            self.vm_cpu_history[stat['uuid']].append(stat.get('cpuUsage', 0.0))

    def get_cluster_state(self, nodes, vms):
        """
        Analyzes and returns the current state of the cluster.
        This uses the *current* state of the history deques.
        """
        
        node_analysis = {}

        for node in nodes:
            node_uuid = node['uuid']
            # Only consider nodes that can run VMs
            if not node.get('allowRunningVMs', False):
                continue

            # Calculate average CPU from history (even if not full)
            if node_uuid in self.node_cpu_history and len(self.node_cpu_history[node_uuid]) > 0:
                avg_cpu = mean(self.node_cpu_history[node_uuid])
            else:
                avg_cpu = node.get('cpuUsage', 0.0)
                
            # Calculate current RAM usage
            total_ram_bytes = node['memSize']
            used_ram_bytes = node['totalMemUsageBytes']
            ram_percent = (used_ram_bytes / total_ram_bytes) * 100 if total_ram_bytes > 0 else 0
            
            # Find all running VMs on this node
            vms_on_this_node = []
            for vm in vms:
                if vm['nodeUUID'] == node_uuid and vm['state'] == 'RUNNING':
                    vm_avg_cpu = 0
                    if vm['uuid'] in self.vm_cpu_history and len(self.vm_cpu_history[vm['uuid']]) > 0:
                        vm_avg_cpu = mean(self.vm_cpu_history[vm['uuid']])
                    vms_on_this_node.append({
                        "uuid": vm['uuid'],
                        "name": vm['name'],
                        "mem": vm['mem'],
                        "avg_cpu": vm_avg_cpu
                    })
            
            # Sort VMs by highest average CPU
            vms_on_this_node.sort(key=lambda x: x['avg_cpu'], reverse=True)
            
            node_analysis[node_uuid] = {
                "uuid": node_uuid,
                "name": node.get('lanIP', node_uuid), # Use IP for name
                "avg_cpu": avg_cpu,
                "total_ram": total_ram_bytes,
                "used_ram": used_ram_bytes,
                "ram_percent": ram_percent,
                "running_vms": vms_on_this_node,
                "full_object": node
            }
            
        return node_analysis

    def _get_vm_tags(self, vm):
        """Helper to safely parse VM tags."""
        return [t.strip() for t in (vm.get('tags') or "").split(',') if t.strip()]

    def find_and_fix_anti_affinity_violation(self, cluster_state, vms, nodes):
        """
        Finds the first anti-affinity violation and initiates a move to fix it.
        Returns True if a fix was initiated, False otherwise.
        """
        print("Checking for anti-affinity violations...")
        
        # Build VM lookup maps
        vm_name_to_vm_map = {vm['name']: vm for vm in vms}
        vm_uuid_to_vm_map = {vm['uuid']: vm for vm in vms}

        for vm_a in vms:
            vm_a_tags = self._get_vm_tags(vm_a)
            if not vm_a_tags:
                continue

            for tag in vm_a_tags:
                if tag.startswith('anti_'):
                    target_vm_name = tag[len("anti_"):]
                    vm_b = vm_name_to_vm_map.get(target_vm_name)

                    # If tag is stale or VM-B doesn't exist, ignore it
                    if not vm_b:
                        continue 
                    
                    # Check for violation
                    if vm_a['nodeUUID'] == vm_b['nodeUUID'] and vm_a['state'] == 'RUNNING':
                        print(f"  - VIOLATION FOUND: VM {vm_a['name']} (tag '{tag}') is on the same node as {vm_b['name']}.")
                        
                        # Find a new home for vm_a
                        
                        # Get potential target nodes (any node but this one)
                        potential_targets = [n for n in cluster_state.values() if n['uuid'] != vm_a['nodeUUID'] and n['full_object'].get('allowRunningVMs', False)]
                        # Sort by least RAM used
                        potential_targets.sort(key=lambda x: x['ram_percent'])
                        
                        target_node = None
                        for node in potential_targets:
                            # Check RAM capacity
                            projected_ram_use = node['used_ram'] + vm_a['mem']
                            projected_ram_percent = (projected_ram_use / node['total_ram']) * 100
                            
                            if projected_ram_percent <= self.config['RAM_LIMIT_PERCENT']:
                                target_node = node
                                break # Found a valid target
                        
                        if not target_node:
                            print(f"  - ERROR: Violation found for {vm_a['name']} but no other node has enough RAM to move it.")
                            return False # Can't fix it

                        # --- Initiate Migration ---
                        vm_uuid = vm_a['uuid']
                        
                        if self.config['DRY_RUN']:
                            print(f"\n  *** DRY RUN (Anti-Affinity): Would migrate VM '{vm_a['name']}' ({vm_uuid}) ***")
                            print(f"  *** FROM: {cluster_state[vm_a['nodeUUID']]['name']} ({vm_a['nodeUUID']}) ***")
                            print(f"  *** TO:   {target_node['name']} ({target_node['uuid']}) ***")
                            
                            # Simulate cluster and VM cooldown
                            self.last_migration_time = time.time()
                            self.vm_last_moved_times[vm_uuid] = time.time()
                            self.node_cpu_history.clear()
                            self.vm_cpu_history.clear()

                        else:
                            print(f"\n  !!! EXECUTING MIGRATION (Anti-Affinity): Moving VM '{vm_a['name']}' ({vm_uuid}) !!!")
                            print(f"  !!! FROM: {cluster_state[vm_a['nodeUUID']]['name']} ({vm_a['nodeUUID']}) !!!")
                            print(f"  !!! TO:   {target_node['name']} ({target_node['uuid']}) !!!")
                            try:
                                response_data = self.client.migrate_vm(vm_uuid, target_node['uuid'])
                                task_tag = response_data.get('taskTag')
                                
                                if task_tag:
                                    self.active_migration_task = { "taskTag": task_tag, "vm_uuid": vm_uuid }
                                    print(f"  - Migration initiated. Now monitoring task tag: {task_tag}")
                                else:
                                    print("  - Migration initiated, but no task tag. Relying on cooldown only.")
                                    self.last_migration_time = time.time()
                                    self.vm_last_moved_times[vm_uuid] = time.time()

                            except requests.exceptions.RequestException as e:
                                print(f"  - Migration command failed: {e}")
                                self.last_migration_time = time.time()
                        
                        return True # A fix was initiated, stop checking and wait for next cycle

        print("  - No anti-affinity violations found.")
        return False # No violations found

    def find_migration_candidate(self, cluster_state, vms):
        """
        Finds the busiest node, the least busy node, and the best VM to move
        for CPU/RAM balancing, while respecting all constraints.
        Returns (vm_to_move, source_node, target_node) or (None, None, None)
        """
        
        # Sort nodes by average CPU load
        sorted_nodes = sorted(cluster_state.values(), key=lambda x: x['avg_cpu'])
        
        # Busiest node is the last one. All others are potential targets,
        # already sorted from coolest to warmest.
        busiest_node = sorted_nodes[-1]
        potential_target_nodes = sorted_nodes[:-1]

        # Don't try to balance if we don't have at least 2 nodes
        if len(potential_target_nodes) == 0:
            return None, None, None
            
        # Imbalance check still compares busiest to *coolest*
        least_busy_node = potential_target_nodes[0] 
        
        is_imbalanced = (
            busiest_node['avg_cpu'] > self.config['CPU_UPPER_THRESHOLD_PERCENT'] and
            least_busy_node['avg_cpu'] < self.config['CPU_LOWER_THRESHOLD_PERCENT']
        )
        
        if not is_imbalanced:
            # System is within thresholds
            return None, None, None

        print(f"Imbalance detected: Node {busiest_node['name']} (avg {busiest_node['avg_cpu']:.1f}%) is hot. "
              f"Node {least_busy_node['name']} (avg {least_busy_node['avg_cpu']:.1f}%) is cool.")
              
        # --- Build VM lookup maps ---
        vm_name_to_vm_map = {vm['name']: vm for vm in vms}
        vm_uuid_to_vm_map = {vm['uuid']: vm for vm in vms}

        # Outer loop: Iterate through VMs on the busiest node (from busiest to coolest)
        for vm_to_move in busiest_node['running_vms']:
            vm_uuid = vm_to_move['uuid']
            print(f"  - Evaluating candidate VM: {vm_to_move['name']} (avg CPU {vm_to_move['avg_cpu']:.1f}%)")

            # --- 1. VM COOLDOWN CHECK ---
            time_since_last_vm_move = time.time() - self.vm_last_moved_times.get(vm_uuid, 0)
            if time_since_last_vm_move < (self.config['VM_MOVE_COOLDOWN_MINUTES'] * 60):
                print(f"  - VM Cooldown Check: FAILED. (Moved {time_since_last_vm_move/60:.1f} mins ago).")
                continue # Skip this VM entirely, try the next VM
            print(f"  - VM Cooldown Check: OK")

            # --- NEW INNER LOOP: Iterate through potential target nodes (coolest to warmest) ---
            for target_node in potential_target_nodes:
                print(f"  -   Checking target node: {target_node['name']} (avg CPU {target_node['avg_cpu']:.1f}%)")
                target_node_uuid = target_node['uuid']

                # --- 2. RAM CONSTRAINT CHECK (for this target_node) ---
                projected_ram_use = target_node['used_ram'] + vm_to_move['mem']
                projected_ram_percent = (projected_ram_use / target_node['total_ram']) * 100
                
                if projected_ram_percent > self.config['RAM_LIMIT_PERCENT']:
                    print(f"  -     RAM Check: FAILED. (Target would be {projected_ram_percent:.1f}%).")
                    continue # Try next target node
                print(f"  -     RAM Check: OK. (Target would be {projected_ram_percent:.1f}%).")

                # --- 3. ANTI-AFFINITY VETO CHECK (for this target_node) ---
                vm_a = vm_uuid_to_vm_map.get(vm_uuid) # The VM we want to move
                vms_on_target = [vm for vm in vms if vm['nodeUUID'] == target_node_uuid]
                
                will_create_violation = False
                violation_reason = ""

                # Rule 3a: Check tags on the VM we are moving (vm_a)
                vm_a_tags = self._get_vm_tags(vm_a)
                for tag in vm_a_tags:
                    if tag.startswith('anti_'):
                        target_vm_name = tag[len("anti_"):]
                        for vm_b in vms_on_target:
                            if vm_b['name'] == target_vm_name:
                                will_create_violation = True
                                violation_reason = f"VM {vm_a['name']} tag '{tag}' conflicts with {vm_b['name']}"
                                break
                    if will_create_violation: break
                
                # Rule 3b: Check tags on target VMs against the VM we are moving (vm_a)
                if not will_create_violation:
                    for vm_b in vms_on_target:
                        vm_b_tags = self._get_vm_tags(vm_b)
                        for tag in vm_b_tags:
                            if tag == f"anti_{vm_a['name']}":
                                will_create_violation = True
                                violation_reason = f"Target VM {vm_b['name']} tag '{tag}' conflicts with {vm_a['name']}"
                                break
                        if will_create_violation: break
                
                if will_create_violation:
                    print(f"  -     Anti-Affinity Check: FAILED. {violation_reason}.")
                    continue # Try next target node
                
                print(f"  -     Anti-Affinity Check: OK")
                
                # --- All Checks Passed for this VM and this Target ---
                print(f"  -> Selected {vm_to_move['name']} for migration to {target_node['name']}.")
                return vm_to_move, busiest_node, target_node
            
            # If we get here (end of inner loop), this VM couldn't be placed on *any* target node
            print(f"  - VM {vm_to_move['name']} could not be placed on any valid target node.")
            # The outer loop will now continue to the next VM

        
        # If we get here (end of outer loop), no VM could be moved
        print("Imbalance detected, but no suitable VM (meeting all constraints) could be moved.")
        return None, None, None
    # --- END OF MODIFIED FUNCTION ---

    def run(self):
        """Main execution loop for the load balancer."""
        
        while True:
            print(f"\n--- {time.ctime()} ---")

            # --- 1. Check for Active Migration ---
            if self.active_migration_task:
                task_tag = self.active_migration_task['taskTag']
                print(f"Waiting for active migration (Task {task_tag}) to complete...")
                status = self.client.get_task_status(task_tag)
                print(f"  - Current task state: {status}")
                
                # Check for terminal states
                if status in ["COMPLETE", "ERROR", "UNINITIALIZED", "UNKNOWN"]:
                    vm_uuid = self.active_migration_task['vm_uuid']
                    
                    if status == "COMPLETE":
                        print(f"  - Migration task {task_tag} for VM {vm_uuid} is complete.")
                        # Record the VM's specific move time
                        self.vm_last_moved_times[vm_uuid] = time.time()
                        print(f"  - VM {vm_uuid} is now in its personal {self.config['VM_MOVE_COOLDOWN_MINUTES']} min cooldown.")
                    else:
                        print(f"  - WARNING: Migration task {task_tag} for VM {vm_uuid} finished with {status}.")
                    
                    self.active_migration_task = None # Clear the task
                    self.last_migration_time = time.time() # Start cluster cooldown *now*
                    
                    # Clear history to force data recollection after migration
                    self.node_cpu_history.clear()
                    self.vm_cpu_history.clear()
                else:
                    # Task is still QUEUED or RUNNING
                    time.sleep(self.config['SAMPLE_INTERVAL_SECONDS'])
                    continue # Skip to the next loop iteration

            
            # --- 2. Check Cluster Cooldown ---
            time_since_last_move = time.time() - self.last_migration_time
            if time_since_last_move < (self.config['MIGRATION_COOLDOWN_MINUTES'] * 60):
                print(f"In *cluster* migration cooldown. Waiting another "
                      f"{(self.config['MIGRATION_COOLDOWN_MINUTES'] * 60) - time_since_last_move:.0f} seconds.")
                time.sleep(self.config['SAMPLE_INTERVAL_SECONDS'])
                continue

            # --- 3. Collect Data ---
            print("Collecting cluster data...")
            nodes, vms, vm_stats = self.collect_data()
            if not all([nodes, vms, vm_stats]):
                print("Failed to collect data, will retry...")
                time.sleep(self.config['SAMPLE_INTERVAL_SECONDS'])
                continue
                
            # --- 4. Update History ---
            self.update_history(nodes, vms, vm_stats)
            
            # --- 5. Analyze Cluster State (based on current history) ---
            cluster_state = self.get_cluster_state(nodes, vms)
            
            # --- 6. Check for Anti-Affinity Violations (Priority 1) ---
            # This check runs EVERY cycle, regardless of history.
            violation_fix_initiated = self.find_and_fix_anti_affinity_violation(cluster_state, vms, nodes)
            if violation_fix_initiated:
                print("Anti-affinity fix initiated. Waiting for next cycle.")
                time.sleep(self.config['SAMPLE_INTERVAL_SECONDS'])
                continue # Skip load balancing for this cycle
            
            # --- 7. Check if History is Full (for Load Balancing) ---
            first_node_hist = next(iter(self.node_cpu_history.values()), None)
            if not first_node_hist or len(first_node_hist) < self.max_history_size:
                print(f"Collecting data... history {len(first_node_hist or [])}/{self.max_history_size} samples.")
                time.sleep(self.config['SAMPLE_INTERVAL_SECONDS'])
                continue
            
            print("History is full. Analyzing for load balancing...")

            # --- 8. Analyze and Find (Load Balancing) Candidates ---
            vm_to_move, source_node, target_node = self.find_migration_candidate(cluster_state, vms) # Pass vms

            # --- 9. Perform (Load Balancing) Migration ---
            if vm_to_move and source_node and target_node:
                vm_uuid = vm_to_move['uuid']
                
                if self.config['DRY_RUN']:
                    print(f"\n*** DRY RUN (Load Balance): Would migrate VM '{vm_to_move['name']}' ({vm_uuid}) ***")
                    print(f"*** FROM: {source_node['name']} ({source_node['uuid']}) ***")
                    print(f"*** TO:   {target_node['name']} ({target_node['uuid']}) ***")
                    
                    # Simulate starting the cluster cooldown
                    self.last_migration_time = time.time()
                    # Simulate recording the VM's last move time
                    self.vm_last_moved_times[vm_uuid] = time.time()
                    print(f"*** VM {vm_uuid} is now in its personal {self.config['VM_MOVE_COOLDOWN_MINUTES']} min cooldown (simulation). ***")
                    
                    self.node_cpu_history.clear()
                    self.vm_cpu_history.clear()
                    print(f"Entering {self.config['MIGRATION_COOLDOWN_MINUTES']} minute *cluster* cooldown (simulation).")
                    
                else:
                    print(f"\n!!! EXECUTING MIGRATION (Load Balance): Moving VM '{vm_to_move['name']}' ({vm_uuid}) !!!")
                    print(f"!!! FROM: {source_node['name']} ({source_node['uuid']}) !!!")
                    print(f"!!! TO:   {target_node['name']} ({target_node['uuid']}) !!!")
                    try:
                        # Capture the response to get the taskTag
                        response_data = self.client.migrate_vm(vm_uuid, target_node['uuid'])
                        task_tag = response_data.get('taskTag')
                        
                        if task_tag:
                            self.active_migration_task = {
                                "taskTag": task_tag,
                                "vm_uuid": vm_uuid
                            }
                            print(f"Migration initiated. Now monitoring task tag: {task_tag}")
                        else:
                            print("Migration initiated, but no task tag was returned. Relying on cooldown only.")
                            self.last_migration_time = time.time() # Fallback to cluster cooldown
                            self.vm_last_moved_times[vm_uuid] = time.time() # Record VM move

                    except requests.exceptions.RequestException as e:
                        print(f"Migration command failed: {e}")
                        # Start cluster cooldown even on failure to avoid rapid retries
                        self.last_migration_time = time.time()
                
            else:
                print("Cluster is balanced or no valid migration path found for load balancing.")
            
            # --- 10. Wait for next cycle ---
            print(f"Waiting {self.config['SAMPLE_INTERVAL_SECONDS']} seconds for next cycle.")
            time.sleep(self.config['SAMPLE_INTERVAL_SECONDS'])


def main():
    # Pack config into a dict
    config = {
        'DRY_RUN': DRY_RUN,
        'AVG_WINDOW_MINUTES': AVG_WINDOW_MINUTES,
        'SAMPLE_INTERVAL_SECONDS': SAMPLE_INTERVAL_SECONDS,
        'RAM_LIMIT_PERCENT': RAM_LIMIT_PERCENT,
        'CPU_UPPER_THRESHOLD_PERCENT': CPU_UPPER_THRESHOLD_PERCENT,
        'CPU_LOWER_THRESHOLD_PERCENT': CPU_LOWER_THRESHOLD_PERCENT,
        'MIGRATION_COOLDOWN_MINUTES': MIGRATION_COOLDOWN_MINUTES,
        'VM_MOVE_COOLDOWN_MINUTES': VM_MOVE_COOLDOWN_MINUTES
    }

    client = HyperCoreApiClient(BASE_URL, verify_ssl=VERIFY_SSL)
    balancer = LoadBalancer(client, config)

    if not client.login(USERNAME, PASSWORD):
        sys.exit(1)

    try:
        balancer.run()
    except KeyboardInterrupt:
        print("\nCaught interrupt, logging out...")
    finally:
        client.logout()
        print("Script terminated.")

if __name__ == "__main__":
    main()