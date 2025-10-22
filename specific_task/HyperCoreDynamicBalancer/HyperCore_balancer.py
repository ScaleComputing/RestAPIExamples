#!/usr/bin/env python3

"""
Script to demonstrate load balancing virtual machines accross nodes in a Scale Computing Hypercore cluster.

make sure to read the README on github.com/scalecomputing for info on using this script.

THIS SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND
feel free to use without attribution in any way as seen fit, at your own risc.

Usage: Set the variables in the Configuration section and run this script.

HyperCore tags that can be used with this script:

anti_  --> tag two vms that should not run on the same node with each others vm name. e.g. anti_SQL01 on sql server SQL02
           and anti_SQL02 on sql server SQL01

node_  --> tag a vm that should be pinned on a certain node with the last octet of the node ip address. e.g. node_101 to pin
           the vm to a node with IP address 192.168.0.101

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
BASE_URL = "https://your-HyperCore-cluster-ip/rest/v1"  # !! EDIT: Your cluster IP or hostname
USERNAME = "your-username"                             # !! EDIT: API Username
PASSWORD = "your-password"                             # !! EDIT: API Password
VERIFY_SSL = False                                     # Set to True if cluster has a valid SSL cert

# Load Balancer Tunables
DRY_RUN = True  # !! SAFETY: Set to False to enable LIVE migrations !!

# How long (in minutes) of performance data to average for decisions
AVG_WINDOW_MINUTES = 5

# How often (in seconds) to collect new performance data
SAMPLE_INTERVAL_SECONDS = 30

# RAM Constraint: Do not migrate a VM *to* a node if it would exceed this usage %
RAM_LIMIT_PERCENT = 70.0

# CPU Thresholds for Load Balancing:
# A node's avg CPU must be *above* this % to be considered overloaded
CPU_UPPER_THRESHOLD_PERCENT = 80.0  
# A node's avg CPU must be *below* this % to be considered a target for load balancing
CPU_LOWER_THRESHOLD_PERCENT = 50.0  

# Cooldown Periods (in minutes):
# Wait after *any* migration finishes before attempting another
MIGRATION_COOLDOWN_MINUTES = 5
# Wait after a *specific VM* is moved before it can be moved again
VM_MOVE_COOLDOWN_MINUTES = 30
# Wait after a node comes back ONLINE before resuming operations
RECOVERY_COOLDOWN_MINUTES = 15 

# --- End of Configuration ---


# Suppress InsecureRequestWarning if VERIFY_SSL is False
if not VERIFY_SSL:
    try:
        from urllib3.exceptions import InsecureRequestWarning
        warnings.simplefilter('ignore', InsecureRequestWarning)
    except ImportError:
        pass # urllib3 might not be available in all Python environments


class HyperCoreApiClient:
    """A simple client for interacting with the Scale Computing HyperCore REST API."""
    
    def __init__(self, base_url, verify_ssl=True):
        """Initializes the API client session."""
        self.base_url = base_url.rstrip('/') # Ensure no trailing slash
        self.session = requests.Session()
        self.session.verify = verify_ssl

    def login(self, username, password):
        """Logs in to the API and stores the session cookie."""
        login_url = f"{self.base_url}/login"
        credentials = {"username": username, "password": password}
        try:
            response = self.session.post(login_url, json=credentials, timeout=10)
            response.raise_for_status()
            print("Successfully logged in.")
            return True
        except requests.exceptions.RequestException as e:
            print(f"Login failed: {e}")
            return False

    def logout(self):
        """Logs out of the current session."""
        try:
            self.session.post(f"{self.base_url}/logout", timeout=5)
            print("Successfully logged out.")
        except requests.exceptions.RequestException as e:
            # Don't print error if logout fails (e.g., session already expired)
            pass 

    def _request(self, method, endpoint, **kwargs):
        """Helper function for making API requests."""
        url = f"{self.base_url}{endpoint}"
        try:
            response = self.session.request(method, url, timeout=15, **kwargs)
            response.raise_for_status()
            # Handle potential empty responses for methods like PATCH/DELETE
            if response.status_code == 204 or not response.content:
                 return {} 
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"API Error ({method} {endpoint}): {e}")
            # Consider specific error handling if needed (e.g., 401 Unauthorized)
            raise # Re-raise the exception to be handled by the caller

    def _get(self, endpoint): return self._request('get', endpoint)
    def _post(self, endpoint, data): return self._request('post', endpoint, json=data)
    def _patch(self, endpoint, data): return self._request('patch', endpoint, json=data)

    # --- Specific API Call Methods ---
    def get_nodes(self): return self._get("/Node")
    def get_vms(self): return self._get("/VirDomain")
    def get_vm_stats(self): return self._get("/VirDomainStats")
    def get_task_status(self, task_tag):
        """Fetches the status of a specific task tag."""
        try:
            status_list = self._get(f"/TaskTag/{task_tag}")
            # API returns a list, even for a single task tag
            return status_list[0]['state'] if status_list else "UNKNOWN"
        except requests.exceptions.RequestException as e:
            # Don't raise here, just warn and return UNKNOWN
            print(f"  - Warning: Could not get status for task {task_tag}. {e}")
            return "UNKNOWN"

    def migrate_vm(self, vm_uuid, target_node_uuid):
        """Initiates a live migration for a VM."""
        action = [{"virDomainUUID": vm_uuid, "actionType": "LIVEMIGRATE", "nodeUUID": target_node_uuid}]
        return self._post("/VirDomain/action", action)

    def clear_vm_affinity(self, vm_uuid):
        """Clears the preferred and backup node affinity settings for a VM via PATCH."""
        print(f"  - Clearing affinity settings for VM {vm_uuid}...")
        payload = {"affinityStrategy": {"preferredNodeUUID": "", "backupNodeUUID": ""}}
        try:
            self._patch(f"/VirDomain/{vm_uuid}", data=payload)
            print(f"  - Successfully cleared affinity for VM {vm_uuid}.")
            return True
        except requests.exceptions.RequestException as e:
            # Error already logged by _request helper
            print(f"  - FAILED to clear affinity for VM {vm_uuid}.")
            return False


class LoadBalancer:
    """Manages the data collection, analysis, and migration logic."""

    def __init__(self, client, config):
        self.client = client
        self.config = config
        
        # Calculate max history size based on window and interval
        self.max_history_size = int((config['AVG_WINDOW_MINUTES'] * 60) / config['SAMPLE_INTERVAL_SECONDS'])
        if self.max_history_size < 1:
            print("FATAL: AVG_WINDOW_MINUTES must be >= SAMPLE_INTERVAL_SECONDS.")
            sys.exit(1)
        print(f"Performance history window: {self.max_history_size} samples (~{config['AVG_WINDOW_MINUTES']} min).")

        # Data stores for averaging performance metrics
        self.node_cpu_history = {}  # {node_uuid: deque([cpu_usage1, cpu_usage2, ...])}
        self.vm_cpu_history = {}    # {vm_uuid: deque([cpu_usage1, cpu_usage2, ...])}
        
        # Timestamps for cooldown management
        self.last_migration_time = 0      # Tracks end time of the last cluster-wide migration task
        self.vm_last_moved_times = {}     # {vm_uuid: timestamp} - Tracks when each VM was last moved
        self.recovery_start_time = 0      # Timestamp when recovery cooldown began after node came online

        # State tracking
        self.active_migration_task = None # Stores {"taskTag": tag, "vm_uuid": uuid} during migration
        self.cluster_was_unstable = False # Tracks if a node was OFFLINE in the previous cycle


    def collect_data(self):
        """Fetches nodes, VMs, and VM stats from the API."""
        print("Collecting cluster data...")
        try:
            nodes = self.client.get_nodes()
            vms = self.client.get_vms()
            vm_stats = self.client.get_vm_stats()
            return nodes, vms, vm_stats
        except requests.exceptions.RequestException:
            # Error logged by API client helper
            print("Failed to collect data, will retry...")
            return None, None, None

    def update_history(self, nodes, vms, vm_stats):
        """Appends the latest performance data to the history deques."""
        # Update node history (using Node object's cpuUsage)
        for node in nodes:
            node_uuid = node.get('uuid')
            if not node_uuid: continue
            if node_uuid not in self.node_cpu_history:
                self.node_cpu_history[node_uuid] = deque(maxlen=self.max_history_size)
            self.node_cpu_history[node_uuid].append(node.get('cpuUsage', 0.0))
            
        # Update VM history (using VirDomainStats object's cpuUsage)
        for stat in vm_stats:
            vm_uuid = stat.get('uuid')
            if not vm_uuid: continue
            if vm_uuid not in self.vm_cpu_history:
                self.vm_cpu_history[vm_uuid] = deque(maxlen=self.max_history_size)
            self.vm_cpu_history[vm_uuid].append(stat.get('cpuUsage', 0.0))

    def get_cluster_state(self, nodes, vms):
        """Analyzes current data and history to provide a snapshot of node states."""
        node_analysis = {}
        vm_uuid_to_vm_map = {vm['uuid']: vm for vm in vms if vm.get('uuid')} 

        for node in nodes:
            node_uuid = node.get('uuid')
            if not node_uuid: continue

            node_status = node.get('networkStatus')
            is_usable = node.get('allowRunningVMs', False) and node_status == 'ONLINE'
            
            # Default values for unusable nodes
            avg_cpu = -1.0 
            ram_percent = 100.0 if not is_usable else 0.0
            running_vms_on_node = []
            total_ram_bytes = node.get('memSize', 0)
            used_ram_bytes = node.get('totalMemUsageBytes', 0)

            if is_usable:
                # Calculate average CPU from history
                if node_uuid in self.node_cpu_history and self.node_cpu_history[node_uuid]:
                    avg_cpu = mean(self.node_cpu_history[node_uuid])
                else: avg_cpu = node.get('cpuUsage', 0.0) # Use current if no history
                
                # Calculate current RAM usage
                if total_ram_bytes > 0:
                     ram_percent = (used_ram_bytes / total_ram_bytes) * 100.0
                
                # Find running VMs on this node and their average CPU
                for vm_uuid, vm_data in vm_uuid_to_vm_map.items():
                    if vm_data.get('nodeUUID') == node_uuid and vm_data.get('state') == 'RUNNING':
                        vm_avg_cpu = 0.0
                        if vm_uuid in self.vm_cpu_history and self.vm_cpu_history[vm_uuid]:
                            vm_avg_cpu = mean(self.vm_cpu_history[vm_uuid])
                        running_vms_on_node.append({
                            "uuid": vm_uuid,
                            "name": vm_data.get('name', 'UnknownVM'),
                            "mem": vm_data.get('mem', 0),
                            "avg_cpu": vm_avg_cpu
                        })
                # Sort this node's VMs by *their* average CPU (busiest first)
                running_vms_on_node.sort(key=lambda x: x['avg_cpu'], reverse=True)

            node_analysis[node_uuid] = {
                "uuid": node_uuid, 
                "name": node.get('lanIP', node_uuid), # Prefer IP for name
                "avg_cpu": avg_cpu,
                "total_ram": total_ram_bytes, 
                "used_ram": used_ram_bytes,
                "ram_percent": ram_percent, 
                "running_vms": running_vms_on_node, 
                "full_object": node, 
                "is_usable": is_usable
            }
            
        return node_analysis

    # --- Helper Functions for Tag Processing ---
    def _get_vm_tags(self, vm):
        """Safely parses comma-separated tags from a VM object."""
        if not vm: return []
        return [t.strip() for t in (vm.get('tags') or "").split(',') if t.strip()]

    def _get_node_by_ip_suffix(self, nodes, suffix):
        """Finds a node object by the last octet of its LAN IP."""
        target_suffix = f".{suffix}"
        for node in nodes:
            lan_ip = node.get('lanIP')
            if lan_ip and lan_ip.endswith(target_suffix): return node
        return None

    # --- Violation Checking Functions ---
    def check_and_warn_node_affinity_violations(self, vms, nodes):
        """Checks node affinity rules and prints WARNINGS if violated (e.g., during node failure)."""
        vm_uuid_to_vm_map = {vm['uuid']: vm for vm in vms if vm.get('uuid')}
        node_uuid_to_node_map = {n['uuid']: n for n in nodes if n.get('uuid')}
        violations_found = 0

        for vm in vms:
            if vm.get('state') != 'RUNNING': continue
            
            vm_tags = self._get_vm_tags(vm)
            affinity_suffix = None; affinity_tag = None
            for tag in vm_tags:
                if tag.startswith('node_'):
                    try: affinity_suffix = tag.split('_', 1)[1]; affinity_tag = tag; break 
                    except (IndexError, ValueError): continue # Ignore malformed tags like 'node_' or 'node_abc'
            if not affinity_suffix: continue 

            target_node = self._get_node_by_ip_suffix(nodes, affinity_suffix)
            if not target_node:
                print(f"  - AFFINITY WARNING: VM '{vm.get('name', vm['uuid'])}' tag '{affinity_tag}' - no node IP ends '.{affinity_suffix}'.")
                violations_found += 1; continue

            target_node_uuid = target_node.get('uuid')
            target_node_status = target_node.get('networkStatus')
            current_node_uuid = vm.get('nodeUUID')
            current_node_obj = node_uuid_to_node_map.get(current_node_uuid)
            current_node_id = current_node_obj.get('lanIP', current_node_uuid) if current_node_obj else current_node_uuid

            if current_node_uuid != target_node_uuid:
                 if target_node_status == 'OFFLINE':
                     print(f"  - AFFINITY WARNING: VM '{vm.get('name', vm['uuid'])}' wants node ending '.{affinity_suffix}' (OFFLINE). Currently on node '{current_node_id}'.")
                 else:
                     print(f"  - AFFINITY VIOLATION: VM '{vm.get('name', vm['uuid'])}' wants node ending '.{affinity_suffix}'. Currently on node '{current_node_id}'.")
                 violations_found += 1

        if violations_found == 0: print("  - No node affinity violations found.")
        return violations_found > 0

    def check_and_warn_anti_affinity_violations(self, vms):
        """Checks anti-affinity rules and prints WARNINGS if violated."""
        vm_name_to_vm_map = {vm['name']: vm for vm in vms if vm.get('name')}
        # Create a map to quickly find a node's IP using a VM UUID (best effort)
        node_uuid_to_ip_map = {vm.get('nodeUUID'): vm.get('lanIP', vm.get('nodeUUID')) 
                               for vm in vms if vm.get('nodeUUID')}
        violations_found = 0

        for vm_a in vms:
            vm_a_tags = self._get_vm_tags(vm_a)
            if not vm_a_tags: continue

            for tag in vm_a_tags:
                if tag.startswith('anti_'):
                    target_vm_name = tag[len("anti_"):]
                    vm_b = vm_name_to_vm_map.get(target_vm_name)
                    if not vm_b: continue 
                    
                    vm_a_node_uuid = vm_a.get('nodeUUID')
                    # Check if they are on the same node AND vm_a is running
                    if vm_a_node_uuid and vm_a_node_uuid == vm_b.get('nodeUUID') and vm_a.get('state') == 'RUNNING':
                        node_id = node_uuid_to_ip_map.get(vm_a_node_uuid, vm_a_node_uuid) # Use IP if possible
                        print(f"  - ANTI-AFFINITY VIOLATION: VM {vm_a.get('name', vm_a['uuid'])} (tag '{tag}') is on the same node ({node_id}) as {vm_b.get('name', vm_b['uuid'])}.")
                        violations_found += 1
        
        if violations_found == 0: print("  - No anti-affinity violations found.")
        return violations_found > 0

    def _check_anti_affinity_for_move(self, vm_to_move_uuid, target_node_uuid, vms):
        """Checks if moving a VM would create an anti-affinity violation on the target node."""
        vm_uuid_to_vm_map = {vm['uuid']: vm for vm in vms if vm.get('uuid')}
        vm_a = vm_uuid_to_vm_map.get(vm_to_move_uuid) 
        if not vm_a: return False, "Source VM not found for check" 
        vm_a_name = vm_a.get('name', '')
        vm_a_tags = self._get_vm_tags(vm_a)

        # Iterate through VMs already on the target node
        for vm_b in vms:
            if vm_b.get('nodeUUID') != target_node_uuid: continue # Skip VMs not on target
            vm_b_name = vm_b.get('name', '')
            vm_b_tags = self._get_vm_tags(vm_b)

            # Check vm_a's tags against vm_b's name
            for tag_a in vm_a_tags:
                if tag_a == f"anti_{vm_b_name}":
                    return False, f"Moving VM tag '{tag_a}' conflicts with target VM '{vm_b_name}'"
            
            # Check vm_b's tags against vm_a's name
            for tag_b in vm_b_tags:
                 if tag_b == f"anti_{vm_a_name}":
                     return False, f"Target VM '{vm_b_name}' tag '{tag_b}' conflicts with moving VM '{vm_a_name}'"

        return True, "OK" # No conflicts found

    # --- Rule Enforcement Functions (Initiate Migrations) ---
    def find_and_fix_node_affinity_violation(self, cluster_state, vms, nodes):
        """Finds VMs violating node affinity and tries to move them home, potentially evicting."""
        print("Checking for actionable node affinity violations...")
        vm_uuid_to_vm_map = {vm['uuid']: vm for vm in vms if vm.get('uuid')}

        for vm in vms:
            vm_uuid = vm.get('uuid')
            if not vm_uuid or vm.get('state') != 'RUNNING': continue
            
            vm_tags = self._get_vm_tags(vm)
            affinity_suffix = None; affinity_tag = None
            for tag in vm_tags:
                if tag.startswith('node_'):
                    try: affinity_suffix = tag.split('_', 1)[1]; affinity_tag = tag; break 
                    except (IndexError, ValueError): continue
            if not affinity_suffix: continue 

            target_node_obj = self._get_node_by_ip_suffix(nodes, affinity_suffix)
            if not target_node_obj: continue 

            target_node_uuid = target_node_obj.get('uuid')
            target_node_state = cluster_state.get(target_node_uuid) 
            current_node_uuid = vm.get('nodeUUID')

            if current_node_uuid != target_node_uuid:
                print(f"  - VIOLATION: VM '{vm['name']}' ({affinity_tag}) should be on {target_node_obj.get('lanIP')}.")

                if not target_node_state or not target_node_state.get('is_usable'):
                    print(f"  - Cannot fix: Target node {target_node_obj.get('lanIP')} is OFFLINE/unusable."); continue

                projected_ram_use = target_node_state['used_ram'] + vm['mem']
                projected_ram_percent = (projected_ram_use / target_node_state['total_ram']) * 100.0 if target_node_state['total_ram'] > 0 else 100.0
                ram_ok = projected_ram_percent <= self.config['RAM_LIMIT_PERCENT']
                
                # --- Eviction Logic ---
                if not ram_ok:
                    print(f"  - RAM Check FAILED: Target needs {projected_ram_percent:.1f}%. Limit {self.config['RAM_LIMIT_PERCENT']}%. Attempting eviction...")
                    ram_needed_to_free = projected_ram_use - (target_node_state['total_ram'] * self.config['RAM_LIMIT_PERCENT'] / 100.0)
                    
                    # Get VMs on target (use full VM objects), sorted by smallest RAM
                    vms_on_target_info = target_node_state.get('running_vms', [])
                    vms_on_target_full = sorted(
                        [vm_uuid_to_vm_map.get(v_info['uuid']) for v_info in vms_on_target_info if vm_uuid_to_vm_map.get(v_info['uuid'])],
                        key=lambda x: x.get('mem', 0)
                    )
                    
                    eviction_candidate = None; eviction_destination_node = None
                    for candidate in vms_on_target_full:
                        candidate_uuid = candidate['uuid']; candidate_mem = candidate.get('mem', 0)
                        
                        target_node_ip_suffix = target_node_obj.get('lanIP', '').split('.')[-1]
                        if any(t == f"node_{target_node_ip_suffix}" for t in self._get_vm_tags(candidate)):
                             print(f"    - Skip candidate '{candidate['name']}': pinned."); continue
                        if time.time() - self.vm_last_moved_times.get(candidate_uuid, 0) < self.config['VM_MOVE_COOLDOWN_MINUTES'] * 60:
                            print(f"    - Skip candidate '{candidate['name']}': cooldown."); continue
                        if candidate_mem < ram_needed_to_free:
                            print(f"    - Skip candidate '{candidate['name']}': too small."); continue
                            
                        print(f"    - Trying eviction candidate: '{candidate['name']}'. Searching destination...")
                        possible_destinations = [n for n_uuid, n in cluster_state.items() if n.get('is_usable') and n_uuid != target_node_uuid and n_uuid != current_node_uuid]
                        possible_destinations.sort(key=lambda x: x['ram_percent']) 
                        
                        for dest_node in possible_destinations:
                            dest_proj_ram = dest_node['used_ram'] + candidate_mem
                            dest_proj_pct = (dest_proj_ram / dest_node['total_ram']) * 100.0 if dest_node['total_ram'] > 0 else 100.0
                            if dest_proj_pct > self.config['RAM_LIMIT_PERCENT']:
                                print(f"      - Skip dest '{dest_node['name']}': RAM."); continue
                            allowed, reason = self._check_anti_affinity_for_move(candidate_uuid, dest_node['uuid'], vms)
                            if not allowed:
                                print(f"      - Skip dest '{dest_node['name']}': anti-affinity ({reason})."); continue
                            
                            print(f"      - Found valid destination: '{dest_node['name']}'.")
                            eviction_candidate = candidate; eviction_destination_node = dest_node; break 
                        if eviction_destination_node: break 

                    if eviction_candidate and eviction_destination_node:
                        evic_vm_uuid = eviction_candidate['uuid']; evic_target_uuid = eviction_destination_node['uuid']
                        if self.config['DRY_RUN']:
                            print(f"\n  *** DRY RUN (Eviction): Move '{eviction_candidate['name']}' ({evic_vm_uuid}) ***")
                            print(f"  *** FROM: {target_node_state['name']} TO: {eviction_destination_node['name']} ***")
                            print(f"  *** Reason: Make space for affinity VM '{vm['name']}' on {target_node_state['name']} ***")
                            self.last_migration_time=time.time(); self.vm_last_moved_times[evic_vm_uuid]=time.time()
                            self.node_cpu_history.clear(); self.vm_cpu_history.clear()
                        else:
                            print(f"\n  !!! EXECUTE (Eviction): Move '{eviction_candidate['name']}' ({evic_vm_uuid}) !!!")
                            print(f"  !!! FROM: {target_node_state['name']} TO: {eviction_destination_node['name']} !!!")
                            print(f"  !!! Reason: Make space for affinity VM '{vm['name']}' on {target_node_state['name']} !!!")
                            try:
                                resp = self.client.migrate_vm(evic_vm_uuid, evic_target_uuid); task = resp.get('taskTag')
                                if task: self.active_migration_task = { "taskTag": task, "vm_uuid": evic_vm_uuid }; print(f"  - Eviction Task: {task}")
                                else: print("  - Eviction initiated (no task tag)."); self.last_migration_time=time.time(); self.vm_last_moved_times[evic_vm_uuid]=time.time()
                            except requests.exceptions.RequestException: print(f"  - Eviction failed."); self.last_migration_time = time.time() # Error logged by client
                        return True # Eviction initiated
                    else:
                        print(f"  - WARNING: Cannot resolve RAM conflict for affinity VM '{vm['name']}'. No eviction possible."); continue
                # --- End Eviction Logic ---

                # --- Proceed if RAM OK (or eviction started) ---
                if ram_ok: 
                    allowed, reason = self._check_anti_affinity_for_move(vm_uuid, target_node_uuid, vms)
                    if not allowed:
                        print(f"  - WARNING: Move affinity VM '{vm['name']}' to {target_node_obj.get('lanIP')} violates anti-affinity ({reason})."); continue

                    source_node_state = cluster_state.get(current_node_uuid, {}); source_name = source_node_state.get('name', current_node_uuid) 
                    if self.config['DRY_RUN']:
                        print(f"\n  *** DRY RUN (Node Affinity): Move '{vm['name']}' ({vm_uuid}) ***")
                        print(f"  *** FROM: {source_name} TO: {target_node_state['name']} ***")
                        self.last_migration_time=time.time(); self.vm_last_moved_times[vm_uuid]=time.time()
                        self.node_cpu_history.clear(); self.vm_cpu_history.clear()
                    else:
                        print(f"\n  !!! EXECUTE (Node Affinity): Move '{vm['name']}' ({vm_uuid}) !!!")
                        print(f"  !!! FROM: {source_name} TO: {target_node_state['name']} !!!")
                        try:
                            resp = self.client.migrate_vm(vm_uuid, target_node_uuid); task = resp.get('taskTag')
                            if task: self.active_migration_task = { "taskTag": task, "vm_uuid": vm_uuid }; print(f"  - Task: {task}")
                            else: print("  - Initiated (no task tag)."); self.last_migration_time=time.time(); self.vm_last_moved_times[vm_uuid]=time.time()
                        except requests.exceptions.RequestException: print(f"  - Failed."); self.last_migration_time = time.time()
                    return True # Fix initiated

        print("  - No actionable node affinity violations found.")
        return False 

    def find_and_fix_anti_affinity_violation(self, cluster_state, vms, nodes):
        """Finds anti-affinity violations, tries to fix them avoiding pinned VMs."""
        print("Checking for actionable anti-affinity violations...")
        vm_name_to_vm_map = {vm['name']: vm for vm in vms if vm.get('name')}
        vm_uuid_to_vm_map = {vm['uuid']: vm for vm in vms if vm.get('uuid')}

        for vm_a_uuid, vm_a in vm_uuid_to_vm_map.items():
            vm_a_tags = self._get_vm_tags(vm_a)
            if not vm_a_tags or vm_a.get('state') != 'RUNNING': continue

            for tag in vm_a_tags:
                if tag.startswith('anti_'):
                    vm_b = vm_name_to_vm_map.get(tag[len("anti_"):])
                    if not vm_b: continue 
                    
                    current_node_uuid = vm_a.get('nodeUUID')
                    if not current_node_uuid or current_node_uuid != vm_b.get('nodeUUID'): continue
                    
                    print(f"  - VIOLATION: {vm_a['name']} & {vm_b['name']} on {cluster_state.get(current_node_uuid,{}).get('name', current_node_uuid)}.")
                    current_node = next((n for n in nodes if n.get('uuid') == current_node_uuid), None)
                    current_ip_suffix = current_node.get('lanIP', '').split('.')[-1] if current_node else None

                    vm_a_pinned = any(t == f"node_{current_ip_suffix}" for t in vm_a_tags)
                    vm_b_pinned = any(t == f"node_{current_ip_suffix}" for t in self._get_vm_tags(vm_b))

                    vm_to_move_obj = None
                    if vm_a_pinned and not vm_b_pinned: vm_to_move_obj = vm_b; print(f"  - Prefer move '{vm_b['name']}'.")
                    elif not vm_a_pinned: vm_to_move_obj = vm_a; print(f"  - Prefer move '{vm_a['name']}'.")
                    elif vm_a_pinned and vm_b_pinned: print(f"  - WARNING: Both pinned. Cannot fix."); return False 
                    else: vm_to_move_obj = vm_a; print(f"  - (Default) Prefer move '{vm_a['name']}'.")
                    
                    potential_targets = [n for n_uuid, n in cluster_state.items() if n_uuid != current_node_uuid and n.get('is_usable')]
                    potential_targets.sort(key=lambda x: x['ram_percent']) 
                    
                    target_node = None
                    for node in potential_targets:
                        vm_to_move_mem = vm_to_move_obj.get('mem', 0)
                        proj_ram = node['used_ram'] + vm_to_move_mem; proj_pct = (proj_ram / node['total_ram']) * 100.0 if node['total_ram'] > 0 else 100.0
                        if proj_pct > self.config['RAM_LIMIT_PERCENT']: continue
                        allowed, _ = self._check_anti_affinity_for_move(vm_to_move_obj['uuid'], node['uuid'], vms)
                        if not allowed: continue
                        target_node = node; break 
                    
                    if not target_node: print(f"  - ERROR: No suitable node for '{vm_to_move_obj['name']}'."); return False 

                    vm_uuid_to_move = vm_to_move_obj['uuid']
                    if self.config['DRY_RUN']:
                        print(f"\n  *** DRY RUN (Anti-Affinity): Move '{vm_to_move_obj['name']}' ({vm_uuid_to_move}) ***")
                        print(f"  *** FROM: {cluster_state[current_node_uuid]['name']} TO: {target_node['name']} ***")
                        self.last_migration_time=time.time(); self.vm_last_moved_times[vm_uuid_to_move]=time.time()
                        self.node_cpu_history.clear(); self.vm_cpu_history.clear()
                    else:
                        print(f"\n  !!! EXECUTE (Anti-Affinity): Move '{vm_to_move_obj['name']}' ({vm_uuid_to_move}) !!!")
                        print(f"  !!! FROM: {cluster_state[current_node_uuid]['name']} TO: {target_node['name']} !!!")
                        try:
                            resp = self.client.migrate_vm(vm_uuid_to_move, target_node['uuid']); task = resp.get('taskTag')
                            if task: self.active_migration_task = { "taskTag": task, "vm_uuid": vm_uuid_to_move }; print(f"  - Task: {task}")
                            else: print("  - No task tag."); self.last_migration_time=time.time(); self.vm_last_moved_times[vm_uuid_to_move]=time.time()
                        except requests.exceptions.RequestException: print(f"  - Failed."); self.last_migration_time = time.time()
                    return True # Fix initiated

        print("  - No actionable anti-affinity violations found.")
        return False 

    def find_migration_candidate(self, cluster_state, vms, nodes):
        """Finds migration candidates for load balancing, respecting constraints."""
        usable_nodes = {uuid: data for uuid, data in cluster_state.items() if data.get('is_usable')}
        if len(usable_nodes) < 2: print("  - Need >= 2 usable nodes for balancing."); return None, None, None 

        sorted_nodes = sorted(usable_nodes.values(), key=lambda x: x['avg_cpu'])
        busiest = sorted_nodes[-1]; targets = sorted_nodes[:-1]; coolest = targets[0] 
        
        if not (busiest['avg_cpu'] > self.config['CPU_UPPER_THRESHOLD_PERCENT'] and coolest['avg_cpu'] < self.config['CPU_LOWER_THRESHOLD_PERCENT']):
            return None, None, None # Not imbalanced enough

        print(f"Imbalance: {busiest['name']} ({busiest['avg_cpu']:.1f}%) hot; {coolest['name']} ({coolest['avg_cpu']:.1f}%) cool.")
        vm_uuid_to_vm_map = {vm['uuid']: vm for vm in vms if vm.get('uuid')}

        for vm_info in busiest['running_vms']: # Already sorted by VM CPU usage
            vm_uuid = vm_info['uuid']; vm_full = vm_uuid_to_vm_map.get(vm_uuid)
            if not vm_full: continue 
            print(f"  - Eval candidate: {vm_info['name']} (avg CPU {vm_info['avg_cpu']:.1f}%)")

            # Check Node Affinity
            vm_tags = self._get_vm_tags(vm_full); current_ip_suffix = busiest['full_object'].get('lanIP', '').split('.')[-1]
            if current_ip_suffix and any(t == f"node_{current_ip_suffix}" for t in vm_tags): 
                print(f"  - Skip: Pinned here."); continue 

            # Check VM Cooldown
            if time.time() - self.vm_last_moved_times.get(vm_uuid, 0) < self.config['VM_MOVE_COOLDOWN_MINUTES'] * 60:
                print(f"  - Skip: In cooldown."); continue 
            print(f"  - Cooldown OK")

            for target in targets: # Already sorted coolest to warmest
                print(f"  -   Check target: {target['name']} (avg CPU {target['avg_cpu']:.1f}%)")
                # Check RAM
                vm_mem = vm_info.get('mem', 0)
                proj_ram = target['used_ram'] + vm_mem; proj_pct = (proj_ram / target['total_ram']) * 100.0 if target['total_ram'] > 0 else 100.0
                if proj_pct > self.config['RAM_LIMIT_PERCENT']: 
                    print(f"  -     Skip target: RAM ({proj_pct:.1f}% needed)."); continue
                print(f"  -     RAM OK ({proj_pct:.1f}%).")
                # Check Anti-Affinity
                allowed, reason = self._check_anti_affinity_for_move(vm_uuid, target['uuid'], vms)
                if not allowed: print(f"  -     Skip target: Anti-Affinity ({reason})."); continue
                print(f"  -     Anti-Affinity OK")
                
                print(f"  -> Select {vm_info['name']} -> {target['name']}.")
                return vm_info, busiest, target # Return the info dict, source node state, target node state
            
            print(f"  - VM {vm_info['name']} cannot be placed on any target.")

        print("Imbalance detected, but no suitable VM move found.")
        return None, None, None

    def run(self):
        """Main execution loop: check status, cooldowns, violations, balance."""
        while True:
            print(f"\n--- Cycle Start: {time.ctime()} ---")

            # --- 1. Check Active Migration ---
            if self.active_migration_task:
                task_tag = self.active_migration_task['taskTag']
                print(f"Waiting for migration Task {task_tag}...")
                status = self.client.get_task_status(task_tag)
                print(f"  - State: {status}")
                if status in ["COMPLETE", "ERROR", "UNINITIALIZED", "UNKNOWN"]:
                    vm_uuid = self.active_migration_task['vm_uuid']
                    if status == "COMPLETE":
                        print(f"  - Task {task_tag} COMPLETE.")
                        if not self.config['DRY_RUN']: self.client.clear_vm_affinity(vm_uuid)
                        else: print(f"  - *** DRY RUN: Would clear affinity ***")
                        self.vm_last_moved_times[vm_uuid] = time.time()
                        print(f"  - VM {vm_uuid} cooldown started.")
                    else: print(f"  - WARNING: Task {task_tag} state {status}. Affinity NOT cleared.")
                    self.active_migration_task = None; self.last_migration_time = time.time() 
                    self.node_cpu_history.clear(); self.vm_cpu_history.clear() # Clear history after any move
                time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue # Wait for next check or completion
            
            # --- 2. Check Recovery Cooldown ---
            if self.recovery_start_time > 0:
                 time_since_rec = time.time() - self.recovery_start_time; rec_dur = self.config['RECOVERY_COOLDOWN_MINUTES'] * 60
                 if time_since_rec < rec_dur:
                     print(f"In RECOVERY cooldown. Wait {rec_dur - time_since_rec:.0f}s."); time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue
                 else: print("Recovery cooldown finished."); self.recovery_start_time = 0 

            # --- 3. Check Cluster Cooldown ---
            time_since_move = time.time() - self.last_migration_time; cluster_cd = self.config['MIGRATION_COOLDOWN_MINUTES'] * 60
            if time_since_move < cluster_cd:
                print(f"In cluster cooldown. Wait {cluster_cd - time_since_move:.0f}s."); time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue

            # --- 4. Collect Data ---
            nodes, vms, vm_stats = self.collect_data()
            if not all([nodes, vms, vm_stats]): time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue
                
            # --- 5. Check for OFFLINE Nodes & Manage Recovery State ---
            offline_nodes = [n for n in nodes if n.get('networkStatus') == 'OFFLINE']
            if offline_nodes:
                if not self.cluster_was_unstable: # First detection
                    offline_names = [n.get('lanIP', n.get('uuid')) for n in offline_nodes]
                    print("!"*30 + f"\n  WARNING: Node(s) {offline_names} OFFLINE. Pausing operations.\n  Checking violations (warnings only):")
                    self.check_and_warn_node_affinity_violations(vms, nodes)
                    self.check_and_warn_anti_affinity_violations(vms)
                    print("!"*30)
                self.cluster_was_unstable = True # Set flag indicating instability
                time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue # Pause operations
            elif self.cluster_was_unstable: # Cluster was unstable, but now isn't
                print("*"*30 + "\n  INFO: All nodes back ONLINE. Starting RECOVERY cooldown.\n" + "*"*30)
                self.cluster_was_unstable = False # Clear flag
                self.recovery_start_time = time.time() # Start recovery timer
                time.sleep(1); continue # Immediately re-check cooldown in next loop
            
            # --- If we reach here, cluster is stable ---
            # --- 6. Update History ---
            self.update_history(nodes, vms, vm_stats)
            
            # --- 7. Analyze Cluster State ---
            cluster_state = self.get_cluster_state(nodes, vms)
            
            # --- 8. Fix Node Affinity (P1) ---
            if self.find_and_fix_node_affinity_violation(cluster_state, vms, nodes):
                 print("Node affinity fix initiated. Next cycle."); time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue

            # --- 9. Fix Anti-Affinity (P2) ---
            if self.find_and_fix_anti_affinity_violation(cluster_state, vms, nodes):
                print("Anti-affinity fix initiated. Next cycle."); time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue 
            
            # --- 10. Check History Full for Load Balancing ---
            first_hist = next((h for h in self.node_cpu_history.values() if h is not None), None) # Find first non-empty history
            if not first_hist or len(first_hist) < self.max_history_size:
                print(f"Collecting history {len(first_hist or [])}/{self.max_history_size} samples."); time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue
            
            print("History full. Analyzing for load balancing...")

            # --- 11. Find Load Balancing Candidates (P3) ---
            vm_move_info, src_node_state, target_node_state = self.find_migration_candidate(cluster_state, vms, nodes) 

            # --- 12. Perform Load Balancing Migration ---
            if vm_move_info and src_node_state and target_node_state:
                vm_uuid = vm_move_info['uuid'] # Use the info dict returned by find_migration_candidate
                vm_name = vm_move_info['name']
                if self.config['DRY_RUN']:
                    print(f"\n*** DRY RUN (Load Balance): Move '{vm_name}' ({vm_uuid}) ***")
                    print(f"*** FROM: {src_node_state['name']} TO: {target_node_state['name']} ***")
                    self.last_migration_time=time.time(); self.vm_last_moved_times[vm_uuid]=time.time()
                    print(f"*** Cooldowns started (sim). Would clear affinity. ***") 
                    self.node_cpu_history.clear(); self.vm_cpu_history.clear()
                else:
                    print(f"\n!!! EXECUTE (Load Balance): Move '{vm_name}' ({vm_uuid}) !!!")
                    print(f"!!! FROM: {src_node_state['name']} TO: {target_node_state['name']} !!!")
                    try:
                        resp = self.client.migrate_vm(vm_uuid, target_node_state['uuid']); task = resp.get('taskTag')
                        if task: self.active_migration_task = { "taskTag": task, "vm_uuid": vm_uuid }; print(f"  Task: {task}")
                        else: print("  No task tag."); self.last_migration_time=time.time(); self.vm_last_moved_times[vm_uuid]=time.time() 
                    except requests.exceptions.RequestException: print(f"  Failed."); self.last_migration_time = time.time()
            else: print("Cluster balanced or no valid LB move found.")
            
            # --- 13. Wait ---
            print(f"Waiting {self.config['SAMPLE_INTERVAL_SECONDS']} seconds.")
            time.sleep(self.config['SAMPLE_INTERVAL_SECONDS'])

# --- Main Execution ---
def main():
    """Sets up configuration, logs in, runs the balancer loop, and handles logout."""
    config = { # Consolidate config for passing to the balancer instance
        'DRY_RUN': DRY_RUN, 'AVG_WINDOW_MINUTES': AVG_WINDOW_MINUTES,
        'SAMPLE_INTERVAL_SECONDS': SAMPLE_INTERVAL_SECONDS, 'RAM_LIMIT_PERCENT': RAM_LIMIT_PERCENT,
        'CPU_UPPER_THRESHOLD_PERCENT': CPU_UPPER_THRESHOLD_PERCENT, 'CPU_LOWER_THRESHOLD_PERCENT': CPU_LOWER_THRESHOLD_PERCENT,
        'MIGRATION_COOLDOWN_MINUTES': MIGRATION_COOLDOWN_MINUTES, 'VM_MOVE_COOLDOWN_MINUTES': VM_MOVE_COOLDOWN_MINUTES,
        'RECOVERY_COOLDOWN_MINUTES': RECOVERY_COOLDOWN_MINUTES
    }
    client = HyperCoreApiClient(BASE_URL, verify_ssl=VERIFY_SSL)
    balancer = LoadBalancer(client, config)

    if not client.login(USERNAME, PASSWORD): 
        sys.exit(1) # Exit if login fails

    try: 
        balancer.run() # Start the main loop
    except KeyboardInterrupt: 
        print("\nCaught interrupt (Ctrl+C), stopping...")
    except Exception as e:
         print(f"\nAn unexpected error occurred: {e}") # Catch other potential errors
    finally:
        # Ensure logout happens even if the loop exits unexpectedly
        client.logout() 
        print("Script terminated.")

if __name__ == "__main__":
    main()