#!/usr/bin/env python3

"""
Script to demonstrate load balancing virtual machines accross nodes in a Scale Computing Hypercore cluster.

make sure to read the README on github.com/scalecomputing for info on using this script.

THIS SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND
feel free to use without attribution in any way as seen fit, at your own risc.

Usage: Set the variables in the Configuration section (or use environment variables) and run this script.

HyperCore tags that can be used with this script:

anti_  --> tag two vms that should not run on the same node with each others vm name. e.g. anti_SQL01 on sql server SQL02
           and anti_SQL02 on sql server SQL01

node_  --> tag a vm that should be pinned on a certain node with the last octet of the node ip address. e.g. node_101 to pin
           the vm to a node with IP address 192.168.0.101

William David van Collenburg
Scale Computing

dependencies: on Windows systems 'requests' must be installed manually (pip install requests)

Environment Variables for Authentication (optional, overrides script defaults):
SC_HOST=https://your-hypercore-host # Base URL (e.g., https://192.168.1.10)
SC_USERNAME=your_api_username
SC_PASSWORD=your_api_password

"""

import requests
import time
import json
import warnings
import sys
from collections import deque
from statistics import mean
import os # Import os module for environment variables

# --- Configuration (Defaults) ---

# Cluster Connection - Used if corresponding SC_* environment variables are NOT set
DEFAULT_BASE_URL = "https://your-hypercore-host/rest/v1"  # !! EDIT if not using ENV VARS
DEFAULT_USERNAME = "your_api_username"                             # !! EDIT if not using ENV VARS
DEFAULT_PASSWORD = "your_api_password"                             # !! EDIT if not using ENV VARS
VERIFY_SSL = False                                             # Set to True if cluster has a valid SSL cert

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
MIGRATION_COOLDOWN_MINUTES = 3
# Wait after a *specific VM* is moved before it can be moved again
VM_MOVE_COOLDOWN_MINUTES = 30
# Wait after a node comes back ONLINE before resuming operations
RECOVERY_COOLDOWN_MINUTES = 15

# Node Exclusion: List of node LAN IP addresses to completely exclude from balancing actions.
# VMs will not be moved TO or FROM these nodes by this script. Affinity rules targeting these nodes will generate warnings.
EXCLUDE_NODE_IPS = [] # Add IPs as strings, e.g., ["192.168.1.101", "192.168.1.102"]

# --- End of Configuration ---


# Suppress InsecureRequestWarning if VERIFY_SSL is False
if not VERIFY_SSL:
    try:
        from urllib3.exceptions import InsecureRequestWarning
        warnings.simplefilter('ignore', InsecureRequestWarning)
    except ImportError:
        pass # urllib3 might not be available

# --- Helper Function to get credentials ---
def get_credentials():
    """Gets API credentials, prioritizing environment variables."""
    env_host = os.getenv('SC_HOST')
    env_user = os.getenv('SC_USERNAME')
    env_pass = os.getenv('SC_PASSWORD')

    if env_host and env_user and env_pass:
        print("Using credentials from environment variables (SC_HOST, SC_USERNAME, SC_PASSWORD).")
        base_url = env_host.rstrip('/')
        if not base_url.endswith('/rest/v1'): base_url += '/rest/v1'
        return base_url, env_user, env_pass
    else:
        print("Environment variables not fully set. Using script defaults.")
        return DEFAULT_BASE_URL, DEFAULT_USERNAME, DEFAULT_PASSWORD


class HyperCoreApiClient:
    """A simple client for interacting with the Scale Computing HyperCore REST API."""

    def __init__(self, base_url, verify_ssl=True):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = verify_ssl

    def login(self, username, password):
        try:
            response = self.session.post(f"{self.base_url}/login", json={"username": username, "password": password}, timeout=10)
            response.raise_for_status(); print("Successfully logged in."); return True
        except requests.exceptions.RequestException as e: print(f"Login failed: {e}"); return False

    def logout(self):
        try: self.session.post(f"{self.base_url}/logout", timeout=5); print("Successfully logged out.")
        except requests.exceptions.RequestException: pass

    def _request(self, method, endpoint, **kwargs):
        url = f"{self.base_url}{endpoint}"
        try:
            response = self.session.request(method, url, timeout=15, **kwargs)
            response.raise_for_status()
            if response.status_code == 204 or not response.content: return {}
            return response.json()
        except requests.exceptions.RequestException as e: print(f"API Error ({method} {endpoint}): {e}"); raise

    def _get(self, endpoint): return self._request('get', endpoint)
    def _post(self, endpoint, data): return self._request('post', endpoint, json=data)
    def _patch(self, endpoint, data): return self._request('patch', endpoint, json=data)

    def get_nodes(self): return self._get("/Node")
    def get_vms(self): return self._get("/VirDomain")
    def get_vm_stats(self): return self._get("/VirDomainStats")
    def get_task_status(self, task_tag):
        try:
            status_list = self._get(f"/TaskTag/{task_tag}")
            return status_list[0]['state'] if status_list else "UNKNOWN"
        except requests.exceptions.RequestException as e: print(f"  - Warn: Task status check fail {task_tag}: {e}"); return "UNKNOWN"

    def migrate_vm(self, vm_uuid, target_node_uuid):
        action = [{"virDomainUUID": vm_uuid, "actionType": "LIVEMIGRATE", "nodeUUID": target_node_uuid}]
        return self._post("/VirDomain/action", action)

    def clear_vm_affinity(self, vm_uuid):
        print(f"  - Clearing affinity for VM {vm_uuid}...")
        payload = {"affinityStrategy": {"preferredNodeUUID": "", "backupNodeUUID": ""}}
        try:
            self._patch(f"/VirDomain/{vm_uuid}", data=payload); print(f"  - Cleared affinity for VM {vm_uuid}."); return True
        except requests.exceptions.RequestException: print(f"  - FAILED clear affinity for VM {vm_uuid}."); return False


class LoadBalancer:
    """Manages data collection, analysis, and migration logic."""

    def __init__(self, client, config):
        self.client = client
        self.config = config
        self.exclude_ips_set = set(config.get('EXCLUDE_NODE_IPS', [])) # Use set for faster lookups
        if self.exclude_ips_set: print(f"INFO: Excluding nodes with IPs: {', '.join(self.exclude_ips_set)}")

        self.max_history_size = int((config['AVG_WINDOW_MINUTES'] * 60) / config['SAMPLE_INTERVAL_SECONDS'])
        if self.max_history_size < 1: print("FATAL: AVG_WINDOW_MINUTES must be >= SAMPLE_INTERVAL_SECONDS."); sys.exit(1)
        print(f"History window: {self.max_history_size} samples (~{config['AVG_WINDOW_MINUTES']} min).")

        self.node_cpu_history = {}; self.vm_cpu_history = {}
        self.last_migration_time = 0; self.active_migration_task = None
        self.vm_last_moved_times = {}; self.cluster_was_unstable = False; self.recovery_start_time = 0

    def collect_data(self):
        print("Collecting cluster data...")
        try: return self.client.get_nodes(), self.client.get_vms(), self.client.get_vm_stats()
        except requests.exceptions.RequestException: print("Failed collect, retry..."); return None, None, None

    def update_history(self, nodes, vms, vm_stats):
        for node in nodes:
            node_uuid = node.get('uuid')
            if node_uuid:
                if node_uuid not in self.node_cpu_history: self.node_cpu_history[node_uuid] = deque(maxlen=self.max_history_size)
                self.node_cpu_history[node_uuid].append(node.get('cpuUsage', 0.0))
        for stat in vm_stats:
            vm_uuid = stat.get('uuid')
            if vm_uuid:
                if vm_uuid not in self.vm_cpu_history: self.vm_cpu_history[vm_uuid] = deque(maxlen=self.max_history_size)
                self.vm_cpu_history[vm_uuid].append(stat.get('cpuUsage', 0.0))

    def get_cluster_state(self, nodes, vms):
        """Analyzes nodes, marking excluded or offline ones as unusable."""
        node_analysis = {}; vm_map = {vm['uuid']: vm for vm in vms if vm.get('uuid')}
        for node in nodes:
            node_uuid = node.get('uuid'); node_ip = node.get('lanIP', node_uuid)
            if not node_uuid: continue
            node_status = node.get('networkStatus'); is_excluded = node.get('lanIP') in self.exclude_ips_set
            is_usable = node.get('allowRunningVMs', False) and node_status == 'ONLINE' and not is_excluded
            exclude_reason = "Manually Excluded" if is_excluded else ("Offline" if node_status != 'ONLINE' else ("VMs Disallowed" if not node.get('allowRunningVMs') else ""))
            avg_cpu = -1.0; ram_percent = 100.0 if not is_usable else 0.0
            running_vms = []; total_ram = node.get('memSize', 0); used_ram = node.get('totalMemUsageBytes', 0)
            if is_usable:
                if node_uuid in self.node_cpu_history and self.node_cpu_history[node_uuid]: avg_cpu = mean(self.node_cpu_history[node_uuid])
                else: avg_cpu = node.get('cpuUsage', 0.0)
                if total_ram > 0: ram_percent = (used_ram / total_ram) * 100.0
                for vm_uuid, vm_data in vm_map.items():
                    if vm_data.get('nodeUUID') == node_uuid and vm_data.get('state') == 'RUNNING':
                        vm_avg = mean(self.vm_cpu_history[vm_uuid]) if vm_uuid in self.vm_cpu_history and self.vm_cpu_history[vm_uuid] else 0.0
                        running_vms.append({"uuid": vm_uuid, "name": vm_data.get('name', 'N/A'), "mem": vm_data.get('mem', 0), "avg_cpu": vm_avg})
                running_vms.sort(key=lambda x: x['avg_cpu'], reverse=True)
            node_analysis[node_uuid] = {
                "uuid": node_uuid, "name": node_ip, "avg_cpu": avg_cpu, "total_ram": total_ram, "used_ram": used_ram,
                "ram_percent": ram_percent, "running_vms": running_vms, "full_object": node, "is_usable": is_usable, "exclude_reason": exclude_reason
            }
        return node_analysis

    def _get_vm_tags(self, vm):
        if not vm: return []
        return [t.strip() for t in (vm.get('tags') or "").split(',') if t.strip()]

    def _get_node_by_ip_suffix(self, nodes, suffix):
        target = f".{suffix}"
        for node in nodes: ip = node.get('lanIP');
        if ip and ip.endswith(target): return node
        return None

    def check_and_warn_node_affinity_violations(self, vms, nodes):
        node_map = {n['uuid']: n for n in nodes if n.get('uuid')}; violations = 0
        for vm in vms:
            if vm.get('state') != 'RUNNING': continue
            tags = self._get_vm_tags(vm); affinity_suffix = None; affinity_tag = None
            for tag in tags:
                if tag.startswith('node_'):
                    try: affinity_suffix = tag.split('_', 1)[1]; affinity_tag = tag; break
                    except (IndexError, ValueError): continue
            if not affinity_suffix: continue
            target_node = self._get_node_by_ip_suffix(nodes, affinity_suffix)
            if not target_node: print(f"  - AFF WARN: VM '{vm.get('name')}' tag '{affinity_tag}' - no node IP ends '.{affinity_suffix}'."); violations+=1; continue
            target_uuid = target_node.get('uuid'); target_ip = target_node.get('lanIP', target_uuid)
            is_target_excluded = target_ip in self.exclude_ips_set
            target_status = target_node.get('networkStatus'); current_uuid = vm.get('nodeUUID')
            current_node = node_map.get(current_uuid); current_id = current_node.get('lanIP', current_uuid) if current_node else current_uuid
            if current_uuid != target_uuid:
                 if target_status == 'OFFLINE': print(f"  - AFF WARN: VM '{vm.get('name')}' wants '{target_ip}' (OFFLINE). Is on '{current_id}'.")
                 elif is_target_excluded: print(f"  - AFF WARN: VM '{vm.get('name')}' wants '{target_ip}' (EXCLUDED). Is on '{current_id}'.")
                 else: print(f"  - AFF VIOLATION: VM '{vm.get('name')}' wants '{target_ip}'. Is on '{current_id}'.")
                 violations += 1
        if violations == 0: print("  - No node affinity violations found.")
        return violations > 0

    def check_and_warn_anti_affinity_violations(self, vms):
        vm_name_map = {vm['name']: vm for vm in vms if vm.get('name')}; node_map = {vm.get('nodeUUID'): vm.get('lanIP', vm.get('nodeUUID')) for vm in vms if vm.get('nodeUUID')}
        violations = 0
        for vm_a in vms:
            tags = self._get_vm_tags(vm_a); node_a = vm_a.get('nodeUUID')
            if not tags or not node_a or vm_a.get('state') != 'RUNNING': continue
            for tag in tags:
                if tag.startswith('anti_'):
                    vm_b = vm_name_map.get(tag[len("anti_"):])
                    if vm_b and node_a == vm_b.get('nodeUUID'):
                        node_id = node_map.get(node_a, node_a); print(f"  - ANTI-AFF VIOLATION: {vm_a.get('name')} & {vm_b.get('name')} on node {node_id}."); violations += 1
        if violations == 0: print("  - No anti-affinity violations found.")
        return violations > 0

    def _check_anti_affinity_for_move(self, vm_to_move_uuid, target_node_uuid, vms):
        vm_map = {vm['uuid']: vm for vm in vms if vm.get('uuid')}
        vm_a = vm_map.get(vm_to_move_uuid); vm_a_name = vm_a.get('name', '') if vm_a else ''
        if not vm_a: return False, "Source VM not found"
        vm_a_tags = self._get_vm_tags(vm_a)
        for vm_b in vms:
            if vm_b.get('nodeUUID') != target_node_uuid: continue
            vm_b_name = vm_b.get('name', ''); vm_b_tags = self._get_vm_tags(vm_b)
            if any(t == f"anti_{vm_b_name}" for t in vm_a_tags): return False, f"Tag conflict with target '{vm_b_name}'"
            if any(t == f"anti_{vm_a_name}" for t in vm_b_tags): return False, f"Target '{vm_b_name}' tag conflicts"
        return True, "OK"

    def find_and_fix_node_affinity_violation(self, cluster_state, vms, nodes):
        """Finds VMs violating node affinity and tries to move them home, evicting if needed."""
        print("Checking for actionable node affinity violations...")
        vm_map = {vm['uuid']: vm for vm in vms if vm.get('uuid')}

        for vm in vms:
            vm_uuid = vm.get('uuid'); current_node_uuid = vm.get('nodeUUID')
            if not vm_uuid or vm.get('state') != 'RUNNING' or not current_node_uuid: continue
            
            vm_tags = self._get_vm_tags(vm); affinity_suffix = None; affinity_tag = None
            for tag in vm_tags:
                if tag.startswith('node_'):
                    try: affinity_suffix = tag.split('_', 1)[1]; affinity_tag = tag; break
                    except (IndexError, ValueError): continue
            if not affinity_suffix: continue

            target_node_obj = self._get_node_by_ip_suffix(nodes, affinity_suffix)
            if not target_node_obj: continue

            target_node_uuid = target_node_obj.get('uuid')
            target_node_state = cluster_state.get(target_node_uuid)

            if current_node_uuid != target_node_uuid:
                target_ip = target_node_obj.get('lanIP', target_node_uuid)
                current_name = cluster_state.get(current_node_uuid,{}).get('name', current_node_uuid)
                print(f"  - VIOLATION: '{vm['name']}' ({affinity_tag}) wants {target_ip}, is on {current_name}.")

                if not target_node_state or not target_node_state.get('is_usable'):
                    print(f"  - Cannot fix: Target node {target_ip} is unusable ({target_node_state.get('exclude_reason', 'Offline/Disallowed')})."); continue

                proj_ram = target_node_state['used_ram'] + vm['mem']; total_ram = target_node_state.get('total_ram', 1)
                proj_pct = (proj_ram / total_ram) * 100.0 if total_ram > 0 else 100.0
                ram_ok = proj_pct <= self.config['RAM_LIMIT_PERCENT']
                
                if not ram_ok: # --- Attempt Eviction ---
                    print(f"  - RAM fail ({proj_pct:.1f}% needed). Try eviction from {target_ip}...")
                    ram_needed = proj_ram - (total_ram * self.config['RAM_LIMIT_PERCENT'] / 100.0)
                    vms_on_target = sorted([vm_map.get(v['uuid']) for v in target_node_state.get('running_vms', []) if vm_map.get(v['uuid'])], key=lambda x: x.get('mem', 0))
                    eviction_cand = None; eviction_dest = None
                    for cand in vms_on_target:
                        cand_uuid = cand['uuid']; cand_mem = cand.get('mem', 0)
                        target_ip_suffix = target_node_obj.get('lanIP', '').split('.')[-1]
                        if any(t == f"node_{target_ip_suffix}" for t in self._get_vm_tags(cand)): print(f"    - Skip {cand['name']}: pinned."); continue
                        if time.time() - self.vm_last_moved_times.get(cand_uuid, 0) < self.config['VM_MOVE_COOLDOWN_MINUTES'] * 60: print(f"    - Skip {cand['name']}: cooldown."); continue
                        if cand_mem < ram_needed: print(f"    - Skip {cand['name']}: too small."); continue
                        print(f"    - Try evict candidate: '{cand['name']}'. Find dest...")
                        poss_dests = [n for n_uuid, n in cluster_state.items() if n.get('is_usable') and n_uuid != target_node_uuid and n_uuid != current_node_uuid]
                        poss_dests.sort(key=lambda x: x['ram_percent'])
                        for dest in poss_dests:
                            dest_total_ram = dest.get('total_ram', 1)
                            dest_proj_ram = dest['used_ram'] + cand_mem; dest_proj_pct = (dest_proj_ram / dest_total_ram) * 100.0 if dest_total_ram > 0 else 100.0
                            if dest_proj_pct > self.config['RAM_LIMIT_PERCENT']: print(f"      - Skip dest {dest['name']}: RAM."); continue
                            allowed, reason = self._check_anti_affinity_for_move(cand_uuid, dest['uuid'], vms)
                            if not allowed: print(f"      - Skip dest {dest['name']}: anti-affinity ({reason})."); continue
                            print(f"      - Found dest: '{dest['name']}'."); eviction_cand = cand; eviction_dest = dest; break
                        if eviction_dest: break
                    
                    if eviction_cand and eviction_dest: # Initiate Eviction
                        evic_vm_uuid = eviction_cand['uuid']; evic_target_uuid = eviction_dest['uuid']
                        if self.config['DRY_RUN']:
                            print(f"\n  *** DRY RUN (Eviction): Move '{eviction_cand['name']}' ({evic_vm_uuid}) ***")
                            print(f"  *** FROM: {target_node_state['name']} TO: {eviction_dest['name']} ***")
                            print(f"  *** Reason: Make space for affinity VM '{vm['name']}' on {target_node_state['name']} ***")
                            self.last_migration_time=time.time(); self.vm_last_moved_times[evic_vm_uuid]=time.time(); self.node_cpu_history.clear(); self.vm_cpu_history.clear()
                        else:
                            print(f"\n  !!! EXECUTE (Eviction): Move '{eviction_cand['name']}' ({evic_vm_uuid}) !!!")
                            print(f"  !!! FROM: {target_node_state['name']} TO: {eviction_dest['name']} !!!")
                            print(f"  !!! Reason: Make space for affinity VM '{vm['name']}' on {target_node_state['name']} !!!")
                            try:
                                resp=self.client.migrate_vm(evic_vm_uuid, evic_target_uuid); task=resp.get('taskTag')
                                if task: self.active_migration_task = { "taskTag": task, "vm_uuid": evic_vm_uuid }; print(f"  - Eviction Task: {task}")
                                else: print("  - Eviction init (no task)."); self.last_migration_time=time.time(); self.vm_last_moved_times[evic_vm_uuid]=time.time()
                            except requests.exceptions.RequestException: print(f"  - Eviction failed."); self.last_migration_time = time.time()
                        return True # Eviction initiated
                    else: print(f"  - WARN: Cannot resolve RAM conflict for '{vm['name']}'. No eviction possible."); continue
                
                # --- Proceed if RAM OK (or eviction started) ---
                if ram_ok:
                    allowed, reason = self._check_anti_affinity_for_move(vm_uuid, target_node_uuid, vms)
                    if not allowed: print(f"  - WARN: Move affinity VM '{vm['name']}' violates anti-affinity ({reason})."); continue
                    source_state = cluster_state.get(current_node_uuid, {}); source_name = source_state.get('name', current_node_uuid)
                    if self.config['DRY_RUN']:
                        print(f"\n  *** DRY RUN (Node Affinity): Move '{vm['name']}' ({vm_uuid}) FROM {source_name} TO {target_node_state['name']} ***")
                        self.last_migration_time=time.time(); self.vm_last_moved_times[vm_uuid]=time.time(); self.node_cpu_history.clear(); self.vm_cpu_history.clear()
                    else:
                        print(f"\n  !!! EXECUTE (Node Affinity): Move '{vm['name']}' ({vm_uuid}) FROM {source_name} TO {target_node_state['name']} !!!")
                        try:
                            resp=self.client.migrate_vm(vm_uuid, target_node_uuid); task=resp.get('taskTag')
                            if task: self.active_migration_task = { "taskTag": task, "vm_uuid": vm_uuid }; print(f"  - Task: {task}")
                            else: print("  - Initiated (no task tag)."); self.last_migration_time=time.time(); self.vm_last_moved_times[vm_uuid]=time.time()
                        except requests.exceptions.RequestException: print(f"  - Failed."); self.last_migration_time = time.time()
                    return True # Fix initiated

        print("  - No actionable node affinity violations found.")
        return False

    def find_and_fix_anti_affinity_violation(self, cluster_state, vms, nodes):
        """Finds anti-affinity violations, tries to fix them avoiding pinned VMs."""
        print("Checking for actionable anti-affinity violations...")
        vm_name_map = {vm['name']: vm for vm in vms if vm.get('name')}; vm_uuid_map = {vm['uuid']: vm for vm in vms if vm.get('uuid')}

        for vm_a_uuid, vm_a in vm_uuid_map.items():
            tags_a = self._get_vm_tags(vm_a); node_a = vm_a.get('nodeUUID')
            if not tags_a or not node_a or vm_a.get('state') != 'RUNNING': continue
            for tag in tags_a:
                if tag.startswith('anti_'):
                    vm_b = vm_name_map.get(tag[len("anti_"):])
                    if not vm_b or node_a != vm_b.get('nodeUUID'): continue
                    
                    print(f"  - VIOLATION: {vm_a['name']} & {vm_b['name']} on {cluster_state.get(node_a,{}).get('name', node_a)}.")
                    node = next((n for n in nodes if n.get('uuid') == node_a), None); ip_suffix = node.get('lanIP', '').split('.')[-1] if node else None
                    pinned_a = ip_suffix and any(t == f"node_{ip_suffix}" for t in tags_a)
                    pinned_b = ip_suffix and any(t == f"node_{ip_suffix}" for t in self._get_vm_tags(vm_b))

                    vm_to_move = None
                    if pinned_a and not pinned_b: vm_to_move = vm_b; print(f"  - Prefer move '{vm_b['name']}'.")
                    elif not pinned_a: vm_to_move = vm_a; print(f"  - Prefer move '{vm_a['name']}'.")
                    elif pinned_a and pinned_b: print(f"  - WARN: Both pinned. Cannot fix."); return False
                    else: vm_to_move = vm_a; print(f"  - (Default) Prefer move '{vm_a['name']}'.")
                    
                    targets = [n for n_uuid, n in cluster_state.items() if n_uuid != node_a and n.get('is_usable')]
                    targets.sort(key=lambda x: x['ram_percent'])
                    
                    target_node = None
                    for node in targets:
                        mem = vm_to_move.get('mem', 0); total_ram = node.get('total_ram', 1)
                        proj_ram = node['used_ram'] + mem; proj_pct = (proj_ram / total_ram) * 100.0 if total_ram > 0 else 100.0
                        if proj_pct > self.config['RAM_LIMIT_PERCENT']: continue
                        allowed, _ = self._check_anti_affinity_for_move(vm_to_move['uuid'], node['uuid'], vms)
                        if not allowed: continue
                        target_node = node; break
                    
                    if not target_node: print(f"  - ERROR: No suitable node for '{vm_to_move['name']}'."); return False

                    vm_uuid_move = vm_to_move['uuid']
                    if self.config['DRY_RUN']:
                        print(f"\n  *** DRY RUN (Anti-Affinity): Move '{vm_to_move['name']}' ({vm_uuid_move}) FROM {cluster_state[node_a]['name']} TO {target_node['name']} ***")
                        self.last_migration_time=time.time(); self.vm_last_moved_times[vm_uuid_move]=time.time(); self.node_cpu_history.clear(); self.vm_cpu_history.clear()
                    else:
                        print(f"\n  !!! EXECUTE (Anti-Affinity): Move '{vm_to_move['name']}' ({vm_uuid_move}) FROM {cluster_state[node_a]['name']} TO {target_node['name']} !!!")
                        try:
                            resp=self.client.migrate_vm(vm_uuid_move, target_node['uuid']); task=resp.get('taskTag')
                            if task: self.active_migration_task = { "taskTag": task, "vm_uuid": vm_uuid_move }; print(f"  - Task: {task}")
                            else: print("  - No task tag."); self.last_migration_time=time.time(); self.vm_last_moved_times[vm_uuid_move]=time.time()
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
            return None, None, None # Not imbalanced

        print(f"Imbalance: {busiest['name']} ({busiest['avg_cpu']:.1f}%) hot; {coolest['name']} ({coolest['avg_cpu']:.1f}%) cool.")
        vm_map = {vm['uuid']: vm for vm in vms if vm.get('uuid')}

        for vm_info in busiest['running_vms']: # Already sorted by VM CPU
            vm_uuid = vm_info['uuid']; vm_full = vm_map.get(vm_uuid)
            if not vm_full: continue
            print(f"  - Eval candidate: {vm_info['name']} (avg CPU {vm_info['avg_cpu']:.1f}%)")

            vm_tags = self._get_vm_tags(vm_full); current_ip_suffix = busiest['full_object'].get('lanIP', '').split('.')[-1]
            if current_ip_suffix and any(t == f"node_{current_ip_suffix}" for t in vm_tags): print(f"  - Skip: Pinned here."); continue
            if time.time() - self.vm_last_moved_times.get(vm_uuid, 0) < self.config['VM_MOVE_COOLDOWN_MINUTES'] * 60: print(f"  - Skip: In cooldown."); continue
            print(f"  - Cooldown OK")

            for target in targets: # Already sorted coolest to warmest
                print(f"  -   Check target: {target['name']} ({target['avg_cpu']:.1f}%)")
                vm_mem = vm_info.get('mem', 0); total_ram = target.get('total_ram', 1)
                proj_ram = target['used_ram'] + vm_mem; proj_pct = (proj_ram / total_ram) * 100.0 if total_ram > 0 else 100.0
                if proj_pct > self.config['RAM_LIMIT_PERCENT']: print(f"  -     Skip target: RAM ({proj_pct:.1f}% needed)."); continue
                print(f"  -     RAM OK ({proj_pct:.1f}%).")
                allowed, reason = self._check_anti_affinity_for_move(vm_uuid, target['uuid'], vms)
                if not allowed: print(f"  -     Skip target: Anti-Affinity ({reason})."); continue
                print(f"  -     Anti-Affinity OK")
                print(f"  -> Select {vm_info['name']} -> {target['name']}.")
                return vm_info, busiest, target # Return info dict, source state, target state

            print(f"  - VM {vm_info['name']} cannot be placed.")

        print("Imbalance detected, but no suitable VM move found.")
        return None, None, None

    def run(self):
        """Main execution loop: check status, cooldowns, violations, balance."""
        while True:
            print(f"\n--- Cycle Start: {time.ctime()} ---")
            try:
                # --- 1. Check Active Migration ---
                if self.active_migration_task:
                    task_tag = self.active_migration_task['taskTag']; vm_uuid = self.active_migration_task['vm_uuid']
                    print(f"Waiting for migration Task {task_tag} (VM {vm_uuid})...")
                    status = self.client.get_task_status(task_tag)
                    print(f"  - State: {status}")
                    if status in ["COMPLETE", "ERROR", "UNINITIALIZED", "UNKNOWN"]:
                        if status == "COMPLETE":
                            print(f"  - Task {task_tag} COMPLETE.")
                            if not self.config['DRY_RUN']: self.client.clear_vm_affinity(vm_uuid)
                            else: print(f"  - *** DRY RUN: Would clear affinity ***")
                            self.vm_last_moved_times[vm_uuid] = time.time()
                            print(f"  - VM {vm_uuid} cooldown started.")
                        else: print(f"  - WARNING: Task {task_tag} state {status}. Affinity NOT cleared.")
                        self.active_migration_task = None; self.last_migration_time = time.time()
                        self.node_cpu_history.clear(); self.vm_cpu_history.clear() # Clear history after move
                    time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue

                # --- 2. Check Recovery Cooldown ---
                if self.recovery_start_time > 0:
                     time_since_rec=time.time()-self.recovery_start_time; rec_dur=self.config['RECOVERY_COOLDOWN_MINUTES']*60
                     if time_since_rec < rec_dur: print(f"In RECOVERY cooldown. Wait {rec_dur-time_since_rec:.0f}s."); time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue
                     else: print("Recovery cooldown finished."); self.recovery_start_time = 0

                # --- 3. Check Cluster Cooldown ---
                time_since_move=time.time()-self.last_migration_time; cluster_cd=self.config['MIGRATION_COOLDOWN_MINUTES']*60
                if time_since_move < cluster_cd: print(f"In cluster cooldown. Wait {cluster_cd-time_since_move:.0f}s."); time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue

                # --- 4. Collect Data ---
                nodes, vms, vm_stats = self.collect_data()
                if not all([nodes, vms, vm_stats]): time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue

                # --- 5. Check OFFLINE Nodes & Manage Recovery ---
                offline_nodes = [n for n in nodes if n.get('networkStatus') == 'OFFLINE']
                if offline_nodes:
                    if not self.cluster_was_unstable: # First detection
                        offline_names = [n.get('lanIP', n.get('uuid')) for n in offline_nodes]
                        print("!"*30 + f"\n  WARNING: Node(s) {offline_names} OFFLINE. Pausing.\n  Checking violations (warnings only):")
                        self.check_and_warn_node_affinity_violations(vms, nodes)
                        self.check_and_warn_anti_affinity_violations(vms)
                        print("!"*30)
                    self.cluster_was_unstable = True # Set flag
                    time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue # Pause
                elif self.cluster_was_unstable: # Recovered
                    print("*"*30 + "\n  INFO: All nodes back ONLINE. Starting RECOVERY cooldown.\n" + "*"*30)
                    self.cluster_was_unstable = False # Clear flag
                    self.recovery_start_time = time.time() # Start recovery timer
                    time.sleep(1); continue # Re-check cooldown

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
                first_hist = next((h for h in self.node_cpu_history.values() if h is not None), None)
                if not first_hist or len(first_hist) < self.max_history_size:
                    print(f"Collecting history {len(first_hist or [])}/{self.max_history_size} samples."); time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue

                print("History full. Analyzing for load balancing...")

                # --- 11. Find Load Balancing Candidates (P3) ---
                vm_move_info, src_node_state, target_node_state = self.find_migration_candidate(cluster_state, vms, nodes)

                # --- 12. Perform Load Balancing Migration ---
                if vm_move_info and src_node_state and target_node_state:
                    vm_uuid = vm_move_info['uuid']; vm_name = vm_move_info['name']
                    if self.config['DRY_RUN']:
                        print(f"\n*** DRY RUN (Load Balance): Move '{vm_name}' ({vm_uuid}) FROM {src_node_state['name']} TO {target_node_state['name']} ***")
                        self.last_migration_time=time.time(); self.vm_last_moved_times[vm_uuid]=time.time()
                        print(f"*** Cooldowns started (sim). Would clear affinity. ***")
                        self.node_cpu_history.clear(); self.vm_cpu_history.clear()
                    else:
                        print(f"\n!!! EXECUTE (Load Balance): Move '{vm_name}' ({vm_uuid}) FROM {src_node_state['name']} TO {target_node_state['name']} !!!")
                        try:
                            resp = self.client.migrate_vm(vm_uuid, target_node_state['uuid']); task = resp.get('taskTag')
                            if task: self.active_migration_task = { "taskTag": task, "vm_uuid": vm_uuid }; print(f"  Task: {task}")
                            else: print("  No task tag."); self.last_migration_time=time.time(); self.vm_last_moved_times[vm_uuid]=time.time()
                        except requests.exceptions.RequestException: print(f"  Failed."); self.last_migration_time = time.time()
                else: print("Cluster balanced or no valid LB move found.")

                # --- 13. Wait ---
                print(f"Waiting {self.config['SAMPLE_INTERVAL_SECONDS']} seconds.")
                time.sleep(self.config['SAMPLE_INTERVAL_SECONDS'])

            except Exception as e: # Catch unexpected errors within the loop
                 print(f"\n!!! UNEXPECTED ERROR IN CYCLE: {e} !!!")
                 print("Attempting to continue after delay...")
                 time.sleep(self.config['SAMPLE_INTERVAL_SECONDS'] * 2) # Longer delay after error

# --- Main Execution ---
def main():
    """Sets up configuration, logs in, runs the balancer loop, and handles logout."""
    config = { # Consolidate config
        'DRY_RUN': DRY_RUN, 'AVG_WINDOW_MINUTES': AVG_WINDOW_MINUTES,
        'SAMPLE_INTERVAL_SECONDS': SAMPLE_INTERVAL_SECONDS, 'RAM_LIMIT_PERCENT': RAM_LIMIT_PERCENT,
        'CPU_UPPER_THRESHOLD_PERCENT': CPU_UPPER_THRESHOLD_PERCENT, 'CPU_LOWER_THRESHOLD_PERCENT': CPU_LOWER_THRESHOLD_PERCENT,
        'MIGRATION_COOLDOWN_MINUTES': MIGRATION_COOLDOWN_MINUTES, 'VM_MOVE_COOLDOWN_MINUTES': VM_MOVE_COOLDOWN_MINUTES,
        'RECOVERY_COOLDOWN_MINUTES': RECOVERY_COOLDOWN_MINUTES, 'EXCLUDE_NODE_IPS': EXCLUDE_NODE_IPS # Include exclude list
    }
    base_url, username, password = get_credentials() # Get credentials
    client = HyperCoreApiClient(base_url, verify_ssl=VERIFY_SSL)
    balancer = LoadBalancer(client, config)

    if not client.login(username, password): sys.exit(1)

    try: balancer.run()
    except KeyboardInterrupt: print("\nCaught interrupt (Ctrl+C), stopping...")
    except Exception as e: print(f"\nFATAL ERROR during execution: {e}")
    finally: client.logout(); print("Script terminated.")

if __name__ == "__main__":
    main()
