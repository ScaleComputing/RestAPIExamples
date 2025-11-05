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

Environment Variables (Optional - Override script defaults):
# Connection
SC_HOST=https://your-hypercore-host # Base URL (e.g., https://192.168.1.10)
SC_USERNAME=your_api_username
SC_PASSWORD=your_api_password
SC_VERIFY_SSL=False # Set to True/1/Yes if cluster has a valid SSL cert

# Behavior
SC_DRY_RUN=True # Set to False/0/No to enable LIVE migrations
SC_AVG_WINDOW_MINUTES=5
SC_SAMPLE_INTERVAL_SECONDS=30
SC_RAM_LIMIT_PERCENT=70.0
SC_CPU_UPPER_THRESHOLD_PERCENT=80.0
SC_CPU_LOWER_THRESHOLD_PERCENT=50.0
SC_MIGRATION_COOLDOWN_MINUTES=5
SC_VM_MOVE_COOLDOWN_MINUTES=30
SC_RECOVERY_COOLDOWN_MINUTES=15
SC_EXCLUDE_NODE_IPS="192.168.1.101,192.168.1.102" # Comma-separated IPs

"""

import requests
import time
import json
import warnings
import sys
from collections import deque
from statistics import mean
import os
import traceback

# --- Configuration (Defaults - Can be overridden by ENV VARS) ---

# Cluster Connection - Used if corresponding SC_* environment variables are NOT set
DEFAULT_BASE_URL = "https://your-HyperCore-cluster-ip/rest/v1"  # !! EDIT if not using ENV VARS
DEFAULT_USERNAME = "your-username"                             # !! EDIT if not using ENV VARS
DEFAULT_PASSWORD = "your-password"                             # !! EDIT if not using ENV VARS
DEFAULT_VERIFY_SSL = False                                     # Default SSL verification

# Load Balancer Tunables - Used if corresponding SC_* environment variables are NOT set
DEFAULT_DRY_RUN = True                          # !! SAFETY: Set to False to enable LIVE migrations !!
DEFAULT_AVG_WINDOW_MINUTES = 5                  # How long (in minutes) of performance data to average for decisions
DEFAULT_SAMPLE_INTERVAL_SECONDS = 30            # How often (in seconds) to collect new performance data
DEFAULT_RAM_LIMIT_PERCENT = 70.0                # RAM Constraint: Do not migrate a VM *to* a node if it would exceed this usage %
DEFAULT_CPU_UPPER_THRESHOLD_PERCENT = 80.0      # CPU Threshold: Node avg CPU must be *above* this % to be source
DEFAULT_CPU_LOWER_THRESHOLD_PERCENT = 50.0      # CPU Threshold: Node avg CPU must be *below* this % to be target
DEFAULT_MIGRATION_COOLDOWN_MINUTES = 5          # Wait after *any* migration finishes before attempting another
DEFAULT_VM_MOVE_COOLDOWN_MINUTES = 30           # Wait after a *specific VM* is moved before it can be moved again
DEFAULT_RECOVERY_COOLDOWN_MINUTES = 15          # Wait after a node comes back ONLINE before resuming operations
DEFAULT_EXCLUDE_NODE_IPS = []                   # !! EDIT: List of node IPs to exclude, e.g., ["192.168.1.101"]

# --- End of Configuration ---


# --- Helper Function to get configuration values ---
def get_config_value(env_var_name, default_value, expected_type=str):
    """
    Reads an environment variable, attempts to cast it, and returns
    the value or the default if missing/invalid.
    """
    env_value = os.getenv(env_var_name)
    if env_value is None:
        return default_value

    original_env_value = env_value
    try:
        if expected_type == bool:
            env_value = env_value.lower()
            if env_value in ('true', '1', 'yes', 'y'): return True
            if env_value in ('false', '0', 'no', 'n'): return False
            raise ValueError("Invalid boolean value")
        elif expected_type == int:
            val = int(env_value)
            if env_var_name.endswith(('_SECONDS', '_MINUTES')) and val < 0:
                 raise ValueError("Time values cannot be negative")
            return val
        elif expected_type == float:
            val = float(env_value)
            if env_var_name.endswith('_PERCENT') and (val < 0 or val > 100):
                raise ValueError("Percentage values must be between 0 and 100")
            return val
        elif expected_type == list:
            return [ip.strip() for ip in env_value.split(',') if ip.strip()]
        else:
            return str(env_value)
    except ValueError as e:
        print(f"WARN: Invalid value '{original_env_value}' for ENV VAR '{env_var_name}' (expected {expected_type.__name__}): {e}. Using default: {default_value}")
        return default_value

# --- API Client Class ---
class HyperCoreApiClient:
    """A simple client for interacting with the Scale Computing HyperCore REST API."""

    def __init__(self, base_url, username, password, verify_ssl=True):
        self.base_url = base_url.rstrip('/')
        self.base_host = '/'.join(self.base_url.split('/')[:3])
        self.primary_host_address = self.base_host.split('//')[-1]
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.username = username
        self.password = password
        self.logged_in = False

        if not verify_ssl:
            try:
                from urllib3.exceptions import InsecureRequestWarning
                warnings.simplefilter('ignore', InsecureRequestWarning)
            except ImportError: pass

    def login(self, username=None, password=None):
        user = username if username is not None else self.username
        pw = password if password is not None else self.password
        if not user or not pw: print("Login failed: Credentials missing."); return False
        if username is not None: self.username = username
        if password is not None: self.password = password
        login_url = f"{self.base_url}/login"
        credentials = {"username": user, "password": pw}
        try:
            self.session.cookies.clear()
            response = self.session.post(login_url, json=credentials, timeout=10)
            response.raise_for_status(); print("Successfully logged in."); self.logged_in = True; return True
        except requests.exceptions.RequestException as e: print(f"Login failed: {e}"); self.logged_in = False; return False

    def logout(self):
        if self.logged_in:
            try: self.session.post(f"{self.base_url}/logout", timeout=5); print("Successfully logged out.")
            except requests.exceptions.RequestException: pass
            finally: self.logged_in = False

    def _request(self, method, endpoint, base_override=None, is_retry=False, **kwargs):
        effective_base = base_override if base_override else self.base_url
        url = f"{effective_base}{endpoint}"
        try:
            timeout = kwargs.pop('timeout', 15)
            response = self.session.request(method, url, timeout=timeout, **kwargs)
            response.raise_for_status()
            if response.status_code == 204 or not response.content: return {}
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401 and not is_retry:
                print("WARN: Received 401 Unauthorized. Attempting re-login..."); self.logged_in = False
                if self.login():
                    print("Re-login successful. Retrying original request...")
                    kwargs['is_retry'] = True
                    return self._request(method, endpoint, base_override=base_override, **kwargs)
                else: print("ERROR: Re-login failed."); raise e
            else: target_display = (base_override or self.base_url).split('/')[2]; print(f"API Error ({method} {endpoint} on {target_display}): {e}"); raise e
        except requests.exceptions.RequestException as e: target_display = (base_override or self.base_url).split('/')[2]; print(f"API Error ({method} {endpoint} on {target_display}): {e}"); raise e

    def _get(self, endpoint, base_override=None): return self._request('get', endpoint, base_override=base_override)
    def _post(self, endpoint, data): return self._request('post', endpoint, json=data)
    def _patch(self, endpoint, data): return self._request('patch', endpoint, json=data)

    def get_nodes(self, base_override=None): return self._get("/Node", base_override=base_override)
    def get_vms(self): return self._get("/VirDomain")
    def get_vm_stats(self): return self._get("/VirDomainStats")
    def get_task_status(self, task_tag):
        try: status_list = self._request('get', f"/TaskTag/{task_tag}"); return status_list[0]['state'] if status_list else "UNKNOWN"
        except requests.exceptions.RequestException as e: print(f"  - Warn: Task status check fail {task_tag}: {e}"); return "UNKNOWN"

    def migrate_vm(self, vm_uuid, target_node_uuid):
        action = [{"virDomainUUID": vm_uuid, "actionType": "LIVEMIGRATE", "nodeUUID": target_node_uuid}]; return self._post("/VirDomain/action", action)

    def is_update_active(self, all_nodes):
        nodes_to_check = []; other_node_ips = []; primary_check_failed = False; primary_node_details = None
        if not all_nodes: print("  - WARN: No node list for update check. Only trying primary."); nodes_to_check = [self.primary_host_address]
        else:
            primary_node_details = next((n for n in all_nodes if n.get('lanIP') == self.primary_host_address), None)
            other_node_ips = [node.get('lanIP') for node in all_nodes if node.get('lanIP') and node.get('networkStatus') == 'ONLINE' and node.get('lanIP') != self.primary_host_address]
            if self.primary_host_address not in nodes_to_check: nodes_to_check.append(self.primary_host_address)
            nodes_to_check.extend(other_node_ips); nodes_to_check = list(dict.fromkeys(nodes_to_check))

        print(f"  - Checking update status on nodes (order: {', '.join(nodes_to_check)})...")
        for node_ip in nodes_to_check:
            is_primary = (node_ip == self.primary_host_address); scheme = self.base_host.split('://')[0]; status_url = f"{scheme}://{node_ip}/update/update_status.json"
            try:
                response = self.session.get(status_url, timeout=5, verify=self.session.verify); response.raise_for_status(); status_data = response.json()
                prepare_state = status_data.get('prepareStatus', {}).get('state')
                if prepare_state and prepare_state != "COMPLETE": print(f"  - Update Status: Prepare state '{prepare_state}' from {node_ip}."); return True
                master_state = status_data.get('updateStatus', {}).get('masterState')
                if master_state and master_state != "COMPLETE": print(f"  - Update Status: Update state '{master_state}' from {node_ip}."); return True
                else:
                    print(f"  - Update Status: Prepare='{prepare_state or 'N/A'}', Update='{master_state or 'N/A'}' on {node_ip}. Not active.")
                    if not is_primary and primary_check_failed:
                        if not primary_node_details and all_nodes: primary_node_details = next((n for n in all_nodes if n.get('lanIP') == self.primary_host_address), None)
                        if primary_node_details:
                            print(f"  - Double-checking primary ({self.primary_host_address}) status via secondary ({node_ip})...")
                            secondary_api_base = f"{scheme}://{node_ip}/rest/v1"
                            try:
                                nodes_from_secondary = self.get_nodes(base_override=secondary_api_base)
                                primary_status = "UNKNOWN (Not in list)"; primary_uuid = primary_node_details.get('uuid')
                                if primary_uuid:
                                    for node in nodes_from_secondary:
                                        if node.get('uuid') == primary_uuid: primary_status = node.get('networkStatus', 'UNKNOWN'); break
                                print(f"  - Secondary {node_ip} reports primary node status: {primary_status}")
                            except requests.exceptions.RequestException as e_check: print(f"  - WARN: Failed double-check via {node_ip}: {e_check}")
                        else: print(f"  - Info: Cannot double-check primary (details unavailable).")
                    return False # No active update/prepare
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                print(f"  - Info: Node {node_ip} unreachable for update check.")
                if is_primary: primary_check_failed = True
            except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
                print(f"  - Info: Failed get/parse update status from {node_ip}: {e}")
                if is_primary: primary_check_failed = True
            except Exception as e:
                 print(f"  - WARN: Unexpected error check update on {node_ip}: {e}")
                 if is_primary: primary_check_failed = True
        print(f"  - Info: Cannot determine update status from any node. Assuming no update history present. Continue operations"); return False


# --- Load Balancer Class ---
class LoadBalancer:
    """Manages data collection, analysis, and migration logic."""

    def __init__(self, client, config):
        self.client = client
        self.config = config
        self.exclude_ips_set = set(config.get('EXCLUDE_NODE_IPS', []))
        if self.exclude_ips_set: print(f"INFO: Excluding nodes with IPs: {', '.join(self.exclude_ips_set)}")
        self.max_history_size = int((config['AVG_WINDOW_MINUTES'] * 60) / config['SAMPLE_INTERVAL_SECONDS'])
        if self.max_history_size < 1: print("FATAL: AVG_WINDOW_MINUTES must be >= SAMPLE_INTERVAL_SECONDS."); sys.exit(1)
        print(f"History window: {self.max_history_size} samples (~{config['AVG_WINDOW_MINUTES']} min).")
        self.node_cpu_history = {}; self.vm_cpu_history = {}
        self.last_migration_time = 0; self.active_migration_task = None
        self.vm_last_moved_times = {}; self.cluster_was_unstable = False; self.recovery_start_time = 0
        self.last_known_nodes = []

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
        """Analyzes nodes, marking excluded, offline, or non-virtualization ones as unusable."""
        node_analysis = {}; vm_map = {vm['uuid']: vm for vm in vms if vm.get('uuid')}
        for node in nodes:
            node_uuid = node.get('uuid'); node_ip = node.get('lanIP', node_uuid)
            if not node_uuid: continue
            node_status = node.get('networkStatus'); supports_virt = node.get('supportsVirtualization', True); virt_online = node.get('virtualizationOnline', True)
            is_excluded = node.get('lanIP') in self.exclude_ips_set
            allow_vms = node.get('allowRunningVMs', True) # Default to True, matching API
            is_usable = allow_vms and node_status == 'ONLINE' and not is_excluded and supports_virt and virt_online
            exclude_reason = "Manually Excluded" if is_excluded else ("Offline" if node_status != 'ONLINE' else ("VMs Disallowed" if not allow_vms else ("No Virtualization Support" if not supports_virt else ("Virtualization Offline" if not virt_online else ""))))
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
        """Finds a node object by the last octet of its LAN IP."""
        target_suffix = f".{suffix}"
        for node in nodes:
            lan_ip = node.get('lanIP')
            if lan_ip and lan_ip.endswith(target_suffix):
                return node # Return immediately on first match
        return None # Return None if no match is found

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
                 elif not target_node.get('supportsVirtualization', True) or not target_node.get('virtualizationOnline', True): print(f"  - AFF WARN: VM '{vm.get('name')}' wants '{target_ip}' (NO VIRT SUPPORT/OFFLINE). Is on '{current_id}'.")
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
        action_initiated = False

        for vm in vms:
            vm_uuid = vm.get('uuid'); current_node_uuid = vm.get('nodeUUID')
            if not vm_uuid or vm.get('state') != 'RUNNING' or not current_node_uuid: continue
            
            vm_tags = self._get_vm_tags(vm); affinity_suffix = None; affinity_tag = None
            for tag in vm_tags:
                if tag.startswith('node_'):
                    try: affinity_suffix = tag.split('_', 1)[1]; affinity_tag = tag; break
                    except (IndexError, ValueError): continue
            
            if not affinity_suffix: continue

            # --- Start Debug Block ---
            vm_name = vm.get('name', 'N/A')
            print(f"  - INFO: Found VM '{vm_name}' with affinity tag '{affinity_tag}'.")
            target_node_obj = self._get_node_by_ip_suffix(nodes, affinity_suffix)
            
            if not target_node_obj:
                print(f"  - INFO: Could not find any node with IP suffix '.{affinity_suffix}' for VM '{vm_name}'.")
                continue
                
            target_node_uuid = target_node_obj.get('uuid')
            target_node_ip = target_node_obj.get('lanIP', target_node_uuid)
            print(f"  - INFO: VM '{vm_name}' wants target node {target_node_ip} ({target_node_uuid}).")
            print(f"  - INFO: VM '{vm_name}' is currently on node {cluster_state.get(current_node_uuid,{}).get('name', current_node_uuid)} ({current_node_uuid}).")
            # --- End Debug Block ---

            target_node_state = cluster_state.get(target_node_uuid)

            if current_node_uuid != target_node_uuid:
                target_ip = target_node_obj.get('lanIP', target_node_uuid)
                current_name = cluster_state.get(current_node_uuid,{}).get('name', current_node_uuid)
                print(f"  - VIOLATION: '{vm['name']}' ({affinity_tag}) wants {target_ip}, is on {current_name}.")

                if not target_node_state or not target_node_state.get('is_usable'):
                    print(f"  - Cannot fix: Target node {target_ip} is unusable ({target_node_state.get('exclude_reason', 'Offline/Disallowed')})."); continue

                proj_ram = target_node_state['used_ram'] + vm.get('mem', 0); total_ram = target_node_state.get('total_ram', 1)
                proj_pct = (proj_ram / total_ram) * 100.0 if total_ram > 0 else 100.0
                ram_ok = proj_pct <= self.config['RAM_LIMIT_PERCENT']
                
                if not ram_ok: # --- Attempt Eviction ---
                    print(f"  - RAM fail ({proj_pct:.1f}% needed). Try eviction from {target_ip}...")
                    ram_needed = proj_ram - (total_ram * self.config['RAM_LIMIT_PERCENT'] / 100.0)
                    vms_on_target_info = target_node_state.get('running_vms', [])
                    valid_vms_on_target = [vm_map.get(v_info['uuid']) for v_info in vms_on_target_info if vm_map.get(v_info['uuid'])]
                    if not valid_vms_on_target: print(f"    - No valid VMs found on {target_ip} to evict."); continue
                    vms_on_target_sorted = sorted(valid_vms_on_target, key=lambda x: x.get('mem', 0))

                    eviction_cand = None; eviction_dest = None
                    for cand in vms_on_target_sorted:
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
                        action_initiated = True; break 
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
                    action_initiated = True; break 
            
            if action_initiated: break

        if not action_initiated: print("  - No actionable node affinity violations found.")
        return action_initiated

    def find_and_fix_anti_affinity_violation(self, cluster_state, vms, nodes):
        """Finds anti-affinity violations, tries to fix them avoiding pinned VMs."""
        print("Checking for actionable anti-affinity violations...")
        vm_name_map = {vm['name']: vm for vm in vms if vm.get('name')}; vm_uuid_map = {vm['uuid']: vm for vm in vms if vm.get('uuid')}
        action_initiated = False

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
                    action_initiated = True; break # Exit inner tag loop
            if action_initiated: break # Exit outer VM loop

        if not action_initiated: print("  - No actionable anti-affinity violations found.")
        return action_initiated

    def find_migration_candidate(self, cluster_state, vms, nodes):
        """Finds migration candidates for load balancing, respecting constraints."""
        usable_nodes = {uuid: data for uuid, data in cluster_state.items() if data.get('is_usable')}
        if len(usable_nodes) < 2: print("  - Need >= 2 usable nodes for balancing."); return None, None, None

        sorted_nodes = sorted(usable_nodes.values(), key=lambda x: x['avg_cpu'])
        busiest = sorted_nodes[-1]; targets = sorted_nodes[:-1]; coolest = targets[0]

        if not (busiest['avg_cpu'] > self.config['CPU_UPPER_THRESHOLD_PERCENT'] and coolest['avg_cpu'] < self.config['CPU_LOWER_THRESHOLD_PERCENT']):
             if coolest: print(f"  - No imbalance based on thresholds ({self.config['CPU_UPPER_THRESHOLD_PERCENT']}%/{self.config['CPU_LOWER_THRESHOLD_PERCENT']}%). Busiest: {busiest['avg_cpu']:.1f}%, Coolest: {coolest['avg_cpu']:.1f}%")
             return None, None, None # Not imbalanced enough or only one usable node

        print(f"Imbalance detected: Node {busiest['name']} (avg {busiest['avg_cpu']:.1f}%) hot; Node {coolest['name']} (avg {coolest['avg_cpu']:.1f}%) cool.")
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
                if proj_pct > self.config['RAM_LIMIT_PERCENT']: print(f"  -     Skip target: RAM ({proj_pct:.1f}% needed > {self.config['RAM_LIMIT_PERCENT']}% limit)."); continue
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
                            self.vm_last_moved_times[vm_uuid] = time.time()
                            print(f"  - VM {vm_uuid} cooldown started.")
                        else: print(f"  - WARNING: Task {task_tag} state {status}.")
                        self.active_migration_task = None; self.last_migration_time = time.time()
                        self.node_cpu_history.clear(); self.vm_cpu_history.clear()
                    time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue

                # --- 2. Check Recovery Cooldown ---
                if self.recovery_start_time > 0:
                     time_since_rec=time.time()-self.recovery_start_time; rec_dur=self.config['RECOVERY_COOLDOWN_MINUTES']*60
                     if time_since_rec < rec_dur: print(f"In RECOVERY cooldown. Wait {rec_dur-time_since_rec:.0f}s."); time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue
                     else: print("Recovery cooldown finished."); self.recovery_start_time = 0

                # --- 3. Check Cluster Cooldown ---
                time_since_move=time.time()-self.last_migration_time; cluster_cd=self.config['MIGRATION_COOLDOWN_MINUTES']*60
                if time_since_move < cluster_cd: print(f"In cluster cooldown. Wait {cluster_cd-time_since_move:.0f}s."); time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue

                # --- 4. Collect Data (and potentially update last known nodes) ---
                print("Collecting cluster data...")
                nodes_data, vms_data, vm_stats_data = self.collect_data()

                current_nodes_list = []
                if nodes_data is not None:
                     self.last_known_nodes = nodes_data
                     current_nodes_list = nodes_data
                     if time.time() - self.last_migration_time > 1 :
                         print(f"  - Successfully collected data for {len(nodes_data)} nodes.")
                elif self.last_known_nodes:
                     print("  - WARN: Failed collect node data. Using last known list for checks.")
                     current_nodes_list = self.last_known_nodes
                else:
                     print("  - ERROR: Failed collect node data & no previous list. Cannot proceed.")
                     time.sleep(self.config['SAMPLE_INTERVAL_SECONDS'] * 2); continue

                if vms_data is None or vm_stats_data is None:
                    if nodes_data is None: # Only error out if *fresh* data failed entirely
                        print("  - ERROR: Failed collect VM/Stats data. Cannot proceed this cycle.")
                        time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue

                # --- 5. Check for Active Cluster Update (using current or last known nodes) ---
                print("Checking cluster update status...")
                if self.client.is_update_active(current_nodes_list): # Pass the node list
                    print("  - Cluster update active or status unknown. Pausing balancing operations.")
                    time.sleep(self.config['SAMPLE_INTERVAL_SECONDS'] * 2); continue
                else:
                    print("  - No active cluster update detected.")

                # --- 6. Check OFFLINE Nodes & Manage Recovery ---
                offline_nodes = [n for n in current_nodes_list if n.get('networkStatus') == 'OFFLINE']
                if offline_nodes:
                    if not self.cluster_was_unstable:
                        offline_names = [n.get('lanIP', n.get('uuid')) for n in offline_nodes]
                        print("!"*30 + f"\n  WARNING: Node(s) {offline_names} OFFLINE. Pausing.\n  Checking violations (warnings only):")
                        self.check_and_warn_node_affinity_violations(vms_data if vms_data is not None else [], current_nodes_list)
                        self.check_and_warn_anti_affinity_violations(vms_data if vms_data is not None else [])
                        print("!"*30)
                    self.cluster_was_unstable = True
                    time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue
                elif self.cluster_was_unstable:
                    print("*"*30 + "\n  INFO: All nodes previously OFFLINE now appear ONLINE. Starting RECOVERY cooldown.\n" + "*"*30)
                    self.cluster_was_unstable = False
                    self.recovery_start_time = time.time()
                    time.sleep(1); continue
                
                # --- Stop if data collection failed ---
                if nodes_data is None:
                    print("  - Skipping affinity/balancing checks due to failed data collection this cycle.")
                    time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue

                # --- 7. Update History (Only if data collection was fully successful this cycle) ---
                self.update_history(nodes_data, vms_data, vm_stats_data)

                # --- 8. Analyze Cluster State (Use fresh data) ---
                cluster_state = self.get_cluster_state(nodes_data, vms_data)

                # --- 9. Fix Node Affinity (P1 - Use fresh data) ---
                if self.find_and_fix_node_affinity_violation(cluster_state, vms_data, nodes_data):
                     print("Node affinity fix initiated. Next cycle."); time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue

                # --- 10. Fix Anti-Affinity (P2 - Use fresh data) ---
                if self.find_and_fix_anti_affinity_violation(cluster_state, vms_data, nodes_data):
                    print("Anti-affinity fix initiated. Next cycle."); time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue

                # --- 11. Check History Full for Load Balancing ---
                first_hist = next((h for h in self.node_cpu_history.values() if h is not None), None)
                if not first_hist or len(first_hist) < self.max_history_size:
                    print(f"Collecting history {len(first_hist or [])}/{self.max_history_size} samples."); time.sleep(self.config['SAMPLE_INTERVAL_SECONDS']); continue

                print("History full. Analyzing for load balancing...")

                # --- 12. Find Load Balancing Candidates (P3 - Use fresh data) ---
                vm_move_info, src_node_state, target_node_state = self.find_migration_candidate(cluster_state, vms_data, nodes_data)

                # --- 13. Perform Load Balancing Migration ---
                if vm_move_info and src_node_state and target_node_state:
                    vm_uuid = vm_move_info['uuid']; vm_name = vm_move_info['name']
                    if self.config['DRY_RUN']:
                        print(f"\n*** DRY RUN (Load Balance): Move '{vm_name}' ({vm_uuid}) FROM {src_node_state['name']} TO {target_node_state['name']} ***")
                        self.last_migration_time=time.time(); self.vm_last_moved_times[vm_uuid]=time.time()
                        print(f"*** Cooldowns started (simulated). ***")
                        self.node_cpu_history.clear(); self.vm_cpu_history.clear()
                    else:
                        print(f"\n!!! EXECUTE (Load Balance): Move '{vm_name}' ({vm_uuid}) FROM {src_node_state['name']} TO {target_node_state['name']} !!!")
                        try:
                            resp = self.client.migrate_vm(vm_uuid, target_node_state['uuid']); task = resp.get('taskTag')
                            if task: self.active_migration_task = { "taskTag": task, "vm_uuid": vm_uuid }; print(f"  Task: {task}")
                            else: print("  No task tag."); self.last_migration_time=time.time(); self.vm_last_moved_times[vm_uuid]=time.time()
                        except requests.exceptions.RequestException: print(f"  Failed."); self.last_migration_time = time.time()
                else: print("Cluster balanced or no valid LB move found.")

                # --- 14. Wait ---
                print(f"Waiting {self.config['SAMPLE_INTERVAL_SECONDS']} seconds.")
                time.sleep(self.config['SAMPLE_INTERVAL_SECONDS'])

            except Exception as e: # Catch unexpected errors within the loop
                 print(f"\n!!! UNEXPECTED ERROR IN CYCLE: {e} !!!")
                 traceback.print_exc() # Print full traceback for debugging
                 print("Attempting to continue after delay...")
                 time.sleep(self.config['SAMPLE_INTERVAL_SECONDS'] * 2) # Longer delay

# --- Main Execution ---
def main():
    """Sets up configuration, logs in, runs the balancer loop, and handles logout."""
    # --- Read Config from ENV or Defaults ---
    print("--- Loading Configuration ---")
    config_map = {
        'SC_HOST': (DEFAULT_BASE_URL, str), 'SC_USERNAME': (DEFAULT_USERNAME, str),
        'SC_PASSWORD': (DEFAULT_PASSWORD, str), 'SC_VERIFY_SSL': (DEFAULT_VERIFY_SSL, bool),
        'SC_DRY_RUN': (DEFAULT_DRY_RUN, bool), 'SC_AVG_WINDOW_MINUTES': (DEFAULT_AVG_WINDOW_MINUTES, int),
        'SC_SAMPLE_INTERVAL_SECONDS': (DEFAULT_SAMPLE_INTERVAL_SECONDS, int), 'SC_RAM_LIMIT_PERCENT': (DEFAULT_RAM_LIMIT_PERCENT, float),
        'SC_CPU_UPPER_THRESHOLD_PERCENT': (DEFAULT_CPU_UPPER_THRESHOLD_PERCENT, float), 'SC_CPU_LOWER_THRESHOLD_PERCENT': (DEFAULT_CPU_LOWER_THRESHOLD_PERCENT, float),
        'SC_MIGRATION_COOLDOWN_MINUTES': (DEFAULT_MIGRATION_COOLDOWN_MINUTES, int), 'SC_VM_MOVE_COOLDOWN_MINUTES': (DEFAULT_VM_MOVE_COOLDOWN_MINUTES, int),
        'SC_RECOVERY_COOLDOWN_MINUTES': (DEFAULT_RECOVERY_COOLDOWN_MINUTES, int), 'SC_EXCLUDE_NODE_IPS': (DEFAULT_EXCLUDE_NODE_IPS, list)
    }
    final_config = {}; config_sources = {}
    env_host = os.getenv('SC_HOST'); env_user = os.getenv('SC_USERNAME'); env_pass = os.getenv('SC_PASSWORD')
    using_env_creds = bool(env_host and env_user and env_pass)
    if using_env_creds:
        print("Using Connection Credentials from ENV VARS.")
        base_url = env_host.rstrip('/'); username = env_user; password = env_pass
        if not base_url.endswith('/rest/v1'): base_url += '/rest/v1'
        config_sources['SC_HOST'] = '(ENV)'; config_sources['SC_USERNAME'] = '(ENV)'; config_sources['SC_PASSWORD'] = '(ENV)'
    else:
        print("Using Connection Credentials from script defaults.")
        base_url = DEFAULT_BASE_URL; username = DEFAULT_USERNAME; password = DEFAULT_PASSWORD
        config_sources['SC_HOST'] = '(Default)'; config_sources['SC_USERNAME'] = '(Default)'; config_sources['SC_PASSWORD'] = '(Default)'

    for env_var, (default, expected_type) in config_map.items():
        if env_var in ['SC_HOST', 'SC_USERNAME', 'SC_PASSWORD']: continue
        value = get_config_value(env_var, default, expected_type); final_config[env_var.replace('SC_', '')] = value
        config_sources[env_var] = '(ENV)' if os.getenv(env_var) is not None else '(Default)'
    final_config['VERIFY_SSL'] = get_config_value('SC_VERIFY_SSL', DEFAULT_VERIFY_SSL, bool)
    config_sources['SC_VERIFY_SSL'] = '(ENV)' if os.getenv('SC_VERIFY_SSL') is not None else '(Default)'

    # --- Print Configuration Summary ---
    print("\n--- Configuration Settings ---")
    print(f"{'Parameter':<30} {'Value':<40} {'Source'}"); print("-" * 75)
    print(f"{'SC_HOST':<30} {base_url:<40} {config_sources['SC_HOST']}")
    print(f"{'SC_USERNAME':<30} {username:<40} {config_sources['SC_USERNAME']}")
    print(f"{'SC_PASSWORD':<30} {'******':<40} {config_sources['SC_PASSWORD']}")
    print(f"{'SC_VERIFY_SSL':<30} {str(final_config['VERIFY_SSL']):<40} {config_sources['SC_VERIFY_SSL']}")
    for env_var, (default, _) in config_map.items():
         if env_var not in ['SC_HOST', 'SC_USERNAME', 'SC_PASSWORD', 'SC_VERIFY_SSL']:
             key_for_final = env_var.replace('SC_', ''); print(f"{env_var:<30} {str(final_config[key_for_final]):<40} {config_sources[env_var]}")
    print("-" * 75)
    
    # --- Initialize and Login ---
    client = HyperCoreApiClient(base_url, username, password, verify_ssl=final_config['VERIFY_SSL']);
    balancer = LoadBalancer(client, final_config)
    if not client.login(): sys.exit(1)

    # --- Run Balancer ---
    try: balancer.run()
    except KeyboardInterrupt: print("\nCaught interrupt (Ctrl+C), stopping...")
    except Exception as e: print(f"\nFATAL ERROR during execution: {e}"); traceback.print_exc()
    finally: client.logout(); print("Script terminated.")

if __name__ == "__main__":
    main()