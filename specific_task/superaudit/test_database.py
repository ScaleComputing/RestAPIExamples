#!/usr/bin/env python3
"""
Quick test script to verify database auto-initialization.
"""

import sys
import os
from datetime import datetime

# Add lib to path
sys.path.insert(0, os.path.dirname(__file__))

from lib.database import AuditDatabase


def test_database_creation():
    """Test database creation and schema initialization."""
    print("=" * 70)
    print("SuperAudit Database Test")
    print("=" * 70)
    print()

    # Create database (should auto-initialize)
    test_db_path = "/tmp/superaudit_test.db"

    # Remove existing test database
    if os.path.exists(test_db_path):
        os.remove(test_db_path)
        print(f"Removed existing test database: {test_db_path}")
        print()

    print("Creating new database...")
    print()

    with AuditDatabase(test_db_path) as db:
        print()
        print("✓ Database initialized successfully!")
        print()

        # Test insertion of sample data
        print("Testing data insertion...")
        sample_audit_data = {
            'cluster_info': {
                'clusterName': 'TestCluster',
                'clusterUUID': 'test-uuid-123',
                'icosVersion': '9.4.33'
            },
            'statistics': {
                'nodes_count': 3,
                'vms_total': 10,
                'vms_running': 7,
                'vms_stopped': 3,
                'vms_paused': 0,
                'storage_allocated_bytes': 5_000_000_000_000,  # 5TB
                'storage_used_bytes': 1_000_000_000_000,       # 1TB
                'memory_allocated_bytes': 128_000_000_000,     # 128GB
                'compliance_score': 87.5,
                'vms_with_snapshots': 8,
                'vms_with_replication': 5,
                'vms_with_ha_policy': 6,
                'warnings_critical': 1,
                'warnings_warning': 3,
                'warnings_info': 2,
                'warnings_total': 6,
                'execution_time': 2.5
            },
            'vms': [
                {
                    'uuid': 'vm-001',
                    'name': 'TestVM01',
                    'state': 'RUNNING',
                    'vm_type': 'PRODUCTION VM',
                    'description': 'Test production VM',
                    'tags': 'production,web',
                    'cpu_count': 4,
                    'memory_bytes': 8_589_934_592,  # 8GB
                    'disk_count': 2,
                    'disk_total_bytes': 107_374_182_400,  # 100GB
                    'disk_used_bytes': 53_687_091_200,    # 50GB
                    'disk_snapshot_bytes': 10_737_418_240, # 10GB
                    'boot_order': 'DISK,NIC',
                    'machine_type': 'UEFI',
                    'operating_system': 'Ubuntu 22.04',
                    'ha_policy': 'STRICT',
                    'ip_addresses': '10.0.1.100',
                    'vlans': '100',
                    'mac_addresses': '00:11:22:33:44:55',
                    'network_adapter_count': 1,
                    'has_snapshots': True,
                    'snapshot_count': 5,
                    'snapshot_schedules': 'daily-backup',
                    'has_replication': True,
                    'replication_partners': 'DR-Cluster',
                    'node_uuid': 'node-001',
                    'node_lan_ip': '10.0.0.1',
                    'node_cpu_percent': 35.2
                }
            ],
            'nodes': [
                {
                    'uuid': 'node-001',
                    'lanIP': '10.0.0.1',
                    'peerID': 1,
                    'model': 'HC3',
                    'serialNumber': 'SN123456',
                    'cpuCores': 16,
                    'cpuModel': 'Intel Xeon',
                    'cpuUsagePercent': 35.2,
                    'memoryTotal': 137_438_953_472,  # 128GB
                    'memoryAvailable': 68_719_476_736,  # 64GB
                    'memoryUsagePercent': 50.0,
                    'status': 'ONLINE',
                    'online': True
                }
            ],
            'warnings': [
                {
                    'severity': 'CRITICAL',
                    'category': 'VM',
                    'message': 'VM without snapshots',
                    'vm_uuid': 'vm-002',
                    'vm_name': 'TestVM02'
                }
            ]
        }

        snapshot_id = db.insert_audit_snapshot(sample_audit_data)
        print(f"✓ Inserted audit snapshot with ID: {snapshot_id}")
        print()

        # Test retrieval
        print("Testing data retrieval...")
        latest = db.get_latest_snapshot('TestCluster')
        if latest:
            print(f"✓ Retrieved latest snapshot:")
            print(f"  - Cluster: {latest['cluster_name']}")
            print(f"  - VMs Total: {latest['vms_total']}")
            print(f"  - Compliance Score: {latest['compliance_score']}")
            print(f"  - Timestamp: {latest['timestamp']}")
        print()

        # Test VM history
        vm_history = db.get_vm_history('vm-001', days=1)
        print(f"✓ Retrieved VM history: {len(vm_history)} record(s)")
        print()

        # Get database stats
        print("Database Statistics:")
        stats = db.get_database_stats()
        for key, value in stats.items():
            print(f"  - {key}: {value}")
        print()

    print("=" * 70)
    print("✓ All tests passed!")
    print("=" * 70)
    print()
    print(f"Test database created at: {test_db_path}")
    print("You can inspect it with: sqlite3", test_db_path)
    print()


if __name__ == '__main__':
    test_database_creation()
