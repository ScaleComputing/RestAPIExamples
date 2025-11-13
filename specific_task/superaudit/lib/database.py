"""
SuperAudit Database Layer

Handles all database operations for historical audit data storage and retrieval.
Supports SQLite (default) and PostgreSQL for production use.

Features:
- Auto-initialization of database schema
- Timestamped audit snapshots
- VM history tracking
- Capacity trend analysis
- Compliance scoring over time
- Data retention policies
"""

import sqlite3
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple


class AuditDatabase:
    """
    Database manager for SuperAudit historical data.

    Automatically creates database and schema on first use.
    Supports both SQLite (default) and PostgreSQL.
    """

    def __init__(self, database_path: str, db_type: str = "sqlite"):
        """
        Initialize database connection.

        Args:
            database_path: Path to SQLite database file or PostgreSQL connection string
            db_type: Database type - "sqlite" or "postgresql" (default: sqlite)
        """
        self.database_path = database_path
        self.db_type = db_type
        self.conn = None

        # Auto-initialize database if it doesn't exist
        self._connect()
        if not self._schema_exists():
            self._create_schema()
        else:
            self._run_migrations()

    def _connect(self):
        """Establish database connection."""
        if self.db_type == "sqlite":
            # Create directory if it doesn't exist
            db_dir = os.path.dirname(self.database_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, mode=0o755)

            # Connect to SQLite database
            self.conn = sqlite3.connect(self.database_path)
            self.conn.row_factory = sqlite3.Row  # Enable column access by name

            # Enable foreign keys
            self.conn.execute("PRAGMA foreign_keys = ON")
        else:
            raise NotImplementedError(f"Database type '{self.db_type}' not yet implemented")

    def _schema_exists(self) -> bool:
        """Check if database schema already exists."""
        cursor = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_snapshots'"
        )
        return cursor.fetchone() is not None

    def _create_schema(self):
        """Create database schema with all required tables."""
        print("Initializing SuperAudit database schema...")

        cursor = self.conn.cursor()

        # Table 1: Audit Snapshots - One record per audit run
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                cluster_name VARCHAR(255) NOT NULL,
                cluster_uuid VARCHAR(255),
                icos_version VARCHAR(50),

                -- Node statistics
                nodes_count INTEGER DEFAULT 0,
                nodes_online INTEGER DEFAULT 0,
                nodes_offline INTEGER DEFAULT 0,

                -- VM statistics
                vms_total INTEGER DEFAULT 0,
                vms_running INTEGER DEFAULT 0,
                vms_stopped INTEGER DEFAULT 0,
                vms_paused INTEGER DEFAULT 0,

                -- Storage statistics (in bytes, we'll convert to GB for display)
                storage_allocated_bytes BIGINT DEFAULT 0,
                storage_used_bytes BIGINT DEFAULT 0,

                -- Memory statistics (in bytes)
                memory_allocated_bytes BIGINT DEFAULT 0,

                -- System utilization metrics
                avg_cpu_usage FLOAT DEFAULT 0.0,
                max_cpu_usage FLOAT DEFAULT 0.0,
                avg_memory_usage FLOAT DEFAULT 0.0,
                max_memory_usage FLOAT DEFAULT 0.0,

                -- Drive health metrics
                total_drives INTEGER DEFAULT 0,
                healthy_drives INTEGER DEFAULT 0,
                unhealthy_drives INTEGER DEFAULT 0,

                vms_with_snapshots INTEGER DEFAULT 0,

                -- Warning counts by severity
                warnings_critical INTEGER DEFAULT 0,
                warnings_warning INTEGER DEFAULT 0,
                warnings_info INTEGER DEFAULT 0,
                warnings_total INTEGER DEFAULT 0,

                -- Execution metadata
                execution_time_seconds FLOAT DEFAULT 0.0,
                collection_successful BOOLEAN DEFAULT 1,
                error_message TEXT,

                -- Store full audit data as JSON for future flexibility
                raw_data_json TEXT,

                -- Indexing for fast queries
                UNIQUE(cluster_name, timestamp)
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_snapshots_cluster_time
            ON audit_snapshots(cluster_name, timestamp DESC)
        """)

        # Table 2: VM History - Time-series data for each VM
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vm_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id INTEGER NOT NULL,
                timestamp TIMESTAMP NOT NULL,

                -- VM identification
                vm_uuid VARCHAR(255) NOT NULL,
                vm_name VARCHAR(255) NOT NULL,
                cluster_name VARCHAR(255) NOT NULL,

                -- VM configuration
                state VARCHAR(50),
                vm_type VARCHAR(100),
                description TEXT,
                tags TEXT,

                -- Resources
                cpu_count INTEGER,
                memory_bytes BIGINT,

                -- Storage
                disk_count INTEGER DEFAULT 0,
                disk_total_bytes BIGINT DEFAULT 0,
                disk_used_bytes BIGINT DEFAULT 0,
                disk_snapshot_bytes BIGINT DEFAULT 0,

                -- Boot configuration
                boot_order VARCHAR(255),
                machine_type VARCHAR(50),
                operating_system VARCHAR(255),

                -- High availability
                ha_policy VARCHAR(50),

                -- Network
                ip_addresses TEXT,
                vlans TEXT,
                mac_addresses TEXT,
                network_adapter_count INTEGER DEFAULT 0,

                -- Snapshots
                has_snapshots BOOLEAN DEFAULT 0,
                snapshot_count INTEGER DEFAULT 0,
                snapshot_schedules TEXT,

                -- Replication
                has_replication BOOLEAN DEFAULT 0,
                replication_partners TEXT,

                -- Node placement
                node_uuid VARCHAR(255),
                node_lan_ip VARCHAR(50),
                node_cpu_percent FLOAT,

                FOREIGN KEY (snapshot_id) REFERENCES audit_snapshots(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vm_history_uuid_time
            ON vm_history(vm_uuid, timestamp DESC)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vm_history_snapshot
            ON vm_history(snapshot_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vm_history_cluster_time
            ON vm_history(cluster_name, timestamp DESC)
        """)

        # Table 3: Capacity History - Aggregate capacity metrics over time
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS capacity_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id INTEGER NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                cluster_name VARCHAR(255) NOT NULL,

                -- Storage capacity
                storage_allocated_gb FLOAT DEFAULT 0.0,
                storage_used_gb FLOAT DEFAULT 0.0,
                storage_free_gb FLOAT DEFAULT 0.0,
                storage_usage_percent FLOAT DEFAULT 0.0,

                -- Memory capacity
                memory_allocated_gb FLOAT DEFAULT 0.0,

                -- Growth rates (calculated)
                storage_growth_gb_per_day FLOAT,
                days_until_full INTEGER,

                FOREIGN KEY (snapshot_id) REFERENCES audit_snapshots(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_capacity_cluster_time
            ON capacity_history(cluster_name, timestamp DESC)
        """)

        # Table 4: Warning History - Track warnings over time
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS warning_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id INTEGER NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                cluster_name VARCHAR(255) NOT NULL,

                -- Warning details
                severity VARCHAR(20) NOT NULL,  -- CRITICAL, WARNING, INFO
                category VARCHAR(100),           -- VM, NODE, STORAGE, etc.
                message TEXT NOT NULL,

                -- Context
                vm_uuid VARCHAR(255),
                vm_name VARCHAR(255),
                node_uuid VARCHAR(255),

                FOREIGN KEY (snapshot_id) REFERENCES audit_snapshots(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_warnings_cluster_time
            ON warning_history(cluster_name, timestamp DESC)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_warnings_severity
            ON warning_history(severity, timestamp DESC)
        """)

        # Table 5: Node History - Track node health over time
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS node_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id INTEGER NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                cluster_name VARCHAR(255) NOT NULL,

                -- Node identification
                node_uuid VARCHAR(255) NOT NULL,
                node_lan_ip VARCHAR(50) NOT NULL,
                node_peer_id INTEGER,

                -- Hardware
                model VARCHAR(255),
                serial_number VARCHAR(255),

                -- CPU
                cpu_cores INTEGER,
                cpu_model VARCHAR(255),
                cpu_usage_percent FLOAT,

                -- Memory
                memory_total_bytes BIGINT,
                memory_available_bytes BIGINT,
                memory_usage_percent FLOAT,

                -- Status
                status VARCHAR(50),
                online BOOLEAN DEFAULT 1,

                FOREIGN KEY (snapshot_id) REFERENCES audit_snapshots(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_node_history_uuid_time
            ON node_history(node_uuid, timestamp DESC)
        """)

        self.conn.commit()
        print("✓ Database schema created successfully")
        print(f"✓ Database location: {self.database_path}")

    def _run_migrations(self):
        """Run database migrations for schema updates."""
        cursor = self.conn.cursor()

        # Check if new columns exist, if not add them
        cursor.execute("PRAGMA table_info(audit_snapshots)")
        columns = {row[1] for row in cursor.fetchall()}

        migrations_run = False

        # Migration 1: Add CPU/memory utilization columns (from previous redesign)
        if 'avg_cpu_usage' not in columns:
            cursor.execute("ALTER TABLE audit_snapshots ADD COLUMN avg_cpu_usage FLOAT DEFAULT 0.0")
            migrations_run = True

        if 'max_cpu_usage' not in columns:
            cursor.execute("ALTER TABLE audit_snapshots ADD COLUMN max_cpu_usage FLOAT DEFAULT 0.0")
            migrations_run = True

        if 'avg_memory_usage' not in columns:
            cursor.execute("ALTER TABLE audit_snapshots ADD COLUMN avg_memory_usage FLOAT DEFAULT 0.0")
            migrations_run = True

        if 'max_memory_usage' not in columns:
            cursor.execute("ALTER TABLE audit_snapshots ADD COLUMN max_memory_usage FLOAT DEFAULT 0.0")
            migrations_run = True

        # Migration 2: Add node status columns
        if 'nodes_online' not in columns:
            cursor.execute("ALTER TABLE audit_snapshots ADD COLUMN nodes_online INTEGER DEFAULT 0")
            migrations_run = True

        if 'nodes_offline' not in columns:
            cursor.execute("ALTER TABLE audit_snapshots ADD COLUMN nodes_offline INTEGER DEFAULT 0")
            migrations_run = True

        # Migration 3: Add drive health columns
        if 'total_drives' not in columns:
            cursor.execute("ALTER TABLE audit_snapshots ADD COLUMN total_drives INTEGER DEFAULT 0")
            migrations_run = True

        if 'healthy_drives' not in columns:
            cursor.execute("ALTER TABLE audit_snapshots ADD COLUMN healthy_drives INTEGER DEFAULT 0")
            migrations_run = True

        if 'unhealthy_drives' not in columns:
            cursor.execute("ALTER TABLE audit_snapshots ADD COLUMN unhealthy_drives INTEGER DEFAULT 0")
            migrations_run = True

        if migrations_run:
            self.conn.commit()
            print("✓ Database schema migrated successfully")

    def insert_audit_snapshot(self, audit_data: Dict[str, Any]) -> int:
        """
        Insert a complete audit snapshot into the database.

        Args:
            audit_data: Dictionary containing audit results from SuperAudit

        Returns:
            snapshot_id: ID of the inserted snapshot record
        """
        cursor = self.conn.cursor()

        # Extract summary statistics
        stats = audit_data.get('statistics', {})
        cluster_info = audit_data.get('cluster_info', {})

        # Insert main snapshot record
        cursor.execute("""
            INSERT INTO audit_snapshots (
                timestamp, cluster_name, cluster_uuid, icos_version,
                nodes_count, nodes_online, nodes_offline,
                vms_total, vms_running, vms_stopped, vms_paused,
                storage_allocated_bytes, storage_used_bytes, memory_allocated_bytes,
                avg_cpu_usage, max_cpu_usage, avg_memory_usage, max_memory_usage,
                total_drives, healthy_drives, unhealthy_drives,
                vms_with_snapshots,
                warnings_critical, warnings_warning, warnings_info, warnings_total,
                execution_time_seconds, collection_successful, raw_data_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().isoformat(),
            cluster_info.get('clusterName', 'Unknown'),
            cluster_info.get('clusterUUID'),
            cluster_info.get('icosVersion'),
            stats.get('nodes_count', 0),
            stats.get('nodes_online', 0),
            stats.get('nodes_offline', 0),
            stats.get('vms_total', 0),
            stats.get('vms_running', 0),
            stats.get('vms_stopped', 0),
            stats.get('vms_paused', 0),
            stats.get('storage_allocated_bytes', 0),
            stats.get('storage_used_bytes', 0),
            stats.get('memory_allocated_bytes', 0),
            stats.get('avg_cpu_usage', 0.0),
            stats.get('max_cpu_usage', 0.0),
            stats.get('avg_memory_usage', 0.0),
            stats.get('max_memory_usage', 0.0),
            stats.get('total_drives', 0),
            stats.get('healthy_drives', 0),
            stats.get('unhealthy_drives', 0),
            stats.get('vms_with_snapshots', 0),
            stats.get('warnings_critical', 0),
            stats.get('warnings_warning', 0),
            stats.get('warnings_info', 0),
            stats.get('warnings_total', 0),
            stats.get('execution_time', 0.0),
            True,
            json.dumps(audit_data)
        ))

        snapshot_id = cursor.lastrowid

        # Insert VM history records
        cluster_name = cluster_info.get('clusterName', 'Unknown')
        timestamp = datetime.now().isoformat()

        for vm in audit_data.get('vms', []):
            cursor.execute("""
                INSERT INTO vm_history (
                    snapshot_id, timestamp, vm_uuid, vm_name, cluster_name,
                    state, vm_type, description, tags,
                    cpu_count, memory_bytes,
                    disk_count, disk_total_bytes, disk_used_bytes, disk_snapshot_bytes,
                    boot_order, machine_type, operating_system, ha_policy,
                    ip_addresses, vlans, mac_addresses, network_adapter_count,
                    has_snapshots, snapshot_count, snapshot_schedules,
                    has_replication, replication_partners,
                    node_uuid, node_lan_ip, node_cpu_percent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                snapshot_id, timestamp,
                vm.get('uuid'), vm.get('name'), cluster_name,
                vm.get('state'), vm.get('vm_type'), vm.get('description'), vm.get('tags'),
                vm.get('cpu_count'), vm.get('memory_bytes'),
                vm.get('disk_count', 0), vm.get('disk_total_bytes', 0),
                vm.get('disk_used_bytes', 0), vm.get('disk_snapshot_bytes', 0),
                vm.get('boot_order'), vm.get('machine_type'), vm.get('operating_system'),
                vm.get('ha_policy'),
                vm.get('ip_addresses'), vm.get('vlans'), vm.get('mac_addresses'),
                vm.get('network_adapter_count', 0),
                vm.get('has_snapshots', False), vm.get('snapshot_count', 0),
                vm.get('snapshot_schedules'),
                vm.get('has_replication', False), vm.get('replication_partners'),
                vm.get('node_uuid'), vm.get('node_lan_ip'), vm.get('node_cpu_percent')
            ))

        # Insert capacity history
        storage_alloc_gb = stats.get('storage_allocated_bytes', 0) / (1024**3)
        storage_used_gb = stats.get('storage_used_bytes', 0) / (1024**3)
        storage_free_gb = storage_alloc_gb - storage_used_gb
        storage_usage_pct = (storage_used_gb / storage_alloc_gb * 100) if storage_alloc_gb > 0 else 0
        memory_alloc_gb = stats.get('memory_allocated_bytes', 0) / (1024**3)

        cursor.execute("""
            INSERT INTO capacity_history (
                snapshot_id, timestamp, cluster_name,
                storage_allocated_gb, storage_used_gb, storage_free_gb, storage_usage_percent,
                memory_allocated_gb
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            snapshot_id, timestamp, cluster_name,
            storage_alloc_gb, storage_used_gb, storage_free_gb, storage_usage_pct,
            memory_alloc_gb
        ))

        # Insert warning history
        for warning in audit_data.get('warnings', []):
            cursor.execute("""
                INSERT INTO warning_history (
                    snapshot_id, timestamp, cluster_name,
                    severity, category, message,
                    vm_uuid, vm_name, node_uuid
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                snapshot_id, timestamp, cluster_name,
                warning.get('severity', 'WARNING'),
                warning.get('category'),
                warning.get('message'),
                warning.get('vm_uuid'),
                warning.get('vm_name'),
                warning.get('node_uuid')
            ))

        # Insert node history
        for node in audit_data.get('nodes', []):
            cursor.execute("""
                INSERT INTO node_history (
                    snapshot_id, timestamp, cluster_name,
                    node_uuid, node_lan_ip, node_peer_id,
                    model, serial_number,
                    cpu_cores, cpu_model, cpu_usage_percent,
                    memory_total_bytes, memory_available_bytes, memory_usage_percent,
                    status, online
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                snapshot_id, timestamp, cluster_name,
                node.get('uuid'), node.get('lanIP'), node.get('peerID'),
                node.get('model'), node.get('serialNumber'),
                node.get('cpuCores'), node.get('cpuModel'), node.get('cpuUsagePercent'),
                node.get('memoryTotal'), node.get('memoryAvailable'), node.get('memoryUsagePercent'),
                node.get('status'), node.get('online', True)
            ))

        self.conn.commit()
        return snapshot_id

    def get_latest_snapshot(self, cluster_name: Optional[str] = None) -> Optional[Dict]:
        """
        Get the most recent audit snapshot.

        Args:
            cluster_name: Optional cluster name filter

        Returns:
            Dictionary with snapshot data or None if no snapshots exist
        """
        query = "SELECT * FROM audit_snapshots"
        params = []

        if cluster_name:
            query += " WHERE cluster_name = ?"
            params.append(cluster_name)

        query += " ORDER BY timestamp DESC LIMIT 1"

        cursor = self.conn.execute(query, params)
        row = cursor.fetchone()

        if row:
            return dict(row)
        return None

    def get_snapshots_in_range(self, cluster_name: str, start_date: datetime,
                               end_date: datetime) -> List[Dict]:
        """
        Get all snapshots within a date range.

        Args:
            cluster_name: Cluster name
            start_date: Start of date range
            end_date: End of date range

        Returns:
            List of snapshot dictionaries
        """
        cursor = self.conn.execute("""
            SELECT * FROM audit_snapshots
            WHERE cluster_name = ? AND timestamp BETWEEN ? AND ?
            ORDER BY timestamp ASC
        """, (cluster_name, start_date.isoformat(), end_date.isoformat()))

        return [dict(row) for row in cursor.fetchall()]

    def get_vm_history(self, vm_uuid: str, days: int = 30) -> List[Dict]:
        """
        Get historical data for a specific VM.

        Args:
            vm_uuid: VM UUID
            days: Number of days of history to retrieve

        Returns:
            List of VM history records
        """
        start_date = datetime.now() - timedelta(days=days)

        cursor = self.conn.execute("""
            SELECT * FROM vm_history
            WHERE vm_uuid = ? AND timestamp >= ?
            ORDER BY timestamp ASC
        """, (vm_uuid, start_date.isoformat()))

        return [dict(row) for row in cursor.fetchall()]

    def get_utilization_trend(self, cluster_name: str, days: int = 30) -> List[Dict]:
        """
        Get system utilization trend over time.

        Args:
            cluster_name: Cluster name
            days: Number of days of history

        Returns:
            List of dictionaries with timestamp and utilization metrics
        """
        start_date = datetime.now() - timedelta(days=days)

        cursor = self.conn.execute("""
            SELECT timestamp, avg_cpu_usage, avg_memory_usage,
                   storage_used_bytes, storage_allocated_bytes
            FROM audit_snapshots
            WHERE cluster_name = ? AND timestamp >= ?
            ORDER BY timestamp ASC
        """, (cluster_name, start_date.isoformat()))

        results = []
        for row in cursor.fetchall():
            storage_usage_percent = (row['storage_used_bytes'] / row['storage_allocated_bytes'] * 100) \
                if row['storage_allocated_bytes'] > 0 else 0
            results.append({
                'timestamp': row['timestamp'],
                'avg_cpu_usage': row['avg_cpu_usage'],
                'avg_memory_usage': row['avg_memory_usage'],
                'storage_usage_percent': storage_usage_percent
            })
        return results

    def get_capacity_trend(self, cluster_name: str, days: int = 30) -> List[Dict]:
        """
        Get storage capacity trend over time.

        Args:
            cluster_name: Cluster name
            days: Number of days of history

        Returns:
            List of capacity history records
        """
        start_date = datetime.now() - timedelta(days=days)

        cursor = self.conn.execute("""
            SELECT * FROM capacity_history
            WHERE cluster_name = ? AND timestamp >= ?
            ORDER BY timestamp ASC
        """, (cluster_name, start_date.isoformat()))

        return [dict(row) for row in cursor.fetchall()]

    def cleanup_old_data(self, days_to_keep: int = 90):
        """
        Remove audit data older than specified days.

        Args:
            days_to_keep: Number of days of data to retain
        """
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)

        cursor = self.conn.cursor()
        cursor.execute("""
            DELETE FROM audit_snapshots
            WHERE timestamp < ?
        """, (cutoff_date.isoformat(),))

        deleted_count = cursor.rowcount
        self.conn.commit()

        return deleted_count

    def get_database_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the database contents.

        Returns:
            Dictionary with database statistics
        """
        stats = {}

        # Count snapshots
        cursor = self.conn.execute("SELECT COUNT(*) as count FROM audit_snapshots")
        stats['total_snapshots'] = cursor.fetchone()['count']

        # Count VMs tracked
        cursor = self.conn.execute("SELECT COUNT(DISTINCT vm_uuid) as count FROM vm_history")
        stats['unique_vms'] = cursor.fetchone()['count']

        # Get date range
        cursor = self.conn.execute("""
            SELECT MIN(timestamp) as earliest, MAX(timestamp) as latest
            FROM audit_snapshots
        """)
        row = cursor.fetchone()
        stats['earliest_snapshot'] = row['earliest']
        stats['latest_snapshot'] = row['latest']

        # Get clusters
        cursor = self.conn.execute("SELECT DISTINCT cluster_name FROM audit_snapshots")
        stats['clusters'] = [row['cluster_name'] for row in cursor.fetchall()]

        # Database file size (SQLite only)
        if self.db_type == "sqlite":
            stats['database_size_bytes'] = os.path.getsize(self.database_path)
            stats['database_size_mb'] = stats['database_size_bytes'] / (1024 * 1024)

        return stats

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
