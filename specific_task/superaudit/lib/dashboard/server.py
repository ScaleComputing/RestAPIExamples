"""
SuperAudit Dashboard Server

Flask-based web server for visualizing historical audit data.

Provides:
- Real-time cluster status
- Historical trends (compliance, capacity, VM counts)
- Individual VM history
- Warning analysis
- Capacity forecasting
"""

import os
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from lib.database import AuditDatabase


class DashboardServer:
    """Flask-based dashboard server for SuperAudit historical data."""

    def __init__(self, database_path: str, host: str = '0.0.0.0', port: int = 8080):
        """
        Initialize dashboard server.

        Args:
            database_path: Path to SQLite database
            host: Host to bind to (default: 0.0.0.0)
            port: Port to listen on (default: 8080)
        """
        self.database_path = database_path
        self.host = host
        self.port = port

        # Get template directory relative to this file
        template_dir = Path(__file__).parent / 'templates'
        static_dir = Path(__file__).parent / 'static'

        # Create Flask app
        self.app = Flask(
            __name__,
            template_folder=str(template_dir),
            static_folder=str(static_dir)
        )

        # Register routes
        self._register_routes()

    def _register_routes(self):
        """Register all Flask routes."""

        @self.app.route('/')
        def index():
            """Main dashboard page."""
            return render_template('dashboard.html')

        @self.app.route('/api/status')
        def api_status():
            """Get current cluster status (latest snapshot)."""
            try:
                with AuditDatabase(self.database_path) as db:
                    latest = db.get_latest_snapshot()

                    if not latest:
                        return jsonify({'error': 'No data available'}), 404

                    # Get database stats
                    db_stats = db.get_database_stats()

                    return jsonify({
                        'cluster_name': latest['cluster_name'],
                        'timestamp': latest['timestamp'],
                        'vms_total': latest['vms_total'],
                        'vms_running': latest['vms_running'],
                        'vms_stopped': latest['vms_stopped'],
                        'nodes_count': latest['nodes_count'],
                        'nodes_online': latest.get('nodes_online', 0),
                        'nodes_offline': latest.get('nodes_offline', 0),
                        'avg_cpu_usage': latest.get('avg_cpu_usage', 0.0),
                        'max_cpu_usage': latest.get('max_cpu_usage', 0.0),
                        'avg_memory_usage': latest.get('avg_memory_usage', 0.0),
                        'max_memory_usage': latest.get('max_memory_usage', 0.0),
                        'total_drives': latest.get('total_drives', 0),
                        'healthy_drives': latest.get('healthy_drives', 0),
                        'unhealthy_drives': latest.get('unhealthy_drives', 0),
                        'warnings_total': latest['warnings_total'],
                        'warnings_critical': latest['warnings_critical'],
                        'warnings_warning': latest['warnings_warning'],
                        'warnings_info': latest['warnings_info'],
                        'storage_allocated_gb': latest['storage_allocated_bytes'] / (1024**3),
                        'storage_used_gb': latest['storage_used_bytes'] / (1024**3),
                        'storage_usage_percent': (latest['storage_used_bytes'] / latest['storage_allocated_bytes'] * 100)
                            if latest['storage_allocated_bytes'] > 0 else 0,
                        'memory_allocated_gb': latest['memory_allocated_bytes'] / (1024**3),
                        'database_stats': db_stats
                    })

            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/utilization-trend')
        def api_utilization_trend():
            """Get system utilization trend over time."""
            try:
                days = int(request.args.get('days', 30))
                cluster = request.args.get('cluster')

                with AuditDatabase(self.database_path) as db:
                    # Get cluster name from latest if not specified
                    if not cluster:
                        latest = db.get_latest_snapshot()
                        if latest:
                            cluster = latest['cluster_name']
                        else:
                            return jsonify({'error': 'No data available'}), 404

                    trend = db.get_utilization_trend(cluster, days)

                    return jsonify({
                        'cluster': cluster,
                        'data': [
                            {
                                'timestamp': row['timestamp'],
                                'avg_cpu': row['avg_cpu_usage'],
                                'avg_memory': row['avg_memory_usage'],
                                'storage_usage': row['storage_usage_percent']
                            }
                            for row in trend
                        ]
                    })

            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/capacity-trend')
        def api_capacity_trend():
            """Get storage capacity trend over time."""
            try:
                days = int(request.args.get('days', 30))
                cluster = request.args.get('cluster')

                with AuditDatabase(self.database_path) as db:
                    # Get cluster name from latest if not specified
                    if not cluster:
                        latest = db.get_latest_snapshot()
                        if latest:
                            cluster = latest['cluster_name']
                        else:
                            return jsonify({'error': 'No data available'}), 404

                    trend = db.get_capacity_trend(cluster, days)

                    return jsonify({
                        'cluster': cluster,
                        'data': [
                            {
                                'timestamp': row['timestamp'],
                                'storage_allocated_gb': row['storage_allocated_gb'],
                                'storage_used_gb': row['storage_used_gb'],
                                'storage_free_gb': row['storage_free_gb'],
                                'storage_usage_percent': row['storage_usage_percent'],
                                'memory_allocated_gb': row['memory_allocated_gb']
                            }
                            for row in trend
                        ]
                    })

            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/vm-count-trend')
        def api_vm_count_trend():
            """Get VM count trend over time."""
            try:
                days = int(request.args.get('days', 30))
                cluster = request.args.get('cluster')

                with AuditDatabase(self.database_path) as db:
                    # Get cluster name from latest if not specified
                    if not cluster:
                        latest = db.get_latest_snapshot()
                        if latest:
                            cluster = latest['cluster_name']
                        else:
                            return jsonify({'error': 'No data available'}), 404

                    # Get snapshots in range
                    start_date = datetime.now() - timedelta(days=days)
                    end_date = datetime.now()
                    snapshots = db.get_snapshots_in_range(cluster, start_date, end_date)

                    return jsonify({
                        'cluster': cluster,
                        'data': [
                            {
                                'timestamp': snap['timestamp'],
                                'vms_total': snap['vms_total'],
                                'vms_running': snap['vms_running'],
                                'vms_stopped': snap['vms_stopped'],
                                'vms_paused': snap['vms_paused']
                            }
                            for snap in snapshots
                        ]
                    })

            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/vm-history/<vm_uuid>')
        def api_vm_history(vm_uuid):
            """Get individual VM history."""
            try:
                days = int(request.args.get('days', 30))

                with AuditDatabase(self.database_path) as db:
                    history = db.get_vm_history(vm_uuid, days)

                    if not history:
                        return jsonify({'error': 'VM not found'}), 404

                    return jsonify({
                        'vm_uuid': vm_uuid,
                        'vm_name': history[0]['vm_name'] if history else 'Unknown',
                        'data': [
                            {
                                'timestamp': row['timestamp'],
                                'state': row['state'],
                                'cpu_count': row['cpu_count'],
                                'memory_gb': row['memory_bytes'] / (1024**3) if row['memory_bytes'] else 0,
                                'disk_total_gb': row['disk_total_bytes'] / (1024**3) if row['disk_total_bytes'] else 0,
                                'disk_used_gb': row['disk_used_bytes'] / (1024**3) if row['disk_used_bytes'] else 0,
                                'node_lan_ip': row['node_lan_ip'],
                                'has_snapshots': row['has_snapshots']
                            }
                            for row in history
                        ]
                    })

            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/warning-summary')
        def api_warning_summary():
            """Get warning summary for recent period."""
            try:
                days = int(request.args.get('days', 7))
                cluster = request.args.get('cluster')

                with AuditDatabase(self.database_path) as db:
                    # Get cluster name from latest if not specified
                    if not cluster:
                        latest = db.get_latest_snapshot()
                        if latest:
                            cluster = latest['cluster_name']
                        else:
                            return jsonify({'error': 'No data available'}), 404

                    # Query warnings
                    start_date = datetime.now() - timedelta(days=days)
                    cursor = db.conn.execute("""
                        SELECT severity, message, COUNT(*) as count
                        FROM warning_history
                        WHERE cluster_name = ? AND timestamp >= ?
                        GROUP BY severity, message
                        ORDER BY count DESC, severity
                        LIMIT 20
                    """, (cluster, start_date.isoformat()))

                    warnings = []
                    for row in cursor.fetchall():
                        warnings.append({
                            'severity': row['severity'],
                            'message': row['message'],
                            'count': row['count']
                        })

                    return jsonify({
                        'cluster': cluster,
                        'period_days': days,
                        'warnings': warnings
                    })

            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/conditions')
        def api_conditions():
            """Get active conditions from latest snapshot."""
            try:
                cluster = request.args.get('cluster')

                with AuditDatabase(self.database_path) as db:
                    # Get cluster name from latest if not specified
                    if not cluster:
                        latest = db.get_latest_snapshot()
                        if latest:
                            cluster = latest['cluster_name']
                        else:
                            return jsonify({'error': 'No data available'}), 404

                    # Get latest snapshot
                    latest = db.get_latest_snapshot(cluster)
                    if not latest:
                        return jsonify({'error': 'No data available'}), 404

                    # Parse raw data to get conditions
                    import json
                    raw_data = json.loads(latest.get('raw_data_json', '{}'))
                    conditions = raw_data.get('conditions', [])

                    return jsonify({
                        'cluster': cluster,
                        'timestamp': latest['timestamp'],
                        'conditions': conditions
                    })

            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/vm-list')
        def api_vm_list():
            """Get list of VMs from latest snapshot."""
            try:
                cluster = request.args.get('cluster')

                with AuditDatabase(self.database_path) as db:
                    # Get cluster name from latest if not specified
                    if not cluster:
                        latest = db.get_latest_snapshot()
                        if latest:
                            cluster = latest['cluster_name']
                        else:
                            return jsonify({'error': 'No data available'}), 404

                    # Get latest snapshot ID
                    latest = db.get_latest_snapshot(cluster)
                    if not latest:
                        return jsonify({'error': 'No data available'}), 404

                    # Get VMs from latest snapshot
                    cursor = db.conn.execute("""
                        SELECT vm_uuid, vm_name, state, vm_type,
                               cpu_count, memory_bytes,
                               disk_total_bytes, disk_used_bytes,
                               has_snapshots, node_lan_ip
                        FROM vm_history
                        WHERE snapshot_id = ?
                        ORDER BY vm_name
                    """, (latest['id'],))

                    vms = []
                    for row in cursor.fetchall():
                        vms.append({
                            'uuid': row['vm_uuid'],
                            'name': row['vm_name'],
                            'state': row['state'],
                            'type': row['vm_type'],
                            'cpu_count': row['cpu_count'],
                            'memory_gb': row['memory_bytes'] / (1024**3) if row['memory_bytes'] else 0,
                            'disk_total_gb': row['disk_total_bytes'] / (1024**3) if row['disk_total_bytes'] else 0,
                            'disk_used_gb': row['disk_used_bytes'] / (1024**3) if row['disk_used_bytes'] else 0,
                            'has_snapshots': bool(row['has_snapshots']),
                            'node_lan_ip': row['node_lan_ip']
                        })

                    return jsonify({
                        'cluster': cluster,
                        'timestamp': latest['timestamp'],
                        'vms': vms
                    })

            except Exception as e:
                return jsonify({'error': str(e)}), 500

    def run(self, debug: bool = False):
        """
        Start the dashboard server.

        Args:
            debug: Enable Flask debug mode
        """
        print(f"\n{'='*70}")
        print(f"SuperAudit Dashboard Server")
        print(f"{'='*70}")
        print(f"Database:     {self.database_path}")
        print(f"URL:          http://{self.host}:{self.port}")
        print(f"              http://localhost:{self.port}")
        print(f"{'='*70}\n")
        print(f"Dashboard is starting...")
        print(f"Open your browser and navigate to the URL above")
        print(f"Press Ctrl+C to stop the server\n")

        try:
            self.app.run(
                host=self.host,
                port=self.port,
                debug=debug,
                threaded=True
            )
        except KeyboardInterrupt:
            print(f"\n{'='*70}")
            print(f"Dashboard server stopped")
            print(f"{'='*70}\n")


def start_dashboard(database_path: str, host: str = '0.0.0.0', port: int = 8080, debug: bool = False):
    """
    Convenience function to start the dashboard server.

    Args:
        database_path: Path to SQLite database
        host: Host to bind to (default: 0.0.0.0)
        port: Port to listen on (default: 8080)
        debug: Enable Flask debug mode
    """
    server = DashboardServer(database_path, host, port)
    server.run(debug)
