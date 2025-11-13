"""
SuperAudit Scheduler Module

Handles daemon mode operation for continuous audit data collection.

Features:
- Runs SuperAudit on a scheduled interval
- Logs collected data to database
- Error handling and retry logic
- Graceful shutdown handling
- Status logging and monitoring
"""

import time
import signal
import sys
from datetime import datetime
from typing import Optional, Callable
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.interval import IntervalTrigger


class AuditDaemon:
    """
    Daemon process for scheduled SuperAudit execution.

    Runs audit collection on a specified interval and stores
    results in the database.
    """

    def __init__(self,
                 audit_function: Callable,
                 interval_minutes: int = 15,
                 database_path: Optional[str] = None):
        """
        Initialize the audit daemon.

        Args:
            audit_function: Function to call for each audit run
            interval_minutes: Minutes between audit runs (default: 15)
            database_path: Path to database for logging (optional)
        """
        self.audit_function = audit_function
        self.interval_minutes = interval_minutes
        self.database_path = database_path
        self.scheduler = BlockingScheduler()
        self.running = False
        self.run_count = 0
        self.last_run_time = None
        self.last_run_success = None
        self.last_error = None

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        print(f"\n{'='*70}")
        print(f"Received shutdown signal (signal {signum})")
        print(f"{'='*70}")
        self.stop()
        sys.exit(0)

    def _run_audit_with_error_handling(self):
        """
        Execute audit with comprehensive error handling.

        Wraps the audit function with try/except and logging.
        """
        self.run_count += 1
        self.last_run_time = datetime.now()

        print(f"\n{'='*70}")
        print(f"Audit Run #{self.run_count}")
        print(f"Time: {self.last_run_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")

        try:
            # Call the audit function
            result = self.audit_function()

            self.last_run_success = True
            self.last_error = None

            print(f"\n{'='*70}")
            print(f"✓ Audit Run #{self.run_count} completed successfully")
            print(f"Duration: {(datetime.now() - self.last_run_time).total_seconds():.1f}s")
            print(f"Next run: {(self.last_run_time.timestamp() + self.interval_minutes * 60)}")
            print(f"{'='*70}\n")

            return result

        except KeyboardInterrupt:
            # Let keyboard interrupt propagate for clean shutdown
            raise

        except Exception as e:
            self.last_run_success = False
            self.last_error = str(e)

            print(f"\n{'='*70}")
            print(f"✗ Audit Run #{self.run_count} FAILED")
            print(f"Error: {e}")
            print(f"{'='*70}")
            print(f"Will retry on next scheduled run in {self.interval_minutes} minutes\n")

            # Don't crash the daemon - just log the error and continue
            return None

    def start(self):
        """
        Start the daemon with scheduled execution.

        Runs immediately on start, then on the specified interval.
        """
        self.running = True

        print(f"{'='*70}")
        print(f"SuperAudit Daemon Starting")
        print(f"{'='*70}")
        print(f"Interval:     {self.interval_minutes} minutes")
        print(f"Database:     {self.database_path or 'Not configured'}")
        print(f"Started:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")

        # Run immediately on startup
        print("Running initial audit...")
        self._run_audit_with_error_handling()

        # Schedule recurring runs
        self.scheduler.add_job(
            self._run_audit_with_error_handling,
            trigger=IntervalTrigger(minutes=self.interval_minutes),
            id='audit_job',
            name='SuperAudit Collection',
            max_instances=1,  # Don't overlap runs
            coalesce=True,    # If missed, run only once
            misfire_grace_time=300  # 5 minute grace period
        )

        print(f"Scheduler configured. Next run in {self.interval_minutes} minutes.")
        print(f"Press Ctrl+C to stop the daemon.\n")

        try:
            # Start the scheduler (blocking call)
            self.scheduler.start()
        except KeyboardInterrupt:
            self.stop()

    def start_once(self):
        """
        Run audit once without scheduling.

        Useful for testing or one-time database logging.
        """
        print(f"{'='*70}")
        print(f"SuperAudit - Single Run with Database Logging")
        print(f"{'='*70}\n")

        result = self._run_audit_with_error_handling()

        if self.last_run_success:
            print(f"\n✓ Single run completed successfully\n")
            return 0
        else:
            print(f"\n✗ Single run failed: {self.last_error}\n")
            return 1

    def stop(self):
        """Stop the daemon gracefully."""
        if not self.running:
            return

        print(f"\n{'='*70}")
        print(f"SuperAudit Daemon Stopping")
        print(f"{'='*70}")
        print(f"Total runs:   {self.run_count}")
        print(f"Last run:     {self.last_run_time.strftime('%Y-%m-%d %H:%M:%S') if self.last_run_time else 'Never'}")
        print(f"Last status:  {'Success' if self.last_run_success else 'Failed'}")
        print(f"{'='*70}\n")

        self.running = False

        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)

    def get_status(self):
        """
        Get current daemon status.

        Returns:
            Dictionary with daemon status information
        """
        return {
            'running': self.running,
            'run_count': self.run_count,
            'interval_minutes': self.interval_minutes,
            'last_run_time': self.last_run_time.isoformat() if self.last_run_time else None,
            'last_run_success': self.last_run_success,
            'last_error': self.last_error,
            'database_path': self.database_path
        }


def create_systemd_service(cluster_host: str,
                          username: str,
                          database_path: str,
                          interval: int = 15,
                          working_dir: str = "/opt/superaudit",
                          user: str = "superaudit") -> str:
    """
    Generate a systemd service file for SuperAudit daemon.

    Args:
        cluster_host: Cluster hostname or IP
        username: Cluster username
        database_path: Path to database file
        interval: Collection interval in minutes
        working_dir: Working directory for the service
        user: Unix user to run as

    Returns:
        String containing systemd service file content
    """
    service_content = f"""[Unit]
Description=SuperAudit Daemon - Continuous HyperCore Audit Collection
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={user}
WorkingDirectory={working_dir}
Environment="SCALE_USER={username}"
Environment="SCALE_PASSWORD=<SET_PASSWORD_HERE>"

# Main command
ExecStart=/usr/bin/python3 {working_dir}/SuperAudit_API.py \\
    --node {cluster_host} \\
    --daemon \\
    --interval {interval} \\
    --database {database_path} \\
    --quiet

# Restart on failure
Restart=on-failure
RestartSec=60

# Resource limits
MemoryLimit=512M
CPUQuota=50%

# Security settings
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""
    return service_content


def create_docker_compose(cluster_host: str,
                          database_path: str = "/data/superaudit.db",
                          interval: int = 15) -> str:
    """
    Generate a docker-compose.yml for SuperAudit daemon.

    Args:
        cluster_host: Cluster hostname or IP
        database_path: Path to database file (inside container)
        interval: Collection interval in minutes

    Returns:
        String containing docker-compose.yml content
    """
    compose_content = f"""version: '3.8'

services:
  superaudit-daemon:
    image: python:3.9-slim
    container_name: superaudit-daemon
    restart: unless-stopped

    environment:
      - SCALE_USER=admin
      - SCALE_PASSWORD=<SET_PASSWORD_HERE>

    volumes:
      - ./:/app
      - superaudit-data:/data

    working_dir: /app/tools/superaudit

    command: >
      sh -c "pip install -q -r requirements.txt &&
             python3 SuperAudit_API.py
             --node {cluster_host}
             --daemon
             --interval {interval}
             --database {database_path}
             --quiet"

    healthcheck:
      test: ["CMD", "test", "-f", "{database_path}"]
      interval: 5m
      timeout: 10s
      retries: 3

volumes:
  superaudit-data:
"""
    return compose_content
