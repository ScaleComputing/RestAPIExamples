# Scale Computing System REST API Examples - Task Specific

This repository contains scripts for running task-specific API queries against a Scale system.

These scripts are only examples and demonstrate common use cases with the API.  
Refer to the API docs on a scale system for a detailed guide on available calls.


### SnapshotReport.ps1

Returns the latest replication snapshot that falls outside of a defined age timeframe.
Includes optional arguments to retrieve additional information about snapshots, schedules,
and remote cluster connections.
