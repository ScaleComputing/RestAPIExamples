// SuperAudit Dashboard JavaScript

// Chart.js default configuration
Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = '#334155';
Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';

// Global chart instances
let utilizationChart = null;
let vmCountChart = null;
let storageChart = null;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    loadDashboard();
    // Refresh every 60 seconds
    setInterval(loadDashboard, 60000);
});

// Load all dashboard data
async function loadDashboard() {
    try {
        await Promise.all([
            loadStatus(),
            loadUtilizationTrend(),
            loadVMCountTrend(),
            loadStorageTrend(),
            loadConditions(),
            loadVMList()
        ]);
    } catch (error) {
        console.error('Error loading dashboard:', error);
    }
}

// Load current status
async function loadStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();

        if (response.ok) {
            // Update header
            document.getElementById('cluster-name').textContent = data.cluster_name;
            document.getElementById('last-updated').textContent =
                `Last updated: ${formatTimestamp(data.timestamp)}`;

            // Update cards - Cluster Health will be updated by loadConditions()

            // Nodes
            document.getElementById('nodes-total').textContent = data.nodes_count;
            document.getElementById('nodes-online').textContent = data.nodes_online;
            document.getElementById('nodes-offline').textContent = data.nodes_offline;

            // Virtual Machines
            document.getElementById('vms-total').textContent = data.vms_total;
            document.getElementById('vms-running').textContent = data.vms_running;
            document.getElementById('vms-stopped').textContent = data.vms_stopped;

            // Storage Capacity
            document.getElementById('storage-usage').textContent =
                `${data.storage_usage_percent.toFixed(1)}%`;
            document.getElementById('storage-details').textContent =
                `${formatStorage(data.storage_used_gb)} / ${formatStorage(data.storage_allocated_gb)}`;

            // Drive Health
            document.getElementById('drives-total').textContent = data.total_drives;
            document.getElementById('drives-healthy').textContent = data.healthy_drives;
            document.getElementById('drives-unhealthy').textContent = data.unhealthy_drives;

            // Update database stats
            const dbStats = data.database_stats;
            document.getElementById('db-stats').textContent =
                `${dbStats.total_snapshots} snapshots, ${dbStats.unique_vms} VMs tracked, ${dbStats.database_size_mb.toFixed(2)} MB`;
        } else {
            console.error('Error loading status:', data.error);
        }
    } catch (error) {
        console.error('Error loading status:', error);
    }
}

// Load system utilization trend chart
async function loadUtilizationTrend() {
    try {
        const response = await fetch('/api/utilization-trend?days=30');
        const data = await response.json();

        if (response.ok) {
            const timestamps = data.data.map(d => new Date(d.timestamp));
            const cpuData = data.data.map(d => d.avg_cpu);
            const memoryData = data.data.map(d => d.avg_memory);
            const storageData = data.data.map(d => d.storage_usage);

            const ctx = document.getElementById('utilization-chart').getContext('2d');

            if (utilizationChart) {
                utilizationChart.destroy();
            }

            utilizationChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: timestamps,
                    datasets: [
                        {
                            label: 'CPU Usage (%)',
                            data: cpuData,
                            borderColor: '#3b82f6',
                            backgroundColor: 'rgba(59, 130, 246, 0.1)',
                            fill: false,
                            tension: 0.4,
                            borderWidth: 2
                        },
                        {
                            label: 'Memory Usage (%)',
                            data: memoryData,
                            borderColor: '#10b981',
                            backgroundColor: 'rgba(16, 185, 129, 0.1)',
                            fill: false,
                            tension: 0.4,
                            borderWidth: 2
                        },
                        {
                            label: 'Storage Usage (%)',
                            data: storageData,
                            borderColor: '#f59e0b',
                            backgroundColor: 'rgba(245, 158, 11, 0.1)',
                            fill: false,
                            tension: 0.4,
                            borderWidth: 2
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    aspectRatio: 2.5,
                    plugins: {
                        legend: {
                            display: true,
                            position: 'top'
                        },
                        tooltip: {
                            backgroundColor: '#1e293b',
                            titleColor: '#f1f5f9',
                            bodyColor: '#f1f5f9',
                            borderColor: '#334155',
                            borderWidth: 1,
                            padding: 12,
                            callbacks: {
                                title: function(context) {
                                    return formatTimestamp(context[0].parsed.x);
                                },
                                label: function(context) {
                                    return `${context.dataset.label}: ${context.parsed.y.toFixed(1)}%`;
                                }
                            }
                        }
                    },
                    scales: {
                        x: {
                            type: 'time',
                            time: {
                                unit: 'day',
                                displayFormats: {
                                    day: 'MMM d'
                                }
                            },
                            grid: {
                                color: '#334155'
                            }
                        },
                        y: {
                            beginAtZero: true,
                            max: 100,
                            grid: {
                                color: '#334155'
                            },
                            ticks: {
                                callback: function(value) {
                                    return value + '%';
                                }
                            }
                        }
                    }
                }
            });
        }
    } catch (error) {
        console.error('Error loading utilization trend:', error);
    }
}

// Load VM count trend chart
async function loadVMCountTrend() {
    try {
        const response = await fetch('/api/vm-count-trend?days=30');
        const data = await response.json();

        if (response.ok) {
            const timestamps = data.data.map(d => new Date(d.timestamp));
            const running = data.data.map(d => d.vms_running);
            const stopped = data.data.map(d => d.vms_stopped);
            const total = data.data.map(d => d.vms_total);

            const ctx = document.getElementById('vm-count-chart').getContext('2d');

            if (vmCountChart) {
                vmCountChart.destroy();
            }

            vmCountChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: timestamps,
                    datasets: [
                        {
                            label: 'Total VMs',
                            data: total,
                            borderColor: '#8b5cf6',
                            backgroundColor: 'rgba(139, 92, 246, 0.1)',
                            fill: true,
                            tension: 0.4,
                            borderWidth: 2
                        },
                        {
                            label: 'Running',
                            data: running,
                            borderColor: '#10b981',
                            backgroundColor: 'rgba(16, 185, 129, 0.1)',
                            fill: false,
                            tension: 0.4,
                            borderWidth: 2
                        },
                        {
                            label: 'Stopped',
                            data: stopped,
                            borderColor: '#94a3b8',
                            backgroundColor: 'rgba(148, 163, 184, 0.1)',
                            fill: false,
                            tension: 0.4,
                            borderWidth: 2
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    aspectRatio: 2.5,
                    plugins: {
                        legend: {
                            display: true,
                            position: 'top',
                            labels: {
                                usePointStyle: true,
                                padding: 15
                            }
                        },
                        tooltip: {
                            backgroundColor: '#1e293b',
                            titleColor: '#f1f5f9',
                            bodyColor: '#f1f5f9',
                            borderColor: '#334155',
                            borderWidth: 1,
                            padding: 12,
                            callbacks: {
                                title: function(context) {
                                    return formatTimestamp(context[0].parsed.x);
                                }
                            }
                        }
                    },
                    scales: {
                        x: {
                            type: 'time',
                            time: {
                                unit: 'day',
                                displayFormats: {
                                    day: 'MMM d'
                                }
                            },
                            grid: {
                                color: '#334155'
                            }
                        },
                        y: {
                            beginAtZero: true,
                            grid: {
                                color: '#334155'
                            },
                            ticks: {
                                precision: 0
                            }
                        }
                    }
                }
            });
        }
    } catch (error) {
        console.error('Error loading VM count trend:', error);
    }
}

// Load storage trend chart
async function loadStorageTrend() {
    try {
        const response = await fetch('/api/capacity-trend?days=30');
        const data = await response.json();

        if (response.ok) {
            const timestamps = data.data.map(d => new Date(d.timestamp));
            const allocated = data.data.map(d => d.storage_allocated_gb);
            const used = data.data.map(d => d.storage_used_gb);
            const free = data.data.map(d => d.storage_free_gb);

            const ctx = document.getElementById('storage-chart').getContext('2d');

            if (storageChart) {
                storageChart.destroy();
            }

            storageChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: timestamps,
                    datasets: [
                        {
                            label: 'Allocated',
                            data: allocated,
                            borderColor: '#3b82f6',
                            backgroundColor: 'rgba(59, 130, 246, 0.1)',
                            fill: true,
                            tension: 0.4,
                            borderWidth: 2
                        },
                        {
                            label: 'Used',
                            data: used,
                            borderColor: '#f59e0b',
                            backgroundColor: 'rgba(245, 158, 11, 0.1)',
                            fill: true,
                            tension: 0.4,
                            borderWidth: 2
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    aspectRatio: 2.5,
                    plugins: {
                        legend: {
                            display: true,
                            position: 'top',
                            labels: {
                                usePointStyle: true,
                                padding: 15
                            }
                        },
                        tooltip: {
                            backgroundColor: '#1e293b',
                            titleColor: '#f1f5f9',
                            bodyColor: '#f1f5f9',
                            borderColor: '#334155',
                            borderWidth: 1,
                            padding: 12,
                            callbacks: {
                                title: function(context) {
                                    return formatTimestamp(context[0].parsed.x);
                                },
                                label: function(context) {
                                    return `${context.dataset.label}: ${formatStorage(context.parsed.y)}`;
                                }
                            }
                        }
                    },
                    scales: {
                        x: {
                            type: 'time',
                            time: {
                                unit: 'day',
                                displayFormats: {
                                    day: 'MMM d'
                                }
                            },
                            grid: {
                                color: '#334155'
                            }
                        },
                        y: {
                            beginAtZero: true,
                            grid: {
                                color: '#334155'
                            },
                            ticks: {
                                callback: function(value) {
                                    return formatStorage(value);
                                }
                            }
                        }
                    }
                }
            });
        }
    } catch (error) {
        console.error('Error loading storage trend:', error);
    }
}

// Global storage for conditions
let allConditions = [];

// Load active conditions
async function loadConditions() {
    try {
        const response = await fetch('/api/conditions');
        const data = await response.json();

        if (response.ok) {
            // Store all conditions globally
            allConditions = data.conditions;

            // Update cluster health card (based on ALL conditions, not filtered)
            const criticalCount = allConditions.filter(c => c.severity === 'CRITICAL').length;
            const warningCount = allConditions.filter(c => c.severity === 'WARNING').length;

            let healthStatus = 'Healthy';
            let healthDetails = 'No critical conditions';

            if (criticalCount > 0) {
                healthStatus = 'Critical';
                healthDetails = `${criticalCount} critical condition${criticalCount > 1 ? 's' : ''}`;
            } else if (warningCount > 0) {
                healthStatus = 'Warning';
                healthDetails = `${warningCount} warning${warningCount > 1 ? 's' : ''}`;
            }

            document.getElementById('cluster-health-status').textContent = healthStatus;
            document.getElementById('cluster-health-details').textContent = healthDetails;

            // Set up filter checkboxes
            setupConditionFilters();

            // Render filtered conditions
            renderConditions();
        }
    } catch (error) {
        console.error('Error loading conditions:', error);
        document.getElementById('cluster-health-status').textContent = 'Unknown';
        document.getElementById('cluster-health-details').textContent = 'Unable to fetch conditions';
    }
}

// Setup condition filter checkboxes
function setupConditionFilters() {
    const filterIds = ['filter-critical', 'filter-warning', 'filter-notice', 'filter-info', 'filter-debug'];

    filterIds.forEach(id => {
        const checkbox = document.getElementById(id);
        if (checkbox && !checkbox.hasAttribute('data-listener')) {
            checkbox.addEventListener('change', renderConditions);
            checkbox.setAttribute('data-listener', 'true');
        }
    });
}

// Render conditions based on selected filters
function renderConditions() {
    const container = document.getElementById('conditions-list');

    if (allConditions.length === 0) {
        container.innerHTML = '<div class="loading">No active conditions</div>';
        return;
    }

    // Get selected severities
    const selectedSeverities = [];
    if (document.getElementById('filter-critical')?.checked) selectedSeverities.push('CRITICAL');
    if (document.getElementById('filter-warning')?.checked) selectedSeverities.push('WARNING');
    if (document.getElementById('filter-notice')?.checked) selectedSeverities.push('NOTICE');
    if (document.getElementById('filter-info')?.checked) selectedSeverities.push('INFO');
    if (document.getElementById('filter-debug')?.checked) selectedSeverities.push('DEBUG');

    // Filter conditions
    const filteredConditions = allConditions.filter(c =>
        selectedSeverities.includes(c.severity)
    );

    if (filteredConditions.length === 0) {
        container.innerHTML = '<div class="loading">No conditions match selected filters</div>';
        return;
    }

    let html = '';
    filteredConditions.forEach(condition => {
        const severity = condition.severity || 'INFO';
        const description = condition.description || 'No description available';
        const nodeLANIP = condition.nodeLANIP || '';
        const conditionName = condition.name || '';

        // Extract condition type from name
        let typeLabel = 'System';
        if (conditionName.includes('.drive')) {
            typeLabel = 'Drive';
        } else if (conditionName.includes('.node')) {
            typeLabel = 'Node';
        } else if (conditionName.includes('.interface')) {
            typeLabel = 'Network';
        } else if (conditionName.includes('.scribe')) {
            typeLabel = 'Storage';
        } else if (conditionName.includes('supporttunnel')) {
            typeLabel = 'Support';
        }

        html += `
            <div class="condition-item ${severity}">
                <div class="condition-header">
                    <span class="condition-badge ${severity}">${severity}</span>
                    <span class="condition-type">${typeLabel}${nodeLANIP ? ' - ' + escapeHtml(nodeLANIP) : ''}</span>
                </div>
                <div class="condition-message">
                    ${escapeHtml(description)}
                </div>
            </div>
        `;
    });

    container.innerHTML = html;
}

// Load VM list
async function loadVMList() {
    try {
        const response = await fetch('/api/vm-list');
        const data = await response.json();

        if (response.ok) {
            const container = document.getElementById('vm-list');

            if (data.vms.length === 0) {
                container.innerHTML = '<div class="loading">No VMs found</div>';
                return;
            }

            let html = '';
            data.vms.forEach(vm => {
                html += `
                    <div class="vm-item" data-vm-name="${vm.name.toLowerCase()}" data-vm-type="${vm.type.toLowerCase()}" data-vm-state="${vm.state.toLowerCase()}">
                        <div>
                            <div class="vm-name">${escapeHtml(vm.name)}</div>
                            <div class="vm-type">${escapeHtml(vm.type)}</div>
                        </div>
                        <div>
                            <span class="vm-state ${vm.state}">${vm.state}</span>
                        </div>
                        <div class="vm-spec">
                            <i class="fas fa-microchip"></i> ${vm.cpu_count} vCPU
                        </div>
                        <div class="vm-spec">
                            <i class="fas fa-memory"></i> ${vm.memory_gb.toFixed(1)} GB
                        </div>
                        <div class="vm-spec">
                            <i class="fas fa-hdd"></i> ${formatStorage(vm.disk_used_gb)}/${formatStorage(vm.disk_total_gb)}
                        </div>
                        <div class="vm-snapshot">
                            ${vm.has_snapshots ?
                                '<i class="fas fa-check-circle has-snapshots" title="Has snapshots"></i>' :
                                '<i class="fas fa-times-circle no-snapshots" title="No snapshots"></i>'}
                        </div>
                    </div>
                `;
            });

            container.innerHTML = html;

            // Setup search
            setupVMSearch();
        }
    } catch (error) {
        console.error('Error loading VM list:', error);
    }
}

// Setup VM search functionality
function setupVMSearch() {
    const searchInput = document.getElementById('vm-search');
    searchInput.addEventListener('input', function(e) {
        const searchTerm = e.target.value.toLowerCase();
        const vmItems = document.querySelectorAll('.vm-item');

        vmItems.forEach(item => {
            const name = item.dataset.vmName;
            const type = item.dataset.vmType;
            const state = item.dataset.vmState;

            if (name.includes(searchTerm) || type.includes(searchTerm) || state.includes(searchTerm)) {
                item.style.display = 'grid';
            } else {
                item.style.display = 'none';
            }
        });
    });
}

// Helper: Format timestamp
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Helper: Format storage size (GB to TB when >= 1024 GB)
function formatStorage(gb, decimals = 1) {
    if (gb >= 1024) {
        return `${(gb / 1024).toFixed(decimals)} TB`;
    }
    return `${gb.toFixed(decimals)} GB`;
}

// Helper: Escape HTML
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
