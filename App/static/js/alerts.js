const POLL_MS = (window.APP_CONFIG?.pollSeconds || 3) * 1000;
const ALERTS_URL = window.APP_CONFIG?.alertsDataUrl || '/api/alerts-data';

const SEVERITY_COLOURS = {
    critical: '#e74c3c',
    high: '#e67e22',
    medium: '#f1c40f',
    low: '#3498db',
};

function makeAlertRow(line, severity = 'low') {
    const div = document.createElement('div');
    div.className = 'alert-row';
    div.style.borderLeft = `3px solid ${SEVERITY_COLOURS[severity] || '#95a5a6'}`;
    div.textContent = line;
    return div;
}

function renderBreakdown(counts) {
    const breakdown = document.getElementById('attack-breakdown');
    if (!breakdown) return;
    breakdown.innerHTML = '';
    const attackEntries = Object.entries(counts || {})
        .filter(([attack]) => attack.toLowerCase() !== 'benign')
        .sort((a, b) => b[1] - a[1]);

    if (attackEntries.length === 0) {
        breakdown.innerHTML = '<p class="alerts-empty">No detected classes yet.</p>';
        return;
    }

    attackEntries.forEach(([attack, count]) => {
        const row = document.createElement('div');
        row.className = 'alerts-breakdown-row';
        row.innerHTML = `<span>${attack}</span><span class="alerts-breakdown-count">${count}</span>`;
        breakdown.appendChild(row);
    });
}

function renderSuspicious(items) {
    const suspicious = document.getElementById('suspicious-feed');
    if (!suspicious) return;
    suspicious.innerHTML = '';
    if (!items || items.length === 0) {
        suspicious.innerHTML = '<p class="alerts-empty">No suspicious flows yet.</p>';
        return;
    }
    items.forEach(line => {
        const div = document.createElement('div');
        div.className = 'suspicious-row';
        div.textContent = line;
        suspicious.appendChild(div);
    });
}

function renderCorrelation(items) {
    const target = document.getElementById('correlation-feed');
    if (!target) return;
    target.innerHTML = '';
    if (!items || items.length === 0) {
        target.innerHTML = '<p class="alerts-empty">No correlated incidents yet.</p>';
        return;
    }
    items.forEach(line => {
        const div = document.createElement('div');
        div.className = 'suspicious-row';
        div.textContent = line;
        target.appendChild(div);
    });
}

function renderAlerts(data) {
    const feed = document.getElementById('alerts-feed');
    if (feed) {
        feed.innerHTML = '';
        if (!data.alerts || data.alerts.length === 0) {
            feed.innerHTML = '<p class="alerts-empty">No alerts yet. Start the stream to generate traffic.</p>';
        } else {
            data.alerts.forEach(line => feed.appendChild(makeAlertRow(line)));
        }
    }

    const badge = document.getElementById('alert-count-badge');
    if (badge) badge.textContent = `${data.total_alerts || 0} alerts`;

    const set = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
    };
    const severities = data.severity_counts || {};
    set('stat-total', data.total_alerts || 0);
    set('stat-critical', severities.critical || 0);
    set('stat-high', severities.high || 0);
    set('stat-medium', severities.medium || 0);
    set('stat-low', severities.low || 0);
    set('pipeline-status', data.pipeline_status || '-');
    set('incident-count', (data.incident_records || []).length);

    renderBreakdown(data.attack_counts || {});
    renderSuspicious(data.not_benign_flows || []);
    renderCorrelation(data.correlation_output || []);
    updateLatestAlert(data.summary?.latest_alert);
}

async function pollAlerts() {
    try {
        const response = await fetch(ALERTS_URL);
        if (!response.ok) return;
        const data = await response.json();
        renderAlerts(data);
    } catch (err) {
        console.warn('Alerts poll failed:', err);
    }
}

pollAlerts();
setInterval(pollAlerts, POLL_MS);
