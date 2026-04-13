const dashboardScript = (() => {
    const pollMs = (window.APP_CONFIG.pollSeconds || 3) * 1000;

    function updateClock(nowText) {
        const parts = (nowText || '').split(' ');
        document.getElementById('clock-date').textContent = parts.slice(0, 1).join(' ') || '-';
        document.getElementById('clock-time').textContent = parts.slice(1).join(' ') || '-';
    }

    async function refreshDashboard() {
        const response = await fetch(window.APP_CONFIG.dashboardDataUrl);
        const data = await response.json();
        const summary = data.summary || {};
        document.getElementById('summary-now').textContent = summary.now || '-';
        document.getElementById('summary-total').textContent = summary.total_flows ?? 0;
        document.getElementById('summary-benign').textContent = summary.benign_count ?? 0;
        document.getElementById('summary-not-benign').textContent = summary.not_benign_count ?? 0;
        renderList('feed-list', data.feed || []);
        renderList('alerts-list', data.alerts || []);
        renderList('not-benign-list', data.not_benign_flows || []);
        updateClock(summary.now || '-');
        updateLatestAlert(summary.latest_alert);
    }

    document.addEventListener('DOMContentLoaded', async () => {
        await refreshDashboard();
        setInterval(refreshDashboard, pollMs);
    });
})();
