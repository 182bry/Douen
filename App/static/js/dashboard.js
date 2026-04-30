const dashboardScript = (() => {
    const pollMs = (window.APP_CONFIG.pollSeconds || 3) * 1000;

    async function postJson(url, payload = {}) {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        return response.json();
    }

    function showStatus(message) {
        const el = document.getElementById('stream-status');
        if (el) el.textContent = message;
    }

    async function saveStreamMode(toggle) {
        const payload = {
            simulator_mode: !!toggle.checked,
        };
        const response = await postJson(window.APP_CONFIG.settingsUrl, payload);
        return response;
    }

    async function refreshDashboard() {
        const response = await fetch(window.APP_CONFIG.dashboardDataUrl);
        const data = await response.json();
        const summary = data.summary || {};
        const sender = data.sender_status || {};
        const settings = data.settings || {};
        document.getElementById('summary-now').textContent = summary.now || '-';
        document.getElementById('summary-total').textContent = summary.total_flows ?? 0;
        document.getElementById('summary-mode').textContent = summary.active_mode || '-';
        document.getElementById('summary-benign').textContent = summary.benign_count ?? 0;
        document.getElementById('summary-not-benign').textContent = summary.not_benign_count ?? 0;
        renderList('feed-list', data.feed || []);
        renderList('correlation-output', data.correlation_output || []);
        document.getElementById('llm-insight').textContent = data.llm_insight || 'No insight yet.';
        showStatus(sender.message || 'No stream message available.');
        const toggle = document.getElementById('simulator-mode-toggle');
        if (toggle) toggle.checked = !!settings.simulator_mode;
        updateLatestAlert(summary.latest_alert);
    }

    document.addEventListener('DOMContentLoaded', async () => {
        const toggle = document.getElementById('simulator-mode-toggle');
        document.getElementById('btn-start-stream').addEventListener('click', async () => {
            await saveStreamMode(toggle);
            const data = await postJson(window.APP_CONFIG.startStreamUrl);
            showStatus(data.message || 'Stream started.');
            await refreshDashboard();
        });

        document.getElementById('btn-stop-stream').addEventListener('click', async () => {
            const data = await postJson(window.APP_CONFIG.stopStreamUrl);
            showStatus(data.message || 'Stream stopped.');
            await refreshDashboard();
        });

        toggle.addEventListener('change', async () => {
            const data = await saveStreamMode(toggle);
            showStatus(data.message || 'Settings saved.');
            await refreshDashboard();
        });

        await refreshDashboard();
        setInterval(refreshDashboard, pollMs);
    });
})();
