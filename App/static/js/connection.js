const connectionScript = (() => {
    const pollMs = (window.APP_CONFIG.pollSeconds || 3) * 1000;

    function showStatus(message, targetId = 'pipeline-status-output') {
        const el = document.getElementById(targetId);
        if (el) el.value = message;
    }

    async function postJson(url, payload = {}) {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        return response.json();
    }

    async function refreshStatus(forceSeed = false) {
        const response = await fetch(window.APP_CONFIG.statusUrl);
        const data = await response.json();
        const sender = data.sender_status || {};
        const settings = data.settings || {};
        updateLatestAlert(data.summary?.latest_alert);

        const hostUrl = `http://${settings.flask_host || '127.0.0.1'}:${settings.flask_port || 5000}`;
        const hostDisplay = document.getElementById('host-url-display');
        const senderDisplay = document.getElementById('sender-target-display');
        if (hostDisplay) hostDisplay.value = hostUrl;
        if (senderDisplay) senderDisplay.value = settings.sender_target || '';

        const form = document.getElementById('settings-form');
        if (form && (forceSeed || !form.dataset.seeded)) {
            form.poll_seconds.value = settings.poll_seconds ?? 3;
            form.correlation_window_minutes.value = settings.correlation_window_minutes ?? 5;
            form.security_api_url.value = settings.security_api_url || 'http://127.0.0.1:5001';
            form.security_api_key.value = settings.security_api_key || '';
            form.llm_base_url.value = settings.llm_base_url || '';
            form.llm_model.value = settings.llm_model || '';
            form.llm_api_key.value = settings.llm_api_key || '';
            form.dataset.seeded = 'true';
        }

        const rows = [
            ['Running', sender.running ? 'Yes' : 'No'],
            ['Mode', sender.mode || '-'],
            ['Source', sender.source || '-'],
            ['Last seen', sender.last_seen || '-'],
            ['Last batch size', sender.last_batch_size ?? 0],
            ['Message', sender.message || '-'],
            ['Detection API', settings.security_api_url || '-'],
        ];
        const statusGrid = document.getElementById('server-status');
        if (statusGrid) {
            statusGrid.innerHTML = rows.map(([key, value]) => (
                `<div class="status-row"><strong>${key}</strong><span>${value}</span></div>`
            )).join('');
        }

        showStatus(data.pipeline_status_text || 'Detection pipeline status unavailable.');
    }

    document.addEventListener('DOMContentLoaded', async () => {
        const settingsForm = document.getElementById('settings-form');

        settingsForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const payload = Object.fromEntries(new FormData(event.target).entries());
            payload.poll_seconds = Number(payload.poll_seconds || 3);
            payload.correlation_window_minutes = Number(payload.correlation_window_minutes || 5);
            const data = await postJson(window.APP_CONFIG.settingsUrl, payload);
            showStatus(data.message || 'Settings saved.');
            await refreshStatus(true);
        });

        document.getElementById('btn-test-llm').addEventListener('click', async () => {
            const data = await postJson(window.APP_CONFIG.llmTestUrl);
            const box = document.getElementById('llm-test-output');
            if (box) box.value = data.message || 'LLM test completed.';
        });

        await refreshStatus(true);
        setInterval(refreshStatus, pollMs);
    });
})();
