const connectionScript = (() => {
    const pollMs = (window.APP_CONFIG.pollSeconds || 3) * 1000;

    function showStatus(message, targetId='simulator-status') {
        const el = document.getElementById(targetId);
        if (el) el.textContent = message;
    }

    async function postJson(url, payload={}) {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        return response.json();
    }

    async function refreshStatus() {
        const response = await fetch(window.APP_CONFIG.statusUrl);
        const data = await response.json();
        const sender = data.sender_status || {};
        const settings = data.settings || {};
        updateLatestAlert(data.summary?.latest_alert);
        showStatus(sender.message || 'No simulator message available.');

        const grid = document.getElementById('server-status');
        grid.innerHTML = '';
        const rows = {
            'Simulator running': String(sender.running),
            'Last seen': sender.last_seen || 'Never',
            'Last batch size': sender.last_batch_size ?? 0,
            'Mode': sender.mode || 'idle',
            'Target': settings.sender_target || '-',
            'LLM base URL': settings.llm_base_url || '-',
            'LLM model': settings.llm_model || '-',
            'Poll seconds': settings.poll_seconds || 3,
        };
        Object.entries(rows).forEach(([label, value]) => {
            const row = document.createElement('div');
            row.className = 'status-row';
            row.innerHTML = `<strong>${label}</strong><span>${value}</span>`;
            grid.appendChild(row);
        });

        const form = document.getElementById('settings-form');
        if (form && !form.dataset.seeded) {
            Object.entries(settings).forEach(([key, value]) => {
                const input = form.querySelector(`[name="${key}"]`);
                if (input) input.value = value;
            });
            form.dataset.seeded = 'true';
        }
    }

    document.addEventListener('DOMContentLoaded', async () => {
        document.getElementById('settings-form').addEventListener('submit', async (event) => {
            event.preventDefault();
            const payload = Object.fromEntries(new FormData(event.target).entries());
            if (payload.flask_port) payload.flask_port = Number(payload.flask_port);
            if (payload.poll_seconds) payload.poll_seconds = Number(payload.poll_seconds);
            const data = await postJson(window.APP_CONFIG.settingsUrl, payload);
            showStatus('Settings saved successfully.');
            console.log(data);
        });

        document.getElementById('btn-start-simulator').addEventListener('click', async () => {
            const data = await postJson(window.APP_CONFIG.startSimulatorUrl);
            showStatus(data.message || 'Simulator started.');
            await refreshStatus();
        });

        document.getElementById('btn-stop-simulator').addEventListener('click', async () => {
            const data = await postJson(window.APP_CONFIG.stopSimulatorUrl);
            showStatus(data.message || 'Simulator stopped.');
            await refreshStatus();
        });

        document.getElementById('btn-test-llm').addEventListener('click', async () => {
            const data = await postJson(window.APP_CONFIG.llmTestUrl);
            showStatus(data.message || 'LLM test completed.');
        });

        await refreshStatus();
        setInterval(refreshStatus, pollMs);
    });
})();
