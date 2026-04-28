const connectionScript = (() => {
    const pollMs = (window.APP_CONFIG.pollSeconds || 3) * 1000;

    function showStatus(message, targetId = 'stream-status') {
        const el = document.getElementById(targetId);
        if (el) el.textContent = message;
    }

    async function postJson(url, payload = {}) {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        return response.json();
    }

    function fillSelect(select, items, selected) {
        if (!select) return;
        select.innerHTML = '';
        items.forEach(item => {
            const option = document.createElement('option');
            option.value = item;
            option.textContent = item;
            if (item === selected) option.selected = true;
            select.appendChild(option);
        });
    }

    async function refreshStatus(forceSeed = false) {
        const response = await fetch(window.APP_CONFIG.statusUrl);
        const data = await response.json();
        const sender = data.sender_status || {};
        const settings = data.settings || {};
        updateLatestAlert(data.summary?.latest_alert);
        showStatus(sender.message || 'No stream message available.');

        const hostUrl = `http://${settings.flask_host || '127.0.0.1'}:${settings.flask_port || 5000}`;
        const hostDisplay = document.getElementById('host-url-display');
        const senderDisplay = document.getElementById('sender-target-display');
        if (hostDisplay) hostDisplay.value = hostUrl;
        if (senderDisplay) senderDisplay.value = settings.sender_target || `${hostUrl}/api/ingest`;

        const grid = document.getElementById('server-status');
        if (grid) {
            grid.innerHTML = '';
            const rows = {
                'Stream running': String(sender.running),
                'Last seen': sender.last_seen || 'Never',
                'Last batch size': sender.last_batch_size ?? 0,
                'Mode': sender.mode || 'idle',
                'Source': sender.source || 'simulator',
                'Poll seconds': settings.poll_seconds || 3,
                'Active page data': data.summary?.active_mode || 'simulator',
                'Simulator total flows': data.stores?.simulator?.total_flows ?? 0,
                'Network total flows': data.stores?.network?.total_flows ?? 0,
            };
            Object.entries(rows).forEach(([label, value]) => {
                const row = document.createElement('div');
                row.className = 'status-row';
                row.innerHTML = `<strong>${label}</strong><span>${value}</span>`;
                grid.appendChild(row);
            });
        }

        const form = document.getElementById('settings-form');
        if (form && (!form.dataset.seeded || forceSeed)) {
            const setField = (name, value) => {
                const input = form.querySelector(`[name="${name}"]`);
                if (input) input.value = value ?? '';
            };
            setField('poll_seconds', settings.poll_seconds);
            setField('llm_base_url', settings.llm_base_url);
            setField('llm_model', settings.llm_model);
            setField('llm_api_key', settings.llm_api_key);
            fillSelect(document.getElementById('binary-model-select'), data.available_models || [], settings.binary_model_name);
            fillSelect(document.getElementById('anomaly-model-select'), data.available_models || [], settings.anomaly_model_name);
            const toggle = document.getElementById('simulator-mode-toggle');
            if (toggle) toggle.checked = !!settings.simulator_mode;
            form.dataset.seeded = 'true';
        }

        const llmBox = document.getElementById('llm-test-output');
        if (llmBox && !llmBox.dataset.seeded) {
            llmBox.value = 'LLM test output will show here.';
            llmBox.dataset.seeded = 'true';
        }

        const modelBox = document.getElementById('model-metrics-output');
        if (modelBox) modelBox.value = data.model_summary_text || 'Model details will show here.';
    }

    document.addEventListener('DOMContentLoaded', async () => {
        const settingsForm = document.getElementById('settings-form');
        const toggle = document.getElementById('simulator-mode-toggle');

        settingsForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const payload = Object.fromEntries(new FormData(event.target).entries());
            payload.poll_seconds = Number(payload.poll_seconds || 3);
            payload.simulator_mode = !!toggle.checked;
            const data = await postJson(window.APP_CONFIG.settingsUrl, payload);
            showStatus(data.message || 'Settings saved.');
            await refreshStatus(true);
        });

        document.getElementById('btn-start-stream').addEventListener('click', async () => {
            const savePayload = Object.fromEntries(new FormData(settingsForm).entries());
            savePayload.poll_seconds = Number(savePayload.poll_seconds || 3);
            savePayload.simulator_mode = !!toggle.checked;
            await postJson(window.APP_CONFIG.settingsUrl, savePayload);
            const data = await postJson(window.APP_CONFIG.startStreamUrl);
            showStatus(data.message || 'Stream started.');
            await refreshStatus(true);
        });

        document.getElementById('btn-stop-stream').addEventListener('click', async () => {
            const data = await postJson(window.APP_CONFIG.stopStreamUrl);
            showStatus(data.message || 'Stream stopped.');
            await refreshStatus(true);
        });

        document.getElementById('btn-test-llm').addEventListener('click', async () => {
            const data = await postJson(window.APP_CONFIG.llmTestUrl);
            const box = document.getElementById('llm-test-output');
            if (box) box.value = data.message || 'LLM test completed.';
        });

        toggle.addEventListener('change', async () => {
            const payload = Object.fromEntries(new FormData(settingsForm).entries());
            payload.poll_seconds = Number(payload.poll_seconds || 3);
            payload.simulator_mode = !!toggle.checked;
            await postJson(window.APP_CONFIG.settingsUrl, payload);
            await refreshStatus(true);
        });

        await refreshStatus(true);
        setInterval(refreshStatus, pollMs);
    });
})();
