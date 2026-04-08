function renderList(elementId, items) {
    const target = document.getElementById(elementId);
    if (!target) return;
    target.innerHTML = '';
    if (!items || items.length === 0) {
        const div = document.createElement('div');
        div.className = 'list-item';
        div.textContent = 'No data yet.';
        target.appendChild(div);
        return;
    }
    items.forEach(item => {
        const div = document.createElement('div');
        div.className = 'list-item';
        div.textContent = item;
        target.appendChild(div);
    });
}

function updateLatestAlert(text) {
    const target = document.getElementById('latest-alert-text');
    if (target) target.textContent = text || 'No alerts yet.';
}
