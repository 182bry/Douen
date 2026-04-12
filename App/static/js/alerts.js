const POLL_MS = (window.APP_CONFIG?.pollSeconds || 3) * 1000;
const ALERTS_URL = '/api/alerts-data';


const SEVERITY_COLOURS = {
    'DDOS':         '#e74c3c',
    'DOS':          '#e67e22',
    'POTENTIAL':    '#f1c40f',
    'IRREGULAR':    '#3498db',
};


function alertColour(line) {
    const upper = line.toUpperCase();
    for (const [keyword, colour] of Object.entries(SEVERITY_COLOURS)) {
        if (upper.includes(keyword)) return colour;
    }
    return '#95a5a6';
}


function makeAlertRow(line) {
    const div = document.createElement('div');
    div.className = 'alert-row';
    div.style.borderLeft = `3px solid ${alertColour(line)}`;
    div.style.padding = '0.4rem 0.8rem';
    div.style.marginBottom = '0.3rem';
    div.style.fontFamily = 'monospace';
    div.style.fontSize = '0.82rem';
    div.textContent = line;
    return div;
}


function renderAlerts(data) {

    
    const feed = document.getElementById('alerts-feed');
    if (feed) {
        feed.innerHTML = '';
        if (data.alerts.length === 0) {
            feed.innerHTML = '<p style="color:#888; padding:1rem;">No alerts yet. Start the simulator to generate traffic.</p>';
        } else {
            data.alerts.forEach(line => feed.appendChild(makeAlertRow(line)));
        }
    }

    
    const badge = document.getElementById('alert-count-badge');
    if (badge) badge.textContent = `${data.total_alerts} alerts`;

    
    const set = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
    };
    set('stat-total',    data.total_alerts);
    set('stat-critical', data.severity_counts.critical);
    set('stat-high',     data.severity_counts.high);
    set('stat-medium',   data.severity_counts.medium);
    set('stat-low',      data.severity_counts.low);

    const breakdown = document.getElementById('attack-breakdown');
    if (breakdown) {
        breakdown.innerHTML = '';
        const counts = data.attack_counts;

        
        const attackEntries = Object.entries(counts)
            .filter(([attack]) => attack.toLowerCase() !== 'benign')
            .sort((a, b) => b[1] - a[1]);

        if (attackEntries.length === 0) {
            breakdown.innerHTML = '<p style="color:#888; padding:1rem;">No attacks detected yet.</p>';
        } else {
            attackEntries.forEach(([attack, count]) => {
                const row = document.createElement('div');
                row.style.cssText = 'display:flex; justify-content:space-between; padding:0.35rem 0; border-bottom:1px solid #222;';
                row.innerHTML = `
                    <span style="font-size:0.85rem;">${attack}</span>
                    <span style="font-weight:bold; color:#e74c3c;">${count}</span>
                `;
                breakdown.appendChild(row);
            });
        }
    }

    
    const suspicious = document.getElementById('suspicious-feed');
    if (suspicious) {
        suspicious.innerHTML = '';
        if (data.not_benign_flows.length === 0) {
            suspicious.innerHTML = '<p style="color:#888; padding:1rem;">No suspicious flows yet.</p>';
        } else {
            data.not_benign_flows.forEach(line => {
                const div = document.createElement('div');
                div.style.cssText = 'font-family:monospace; font-size:0.78rem; padding:0.3rem 0; border-bottom:1px solid #1a1a1a; color:#e67e22;';
                div.textContent = line;
                suspicious.appendChild(div);
            });
        }
    }

    
    const mitreBox = document.getElementById('mitre-tags');
    if (mitreBox) {
        mitreBox.innerHTML = '';
        const MITRE_MAP = {
            'ddos':             { id: 'T1498', name: 'Network Denial of Service' },
            'dos':              { id: 'T1499', name: 'Endpoint Denial of Service' },
            'brute_force':      { id: 'T1110', name: 'Brute Force' },
            'portscan':         { id: 'T1595', name: 'Active Scanning' },
            'web_attack':       { id: 'T1190', name: 'Exploit Public-Facing App' },
            'bot':              { id: 'T1071', name: 'Application Layer Protocol' },
            'reconnaissance':   { id: 'T1595', name: 'Active Scanning' },
            'infiltration':     { id: 'T1071', name: 'Application Layer Protocol' },
        };

        
        const detectedAttacks = Object.keys(data.attack_counts)
            .filter(attack => attack.toLowerCase() !== 'benign');

        if (detectedAttacks.length === 0) {
            mitreBox.innerHTML = '<p style="color:#888; padding:1rem;">No MITRE mappings yet.</p>';
        } else {
            detectedAttacks.forEach(attack => {
                const mapping = MITRE_MAP[attack.toLowerCase()] || { id: 'T????', name: attack };
                const tag = document.createElement('div');
                tag.className = 'mitre-tag';
                tag.innerHTML = `
                    <span class="mitre-id">${mapping.id}</span>
                    <span class="mitre-name">${mapping.name}</span>
                    <span class="mitre-attack">${attack}</span>
                `;
                mitreBox.appendChild(tag);
            });
        }
    }
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