const visualizationScript = (() => {
    const pollMs = (window.APP_CONFIG.pollSeconds || 3) * 1000;

    function renderLineChart(targetId, points, title) {
        const x = points.map(p => p.x);
        const y = points.map(p => p.y);
        Plotly.react(targetId, [{ x, y, type: 'scatter', mode: 'lines+markers' }], {
            title,
            paper_bgcolor: '#ffffff',
            plot_bgcolor: '#f5f1e3',
            margin: { t: 40, r: 20, b: 50, l: 50 },
            xaxis: { tickangle: -30 },
            yaxis: { title: 'Packets' }
        }, { responsive: true });
    }

    function renderBarChart(targetId, counts) {
        const x = Object.keys(counts || {});
        const y = Object.values(counts || {});
        Plotly.react(targetId, [{ x, y, type: 'bar' }], {
            title: 'Attack / Class Counts',
            paper_bgcolor: '#ffffff',
            plot_bgcolor: '#f5f1e3',
            margin: { t: 40, r: 20, b: 80, l: 50 },
            xaxis: { tickangle: -35 },
            yaxis: { title: 'Count' }
        }, { responsive: true });
    }

    async function refreshVisuals() {
        const response = await fetch(window.APP_CONFIG.visualizationDataUrl);
        const data = await response.json();
        renderLineChart('chart-packet-activity', data.charts.packet_activity || [], 'Packet Activity');
        renderBarChart('chart-bar', data.charts.attack_counts_no_benign || {});
        renderLineChart('chart-24h', data.charts.traffic_24h || [], 'Total Packets in the Last 24 Hours');
        updateLatestAlert(data.latest_alert);
    }

    document.addEventListener('DOMContentLoaded', async () => {
        await refreshVisuals();
        setInterval(refreshVisuals, pollMs);
    });
})();
