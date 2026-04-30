const reportScript = (() => {
    function lineChart(targetId, points, title) {
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

    function barChart(targetId, counts, title) {
        const x = Object.keys(counts || {});
        const y = Object.values(counts || {});
        Plotly.react(targetId, [{ x, y, type: 'bar' }], {
            title,
            paper_bgcolor: '#ffffff',
            plot_bgcolor: '#f5f1e3',
            margin: { t: 40, r: 20, b: 80, l: 50 },
            xaxis: { tickangle: -35 },
            yaxis: { title: 'Count' }
        }, { responsive: true });
    }

    function pieChart(targetId, counts, title) {
        const labels = [];
        const values = [];
        Object.entries(counts || {}).forEach(([key, value]) => {
            if (value > 0) {
                labels.push(key);
                values.push(value);
            }
        });
        Plotly.react(targetId, [{ labels, values, type: 'pie' }], {
            title,
            paper_bgcolor: '#ffffff',
            margin: { t: 40, r: 20, b: 20, l: 20 }
        }, { responsive: true });
    }

    function withoutBenign(counts) {
        const cleaned = {};
        Object.entries(counts || {}).forEach(([key, value]) => {
            if (key.toLowerCase() !== 'benign') cleaned[key] = value;
        });
        return cleaned;
    }

    function buildList(targetId, items, emptyText) {
        const target = document.getElementById(targetId);
        if (!target) return;
        target.innerHTML = '';
        if (!items || items.length === 0) {
            const div = document.createElement('div');
            div.className = 'list-item';
            div.textContent = emptyText;
            target.appendChild(div);
            return;
        }
        items.forEach(item => {
            const div = document.createElement('div');
            div.className = 'list-item';
            div.textContent = typeof item === 'string' ? item : JSON.stringify(item);
            target.appendChild(div);
        });
    }

    function drawIndividualDays(days) {
        const holder = document.getElementById('report-days');
        holder.innerHTML = '';
        if (!days || days.length === 0) {
            holder.innerHTML = '<div class="list-item">No day data in the selected range.</div>';
            return;
        }
        days.forEach((day, index) => {
            const wrap = document.createElement('div');
            wrap.className = 'report-day-card';
            wrap.innerHTML = `
                <div class="card-header"><h2>${day.day}</h2><span class="badge">${day.flows} flows</span></div>
                <div class="report-day-grid">
                    <div id="day-pie-${index}" class="graph-box small-graph"></div>
                    <div id="day-bar-${index}" class="graph-box small-graph"></div>
                    <div id="day-line-${index}" class="graph-box small-graph full-day-line"></div>
                </div>
            `;
            holder.appendChild(wrap);
            pieChart(`day-pie-${index}`, day.counts, `${day.day} Pie`);
            barChart(`day-bar-${index}`, withoutBenign(day.counts), `${day.day} Bar`);
            lineChart(`day-line-${index}`, day.hour_series, `${day.day} Hourly Packets`);
        });
    }

    function queryParams() {
        const start = document.getElementById('report-start-date').value;
        const end = document.getElementById('report-end-date').value;
        const params = new URLSearchParams();
        if (start) params.set('start_date', start);
        if (end) params.set('end_date', end);
        return params;
    }

    async function refreshReport() {
        const response = await fetch(`${window.APP_CONFIG.reportDataUrl}?${queryParams().toString()}`);
        const data = await response.json();
        lineChart('report-chart-packet-activity', data.charts.packet_activity || [], 'Packet Activity');
        lineChart('report-chart-second', data.charts.per_second || [], 'Total Packets Per Second');
        lineChart('report-chart-minute', data.charts.per_minute || [], 'Total Packets Per Minute');
        lineChart('report-chart-hour', data.charts.per_hour || [], 'Total Packets Per Hour');
        lineChart('report-chart-day', data.charts.per_day || [], 'Total Packets Per Day');
        barChart('report-chart-bar', data.charts.attack_counts_no_benign || {}, 'Detected Classes');
        pieChart('report-chart-pie', data.charts.attack_counts || {}, 'Flow Type Pie Chart');
        drawIndividualDays(data.individual_days || []);
        buildList('report-insights', data.insight_history || [], 'No insights yet.');
        buildList('report-alerts', data.alerts || [], 'No alerts yet.');
        buildList('report-flows', data.flows || [], 'No flows yet.');
        const badge = document.getElementById('report-total-badge');
        if (badge) badge.textContent = `${data.selected_total || 0} flows`;
        updateLatestAlert(data.latest_alert);
    }

    document.addEventListener('DOMContentLoaded', async () => {
        document.getElementById('btn-refresh-report').addEventListener('click', refreshReport);
        document.getElementById('btn-export-pdf').addEventListener('click', async () => {
            const status = document.getElementById('report-export-status');
            if (status) status.textContent = 'Saving PDF...';
            try {
                const response = await fetch(`${window.APP_CONFIG.reportExportUrl}?${queryParams().toString()}`);
                const data = await response.json();
                if (status) {
                    if (data.opened) {
                        status.textContent = `PDF saved and opened: ${data.file_path}`;
                    } else {
                        status.textContent = `PDF saved to: ${data.file_path}`;
                    }
                }
            } catch (error) {
                if (status) status.textContent = 'PDF export failed.';
            }
        });
        await refreshReport();
    });
})();
