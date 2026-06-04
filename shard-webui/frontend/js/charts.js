// Charts module for SHARD dashboard
class SHARDCharts {
    static commonLayout(title) {
        return {
            paper_bgcolor: 'transparent',
            plot_bgcolor: 'transparent',
            font: { color: '#fff', size: 12 },
            margin: { t: 30, b: 40, l: 50, r: 20 },
            title: { text: title, font: { size: 14, color: '#fff' } },
            xaxis: { gridcolor: 'rgba(255,255,255,0.05)', color: '#fff' },
            yaxis: { gridcolor: 'rgba(255,255,255,0.05)', color: '#fff' }
        };
    }

    static renderPieChart(elementId, data, title) {
        const entries = Object.entries(data || {});
        if (!entries.length) return;
        const colors = ['#00d4ff','#ff4757','#ffa502','#2ed573','#a29bfe','#fd79a8','#00cec9','#fdcb6e'];
        Plotly.react(elementId, [{
            values: entries.map(e => e[1]),
            labels: entries.map(e => e[0]),
            type: 'pie', hole: 0.4,
            marker: { colors: colors.slice(0, entries.length) }
        }], SHARDCharts.commonLayout(title));
    }

    static renderTimeline(elementId, data, title) {
        const hours = Array.from({ length: 24 }, (_, i) => String(i).padStart(2, '0') + ':00');
        const values = hours.map(h => data[h] || 0);
        Plotly.react(elementId, [{
            x: hours, y: values,
            type: 'scatter', mode: 'lines+markers',
            line: { color: '#00d4ff', width: 2 },
            fill: 'tozeroy', fillcolor: 'rgba(0,212,255,0.1)',
            marker: { color: '#00d4ff', size: 4 }
        }], SHARDCharts.commonLayout(title));
    }

    static renderBarChart(elementId, data, title, color = '#ff4757') {
        const items = data || [];
        if (!items.length) return;
        Plotly.react(elementId, [{
            y: items.map(i => i.ip).reverse(),
            x: items.map(i => i.count).reverse(),
            type: 'bar', orientation: 'h',
            marker: { color: color }
        }], { ...SHARDCharts.commonLayout(title), margin: { t: 30, b: 40, l: 150, r: 20 } });
    }
}
