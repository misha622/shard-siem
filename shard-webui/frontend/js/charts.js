// Charts configuration using Plotly.js

class SHARDCharts {
    constructor() {
        this.initCharts();
    }

    // Initialize all charts
    initCharts() {
        this.initAttackTypesChart();
        this.initAlertsTimeline();
        this.initTopAttackers();
        this.initTopTargets();
    }

    // Common chart layout
    getCommonLayout(title) {
        return {
            paper_bgcolor: 'transparent',
            plot_bgcolor: 'transparent',
            font: {
                color: '#ffffff',
                family: 'Inter, Segoe UI, sans-serif',
                size: 12
            },
            title: {
                text: title,
                font: { size: 16, color: '#ffffff' }
            },
            margin: { l: 50, r: 20, t: 40, b: 50 },
            xaxis: {
                gridcolor: 'rgba(255, 255, 255, 0.05)',
                zerolinecolor: 'rgba(255, 255, 255, 0.1)',
                color: '#ffffff'
            },
            yaxis: {
                gridcolor: 'rgba(255, 255, 255, 0.05)',
                zerolinecolor: 'rgba(255, 255, 255, 0.1)',
                color: '#ffffff'
            },
            showlegend: true,
            legend: {
                font: { color: '#ffffff' },
                bgcolor: 'rgba(19, 26, 43, 0.8)',
                bordercolor: 'rgba(255, 255, 255, 0.1)'
            }
        };
    }

    // Attack Types Pie Chart
    initAttackTypesChart() {
        const data = [{
            values: [1],
            labels: ['Loading...'],
            type: 'pie',
            hole: 0.4,
            marker: {
                colors: ['#00d4ff']
            },
            textinfo: 'label+percent',
            textfont: { color: '#ffffff' },
            hoverinfo: 'label+value+percent'
        }];

        const layout = {
            ...this.getCommonLayout('Attack Types Distribution'),
            showlegend: true
        };

        Plotly.newPlot('attackTypesChart', data, layout, { responsive: true });
    }

    // Update Attack Types Chart
    updateAttackTypesChart(alertsByType) {
        const labels = Object.keys(alertsByType);
        const values = Object.values(alertsByType);

        const colors = [
            '#00d4ff', '#ff4757', '#ffa502', '#2ed573',
            '#a29bfe', '#fd79a8', '#00cec9', '#fdcb6e',
            '#6c5ce7', '#e17055'
        ];

        const data = [{
            values: values.length ? values : [1],
            labels: labels.length ? labels : ['No Data'],
            type: 'pie',
            hole: 0.4,
            marker: {
                colors: colors.slice(0, labels.length)
            },
            textinfo: 'label+percent',
            textfont: { color: '#ffffff' },
            hoverinfo: 'label+value+percent'
        }];

        Plotly.react('attackTypesChart', data, this.getCommonLayout('Attack Types Distribution'));
    }

    // Alerts Timeline Chart
    initAlertsTimeline() {
        const hours = Array.from({length: 24}, (_, i) => `${i.toString().padStart(2, '0')}:00`);
        const data = [{
            x: hours,
            y: new Array(24).fill(0),
            type: 'scatter',
            mode: 'lines+markers',
            name: 'Alerts',
            line: {
                color: '#00d4ff',
                width: 2,
                shape: 'spline'
            },
            fill: 'tozeroy',
            fillcolor: 'rgba(0, 212, 255, 0.1)',
            marker: {
                color: '#00d4ff',
                size: 6
            }
        }];

        const layout = {
            ...this.getCommonLayout('Alerts Last 24 Hours'),
            xaxis: {
                ...this.getCommonLayout().xaxis,
                title: 'Hour'
            },
            yaxis: {
                ...this.getCommonLayout().yaxis,
                title: 'Alert Count'
            }
        };

        Plotly.newPlot('alertsTimelineChart', data, layout, { responsive: true });
    }

    // Update Alerts Timeline
    updateAlertsTimeline(alertsByHour) {
        const hours = Array.from({length: 24}, (_, i) => `${i.toString().padStart(2, '0')}:00`);
        const values = hours.map(h => alertsByHour[h] || 0);

        const data = [{
            x: hours,
            y: values,
            type: 'scatter',
            mode: 'lines+markers',
            name: 'Alerts',
            line: {
                color: '#00d4ff',
                width: 2,
                shape: 'spline'
            },
            fill: 'tozeroy',
            fillcolor: 'rgba(0, 212, 255, 0.1)',
            marker: {
                color: '#00d4ff',
                size: 6
            }
        }];

        Plotly.react('alertsTimelineChart', data, this.getCommonLayout('Alerts Last 24 Hours'));
    }

    // Top Attackers Chart
    initTopAttackers() {
        const data = [{
            y: ['No Data'],
            x: [0],
            type: 'bar',
            orientation: 'h',
            marker: {
                color: '#ff4757',
                line: {
                    color: 'rgba(255, 71, 87, 0.5)',
                    width: 1
                }
            },
            text: ['0'],
            textposition: 'outside',
            textfont: { color: '#ffffff' }
        }];

        const layout = {
            ...this.getCommonLayout('Top 10 Attacking IPs'),
            xaxis: {
                ...this.getCommonLayout().xaxis,
                title: 'Number of Attacks'
            },
            yaxis: {
                ...this.getCommonLayout().yaxis,
                autorange: 'reversed'
            },
            margin: { l: 150, r: 50, t: 40, b: 50 }
        };

        Plotly.newPlot('topAttackersChart', data, layout, { responsive: true });
    }

    // Update Top Attackers
    updateTopAttackers(attackers) {
        if (!attackers || attackers.length === 0) {
            this.initTopAttackers();
            return;
        }

        const data = [{
            y: attackers.map(a => a.ip).reverse(),
            x: attackers.map(a => a.count).reverse(),
            type: 'bar',
            orientation: 'h',
            marker: {
                color: attackers.map((_, i) => {
                    const colors = ['#ff4757', '#ff6348', '#ff7f50', '#ff8c00', '#ffa502'];
                    return colors[i % colors.length];
                }),
                line: {
                    color: 'rgba(255, 71, 87, 0.3)',
                    width: 1
                }
            },
            text: attackers.map(a => a.count).reverse(),
            textposition: 'outside',
            textfont: { color: '#ffffff' }
        }];

        Plotly.react('topAttackersChart', data, this.getCommonLayout('Top 10 Attacking IPs'));
    }

    // Top Targets Chart
    initTopTargets() {
        const data = [{
            y: ['No Data'],
            x: [0],
            type: 'bar',
            orientation: 'h',
            marker: {
                color: '#00d4ff',
                line: {
                    color: 'rgba(0, 212, 255, 0.5)',
                    width: 1
                }
            },
            text: ['0'],
            textposition: 'outside',
            textfont: { color: '#ffffff' }
        }];

        const layout = {
            ...this.getCommonLayout('Top 10 Target IPs'),
            xaxis: {
                ...this.getCommonLayout().xaxis,
                title: 'Number of Attacks'
            },
            yaxis: {
                ...this.getCommonLayout().yaxis,
                autorange: 'reversed'
            },
            margin: { l: 150, r: 50, t: 40, b: 50 }
        };

        Plotly.newPlot('topTargetsChart', data, layout, { responsive: true });
    }

    // Update Top Targets
    updateTopTargets(targets) {
        if (!targets || targets.length === 0) {
            this.initTopTargets();
            return;
        }

        const data = [{
            y: targets.map(t => t.ip).reverse(),
            x: targets.map(t => t.count).reverse(),
            type: 'bar',
            orientation: 'h',
            marker: {
                color: targets.map((_, i) => {
                    const colors = ['#00d4ff', '#0099cc', '#007799', '#005566', '#003344'];
                    return colors[i % colors.length];
                }),
                line: {
                    color: 'rgba(0, 212, 255, 0.3)',
                    width: 1
                }
            },
            text: targets.map(t => t.count).reverse(),
            textposition: 'outside',
            textfont: { color: '#ffffff' }
        }];

        Plotly.react('topTargetsChart', data, this.getCommonLayout('Top 10 Target IPs'));
    }

    // Resize all charts
    resizeCharts() {
        Plotly.Plots.resize('attackTypesChart');
        Plotly.Plots.resize('alertsTimelineChart');
        Plotly.Plots.resize('topAttackersChart');
        Plotly.Plots.resize('topTargetsChart');
    }
}

// Handle window resize for charts
window.addEventListener('resize', () => {
    if (window.charts) {
        clearTimeout(window.resizeTimeout);
        window.resizeTimeout = setTimeout(() => {
            window.charts.resizeCharts();
        }, 250);
    }
});