const api = {
    async request(url, options = {}) {
        const token = localStorage.getItem('access_token');
        if (!token) { location.href = '/login.html'; return; }
        const res = await fetch('/api' + url, {
            ...options,
            headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', ...options.headers }
        });
        if (res.status === 401) { localStorage.clear(); location.href = '/login.html'; return; }
        const ct = res.headers.get('content-type');
        if (ct && ct.includes('text/csv')) return res.blob();
        return res.json();
    },
    getDashboardStats: () => api.request('/stats/dashboard'),
    getSystemMetrics: () => api.request('/stats/system'),
    getAlerts: (p = {}) => api.request('/alerts/?' + new URLSearchParams(p).toString()),
    blockAlertSource: (id) => api.request('/alerts/' + id + '/block', { method: 'POST' }),
    getBlockedIPs: () => api.request('/blocked/'),
    blockIP: (ip, r, perm) => api.request('/blocked/block', { method: 'POST', body: JSON.stringify({ ip_address: ip, reason: r, is_permanent: perm }) }),
    unblockIP: (id) => api.request('/blocked/unblock/' + id, { method: 'DELETE' }),
    getCompanies: () => api.request('/companies/'),
    getCurrentUser: () => api.request('/auth/me'),
    exportAlertsCSV: () => api.request('/alerts/export/csv'),
    exportAlertsExcel: () => api.request('/alerts/export/excel'),
    changePassword: (o, n) => api.request('/auth/change-password', { method: 'POST', body: JSON.stringify({ old_password: o, new_password: n }) }),
};
