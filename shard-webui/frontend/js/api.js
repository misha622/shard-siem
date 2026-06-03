const API_BASE_URL = '/api';

class APIClient {
    constructor() {
        this.token = localStorage.getItem('access_token');
    }

    getHeaders() {
        this.token = localStorage.getItem('access_token');
        return {
            'Authorization': 'Bearer ' + this.token,
            'Content-Type': 'application/json'
        };
    }

    async request(url, options = {}) {
        const token = localStorage.getItem('access_token');
        if (!token) {
            window.location.href = '/login.html';
            return;
        }

        const res = await fetch(API_BASE_URL + url, {
            ...options,
            headers: { ...this.getHeaders(), ...options.headers }
        });

        if (res.status === 401) {
            localStorage.clear();
            window.location.href = '/login.html';
            return;
        }

        if (!res.ok) {
            const err = await res.json().catch(() => ({ detail: 'Error' }));
            throw new Error(err.detail || 'Request failed');
        }

        const ct = res.headers.get('content-type');
        if (ct && (ct.includes('text/csv') || ct.includes('spreadsheet'))) {
            return res.blob();
        }
        return res.json();
    }

    async login(username, password) {
        return this.request('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });
    }

    getDashboardStats() { return this.request('/stats/dashboard'); }
    getSystemMetrics() { return this.request('/stats/system'); }
    getAlerts(params = {}) {
        const q = new URLSearchParams(params).toString();
        return this.request('/alerts/?' + q);
    }
    blockAlertSource(id) { return this.request('/alerts/' + id + '/block', { method: 'POST' }); }
    getBlockedIPs() { return this.request('/blocked/'); }
    blockIP(ip, reason, perm) {
        return this.request('/blocked/block', {
            method: 'POST',
            body: JSON.stringify({ ip_address: ip, reason: reason, is_permanent: perm || false })
        });
    }
    unblockIP(id) { return this.request('/blocked/unblock/' + id, { method: 'DELETE' }); }
    getCompanies() { return this.request('/companies/'); }
    getCurrentUser() { return this.request('/auth/me'); }
    exportAlertsCSV() { return this.request('/alerts/export/csv'); }
    exportAlertsExcel() { return this.request('/alerts/export/excel'); }
    changePassword(oldP, newP) {
        return this.request('/auth/change-password', {
            method: 'POST',
            body: JSON.stringify({ old_password: oldP, new_password: newP })
        });
    }
}

const api = new APIClient();
