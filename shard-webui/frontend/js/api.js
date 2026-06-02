// API client for SHARD Enterprise SIEM

const API_BASE_URL = window.location.origin + '/api';

class APIClient {
    constructor() {
        this.token = localStorage.getItem('access_token');
        this.refreshToken = localStorage.getItem('refresh_token');
    }

    // Get headers with authorization
    getHeaders() {
        return {
            'Authorization': `Bearer ${this.token}`,
            'Content-Type': 'application/json',
            'X-Correlation-ID': generateId()
        };
    }

    // Handle API response
    async handleResponse(response) {
        if (response.status === 401) {
            // Try to refresh token
            const refreshed = await this.refreshAccessToken();
            if (refreshed) {
                // Retry the request
                return null; // Signal to retry
            } else {
                // Redirect to login
                localStorage.clear();
                window.location.href = '/login.html';
                throw new Error('Session expired');
            }
        }

        if (response.status === 429) {
            throw new Error('Rate limit exceeded. Please try again later.');
        }

        if (!response.ok) {
            const error = await response.json().catch(() => ({ detail: 'Network error' }));
            throw new Error(error.detail || `HTTP ${response.status}`);
        }

        // Handle different response types
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            return await response.json();
        } else if (contentType && contentType.includes('text/csv')) {
            return await response.blob();
        } else if (contentType && contentType.includes('application/vnd.openxmlformats')) {
            return await response.blob();
        }

        return await response.json();
    }

    // Refresh access token
    async refreshAccessToken() {
        try {
            const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ refresh_token: this.refreshToken })
            });

            if (response.ok) {
                const data = await response.json();
                this.token = data.access_token;
                this.refreshToken = data.refresh_token;
                localStorage.setItem('access_token', data.access_token);
                localStorage.setItem('refresh_token', data.refresh_token);
                return true;
            }
        } catch (error) {
            console.error('Token refresh failed:', error);
        }
        return false;
    }

    // Generic request method
    async request(endpoint, options = {}) {
        const url = `${API_BASE_URL}${endpoint}`;
        const config = {
            headers: this.getHeaders(),
            ...options
        };

        // Remove content-type for FormData
        if (options.body instanceof FormData) {
            delete config.headers['Content-Type'];
        }

        let response = await fetch(url, config);
        let result = await this.handleResponse(response);

        // If token was refreshed, retry once
        if (result === null) {
            config.headers = this.getHeaders();
            response = await fetch(url, config);
            result = await this.handleResponse(response);
        }

        return result;
    }

    // Auth endpoints
    async login(username, password) {
        return await this.request('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });
    }

    async logout() {
        await this.request('/auth/logout', { method: 'POST' });
    }

    async getCurrentUser() {
        return await this.request('/auth/me');
    }

    async changePassword(oldPassword, newPassword) {
        return await this.request('/auth/change-password', {
            method: 'POST',
            body: JSON.stringify({ old_password: oldPassword, new_password: newPassword })
        });
    }

    // Alerts endpoints
    async getAlerts(params = {}) {
        const queryString = new URLSearchParams(
            Object.entries(params).filter(([_, v]) => v != null && v !== '')
        ).toString();
        return await this.request(`/alerts/?${queryString}`);
    }

    async getAlert(alertId) {
        return await this.request(`/alerts/${alertId}`);
    }

    async blockAlertSource(alertId) {
        return await this.request(`/alerts/${alertId}/block`, { method: 'POST' });
    }

    async exportAlertsCSV(params = {}) {
        const queryString = new URLSearchParams(params).toString();
        return await this.request(`/alerts/export/csv?${queryString}`);
    }

    async exportAlertsExcel(params = {}) {
        const queryString = new URLSearchParams(params).toString();
        return await this.request(`/alerts/export/excel?${queryString}`);
    }

    // Blocked IPs endpoints
    async getBlockedIPs() {
        return await this.request('/blocked/');
    }

    async blockIP(ipAddress, reason, isPermanent = false) {
        return await this.request('/blocked/block', {
            method: 'POST',
            body: JSON.stringify({
                ip_address: ipAddress,
                reason: reason,
                is_permanent: isPermanent
            })
        });
    }

    async unblockIP(blockId) {
        return await this.request(`/blocked/unblock/${blockId}`, { method: 'DELETE' });
    }

    // Stats endpoints
    async getDashboardStats() {
        return await this.request('/stats/dashboard');
    }

    async getSystemMetrics() {
        return await this.request('/stats/system');
    }

    async getAlertsByHour() {
        return await this.request('/stats/alerts-by-hour');
    }

    async getTopAttackers(limit = 10) {
        return await this.request(`/stats/top-attackers?limit=${limit}`);
    }

    async getTopTargets(limit = 10) {
        return await this.request(`/stats/top-targets?limit=${limit}`);
    }

    // Settings endpoints
    async getSystemLogs(lines = 100) {
        return await this.request(`/settings/logs?lines=${lines}`);
    }

    async getSystemInfo() {
        return await this.request('/settings/system-info');
    }

    // Health check
    async healthCheck() {
        return await this.request('/health');
    }
}

// Create global API instance
const api = new APIClient();