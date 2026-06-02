// Authentication and session management

// Check authentication status
function checkAuth() {
    const token = localStorage.getItem('access_token');
    if (!token) {
        redirectToLogin();
        return false;
    }

    if (isTokenExpired(token)) {
        // Try to refresh
        refreshToken();
    }

    return true;
}

// Refresh token
async function refreshToken() {
    const refreshToken = localStorage.getItem('refresh_token');
    if (!refreshToken) {
        logout();
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refresh_token: refreshToken })
        });

        if (response.ok) {
            const data = await response.json();
            localStorage.setItem('access_token', data.access_token);
            localStorage.setItem('refresh_token', data.refresh_token);
            localStorage.setItem('user', JSON.stringify(data.user));
            return true;
        } else {
            logout();
        }
    } catch (error) {
        console.error('Token refresh failed:', error);
        logout();
    }
}

// Logout
async function logout() {
    try {
        await api.logout();
    } catch (error) {
        console.error('Logout error:', error);
    } finally {
        localStorage.clear();
        sessionStorage.clear();
        window.location.href = '/login.html';
    }
}

// Redirect to login
function redirectToLogin() {
    localStorage.clear();
    window.location.href = '/login.html';
}

// Get current user
function getCurrentUser() {
    const userStr = localStorage.getItem('user');
    return userStr ? JSON.parse(userStr) : null;
}

// Check if user has role
function hasRole(role) {
    const user = getCurrentUser();
    return user && user.role === role;
}

// Check if user is admin
function isAdmin() {
    return hasRole('admin');
}

// Set up axios/fetch interceptor for 401 handling
(function setupAuthInterceptor() {
    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
        const response = await originalFetch.apply(this, args);

        // Clone response to check status without consuming it
        if (response.status === 401) {
            const refreshed = await refreshToken();
            if (refreshed) {
                // Retry the request with new token
                const newArgs = [...args];
                if (newArgs[1] && newArgs[1].headers) {
                    newArgs[1].headers['Authorization'] = `Bearer ${localStorage.getItem('access_token')}`;
                }
                return originalFetch.apply(this, newArgs);
            }
        }

        return response;
    };
})();

// Periodic token refresh
setInterval(() => {
    const token = localStorage.getItem('access_token');
    if (token && isTokenExpired(token)) {
        refreshToken();
    }
}, 60000); // Check every minute

// Export functions
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        checkAuth,
        refreshToken,
        logout,
        getCurrentUser,
        hasRole,
        isAdmin
    };
}