// Auth module for SHARD Enterprise SIEM
const AUTH_KEY = 'access_token';
const USER_KEY = 'user';
const REFRESH_KEY = 'refresh_token';

function getToken() { return localStorage.getItem(AUTH_KEY); }
function getUser() { try { return JSON.parse(localStorage.getItem(USER_KEY)); } catch(e) { return {}; } }

async function login(username, password) {
    const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    if (!res.ok) throw new Error((await res.json()).detail || 'Login failed');
    const data = await res.json();
    localStorage.setItem(AUTH_KEY, data.access_token);
    localStorage.setItem(REFRESH_KEY, data.refresh_token);
    localStorage.setItem(USER_KEY, JSON.stringify(data.user));
    return data.user;
}

function logout() {
    localStorage.clear();
    sessionStorage.clear();
    window.location.href = '/login.html';
}

function checkAuth() {
    if (!getToken() && !window.location.pathname.includes('login') && !window.location.pathname.includes('register')) {
        window.location.href = '/login.html';
    }
}

function getHeaders() {
    return {
        'Authorization': 'Bearer ' + getToken(),
        'Content-Type': 'application/json'
    };
}

async function api(url, options = {}) {
    const res = await fetch('/api' + url, { ...options, headers: { ...getHeaders(), ...options.headers } });
    if (res.status === 401) { logout(); return null; }
    if (!res.ok) throw new Error((await res.json().catch(()=>({detail:'Error'})).detail));
    const ct = res.headers.get('content-type');
    if (ct && ct.includes('text/csv')) return res.blob();
    return res.json();
}

checkAuth();
