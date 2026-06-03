const token = localStorage.getItem('access_token');
if (!token) window.location.href = '/login.html';

const user = JSON.parse(localStorage.getItem('user') || '{}');
document.getElementById('usernameDisplay').textContent = user.username || 'User';
if (user.role === 'admin') document.getElementById('settingsLink').style.display = 'inline-block';

const H = { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' };

async function api(url, options = {}) {
    const res = await fetch('/api' + url, { ...options, headers: { ...H, ...options.headers } });
    if (res.status === 401) { localStorage.clear(); window.location.href = '/login.html'; return null; }
    const ct = res.headers.get('content-type');
    if (ct && ct.includes('text/csv')) return res.blob();
    return res.json();
}
