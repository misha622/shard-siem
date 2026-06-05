// SHARD Navigation Module - единый для всех страниц
document.addEventListener('DOMContentLoaded', function() {
    const token = localStorage.getItem('access_token');
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    const path = window.location.pathname;
    
    // Если нет токена и это не логин/регистрация — редирект
    if (!token && !path.includes('login') && !path.includes('register')) {
        window.location.href = '/login.html';
        return;
    }
    
    // Имя пользователя
    const ud = document.getElementById('usernameDisplay');
    if (ud) ud.textContent = user.username || 'User';
    
    // Settings только для admin
    const sl = document.getElementById('settingsLink');
    if (sl && user.role === 'admin') sl.style.display = 'inline-block';
    
    // Подсветка активной ссылки
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
        const href = link.getAttribute('href');
        if (href && path.includes(href.replace('/','').replace('.html',''))) {
            link.classList.add('active');
        }
    });
});

function logout() {
    localStorage.clear();
    sessionStorage.clear();
    window.location.href = '/login.html';
}
