document.addEventListener('DOMContentLoaded', function() {
    const token = localStorage.getItem('access_token');
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    const path = window.location.pathname;
    
    // Подсветка активной ссылки
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
        if (path.includes(link.getAttribute('href').replace('/',''))) {
            link.classList.add('active');
        }
    });
    
    // Имя пользователя
    const ud = document.getElementById('usernameDisplay');
    if (ud) ud.textContent = user.username || 'User';
    
    // Settings только для admin
    const sl = document.getElementById('settingsLink');
    if (sl && user.role === 'admin') sl.style.display = 'inline-block';
    
    // Проверка авторизации
    if (!token && !path.includes('login') && !path.includes('register')) {
        window.location.href = '/login.html';
    }
});
function logout() {
    localStorage.clear();
    window.location.href = '/login.html';
}
