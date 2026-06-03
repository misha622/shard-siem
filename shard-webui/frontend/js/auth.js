// Auth stub
function logout() {
    localStorage.clear();
    window.location.href = '/login.html';
}
function checkAuth() {
    return !!localStorage.getItem('access_token');
}
