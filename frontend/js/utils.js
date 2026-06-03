function escapeHtml(t){return String(t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function downloadBlob(b,f){const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download=f;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(u)}
function formatNumber(n){return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g,',')}
