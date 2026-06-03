async function loadDashboard() {
    const stats = await api('/stats/dashboard');
    if (!stats) return;
    document.getElementById('kpiPackets').textContent = (stats.total_packets || 0).toLocaleString();
    document.getElementById('kpiAlerts').textContent = (stats.total_alerts || 0).toLocaleString();
    document.getElementById('kpiBlocked').textContent = (stats.total_blocked || 0).toLocaleString();
    document.getElementById('kpiThreats').textContent = (stats.active_threats || 0).toLocaleString();
    
    const types = Object.entries(stats.alerts_by_type || {});
    if (types.length) Plotly.react('attackTypesChart', [{values:types.map(t=>t[1]),labels:types.map(t=>t[0]),type:'pie',hole:.4,marker:{colors:['#00d4ff','#ff4757','#ffa502','#2ed573','#a29bfe','#fd79a8']}}],{paper_bgcolor:'transparent',plot_bgcolor:'transparent',font:{color:'#fff'},margin:{t:10}});
    
    const hours=Array.from({length:24},(_,i)=>String(i).padStart(2,'0')+':00');
    const hd=stats.alerts_by_hour||{};
    Plotly.react('alertsTimelineChart',[{x:hours,y:hours.map(h=>hd[h]||0),type:'scatter',mode:'lines+markers',line:{color:'#00d4ff',width:2},fill:'tozeroy',fillcolor:'rgba(0,212,255,0.1)'}],{paper_bgcolor:'transparent',plot_bgcolor:'transparent',font:{color:'#fff'},margin:{t:10}});
    
    const ta=stats.top_attackers||[];
    if(ta.length) Plotly.react('topAttackersChart',[{y:ta.map(a=>a.ip).reverse(),x:ta.map(a=>a.count).reverse(),type:'bar',orientation:'h',marker:{color:'#ff4757'}}],{paper_bgcolor:'transparent',plot_bgcolor:'transparent',font:{color:'#fff'},margin:{t:10,l:150}});
    
    const tt=stats.top_targets||[];
    if(tt.length) Plotly.react('topTargetsChart',[{y:tt.map(a=>a.ip).reverse(),x:tt.map(a=>a.count).reverse(),type:'bar',orientation:'h',marker:{color:'#00d4ff'}}],{paper_bgcolor:'transparent',plot_bgcolor:'transparent',font:{color:'#fff'},margin:{t:10,l:150}});
    
    const sys=await api('/stats/system');
    if(sys){document.getElementById('cpuValue').textContent=(sys.cpu_percent||0).toFixed(1)+'%';document.getElementById('cpuBar').style.width=(sys.cpu_percent||0)+'%';document.getElementById('ramValue').textContent=(sys.memory_percent||0).toFixed(1)+'%';document.getElementById('ramBar').style.width=(sys.memory_percent||0)+'%';document.getElementById('diskValue').textContent=(sys.disk_percent||0).toFixed(1)+'%';document.getElementById('diskBar').style.width=(sys.disk_percent||0)+'%';}
    
    const alerts=await api('/alerts/?page_size=10');
    if(alerts&&alerts.alerts) document.getElementById('alertsTableBody').innerHTML=alerts.alerts.map(a=>`<tr class="severity-${(a.severity||'').toLowerCase()}"><td>${new Date(a.timestamp).toLocaleTimeString()}</td><td><span class="alert-type-badge">${a.alert_type}</span></td><td><span class="severity-badge severity-${(a.severity||'').toLowerCase()}">${a.severity}</span></td><td>${a.source_ip}</td><td>${a.destination_ip}</td><td>${a.is_blocked?'<span class="blocked-badge">Blocked</span>':'<button onclick="blockIP(\''+a.id+'\')" class="block-btn">Block</button>'}</td></tr>`).join('');
}

async function blockIP(id){await api('/alerts/'+id+'/block',{method:'POST'});loadDashboard();}
function logout(){localStorage.clear();window.location.href='/login.html';}
loadDashboard();setInterval(loadDashboard,5000);
