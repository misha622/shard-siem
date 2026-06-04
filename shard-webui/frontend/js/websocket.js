// WebSocket client for real-time alerts
class SHARDWebSocket {
    constructor() {
        this.ws = null;
        this.reconnectDelay = 2000;
        this.handlers = {};
    }

    connect() {
        const token = localStorage.getItem('access_token');
        if (!token) return;
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const url = `${proto}//${location.host}/ws?token=${token}`;
        try {
            this.ws = new WebSocket(url);
            this.ws.onopen = () => console.log('WebSocket connected');
            this.ws.onmessage = (e) => {
                try {
                    const msg = JSON.parse(e.data);
                    if (this.handlers[msg.type]) this.handlers[msg.type].forEach(h => h(msg.data));
                } catch(err) { console.error('WS parse error:', err); }
            };
            this.ws.onclose = () => { console.log('WebSocket closed, reconnecting...'); setTimeout(() => this.connect(), this.reconnectDelay); };
            this.ws.onerror = () => this.ws.close();
        } catch(e) { setTimeout(() => this.connect(), this.reconnectDelay); }
    }

    on(event, handler) {
        if (!this.handlers[event]) this.handlers[event] = [];
        this.handlers[event].push(handler);
    }

    disconnect() { if (this.ws) this.ws.close(); }
}

const wsClient = new SHARDWebSocket();
