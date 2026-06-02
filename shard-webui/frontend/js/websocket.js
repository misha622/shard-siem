// WebSocket client for real-time updates

class SHARDWebSocket {
    constructor() {
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 10;
        this.reconnectDelay = 1000;
        this.isConnected = false;
        this.eventHandlers = {};
        this.pingInterval = null;
    }

    // Connect to WebSocket
    connect() {
        const token = localStorage.getItem('access_token');
        if (!token) return;

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws?token=${token}`;

        try {
            this.ws = new WebSocket(wsUrl);
            this.setupEventListeners();
        } catch (error) {
            console.error('WebSocket connection failed:', error);
            this.handleReconnect();
        }
    }

    // Setup WebSocket event listeners
    setupEventListeners() {
        this.ws.onopen = () => {
            console.log('WebSocket connected');
            this.isConnected = true;
            this.reconnectAttempts = 0;
            this.updateStatus(true);
            this.startPing();
        };

        this.ws.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                this.handleMessage(message);
            } catch (error) {
                console.error('Error parsing WebSocket message:', error);
            }
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };

        this.ws.onclose = (event) => {
            console.log('WebSocket closed:', event.code, event.reason);
            this.isConnected = false;
            this.updateStatus(false);
            this.stopPing();

            if (!event.wasClean) {
                this.handleReconnect();
            }
        };
    }

    // Handle incoming message
    handleMessage(message) {
        const { type, data, timestamp } = message;

        // Call registered event handlers
        if (this.eventHandlers[type]) {
            this.eventHandlers[type].forEach(handler => {
                handler(data, timestamp);
            });
        }

        // Handle alert notifications
        if (type === 'alert.detected') {
            this.showAlertNotification(data);
        }
    }

    // Register event handler
    on(eventType, handler) {
        if (!this.eventHandlers[eventType]) {
            this.eventHandlers[eventType] = [];
        }
        this.eventHandlers[eventType].push(handler);
    }

    // Remove event handler
    off(eventType, handler) {
        if (this.eventHandlers[eventType]) {
            this.eventHandlers[eventType] = this.eventHandlers[eventType]
                .filter(h => h !== handler);
        }
    }

    // Show alert notification
    showAlertNotification(data) {
        // Show browser notification
        showBrowserNotification(
            `SHARD Alert: ${data.severity}`,
            `${data.alert_type} from ${data.source_ip}`
        );

        // Play sound (optional)
        if (localStorage.getItem('notificationSound') !== 'disabled') {
            playNotificationSound();
        }

        // Show toast
        if (typeof showToast === 'function') {
            const severityIcon = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢'
            };
            showToast('info', `${severityIcon[data.severity]} ${data.severity}: ${data.alert_type} from ${data.source_ip}`);
        }
    }

    // Send message
    send(data) {
        if (this.isConnected && this.ws) {
            this.ws.send(JSON.stringify(data));
        }
    }

    // Send ping
    sendPing() {
        this.send({ type: 'ping' });
    }

    // Start ping interval
    startPing() {
        this.stopPing();
        this.pingInterval = setInterval(() => {
            this.sendPing();
        }, 30000); // Ping every 30 seconds
    }

    // Stop ping interval
    stopPing() {
        if (this.pingInterval) {
            clearInterval(this.pingInterval);
            this.pingInterval = null;
        }
    }

    // Handle reconnection
    handleReconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('Max reconnection attempts reached');
            return;
        }

        this.reconnectAttempts++;
        const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

        console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);

        setTimeout(() => {
            this.connect();
        }, delay);
    }

    // Update connection status indicator
    updateStatus(connected) {
        const statusDot = document.querySelector('#wsStatus .status-dot');
        if (statusDot) {
            statusDot.className = `status-dot ${connected ? 'online pulse' : 'offline'}`;
        }
    }

    // Close connection
    disconnect() {
        this.stopPing();
        if (this.ws) {
            this.ws.close(1000, 'Client disconnecting');
        }
        this.isConnected = false;
        this.updateStatus(false);
    }
}

// Global WebSocket instance
let wsClient = null;

// Connect WebSocket
function connectWebSocket() {
    if (!wsClient) {
        wsClient = new SHARDWebSocket();

        // Register default handlers
        wsClient.on('alert.detected', (data) => {
            if (typeof handleAlertEvent === 'function') {
                handleAlertEvent(data);
            }
        });

        wsClient.on('firewall.blocked', (data) => {
            if (typeof handleBlockEvent === 'function') {
                handleBlockEvent(data);
            }
        });
    }

    wsClient.connect();
}

// Disconnect WebSocket
function disconnectWebSocket() {
    if (wsClient) {
        wsClient.disconnect();
        wsClient = null;
    }
}

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        SHARDWebSocket,
        connectWebSocket,
        disconnectWebSocket
    };
}