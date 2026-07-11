class DashboardServerStatusManager {
    constructor() {
        this.statusCache = new Map();
        this.updateInterval = 30000;
        this.init();
    }

    init() {
        this.updateAllServerStatus();
        setInterval(() => this.updateAllServerStatus(), this.updateInterval);
    }

    serverElements() {
        return document.querySelectorAll('[data-server-id]');
    }

    async updateAllServerStatus() {
        const elements = Array.from(this.serverElements()).filter(element => {
            const serverId = element.dataset.serverId;
            return serverId && document.getElementById(`status_${serverId}`);
        });
        await Promise.all(elements.map(element => this.updateServerStatus(element.dataset.serverId)));
        this.updateMetrics();
    }

    async updateServerStatus(serverId) {
        try {
            const response = await fetch(`/api/server/${serverId}/status/`);
            if (!response.ok) {
                this.statusCache.set(serverId, 'offline');
                this.updateStatusIndicator(serverId, 'offline');
                return 'offline';
            }
            const data = await response.json();
            const status = data.status || 'offline';
            this.statusCache.set(serverId, status);
            this.updateStatusIndicator(serverId, status);
            return status;
        } catch (error) {
            this.statusCache.set(serverId, 'offline');
            this.updateStatusIndicator(serverId, 'offline');
            return 'offline';
        }
    }

    updateStatusIndicator(serverId, status) {
        const statusElement = document.querySelector(`#status_${serverId}`);
        if (!statusElement) return;
        const dot = statusElement.querySelector('.status-dot');
        if (dot) {
            dot.style.background = status === 'online' ? '#16a34a' : '#dc2626';
        }
        statusElement.classList.remove('btn-outline-secondary', 'btn-outline-success', 'btn-outline-danger');
        statusElement.classList.add(status === 'online' ? 'btn-outline-success' : 'btn-outline-danger');
        statusElement.innerHTML = `<span class="status-dot" style="background:${status === 'online' ? '#16a34a' : '#dc2626'}"></span>${status === 'online' ? '在线' : '离线'}`;
    }

    updateMetrics() {
        const onlineCount = Array.from(this.statusCache.values()).filter(status => status === 'online').length;
        const offlineCount = Array.from(this.statusCache.values()).filter(status => status === 'offline').length;
        const onlineElement = document.getElementById('onlineCount');
        const offlineElement = document.getElementById('offlineCount');
        if (onlineElement) onlineElement.textContent = onlineCount;
        if (offlineElement) offlineElement.textContent = offlineCount;
    }
}

class DashboardConnectionTester {
    async testConnection(serverId) {
        const button = document.querySelector(`[onclick="testConnection('${serverId}')"]`);
        if (!button) return;
        const originalContent = button.innerHTML;
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        button.disabled = true;
        try {
            const status = await window.serverStatusManager.updateServerStatus(serverId);
            this.showNotification(status === 'online' ? '连接测试成功' : '连接测试失败', status === 'online' ? 'success' : 'error');
        } finally {
            button.innerHTML = originalContent;
            button.disabled = false;
        }
    }

    showNotification(message, type) {
        if (window.showNotification) {
            window.showNotification(message, type === 'error' ? 'error' : 'success');
            return;
        }
        alert(message);
    }
}

function refreshServers() {
    if (window.serverStatusManager) {
        window.serverStatusManager.updateAllServerStatus();
    }
}

function confirmDelete(serverId, serverName) {
    if (confirm(`确认删除服务器 "${serverName}"？`)) {
        const form = document.getElementById(`delete-server-form-${serverId}`);
        if (form) form.submit();
    }
}

function testConnection(serverId) {
    if (window.dashboardConnectionTester) {
        window.dashboardConnectionTester.testConnection(serverId);
    }
}

document.addEventListener('DOMContentLoaded', function () {
    window.serverStatusManager = new DashboardServerStatusManager();
    window.dashboardConnectionTester = new DashboardConnectionTester();
});
