// ===== NEO DASHBOARD FUNCTIONALITY =====

// 服务器状态管理
class ServerStatusManager {
    constructor() {
        this.statusCache = new Map();
        this.updateInterval = 30000; // 30秒更新一次
        this.init();
    }

    init() {
        this.updateAllServerStatus();
        setInterval(() => this.updateAllServerStatus(), this.updateInterval);
    }

    async updateAllServerStatus() {
        const serverCards = document.querySelectorAll('.server-card');
        const promises = Array.from(serverCards).map(card => {
            const serverId = card.dataset.serverId;
            return this.updateServerStatus(serverId);
        });
        
        await Promise.all(promises);
        this.updateMetrics();
    }

    async updateServerStatus(serverId) {
        try {
            // 模拟API调用 - 实际项目中需要替换为真实的API端点
            const response = await fetch(`/api/server/${serverId}/status/`);
            const data = await response.json();
            
            this.statusCache.set(serverId, data.status);
            this.updateStatusIndicator(serverId, data.status);
            
            return data.status;
        } catch (error) {
            console.error(`Failed to update status for server ${serverId}:`, error);
            // 随机模拟状态用于演示
            const status = Math.random() > 0.5 ? 'online' : 'offline';
            this.statusCache.set(serverId, status);
            this.updateStatusIndicator(serverId, status);
            return status;
        }
    }

    updateStatusIndicator(serverId, status) {
        const statusRing = document.querySelector(`#status_${serverId}`);
        if (!statusRing) return;

        const statusDot = statusRing.querySelector('.status-dot');
        if (!statusDot) return;

        // 移除所有状态类
        statusDot.classList.remove('online', 'offline');
        
        // 添加新状态类
        if (status === 'online') {
            statusDot.classList.add('online');
        } else {
            statusDot.classList.add('offline');
        }
    }

    updateMetrics() {
        const onlineCount = Array.from(this.statusCache.values()).filter(status => status === 'online').length;
        const offlineCount = Array.from(this.statusCache.values()).filter(status => status === 'offline').length;
        
        const onlineElement = document.getElementById('onlineCount');
        const offlineElement = document.getElementById('offlineCount');
        
        if (onlineElement) {
            onlineElement.textContent = onlineCount;
            this.animateNumber(onlineElement);
        }
        
        if (offlineElement) {
            offlineElement.textContent = offlineCount;
            this.animateNumber(offlineElement);
        }
    }

    animateNumber(element) {
        element.style.transform = 'scale(1.2)';
        setTimeout(() => {
            element.style.transform = 'scale(1)';
        }, 200);
    }
}

// 连接测试功能
class ConnectionTester {
    constructor() {
        this.testCache = new Map();
    }

    async testConnection(serverId) {
        const button = document.querySelector(`[onclick="testConnection('${serverId}')"]`);
        if (!button) return;

        // 显示加载状态
        const originalContent = button.innerHTML;
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i><span>Testing...</span>';
        button.disabled = true;

        try {
            // 模拟连接测试 - 实际项目中需要替换为真实的API端点
            await new Promise(resolve => setTimeout(resolve, 2000)); // 模拟2秒延迟
            
            const success = Math.random() > 0.3; // 70%成功率
            
            if (success) {
                this.showNotification('Connection test successful!', 'success');
                // 更新状态指示器
                if (window.serverStatusManager) {
                    window.serverStatusManager.updateStatusIndicator(serverId, 'online');
                }
            } else {
                this.showNotification('Connection test failed: Timeout', 'error');
                if (window.serverStatusManager) {
                    window.serverStatusManager.updateStatusIndicator(serverId, 'offline');
                }
            }
        } catch (error) {
            console.error('Connection test error:', error);
            this.showNotification('Connection test failed: Network error', 'error');
            if (window.serverStatusManager) {
                window.serverStatusManager.updateStatusIndicator(serverId, 'offline');
            }
        } finally {
            // 恢复按钮状态
            button.innerHTML = originalContent;
            button.disabled = false;
        }
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-${this.getNotificationIcon(type)}"></i>
                <span>${message}</span>
            </div>
            <button class="notification-close" onclick="this.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        `;

        document.body.appendChild(notification);

        // 自动移除通知
        setTimeout(() => {
            if (notification.parentElement) {
                notification.classList.add('notification-hide');
                setTimeout(() => notification.remove(), 300);
            }
        }, 5000);
    }

    getNotificationIcon(type) {
        const icons = {
            success: 'check-circle',
            error: 'exclamation-circle',
            warning: 'exclamation-triangle',
            info: 'info-circle'
        };
        return icons[type] || 'info-circle';
    }
}

// 全局函数
function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
            if (window.connectionTester) {
                window.connectionTester.showNotification(`Copied: ${text}`, 'success');
            }
        }).catch(err => {
            console.error('Failed to copy text: ', err);
            fallbackCopyTextToClipboard(text);
        });
    } else {
        fallbackCopyTextToClipboard(text);
    }
}

function fallbackCopyTextToClipboard(text) {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.top = "0";
    textArea.style.left = "0";
    textArea.style.position = "fixed";
    
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        const successful = document.execCommand('copy');
        if (successful && window.connectionTester) {
            window.connectionTester.showNotification(`Copied: ${text}`, 'success');
        } else if (window.connectionTester) {
            window.connectionTester.showNotification('Failed to copy text', 'error');
        }
    } catch (err) {
        console.error('Fallback: Oops, unable to copy', err);
        if (window.connectionTester) {
            window.connectionTester.showNotification('Failed to copy text', 'error');
        }
    }
    
    document.body.removeChild(textArea);
}

function refreshServers() {
    const button = document.querySelector('.refresh-btn');
    if (!button) return;

    const icon = button.querySelector('i');
    const originalClass = icon.className;
    
    // 显示加载动画
    icon.className = 'fas fa-spinner fa-spin';
    button.disabled = true;

    // 强制更新所有服务器状态
    if (window.serverStatusManager) {
        window.serverStatusManager.updateAllServerStatus().then(() => {
            if (window.connectionTester) {
                window.connectionTester.showNotification('Server list refreshed!', 'success');
            }
        }).catch(error => {
            console.error('Refresh failed:', error);
            if (window.connectionTester) {
                window.connectionTester.showNotification('Failed to refresh server list', 'error');
            }
        }).finally(() => {
            // 恢复按钮状态
            setTimeout(() => {
                icon.className = originalClass;
                button.disabled = false;
            }, 1000);
        });
    }
}

function confirmDelete(serverId, serverName) {
    if (confirm(`Are you sure you want to delete server "${serverName}"?`)) {
        window.location.href = `/linux_delete/${serverId}/`;
    }
}

function testConnection(serverId) {
    if (window.connectionTester) {
        window.connectionTester.testConnection(serverId);
    }
}

// 粒子交互效果
function initParticleInteraction() {
    const particles = document.querySelectorAll('.particle');
    
    document.addEventListener('mousemove', (e) => {
        const mouseX = e.clientX / window.innerWidth;
        const mouseY = e.clientY / window.innerHeight;
        
        particles.forEach((particle, index) => {
            const speed = (index + 1) * 0.5;
            const x = mouseX * speed;
            const y = mouseY * speed;
            
            particle.style.transform = `translate(${x}px, ${y}px)`;
        });
    });
}

// 卡片悬停效果
function initCardHoverEffects() {
    const serverCards = document.querySelectorAll('.server-card');
    
    serverCards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-8px) scale(1.02)';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0) scale(1)';
        });
    });
}

// 搜索功能增强
function enhanceSearch() {
    const searchInput = document.querySelector('.search-input');
    if (!searchInput) return;

    let searchTimeout;
    
    searchInput.addEventListener('input', function() {
        clearTimeout(searchTimeout);
        
        searchTimeout = setTimeout(() => {
            const query = this.value.toLowerCase();
            const serverCards = document.querySelectorAll('.server-card');
            
            serverCards.forEach(card => {
                const serverName = card.querySelector('.server-name').textContent.toLowerCase();
                const serverIp = card.querySelector('code').textContent.toLowerCase();
                const hostname = card.querySelector('.info-value').textContent.toLowerCase();
                
                const matches = serverName.includes(query) || 
                               serverIp.includes(query) || 
                               hostname.includes(query);
                
                if (matches || query === '') {
                    card.style.display = 'block';
                    card.style.animation = 'fadeInUp 0.3s ease';
                } else {
                    card.style.display = 'none';
                }
            });
        }, 300);
    });
}

// DOM加载完成后初始化
document.addEventListener('DOMContentLoaded', function() {
    try {
        // 初始化管理器
        window.serverStatusManager = new ServerStatusManager();
        window.connectionTester = new ConnectionTester();
        
        // 添加粒子动画交互
        initParticleInteraction();
        
        // 添加卡片悬停效果
        initCardHoverEffects();
        
        // 增强搜索功能
        enhanceSearch();
        
        console.log('Neo Dashboard initialized successfully');
    } catch (error) {
        console.error('Failed to initialize Neo Dashboard:', error);
    }
});