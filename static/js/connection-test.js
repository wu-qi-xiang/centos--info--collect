// Linux服务器连接测试模块 - 独立的连接测试功能

class ConnectionTester {
    constructor() {
        this.testUrl = '/connect_test/';
        this.activeTests = new Map(); // 存储正在进行的测试
    }

    /**
     * 测试服务器连接
     * @param {Object} serverData - 服务器连接信息
     * @param {string} serverData.linux_ip - IP地址
     * @param {string} serverData.linux_port - 端口
     * @param {string} serverData.linux_user - 用户名
     * @param {string} serverData.linux_passwd - 密码
     * @param {Object} options - 选项
     * @param {Function} options.onStart - 开始测试回调
     * @param {Function} options.onSuccess - 成功回调
     * @param {Function} options.onError - 失败回调
     * @param {Function} options.onComplete - 完成回调
     * @returns {Promise} 测试结果
     */
    async testConnection(serverData, options = {}) {
        const testId = this.generateTestId(serverData);
        
        // 检查是否已有相同的测试在进行
        if (this.activeTests.has(testId)) {
            console.log('连接测试已在进行中...');
            return this.activeTests.get(testId);
        }

        // 验证必要字段
        const validation = this.validateServerData(serverData);
        if (!validation.isValid) {
            const error = new Error(validation.message);
            if (options.onError) options.onError(error);
            throw error;
        }

        // 开始测试
        if (options.onStart) options.onStart();

        // 创建测试Promise
        const testPromise = this.performTest(serverData, options);
        this.activeTests.set(testId, testPromise);

        try {
            const result = await testPromise;
            if (options.onSuccess) options.onSuccess(result);
            return result;
        } catch (error) {
            if (options.onError) options.onError(error);
            throw error;
        } finally {
            this.activeTests.delete(testId);
            if (options.onComplete) options.onComplete();
        }
    }

    /**
     * 执行实际的连接测试
     */
    async performTest(serverData, options) {
        const formData = new FormData();
        formData.append('linux_ip', serverData.linux_ip);
        formData.append('linux_port', serverData.linux_port || '22');
        formData.append('linux_user', serverData.linux_user);
        formData.append('linux_passwd', serverData.linux_passwd);
        
        // 添加CSRF token
        const csrfToken = this.getCSRFToken();
        if (csrfToken) {
            formData.append('csrfmiddlewaretoken', csrfToken);
        }

        const response = await fetch(this.testUrl, {
            method: 'POST',
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP错误: ${response.status}`);
        }

        const responseText = await response.text();
        
        // 判断连接是否成功
        const isSuccess = responseText.includes('成功') || responseText.includes('连接正常');
        
        return {
            success: isSuccess,
            message: responseText,
            serverData: serverData,
            timestamp: new Date().toISOString()
        };
    }

    /**
     * 验证服务器数据
     */
    validateServerData(serverData) {
        if (!serverData.linux_ip || !serverData.linux_ip.trim()) {
            return { isValid: false, message: 'IP地址不能为空' };
        }

        if (!serverData.linux_user || !serverData.linux_user.trim()) {
            return { isValid: false, message: '用户名不能为空' };
        }

        if (!serverData.linux_passwd || !serverData.linux_passwd.trim()) {
            return { isValid: false, message: '密码不能为空' };
        }

        // IP地址格式验证
        const ipPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        if (!ipPattern.test(serverData.linux_ip.trim())) {
            return { isValid: false, message: 'IP地址格式不正确' };
        }

        // 端口验证
        const port = parseInt(serverData.linux_port) || 22;
        if (port < 1 || port > 65535) {
            return { isValid: false, message: '端口号必须在1-65535之间' };
        }

        return { isValid: true };
    }

    /**
     * 生成测试ID
     */
    generateTestId(serverData) {
        return `${serverData.linux_ip}:${serverData.linux_port || 22}:${serverData.linux_user}`;
    }

    /**
     * 获取CSRF Token
     */
    getCSRFToken() {
        const csrfInput = document.querySelector('[name=csrfmiddlewaretoken]');
        if (csrfInput) {
            return csrfInput.value;
        }
        
        // 从cookie中获取
        const cookies = document.cookie.split(';');
        for (let cookie of cookies) {
            const [name, value] = cookie.trim().split('=');
            if (name === 'csrftoken') {
                return value;
            }
        }
        
        return null;
    }

    /**
     * 批量测试多个服务器
     */
    async testMultipleConnections(serverList, options = {}) {
        const results = [];
        const maxConcurrent = options.maxConcurrent || 3; // 最大并发数
        
        for (let i = 0; i < serverList.length; i += maxConcurrent) {
            const batch = serverList.slice(i, i + maxConcurrent);
            const batchPromises = batch.map(server => 
                this.testConnection(server, {
                    onStart: () => options.onBatchStart && options.onBatchStart(server),
                    onSuccess: (result) => options.onBatchSuccess && options.onBatchSuccess(result),
                    onError: (error) => options.onBatchError && options.onBatchError(error, server)
                }).catch(error => ({ success: false, error, serverData: server }))
            );
            
            const batchResults = await Promise.all(batchPromises);
            results.push(...batchResults);
            
            // 批次间延迟，避免服务器压力过大
            if (i + maxConcurrent < serverList.length) {
                await this.delay(1000);
            }
        }
        
        return results;
    }

    /**
     * 延迟函数
     */
    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * 取消所有正在进行的测试
     */
    cancelAllTests() {
        this.activeTests.clear();
    }
}

// 服务器状态管理器
class ServerStatusManager {
    constructor() {
        this.connectionTester = new ConnectionTester();
        this.statusCache = new Map(); // 状态缓存
        this.updateInterval = 30000; // 30秒更新间隔
        this.autoUpdateTimer = null;
    }

    /**
     * 更新单个服务器状态
     */
    async updateServerStatus(serverId, serverData) {
        const statusElement = document.getElementById(`status_${serverId}`);
        const lastCheckElement = document.getElementById(`lastCheck_${serverId}`);
        const statusIndicator = document.querySelector(`[data-server-id="${serverId}"]`);

        if (!statusElement) return;

        try {
            // 显示检查中状态
            this.setStatusChecking(statusElement, statusIndicator);

            const result = await this.connectionTester.testConnection(serverData);
            
            // 更新状态显示
            if (result.success) {
                this.setStatusOnline(statusElement, statusIndicator);
            } else {
                this.setStatusOffline(statusElement, statusIndicator);
            }

            // 更新最后检查时间
            if (lastCheckElement) {
                lastCheckElement.textContent = new Date().toLocaleTimeString();
            }

            // 缓存状态
            this.statusCache.set(serverId, {
                status: result.success ? 'online' : 'offline',
                lastCheck: new Date(),
                message: result.message
            });

            return result;

        } catch (error) {
            console.error(`服务器 ${serverId} 状态检查失败:`, error);
            this.setStatusError(statusElement, statusIndicator);
            
            if (lastCheckElement) {
                lastCheckElement.textContent = '检查失败';
            }

            throw error;
        }
    }

    /**
     * 设置检查中状态
     */
    setStatusChecking(statusElement, statusIndicator) {
        statusElement.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>检查中';
        statusElement.className = 'badge bg-secondary';
        
        if (statusIndicator) {
            statusIndicator.className = 'status-indicator server-status me-2';
        }
    }

    /**
     * 设置在线状态
     */
    setStatusOnline(statusElement, statusIndicator) {
        statusElement.innerHTML = '<i class="fas fa-check-circle me-1"></i>在线';
        statusElement.className = 'badge bg-success';
        
        if (statusIndicator) {
            statusIndicator.className = 'status-indicator server-status me-2 status-online';
        }
    }

    /**
     * 设置离线状态
     */
    setStatusOffline(statusElement, statusIndicator) {
        statusElement.innerHTML = '<i class="fas fa-times-circle me-1"></i>离线';
        statusElement.className = 'badge bg-danger';
        
        if (statusIndicator) {
            statusIndicator.className = 'status-indicator server-status me-2 status-offline';
        }
    }

    /**
     * 设置错误状态
     */
    setStatusError(statusElement, statusIndicator) {
        statusElement.innerHTML = '<i class="fas fa-exclamation-triangle me-1"></i>错误';
        statusElement.className = 'badge bg-warning';
        
        if (statusIndicator) {
            statusIndicator.className = 'status-indicator server-status me-2 status-warning';
        }
    }

    /**
     * 批量更新服务器状态
     */
    async updateAllServerStatus() {
        const serverRows = document.querySelectorAll('.server-row[data-server-id]');
        const serverList = [];

        serverRows.forEach(row => {
            const serverId = row.getAttribute('data-server-id');
            const serverName = row.getAttribute('data-server-name');
            
            // 从行中提取服务器信息（这里需要根据实际情况调整）
            const ipElement = row.querySelector('.server-ip');
            const ip = ipElement ? ipElement.textContent.trim() : '';
            
            if (ip) {
                serverList.push({
                    id: serverId,
                    name: serverName,
                    linux_ip: ip,
                    linux_port: '22', // 默认端口，实际应该从数据中获取
                    linux_user: 'root', // 默认用户，实际应该从数据中获取
                    linux_passwd: '' // 密码需要从安全的地方获取
                });
            }
        });

        // 批量测试（这里需要服务器密码信息，实际使用时需要通过API获取）
        console.log(`准备检查 ${serverList.length} 台服务器状态`);
        
        // 由于密码信息的安全性，这里采用逐个检查的方式
        for (const server of serverList) {
            try {
                // 这里需要通过API获取服务器的完整信息包括密码
                await this.fetchAndUpdateServerStatus(server.id);
            } catch (error) {
                console.error(`更新服务器 ${server.id} 状态失败:`, error);
            }
            
            // 添加延迟避免服务器压力过大
            await this.connectionTester.delay(500);
        }
    }

    /**
     * 通过API获取服务器信息并更新状态
     */
    async fetchAndUpdateServerStatus(serverId) {
        try {
            // 这里应该调用后端API获取服务器完整信息
            // const response = await fetch(`/api/server/${serverId}/`);
            // const serverData = await response.json();
            
            // 暂时使用模拟数据
            const isOnline = Math.random() > 0.3; // 70%概率在线
            const statusElement = document.getElementById(`status_${serverId}`);
            const lastCheckElement = document.getElementById(`lastCheck_${serverId}`);
            const statusIndicator = document.querySelector(`[data-server-id="${serverId}"]`);
            
            if (statusElement) {
                this.setStatusChecking(statusElement, statusIndicator);
                
                // 模拟网络延迟
                await this.connectionTester.delay(1000 + Math.random() * 2000);
                
                if (isOnline) {
                    this.setStatusOnline(statusElement, statusIndicator);
                } else {
                    this.setStatusOffline(statusElement, statusIndicator);
                }
                
                if (lastCheckElement) {
                    lastCheckElement.textContent = new Date().toLocaleTimeString();
                }
            }
            
        } catch (error) {
            console.error(`获取服务器 ${serverId} 信息失败:`, error);
            throw error;
        }
    }

    /**
     * 开始自动更新
     */
    startAutoUpdate() {
        this.stopAutoUpdate(); // 先停止之前的定时器
        
        this.autoUpdateTimer = setInterval(() => {
            if (!document.hidden) { // 只在页面可见时更新
                this.updateAllServerStatus();
            }
        }, this.updateInterval);
    }

    /**
     * 停止自动更新
     */
    stopAutoUpdate() {
        if (this.autoUpdateTimer) {
            clearInterval(this.autoUpdateTimer);
            this.autoUpdateTimer = null;
        }
    }

    /**
     * 获取缓存的状态
     */
    getCachedStatus(serverId) {
        return this.statusCache.get(serverId);
    }
}

// 导出类供其他模块使用
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ConnectionTester, ServerStatusManager };
} else {
    // 浏览器环境
    window.ConnectionTester = ConnectionTester;
    window.ServerStatusManager = ServerStatusManager;
}