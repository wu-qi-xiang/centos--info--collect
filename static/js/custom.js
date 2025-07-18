// Linux服务器监控系统 - 现代化前端交互脚本 v2.1

// 全局配置
const AppConfig = {
    version: '2.1.0',
    debug: false,
    theme: {
        primary: '#2563eb',
        success: '#10b981',
        warning: '#f59e0b',
        danger: '#ef4444',
        info: '#06b6d4'
    },
    animations: {
        enabled: !window.matchMedia('(prefers-reduced-motion: reduce)').matches,
        duration: {
            fast: 150,
            normal: 300,
            slow: 500
        },
        easing: {
            ease: 'cubic-bezier(0.4, 0, 0.2, 1)',
            easeIn: 'cubic-bezier(0.4, 0, 1, 1)',
            easeOut: 'cubic-bezier(0, 0, 0.2, 1)',
            bounce: 'cubic-bezier(0.68, -0.55, 0.265, 1.55)'
        }
    },
    notifications: {
        duration: 5000,
        position: 'top-right',
        maxVisible: 3
    },
    performance: {
        debounceDelay: 300,
        throttleDelay: 100,
        animationFrame: true
    }
};

// 工具函数库
const Utils = {
    // 防抖函数
    debounce(func, wait, immediate = false) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                if (!immediate) func(...args);
            };
            const callNow = immediate && !timeout;
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
            if (callNow) func(...args);
        };
    },

    // 节流函数
    throttle(func, limit) {
        let inThrottle;
        return function() {
            const args = arguments;
            const context = this;
            if (!inThrottle) {
                func.apply(context, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    },

    // 格式化文件大小
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },

    // 生成唯一ID
    generateId() {
        return Date.now().toString(36) + Math.random().toString(36).substring(2);
    },

    // 检查元素是否在视口中
    isInViewport(element) {
        const rect = element.getBoundingClientRect();
        return (
            rect.top >= 0 &&
            rect.left >= 0 &&
            rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
            rect.right <= (window.innerWidth || document.documentElement.clientWidth)
        );
    }
};

// 通知系统类
class NotificationSystem {
    constructor() {
        this.notifications = new Map();
        this.container = this.createContainer();
    }

    createContainer() {
        const container = document.createElement('div');
        container.className = 'notification-container';
        container.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 10000;
            pointer-events: none;
        `;
        document.body.appendChild(container);
        return container;
    }

    show(message, type = 'info', duration = AppConfig.notifications.duration) {
        const id = Utils.generateId();
        const notification = this.createNotification(message, type, id);
        
        this.notifications.set(id, notification);
        this.container.appendChild(notification);
        
        // 触发动画
        requestAnimationFrame(() => {
            notification.style.transform = 'translateX(0)';
            notification.style.opacity = '1';
        });
        
        // 自动关闭
        if (duration > 0) {
            setTimeout(() => this.hide(id), duration);
        }
        
        return id;
    }

    createNotification(message, type, id) {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.style.cssText = `
            background: var(--bg-light);
            border-radius: var(--border-radius);
            padding: 1rem 1.5rem;
            margin-bottom: 0.5rem;
            box-shadow: var(--box-shadow-lg);
            display: flex;
            align-items: center;
            gap: 1rem;
            transform: translateX(100%);
            opacity: 0;
            transition: all 0.3s ease;
            pointer-events: auto;
            border-left: 4px solid var(--${type === 'error' ? 'danger' : type}-color);
            max-width: 400px;
            word-wrap: break-word;
        `;
        
        const icon = this.getIcon(type);
        const closeBtn = document.createElement('button');
        closeBtn.innerHTML = '×';
        closeBtn.style.cssText = `
            background: none;
            border: none;
            font-size: 1.5rem;
            cursor: pointer;
            color: var(--text-secondary);
            padding: 0;
            margin-left: auto;
            transition: var(--transition-fast);
        `;
        
        closeBtn.addEventListener('click', () => this.hide(id));
        
        notification.innerHTML = `
            <i class="fas fa-${icon} me-2"></i>
            <span class="flex-grow-1">${message}</span>
        `;
        notification.appendChild(closeBtn);
        
        return notification;
    }

    getIcon(type) {
        const icons = {
            success: 'check-circle',
            error: 'exclamation-circle',
            warning: 'exclamation-triangle',
            info: 'info-circle'
        };
        return icons[type] || icons.info;
    }

    hide(id) {
        const notification = this.notifications.get(id);
        if (notification) {
            notification.style.transform = 'translateX(100%)';
            notification.style.opacity = '0';
            
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
                this.notifications.delete(id);
            }, 300);
        }
    }
}

// 应用主类
class App {
    constructor() {
        this.notifications = new NotificationSystem();
        this.init();
    }

    init() {
        this.setupGlobalFeatures();
        this.setupPageAnimations();
        this.setupInteractiveElements();
        this.setupFormEnhancements();
        this.setupTableEnhancements();
        this.setupSearchEnhancements();
    }

    setupGlobalFeatures() {
        // 返回顶部按钮
        this.setupBackToTop();
        
        // 键盘快捷键
        this.setupKeyboardShortcuts();
        
        // 网络状态监测
        this.setupNetworkMonitoring();
        
        // 服务器状态检查
        this.setupServerStatusCheck();
    }

    setupBackToTop() {
        const backToTopButton = document.getElementById('back-to-top');
        if (backToTopButton) {
            const throttledScroll = Utils.throttle(() => {
                if (window.scrollY > 300) {
                    backToTopButton.classList.add('show');
                } else {
                    backToTopButton.classList.remove('show');
                }
            }, 100);

            window.addEventListener('scroll', throttledScroll);
            
            backToTopButton.addEventListener('click', () => {
                window.scrollTo({
                    top: 0,
                    behavior: 'smooth'
                });
            });
        }
    }

    setupPageAnimations() {
        if (!AppConfig.animations.enabled) return;

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }
            });
        }, { threshold: 0.1 });

        document.querySelectorAll('.card-custom, .table-custom, .form-custom').forEach((element, index) => {
            element.style.opacity = '0';
            element.style.transform = 'translateY(20px)';
            element.style.transition = `all 0.6s ease ${index * 0.1}s`;
            observer.observe(element);
        });
    }

    setupInteractiveElements() {
        // 按钮波纹效果
        document.querySelectorAll('.btn-custom').forEach(button => {
            button.addEventListener('click', this.createRippleEffect);
        });

        // 工具提示
        document.querySelectorAll('[data-tooltip]').forEach(element => {
            this.setupTooltip(element);
        });
    }

    createRippleEffect(e) {
        const button = e.currentTarget;
        const ripple = document.createElement('span');
        const rect = button.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = e.clientX - rect.left - size / 2;
        const y = e.clientY - rect.top - size / 2;
        
        ripple.style.cssText = `
            position: absolute;
            width: ${size}px;
            height: ${size}px;
            left: ${x}px;
            top: ${y}px;
            background: rgba(255, 255, 255, 0.6);
            border-radius: 50%;
            transform: scale(0);
            animation: ripple-animation 0.6s linear;
            pointer-events: none;
        `;
        
        button.appendChild(ripple);
        
        setTimeout(() => {
            ripple.remove();
        }, 600);
    }

    setupTooltip(element) {
        let tooltip = null;
        
        element.addEventListener('mouseenter', () => {
            tooltip = document.createElement('div');
            tooltip.className = 'tooltip-popup';
            tooltip.textContent = element.getAttribute('data-tooltip');
            document.body.appendChild(tooltip);
            
            const rect = element.getBoundingClientRect();
            tooltip.style.left = rect.left + rect.width / 2 - tooltip.offsetWidth / 2 + 'px';
            tooltip.style.top = rect.top - tooltip.offsetHeight - 10 + 'px';
        });
        
        element.addEventListener('mouseleave', () => {
            if (tooltip) {
                tooltip.remove();
                tooltip = null;
            }
        });
    }

    setupFormEnhancements() {
        document.querySelectorAll('form').forEach(form => {
            this.enhanceForm(form);
        });
    }

    enhanceForm(form) {
        // 表单验证
        const requiredFields = form.querySelectorAll('[required]');
        
        requiredFields.forEach(field => {
            field.addEventListener('blur', () => this.validateField(field));
            field.addEventListener('input', () => this.clearFieldError(field));
        });

        form.addEventListener('submit', (e) => {
            if (!this.validateForm(form)) {
                e.preventDefault();
                this.notifications.show('请填写所有必填字段', 'error');
            }
        });

        // 提交按钮增强
        const submitBtn = form.querySelector('button[type="submit"]');
        if (submitBtn) {
            form.addEventListener('submit', () => {
                const originalText = submitBtn.innerHTML;
                submitBtn.innerHTML = '<span class="loading"></span> 处理中...';
                submitBtn.disabled = true;

                setTimeout(() => {
                    submitBtn.innerHTML = originalText;
                    submitBtn.disabled = false;
                }, 2000);
            });
        }
    }

    validateField(field) {
        const value = field.value.trim();
        let isValid = true;
        let message = '';

        if (field.hasAttribute('required') && !value) {
            isValid = false;
            message = '此字段为必填项';
        } else if (field.type === 'email' && value && !this.isValidEmail(value)) {
            isValid = false;
            message = '请输入有效的邮箱地址';
        }

        if (isValid) {
            field.classList.remove('is-invalid');
            field.classList.add('is-valid');
            this.clearFieldError(field);
        } else {
            field.classList.remove('is-valid');
            field.classList.add('is-invalid');
            this.showFieldError(field, message);
        }

        return isValid;
    }

    validateForm(form) {
        const requiredFields = form.querySelectorAll('[required]');
        let isValid = true;

        requiredFields.forEach(field => {
            if (!this.validateField(field)) {
                isValid = false;
            }
        });

        return isValid;
    }

    showFieldError(field, message) {
        this.clearFieldError(field);
        const errorElement = document.createElement('div');
        errorElement.className = 'field-error';
        errorElement.textContent = message;
        field.parentNode.appendChild(errorElement);
    }

    clearFieldError(field) {
        const errorElement = field.parentNode.querySelector('.field-error');
        if (errorElement) {
            errorElement.remove();
        }
    }

    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    setupTableEnhancements() {
        document.querySelectorAll('.table').forEach(table => {
            this.enhanceTable(table);
        });
    }

    enhanceTable(table) {
        // 表格行悬停效果
        const rows = table.querySelectorAll('tbody tr');
        rows.forEach(row => {
            row.addEventListener('mouseenter', function() {
                if (AppConfig.animations.enabled) {
                    this.style.transform = 'scale(1.01)';
                    this.style.transition = 'transform 0.2s ease';
                }
            });
            
            row.addEventListener('mouseleave', function() {
                this.style.transform = 'scale(1)';
            });
        });

        // 表格排序
        const sortableHeaders = table.querySelectorAll('th[data-sortable]');
        sortableHeaders.forEach(header => {
            header.style.cursor = 'pointer';
            header.classList.add('sortable');
            header.addEventListener('click', () => this.sortTable(table, header));
        });
    }

    sortTable(table, header) {
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const columnIndex = Array.from(header.parentNode.children).indexOf(header);
        const isAscending = !header.classList.contains('sort-asc');
        
        // 清除其他列的排序状态
        header.parentNode.querySelectorAll('th').forEach(th => {
            th.classList.remove('sort-asc', 'sort-desc');
        });
        
        // 设置当前列的排序状态
        header.classList.add(isAscending ? 'sort-asc' : 'sort-desc');
        
        // 排序行
        rows.sort((a, b) => {
            const aText = a.children[columnIndex].textContent.trim();
            const bText = b.children[columnIndex].textContent.trim();
            
            // 尝试数字排序
            const aNum = parseFloat(aText);
            const bNum = parseFloat(bText);
            
            if (!isNaN(aNum) && !isNaN(bNum)) {
                return isAscending ? aNum - bNum : bNum - aNum;
            }
            
            // 文本排序
            return isAscending ? 
                aText.localeCompare(bText) : 
                bText.localeCompare(aText);
        });
        
        // 重新插入排序后的行
        rows.forEach(row => tbody.appendChild(row));
    }

    setupSearchEnhancements() {
        const searchInput = document.querySelector('input[name="search"]');
        if (searchInput) {
            // 实时搜索提示
            searchInput.addEventListener('input', function() {
                const value = this.value.trim();
                if (value.length > 0) {
                    this.classList.add('search-active');
                } else {
                    this.classList.remove('search-active');
                }
            });
            
            // 搜索快捷键
            document.addEventListener('keydown', function(e) {
                if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                    e.preventDefault();
                    searchInput.focus();
                    searchInput.select();
                }
            });
        }
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl + N: 新增服务器
            if (e.ctrlKey && e.key === 'n') {
                e.preventDefault();
                const createButton = document.querySelector('a[href*="create"]');
                if (createButton) {
                    createButton.click();
                }
            }
            
            // ESC: 关闭模态框
            if (e.key === 'Escape') {
                const openModals = document.querySelectorAll('.modal.show');
                openModals.forEach(modal => {
                    const closeButton = modal.querySelector('.btn-close, .close');
                    if (closeButton) closeButton.click();
                });
            }
        });
    }

    setupNetworkMonitoring() {
        window.addEventListener('online', () => {
            this.notifications.show('网络连接已恢复', 'success');
        });

        window.addEventListener('offline', () => {
            this.notifications.show('网络连接已断开', 'warning');
        });
    }

    setupServerStatusCheck() {
        const checkServerStatus = () => {
            const statusElements = document.querySelectorAll('.server-status');
            statusElements.forEach(element => {
                // 模拟服务器状态检查
                const isOnline = Math.random() > 0.2;
                element.className = `status-indicator ${isOnline ? 'status-online' : 'status-offline'}`;
                element.setAttribute('data-tooltip', isOnline ? '服务器在线' : '服务器离线');
            });
        };

        // 初始检查
        checkServerStatus();
        
        // 定期检查
        setInterval(checkServerStatus, 30000);
        
        // 页面重新可见时检查
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden) {
                checkServerStatus();
            }
        });
    }
}

// 全局函数
window.showNotification = (message, type = 'info', duration) => {
    if (window.app && window.app.notifications) {
        return window.app.notifications.show(message, type, duration);
    }
};

// DOM加载完成后初始化应用
document.addEventListener('DOMContentLoaded', () => {
    window.app = new App();
});

// 页面加载完成后隐藏加载器
window.addEventListener('load', () => {
    const loader = document.getElementById('page-loader');
    if (loader) {
        loader.style.opacity = '0';
        setTimeout(() => {
            loader.style.display = 'none';
        }, 300);
    }
});

// 导出工具函数供其他脚本使用
window.Utils = Utils;
window.AppConfig = AppConfig;

// 数字动画类
class NumberAnimation {
    constructor(element, target, duration = 2000) {
        this.element = element;
        this.target = parseFloat(target);
        this.duration = duration;
        this.startValue = 0;
        this.startTime = null;
    }

    start() {
        const animate = (currentTime) => {
            if (!this.startTime) this.startTime = currentTime;
            
            const elapsed = currentTime - this.startTime;
            const progress = Math.min(elapsed / this.duration, 1);
            
            // 使用缓动函数
            const easeOutQuart = 1 - Math.pow(1 - progress, 4);
            const currentValue = this.startValue + (this.target - this.startValue) * easeOutQuart;
            
            // 格式化数字显示
            if (this.target % 1 === 0) {
                this.element.textContent = Math.floor(currentValue);
            } else {
                this.element.textContent = currentValue.toFixed(1);
            }
            
            if (progress < 1) {
                requestAnimationFrame(animate);
            } else {
                this.element.textContent = this.target % 1 === 0 ? this.target : this.target.toFixed(1);
            }
        };
        
        requestAnimationFrame(animate);
    }
}

// 进度条动画类
class ProgressBarAnimation {
    constructor(element, targetWidth, delay = 0) {
        this.element = element;
        this.targetWidth = targetWidth;
        this.delay = delay;
    }

    start() {
        setTimeout(() => {
            this.element.style.width = this.targetWidth;
        }, this.delay);
    }
}

// 扩展App类以包含新功能
if (window.app) {
    // 添加统计数字动画
    window.app.animateStatNumbers = function() {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const element = entry.target;
                    const target = element.getAttribute('data-target');
                    
                    if (target && !element.classList.contains('animated')) {
                        element.classList.add('animated');
                        const animation = new NumberAnimation(element, target);
                        animation.start();
                        
                        // 同时动画进度条
                        const card = element.closest('.stat-card');
                        if (card) {
                            const progressBar = card.querySelector('.progress-bar-custom');
                            if (progressBar) {
                                const progressAnimation = new ProgressBarAnimation(
                                    progressBar, 
                                    progressBar.style.width,
                                    500
                                );
                                progressAnimation.start();
                            }
                        }
                    }
                    
                    observer.unobserve(element);
                }
            });
        }, { threshold: 0.5 });

        document.querySelectorAll('.stat-number').forEach(element => {
            observer.observe(element);
        });
    };

    // 添加活动时间线动画
    window.app.animateActivityTimeline = function() {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const items = entry.target.querySelectorAll('.activity-item');
                    items.forEach((item, index) => {
                        setTimeout(() => {
                            item.style.opacity = '1';
                            item.style.transform = 'translateX(0)';
                        }, index * 200);
                    });
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.3 });

        const timeline = document.querySelector('.activity-timeline');
        if (timeline) {
            // 初始化样式
            timeline.querySelectorAll('.activity-item').forEach(item => {
                item.style.opacity = '0';
                item.style.transform = 'translateX(-20px)';
                item.style.transition = 'all 0.5s ease';
            });
            
            observer.observe(timeline);
        }
    };

    // 添加资源使用动画
    window.app.animateResourceBars = function() {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const progressBars = entry.target.querySelectorAll('.progress-bar-custom');
                    progressBars.forEach((bar, index) => {
                        const targetWidth = bar.style.width;
                        bar.style.width = '0%';
                        
                        setTimeout(() => {
                            bar.style.width = targetWidth;
                        }, index * 200 + 300);
                    });
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.5 });

        const resourceSection = document.querySelector('.resource-item');
        if (resourceSection) {
            observer.observe(resourceSection.closest('.card-body'));
        }
    };

    // 页面加载完成后启动动画
    document.addEventListener('DOMContentLoaded', () => {
        setTimeout(() => {
            if (window.app.animateStatNumbers) window.app.animateStatNumbers();
            if (window.app.animateActivityTimeline) window.app.animateActivityTimeline();
            if (window.app.animateResourceBars) window.app.animateResourceBars();
        }, 500);
    });
}

// 实时时间更新
function updateActivityTimes() {
    const timeElements = document.querySelectorAll('.activity-time');
    timeElements.forEach(element => {
        // 这里可以实现实际的时间更新逻辑
        // 现在只是示例
    });
}

// 每分钟更新一次时间
setInterval(updateActivityTimes, 60000);

// 添加页面可见性检测优化
document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
        // 页面重新可见时刷新数据
        updateActivityTimes();
        
        // 重新检查服务器状态
        if (window.app && window.app.setupServerStatusCheck) {
            // 触发状态检查
        }
    }
});

// 添加键盘快捷键提示
function showKeyboardShortcuts() {
    const shortcuts = [
        { key: 'Ctrl + K', desc: '聚焦搜索框' },
        { key: 'Ctrl + N', desc: '新增服务器' },
        { key: 'ESC', desc: '关闭模态框' }
    ];
    
    const content = shortcuts.map(shortcut => 
        `<div class="d-flex justify-content-between mb-2">
            <kbd>${shortcut.key}</kbd>
            <span>${shortcut.desc}</span>
        </div>`
    ).join('');
    
    if (window.showNotification) {
        window.showNotification(`
            <div class="keyboard-shortcuts">
                <h6 class="mb-3">键盘快捷键</h6>
                ${content}
            </div>
        `, 'info', 8000);
    }
}

// 添加快捷键帮助
document.addEventListener('keydown', (e) => {
    if (e.key === 'F1' || (e.ctrlKey && e.key === '?')) {
        e.preventDefault();
        showKeyboardShortcuts();
    }
});

// 添加性能监控
class PerformanceMonitor {
    constructor() {
        this.metrics = {
            pageLoadTime: 0,
            domContentLoaded: 0,
            firstPaint: 0,
            largestContentfulPaint: 0
        };
        this.init();
    }

    init() {
        // 监控页面加载性能
        window.addEventListener('load', () => {
            this.collectMetrics();
        });

        // 监控LCP
        if ('PerformanceObserver' in window) {
            const observer = new PerformanceObserver((list) => {
                const entries = list.getEntries();
                const lastEntry = entries[entries.length - 1];
                this.metrics.largestContentfulPaint = lastEntry.startTime;
            });
            observer.observe({ entryTypes: ['largest-contentful-paint'] });
        }
    }

    collectMetrics() {
        if ('performance' in window) {
            const navigation = performance.getEntriesByType('navigation')[0];
            if (navigation) {
                this.metrics.pageLoadTime = navigation.loadEventEnd - navigation.fetchStart;
                this.metrics.domContentLoaded = navigation.domContentLoadedEventEnd - navigation.fetchStart;
            }

            const paintEntries = performance.getEntriesByType('paint');
            const firstPaint = paintEntries.find(entry => entry.name === 'first-paint');
            if (firstPaint) {
                this.metrics.firstPaint = firstPaint.startTime;
            }

            if (AppConfig.debug) {
                console.log('性能指标:', this.metrics);
            }
        }
    }

    getMetrics() {
        return this.metrics;
    }
}

// 初始化性能监控
const performanceMonitor = new PerformanceMonitor();

// 导出性能监控器
window.PerformanceMonitor = performanceMonitor;

// ===== 现代化通知系统增强 =====
class ModernNotificationSystem extends NotificationSystem {
    constructor() {
        super();
        this.queue = [];
        this.activeNotifications = 0;
        this.maxVisible = AppConfig.notifications.maxVisible;
    }

    show(message, type = 'info', duration = AppConfig.notifications.duration, options = {}) {
        const notification = {
            id: Utils.generateId(),
            message,
            type,
            duration,
            options: {
                persistent: false,
                actions: [],
                ...options
            }
        };

        if (this.activeNotifications >= this.maxVisible) {
            this.queue.push(notification);
            return notification.id;
        }

        this.displayNotification(notification);
        return notification.id;
    }

    displayNotification(notification) {
        const element = this.createModernNotification(notification);
        this.notifications.set(notification.id, element);
        this.container.appendChild(element);
        this.activeNotifications++;

        // 动画进入
        requestAnimationFrame(() => {
            element.classList.add('show');
        });

        // 自动关闭
        if (notification.duration > 0 && !notification.options.persistent) {
            setTimeout(() => this.hide(notification.id), notification.duration);
        }
    }

    createModernNotification(notification) {
        const element = document.createElement('div');
        element.className = `notification-modern ${notification.type}`;
        element.setAttribute('data-id', notification.id);

        const iconMap = {
            success: 'check-circle',
            error: 'exclamation-circle',
            warning: 'exclamation-triangle',
            info: 'info-circle'
        };

        const titleMap = {
            success: '成功',
            error: '错误',
            warning: '警告',
            info: '信息'
        };

        element.innerHTML = `
            <div class="notification-header">
                <div class="notification-title">
                    <i class="fas fa-${iconMap[notification.type]}"></i>
                    ${titleMap[notification.type]}
                </div>
                <button class="notification-close" onclick="window.app.notifications.hide('${notification.id}')">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="notification-body">
                ${notification.message}
            </div>
            ${notification.options.actions.length > 0 ? this.createActionButtons(notification.options.actions) : ''}
        `;

        return element;
    }

    createActionButtons(actions) {
        const buttonsHtml = actions.map(action => 
            `<button class="btn btn-sm btn-outline-primary me-2" onclick="${action.handler}">
                ${action.label}
            </button>`
        ).join('');

        return `<div class="notification-actions p-3 pt-0">${buttonsHtml}</div>`;
    }

    hide(id) {
        const element = this.notifications.get(id);
        if (element) {
            element.classList.remove('show');
            
            setTimeout(() => {
                if (element.parentNode) {
                    element.parentNode.removeChild(element);
                }
                this.notifications.delete(id);
                this.activeNotifications--;
                
                // 显示队列中的下一个通知
                if (this.queue.length > 0) {
                    const nextNotification = this.queue.shift();
                    this.displayNotification(nextNotification);
                }
            }, 400);
        }
    }
}

// ===== 现代化表单验证系统 =====
class FormValidator {
    constructor(form, options = {}) {
        this.form = form;
        this.options = {
            validateOnBlur: true,
            validateOnInput: true,
            showSuccessState: true,
            ...options
        };
        this.rules = new Map();
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupCustomRules();
    }

    setupEventListeners() {
        if (this.options.validateOnBlur) {
            this.form.addEventListener('blur', (e) => {
                if (e.target.matches('input, select, textarea')) {
                    this.validateField(e.target);
                }
            }, true);
        }

        if (this.options.validateOnInput) {
            this.form.addEventListener('input', (e) => {
                if (e.target.matches('input, select, textarea')) {
                    this.clearFieldError(e.target);
                    if (e.target.value.trim()) {
                        this.validateField(e.target);
                    }
                }
            });
        }

        this.form.addEventListener('submit', (e) => {
            if (!this.validateForm()) {
                e.preventDefault();
                this.focusFirstError();
            }
        });
    }

    setupCustomRules() {
        // IP地址验证
        this.addRule('ip', (value) => {
            const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
            return ipRegex.test(value) || 'IP地址格式不正确';
        });

        // 端口号验证
        this.addRule('port', (value) => {
            const port = parseInt(value);
            return (port >= 1 && port <= 65535) || '端口号必须在1-65535之间';
        });

        // 强密码验证
        this.addRule('strong-password', (value) => {
            const hasLower = /[a-z]/.test(value);
            const hasUpper = /[A-Z]/.test(value);
            const hasNumber = /\d/.test(value);
            const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(value);
            const isLongEnough = value.length >= 8;

            if (!isLongEnough) return '密码至少需要8个字符';
            if (!hasLower) return '密码需要包含小写字母';
            if (!hasUpper) return '密码需要包含大写字母';
            if (!hasNumber) return '密码需要包含数字';
            if (!hasSpecial) return '密码需要包含特殊字符';
            
            return true;
        });
    }

    addRule(name, validator) {
        this.rules.set(name, validator);
    }

    validateField(field) {
        const value = field.value.trim();
        const rules = field.getAttribute('data-rules')?.split('|') || [];
        
        // 必填验证
        if (field.hasAttribute('required') && !value) {
            this.showFieldError(field, '此字段为必填项');
            return false;
        }

        // 跳过空值的其他验证
        if (!value) {
            this.clearFieldError(field);
            return true;
        }

        // 内置类型验证
        if (field.type === 'email' && !this.isValidEmail(value)) {
            this.showFieldError(field, '请输入有效的邮箱地址');
            return false;
        }

        // 自定义规则验证
        for (const rule of rules) {
            if (this.rules.has(rule)) {
                const result = this.rules.get(rule)(value);
                if (result !== true) {
                    this.showFieldError(field, result);
                    return false;
                }
            }
        }

        // 验证通过
        this.clearFieldError(field);
        if (this.options.showSuccessState) {
            field.classList.add('is-valid');
        }
        return true;
    }

    validateForm() {
        const fields = this.form.querySelectorAll('input, select, textarea');
        let isValid = true;

        fields.forEach(field => {
            if (!this.validateField(field)) {
                isValid = false;
            }
        });

        return isValid;
    }

    showFieldError(field, message) {
        this.clearFieldError(field);
        field.classList.remove('is-valid');
        field.classList.add('is-invalid');

        const errorElement = document.createElement('div');
        errorElement.className = 'field-error';
        errorElement.innerHTML = `<i class="fas fa-exclamation-circle me-1"></i>${message}`;
        
        const container = field.closest('.form-group-custom') || field.parentNode;
        container.appendChild(errorElement);
    }

    clearFieldError(field) {
        field.classList.remove('is-invalid', 'is-valid');
        const container = field.closest('.form-group-custom') || field.parentNode;
        const errorElement = container.querySelector('.field-error');
        if (errorElement) {
            errorElement.remove();
        }
    }

    focusFirstError() {
        const firstError = this.form.querySelector('.is-invalid');
        if (firstError) {
            firstError.focus();
            firstError.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    }

    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }
}

// ===== 现代化数据表格系统 =====
class ModernDataTable {
    constructor(table, options = {}) {
        this.table = table;
        this.options = {
            sortable: true,
            searchable: true,
            pagination: false,
            pageSize: 10,
            ...options
        };
        this.data = [];
        this.filteredData = [];
        this.currentSort = { column: null, direction: 'asc' };
        this.init();
    }

    init() {
        this.extractData();
        this.setupSorting();
        this.setupSearch();
        this.setupRowActions();
    }

    extractData() {
        const rows = this.table.querySelectorAll('tbody tr');
        this.data = Array.from(rows).map((row, index) => ({
            index,
            element: row,
            data: Array.from(row.cells).map(cell => cell.textContent.trim())
        }));
        this.filteredData = [...this.data];
    }

    setupSorting() {
        if (!this.options.sortable) return;

        const headers = this.table.querySelectorAll('thead th[data-sortable]');
        headers.forEach((header, index) => {
            header.style.cursor = 'pointer';
            header.classList.add('sortable');
            
            header.addEventListener('click', () => {
                this.sort(index, header.getAttribute('data-sortable'));
            });
        });
    }

    sort(columnIndex, dataType = 'string') {
        const isAscending = this.currentSort.column !== columnIndex || this.currentSort.direction === 'desc';
        
        // 更新排序状态
        this.table.querySelectorAll('thead th').forEach(th => {
            th.classList.remove('sort-asc', 'sort-desc');
        });
        
        const header = this.table.querySelectorAll('thead th')[columnIndex];
        header.classList.add(isAscending ? 'sort-asc' : 'sort-desc');
        
        this.currentSort = { column: columnIndex, direction: isAscending ? 'asc' : 'desc' };

        // 排序数据
        this.filteredData.sort((a, b) => {
            let aVal = a.data[columnIndex];
            let bVal = b.data[columnIndex];

            // 数据类型转换
            if (dataType === 'number') {
                aVal = parseFloat(aVal) || 0;
                bVal = parseFloat(bVal) || 0;
            } else if (dataType === 'date') {
                aVal = new Date(aVal);
                bVal = new Date(bVal);
            }

            if (aVal < bVal) return isAscending ? -1 : 1;
            if (aVal > bVal) return isAscending ? 1 : -1;
            return 0;
        });

        this.render();
    }

    setupSearch() {
        if (!this.options.searchable) return;

        const searchInput = document.querySelector(`[data-table-search="${this.table.id}"]`);
        if (searchInput) {
            const debouncedSearch = Utils.debounce((query) => {
                this.search(query);
            }, AppConfig.performance.debounceDelay);

            searchInput.addEventListener('input', (e) => {
                debouncedSearch(e.target.value);
            });
        }
    }

    search(query) {
        if (!query.trim()) {
            this.filteredData = [...this.data];
        } else {
            const searchTerm = query.toLowerCase();
            this.filteredData = this.data.filter(row => 
                row.data.some(cell => 
                    cell.toLowerCase().includes(searchTerm)
                )
            );
        }
        this.render();
    }

    setupRowActions() {
        this.table.addEventListener('click', (e) => {
            const action = e.target.closest('[data-action]');
            if (action) {
                const actionType = action.getAttribute('data-action');
                const row = action.closest('tr');
                const rowIndex = Array.from(row.parentNode.children).indexOf(row);
                
                this.handleRowAction(actionType, rowIndex, row);
            }
        });
    }

    handleRowAction(action, rowIndex, rowElement) {
        const rowData = this.filteredData[rowIndex];
        
        switch (action) {
            case 'edit':
                this.editRow(rowData);
                break;
            case 'delete':
                this.deleteRow(rowData);
                break;
            case 'view':
                this.viewRow(rowData);
                break;
            default:
                console.log(`未知操作: ${action}`);
        }
    }

    editRow(rowData) {
        // 触发编辑事件
        this.table.dispatchEvent(new CustomEvent('row-edit', {
            detail: { rowData }
        }));
    }

    deleteRow(rowData) {
        // 触发删除事件
        this.table.dispatchEvent(new CustomEvent('row-delete', {
            detail: { rowData }
        }));
    }

    viewRow(rowData) {
        // 触发查看事件
        this.table.dispatchEvent(new CustomEvent('row-view', {
            detail: { rowData }
        }));
    }

    render() {
        const tbody = this.table.querySelector('tbody');
        tbody.innerHTML = '';

        this.filteredData.forEach(row => {
            tbody.appendChild(row.element);
        });

        // 更新统计信息
        this.updateStats();
    }

    updateStats() {
        const statsElement = document.querySelector(`[data-table-stats="${this.table.id}"]`);
        if (statsElement) {
            statsElement.textContent = `显示 ${this.filteredData.length} 条记录，共 ${this.data.length} 条`;
        }
    }
}

// ===== 现代化模态框系统 =====
class ModernModal {
    constructor(options = {}) {
        this.options = {
            title: '提示',
            content: '',
            type: 'info',
            showClose: true,
            backdrop: true,
            keyboard: true,
            size: 'md',
            ...options
        };
        this.element = null;
        this.isOpen = false;
    }

    create() {
        const modal = document.createElement('div');
        modal.className = `modal fade modal-modern`;
        modal.setAttribute('tabindex', '-1');
        modal.setAttribute('role', 'dialog');

        const sizeClass = this.options.size !== 'md' ? `modal-${this.options.size}` : '';
        
        modal.innerHTML = `
            <div class="modal-dialog ${sizeClass}" role="document">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">
                            <i class="fas fa-${this.getIcon()} me-2"></i>
                            ${this.options.title}
                        </h5>
                        ${this.options.showClose ? '<button type="button" class="btn-close" data-bs-dismiss="modal"></button>' : ''}
                    </div>
                    <div class="modal-body">
                        ${this.options.content}
                    </div>
                    ${this.options.footer ? `<div class="modal-footer">${this.options.footer}</div>` : ''}
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        this.element = modal;
        return this;
    }

    getIcon() {
        const icons = {
            info: 'info-circle',
            success: 'check-circle',
            warning: 'exclamation-triangle',
            error: 'exclamation-circle',
            question: 'question-circle'
        };
        return icons[this.options.type] || icons.info;
    }

    show() {
        if (!this.element) this.create();
        
        const bsModal = new bootstrap.Modal(this.element, {
            backdrop: this.options.backdrop,
            keyboard: this.options.keyboard
        });
        
        bsModal.show();
        this.isOpen = true;

        // 事件监听
        this.element.addEventListener('hidden.bs.modal', () => {
            this.isOpen = false;
            if (this.options.onClose) this.options.onClose();
            this.destroy();
        });

        return this;
    }

    hide() {
        if (this.element && this.isOpen) {
            const bsModal = bootstrap.Modal.getInstance(this.element);
            if (bsModal) bsModal.hide();
        }
        return this;
    }

    destroy() {
        if (this.element) {
            this.element.remove();
            this.element = null;
        }
    }

    static confirm(options = {}) {
        const confirmOptions = {
            type: 'question',
            title: '确认操作',
            content: '您确定要执行此操作吗？',
            footer: `
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                <button type="button" class="btn btn-primary confirm-btn">确认</button>
            `,
            ...options
        };

        return new Promise((resolve) => {
            const modal = new ModernModal(confirmOptions);
            modal.create();
            
            modal.element.querySelector('.confirm-btn').addEventListener('click', () => {
                resolve(true);
                modal.hide();
            });

            modal.element.addEventListener('hidden.bs.modal', () => {
                resolve(false);
            });

            modal.show();
        });
    }

    static alert(message, type = 'info', title = '提示') {
        const modal = new ModernModal({
            title,
            content: message,
            type,
            footer: '<button type="button" class="btn btn-primary" data-bs-dismiss="modal">确定</button>'
        });
        
        return modal.show();
    }
}

// ===== 现代化加载状态管理 =====
class LoadingManager {
    constructor() {
        this.activeLoaders = new Set();
        this.globalLoader = null;
    }

    show(target = 'global', options = {}) {
        const loaderId = Utils.generateId();
        
        if (target === 'global') {
            this.showGlobalLoader(loaderId, options);
        } else {
            this.showElementLoader(target, loaderId, options);
        }
        
        this.activeLoaders.add(loaderId);
        return loaderId;
    }

    hide(loaderId) {
        if (!this.activeLoaders.has(loaderId)) return;
        
        const loader = document.querySelector(`[data-loader-id="${loaderId}"]`);
        if (loader) {
            loader.remove();
        }
        
        this.activeLoaders.delete(loaderId);
        
        // 如果是全局加载器且没有其他加载器，隐藏全局加载器
        if (this.globalLoader && this.activeLoaders.size === 0) {
            this.globalLoader.style.opacity = '0';
            setTimeout(() => {
                if (this.globalLoader) {
                    this.globalLoader.style.display = 'none';
                }
            }, 300);
        }
    }

    showGlobalLoader(loaderId, options = {}) {
        if (!this.globalLoader) {
            this.createGlobalLoader();
        }
        
        this.globalLoader.style.display = 'flex';
        this.globalLoader.style.opacity = '1';
        this.globalLoader.setAttribute('data-loader-id', loaderId);
        
        if (options.message) {
            const messageEl = this.globalLoader.querySelector('.loader-message');
            if (messageEl) {
                messageEl.textContent = options.message;
            }
        }
    }

    showElementLoader(element, loaderId, options = {}) {
        if (typeof element === 'string') {
            element = document.querySelector(element);
        }
        
        if (!element) return;
        
        const loader = document.createElement('div');
        loader.className = 'element-loader';
        loader.setAttribute('data-loader-id', loaderId);
        loader.innerHTML = `
            <div class="loader-spinner"></div>
            ${options.message ? `<div class="loader-message">${options.message}</div>` : ''}
        `;
        
        // 设置样式
        const rect = element.getBoundingClientRect();
        loader.style.cssText = `
            position: absolute;
            top: ${rect.top + window.scrollY}px;
            left: ${rect.left + window.scrollX}px;
            width: ${rect.width}px;
            height: ${rect.height}px;
            background: rgba(255, 255, 255, 0.9);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            border-radius: var(--border-radius);
        `;
        
        document.body.appendChild(loader);
    }

    createGlobalLoader() {
        this.globalLoader = document.createElement('div');
        this.globalLoader.className = 'global-loader';
        this.globalLoader.innerHTML = `
            <div class="loader-content">
                <div class="loader-spinner"></div>
                <div class="loader-message">加载中...</div>
            </div>
        `;
        
        this.globalLoader.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(255, 255, 255, 0.9);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            backdrop-filter: blur(5px);
        `;
        
        document.body.appendChild(this.globalLoader);
    }

    hideAll() {
        this.activeLoaders.forEach(loaderId => this.hide(loaderId));
    }
}

// ===== 更新App类以使用新组件 =====
class ModernApp extends App {
    constructor() {
        super();
        this.notifications = new ModernNotificationSystem();
        this.loadingManager = new LoadingManager();
        this.validators = new Map();
        this.dataTables = new Map();
        this.initModernFeatures();
    }

    initModernFeatures() {
        this.setupModernForms();
        this.setupModernTables();
        this.setupModernInteractions();
    }

    setupModernForms() {
        document.querySelectorAll('form[data-validate]').forEach(form => {
            const validator = new FormValidator(form);
            this.validators.set(form.id || Utils.generateId(), validator);
        });
    }

    setupModernTables() {
        document.querySelectorAll('table[data-modern]').forEach(table => {
            const options = JSON.parse(table.getAttribute('data-options') || '{}');
            const dataTable = new ModernDataTable(table, options);
            this.dataTables.set(table.id || Utils.generateId(), dataTable);
        });
    }

    setupModernInteractions() {
        // 现代化按钮点击效果
        document.querySelectorAll('.btn-modern').forEach(btn => {
            btn.addEventListener('click', this.createModernRipple);
        });

        // 现代化卡片悬停效果
        document.querySelectorAll('.card-modern').forEach(card => {
            this.setupCardHover(card);
        });
    }

    createModernRipple(e) {
        const button = e.currentTarget;
        const ripple = document.createElement('span');
        const rect = button.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = e.clientX - rect.left - size / 2;
        const y = e.clientY - rect.top - size / 2;
        
        ripple.style.cssText = `
            position: absolute;
            width: ${size}px;
            height: ${size}px;
            left: ${x}px;
            top: ${y}px;
            background: rgba(255, 255, 255, 0.4);
            border-radius: 50%;
            transform: scale(0);
            animation: modern-ripple 0.6s ease-out;
            pointer-events: none;
            z-index: 1;
        `;
        
        button.appendChild(ripple);
        
        setTimeout(() => ripple.remove(), 600);
    }

    setupCardHover(card) {
        card.addEventListener('mouseenter', () => {
            if (AppConfig.animations.enabled) {
                card.style.transform = 'translateY(-8px) scale(1.02)';
            }
        });

        card.addEventListener('mouseleave', () => {
            card.style.transform = 'translateY(0) scale(1)';
        });
    }

    // 公共API方法
    showLoading(target, message) {
        return this.loadingManager.show(target, { message });
    }

    hideLoading(loaderId) {
        this.loadingManager.hide(loaderId);
    }

    showModal(options) {
        return new ModernModal(options).show();
    }

    confirm(message, title = '确认') {
        return ModernModal.confirm({ content: message, title });
    }

    alert(message, type = 'info', title = '提示') {
        return ModernModal.alert(message, type, title);
    }
}

// 添加现代化动画关键帧
const modernAnimations = `
@keyframes modern-ripple {
    to {
        transform: scale(4);
        opacity: 0;
    }
}

@keyframes slideInUp {
    from {
        transform: translateY(100%);
        opacity: 0;
    }
    to {
        transform: translateY(0);
        opacity: 1;
    }
}

@keyframes slideInDown {
    from {
        transform: translateY(-100%);
        opacity: 0;
    }
    to {
        transform: translateY(0);
        opacity: 1;
    }
}

@keyframes fadeInScale {
    from {
        transform: scale(0.8);
        opacity: 0;
    }
    to {
        transform: scale(1);
        opacity: 1;
    }
}
`;

// 注入动画样式
const styleSheet = document.createElement('style');
styleSheet.textContent = modernAnimations;
document.head.appendChild(styleSheet);

// 替换原有的App实例
document.addEventListener('DOMContentLoaded', () => {
    window.app = new ModernApp();
    
    // 导出现代化组件
    window.ModernModal = ModernModal;
    window.FormValidator = FormValidator;
    window.ModernDataTable = ModernDataTable;
    window.LoadingManager = LoadingManager;
});