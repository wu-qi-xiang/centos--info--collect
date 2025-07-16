// 自定义JavaScript文件 - Linux服务器监控系统

// DOM加载完成后执行
document.addEventListener('DOMContentLoaded', function() {
    
    // 初始化所有功能
    initializeApp();
    
    function initializeApp() {
        // 添加页面加载动画
        addPageAnimations();
        
        // 初始化搜索功能
        initializeSearch();
        
        // 初始化表格功能
        initializeTable();
        
        // 初始化按钮交互
        initializeButtons();
        
        // 初始化工具提示
        initializeTooltips();
        
        // 初始化表单验证
        initializeFormValidation();
    }
    
    // 页面动画
    function addPageAnimations() {
        // 为所有卡片添加淡入动画
        const cards = document.querySelectorAll('.card, .table, .jumbotron');
        cards.forEach((card, index) => {
            card.style.opacity = '0';
            card.style.transform = 'translateY(20px)';
            
            setTimeout(() => {
                card.style.transition = 'all 0.6s ease';
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            }, index * 100);
        });
    }
    
    // 搜索功能增强
    function initializeSearch() {
        const searchInput = document.querySelector('input[name="search"]');
        if (searchInput) {
            // 添加实时搜索提示
            searchInput.addEventListener('input', function() {
                const value = this.value.trim();
                if (value.length > 0) {
                    this.classList.add('search-active');
                } else {
                    this.classList.remove('search-active');
                }
            });
            
            // 添加搜索快捷键 (Ctrl+F)
            document.addEventListener('keydown', function(e) {
                if (e.ctrlKey && e.key === 'f') {
                    e.preventDefault();
                    searchInput.focus();
                }
            });
        }
    }
    
    // 表格功能增强
    function initializeTable() {
        const tables = document.querySelectorAll('.table');
        tables.forEach(table => {
            // 添加表格行点击效果
            const rows = table.querySelectorAll('tbody tr');
            rows.forEach(row => {
                row.addEventListener('mouseenter', function() {
                    this.style.transform = 'scale(1.02)';
                    this.style.boxShadow = '0 4px 8px rgba(0,0,0,0.1)';
                });
                
                row.addEventListener('mouseleave', function() {
                    this.style.transform = 'scale(1)';
                    this.style.boxShadow = 'none';
                });
            });
        });
    }
    
    // 按钮交互增强
    function initializeButtons() {
        const buttons = document.querySelectorAll('.btn');
        buttons.forEach(button => {
            // 添加点击波纹效果
            button.addEventListener('click', function(e) {
                const ripple = document.createElement('span');
                const rect = this.getBoundingClientRect();
                const size = Math.max(rect.width, rect.height);
                const x = e.clientX - rect.left - size / 2;
                const y = e.clientY - rect.top - size / 2;
                
                ripple.style.width = ripple.style.height = size + 'px';
                ripple.style.left = x + 'px';
                ripple.style.top = y + 'px';
                ripple.classList.add('ripple');
                
                this.appendChild(ripple);
                
                setTimeout(() => {
                    ripple.remove();
                }, 600);
            });
            
            // 添加加载状态
            if (button.type === 'submit') {
                button.addEventListener('click', function() {
                    const originalText = this.innerHTML;
                    this.innerHTML = '<span class="loading"></span> 处理中...';
                    this.disabled = true;
                    
                    // 模拟加载时间（实际项目中应该在表单提交完成后恢复）
                    setTimeout(() => {
                        this.innerHTML = originalText;
                        this.disabled = false;
                    }, 2000);
                });
            }
        });
    }
    
    // 工具提示功能
    function initializeTooltips() {
        const tooltipElements = document.querySelectorAll('[data-tooltip]');
        tooltipElements.forEach(element => {
            element.addEventListener('mouseenter', function() {
                const tooltip = document.createElement('div');
                tooltip.className = 'tooltip-popup';
                tooltip.textContent = this.getAttribute('data-tooltip');
                document.body.appendChild(tooltip);
                
                const rect = this.getBoundingClientRect();
                tooltip.style.left = rect.left + rect.width / 2 - tooltip.offsetWidth / 2 + 'px';
                tooltip.style.top = rect.top - tooltip.offsetHeight - 10 + 'px';
            });
            
            element.addEventListener('mouseleave', function() {
                const tooltip = document.querySelector('.tooltip-popup');
                if (tooltip) {
                    tooltip.remove();
                }
            });
        });
    }
    
    // 表单验证
    function initializeFormValidation() {
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            form.addEventListener('submit', function(e) {
                const requiredFields = this.querySelectorAll('[required]');
                let isValid = true;
                
                requiredFields.forEach(field => {
                    if (!field.value.trim()) {
                        isValid = false;
                        field.classList.add('is-invalid');
                        showFieldError(field, '此字段为必填项');
                    } else {
                        field.classList.remove('is-invalid');
                        hideFieldError(field);
                    }
                });
                
                if (!isValid) {
                    e.preventDefault();
                    showNotification('请填写所有必填字段', 'error');
                }
            });
        });
    }
    
    // 显示字段错误
    function showFieldError(field, message) {
        let errorElement = field.parentNode.querySelector('.field-error');
        if (!errorElement) {
            errorElement = document.createElement('div');
            errorElement.className = 'field-error';
            field.parentNode.appendChild(errorElement);
        }
        errorElement.textContent = message;
    }
    
    // 隐藏字段错误
    function hideFieldError(field) {
        const errorElement = field.parentNode.querySelector('.field-error');
        if (errorElement) {
            errorElement.remove();
        }
    }
    
    // 通知系统
    function showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <span>${message}</span>
            <button class="notification-close">&times;</button>
        `;
        
        document.body.appendChild(notification);
        
        // 自动关闭
        setTimeout(() => {
            notification.classList.add('notification-hide');
            setTimeout(() => notification.remove(), 300);
        }, 5000);
        
        // 手动关闭
        notification.querySelector('.notification-close').addEventListener('click', () => {
            notification.classList.add('notification-hide');
            setTimeout(() => notification.remove(), 300);
        });
    }
    
    // 服务器状态检查
    function checkServerStatus() {
        const statusElements = document.querySelectorAll('.server-status');
        statusElements.forEach(element => {
            // 这里可以添加实际的服务器状态检查逻辑
            // 现在只是模拟
            const isOnline = Math.random() > 0.2; // 80%概率在线
            element.className = `status-indicator ${isOnline ? 'status-online' : 'status-offline'}`;
            element.setAttribute('data-tooltip', isOnline ? '服务器在线' : '服务器离线');
        });
    }
    
    // 定期检查服务器状态
    setInterval(checkServerStatus, 30000); // 每30秒检查一次
    
    // 页面可见性API - 当页面重新获得焦点时刷新状态
    document.addEventListener('visibilitychange', function() {
        if (!document.hidden) {
            checkServerStatus();
        }
    });
    
    // 键盘快捷键
    document.addEventListener('keydown', function(e) {
        // Ctrl + N: 新增服务器
        if (e.ctrlKey && e.key === 'n') {
            e.preventDefault();
            const createButton = document.querySelector('a[href*="create"]');
            if (createButton) {
                createButton.click();
            }
        }
        
        // ESC: 关闭模态框或返回
        if (e.key === 'Escape') {
            const modals = document.querySelectorAll('.modal.show');
            if (modals.length > 0) {
                modals.forEach(modal => {
                    const closeButton = modal.querySelector('.btn-close, .close');
                    if (closeButton) closeButton.click();
                });
            }
        }
    });
    
    // 平滑滚动
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
    
    // 懒加载图片
    const images = document.querySelectorAll('img[data-src]');
    const imageObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const img = entry.target;
                img.src = img.dataset.src;
                img.classList.remove('lazy');
                imageObserver.unobserve(img);
            }
        });
    });
    
    images.forEach(img => imageObserver.observe(img));
    
    // 初始化服务器状态检查
    checkServerStatus();
});

// CSS样式注入（用于JavaScript创建的元素）
const style = document.createElement('style');
style.textContent = `
    .ripple {
        position: absolute;
        border-radius: 50%;
        background: rgba(255, 255, 255, 0.6);
        transform: scale(0);
        animation: ripple-animation 0.6s linear;
        pointer-events: none;
    }
    
    @keyframes ripple-animation {
        to {
            transform: scale(4);
            opacity: 0;
        }
    }
    
    .search-active {
        border-color: var(--primary-color) !important;
        box-shadow: 0 0 0 0.2rem rgba(0, 123, 255, 0.25) !important;
    }
    
    .notification {
        position: fixed;
        top: 20px;
        right: 20px;
        background: white;
        border-radius: 8px;
        padding: 1rem 1.5rem;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        z-index: 9999;
        display: flex;
        align-items: center;
        gap: 1rem;
        transform: translateX(100%);
        animation: slideInRight 0.3s ease forwards;
    }
    
    .notification-error {
        border-left: 4px solid var(--danger-color);
    }
    
    .notification-success {
        border-left: 4px solid var(--success-color);
    }
    
    .notification-info {
        border-left: 4px solid var(--info-color);
    }
    
    .notification-close {
        background: none;
        border: none;
        font-size: 1.5rem;
        cursor: pointer;
        color: #999;
    }
    
    .notification-hide {
        animation: slideOutRight 0.3s ease forwards;
    }
    
    @keyframes slideInRight {
        to { transform: translateX(0); }
    }
    
    @keyframes slideOutRight {
        to { transform: translateX(100%); }
    }
    
    .tooltip-popup {
        position: absolute;
        background: #333;
        color: white;
        padding: 0.5rem;
        border-radius: 4px;
        font-size: 0.875rem;
        white-space: nowrap;
        z-index: 1000;
        pointer-events: none;
    }
    
    .field-error {
        color: var(--danger-color);
        font-size: 0.875rem;
        margin-top: 0.25rem;
    }
    
    .is-invalid {
        border-color: var(--danger-color) !important;
    }
`;
document.head.appendChild(style);
// 返
回顶部功能
document.addEventListener('DOMContentLoaded', function() {
    const backToTopButton = document.getElementById('back-to-top');
    
    if (backToTopButton) {
        // 监听滚动事件
        window.addEventListener('scroll', function() {
            if (window.pageYOffset > 300) {
                backToTopButton.classList.add('show');
            } else {
                backToTopButton.classList.remove('show');
            }
        });
        
        // 点击返回顶部
        backToTopButton.addEventListener('click', function() {
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        });
    }
});

// 页面可见性API - 优化性能
document.addEventListener('visibilitychange', function() {
    if (document.hidden) {
        // 页面隐藏时暂停一些操作
        console.log('页面已隐藏，暂停后台操作');
    } else {
        // 页面重新可见时恢复操作
        console.log('页面重新可见，恢复操作');
        // 可以在这里刷新数据或重新启动定时器
    }
});

// 网络状态监测
window.addEventListener('online', function() {
    showNotification('网络连接已恢复', 'success');
});

window.addEventListener('offline', function() {
    showNotification('网络连接已断开', 'warning');
});

// 全局错误处理
window.addEventListener('error', function(e) {
    console.error('JavaScript错误:', e.error);
    // 可以在这里发送错误报告到服务器
});

// 性能监控
window.addEventListener('load', function() {
    // 页面加载完成后的性能统计
    if ('performance' in window) {
        const perfData = performance.timing;
        const loadTime = perfData.loadEventEnd - perfData.navigationStart;
        console.log(`页面加载时间: ${loadTime}ms`);
        
        // 可以将性能数据发送到服务器进行分析
    }
});

// 表格增强功能
function enhanceTable(tableSelector) {
    const table = document.querySelector(tableSelector);
    if (!table) return;
    
    // 添加表格排序功能
    const headers = table.querySelectorAll('th[data-sortable]');
    headers.forEach(header => {
        header.style.cursor = 'pointer';
        header.addEventListener('click', function() {
            sortTable(table, this);
        });
    });
}

// 表格排序功能
function sortTable(table, header) {
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

// 数据导出功能
function exportTableToCSV(tableSelector, filename = 'data.csv') {
    const table = document.querySelector(tableSelector);
    if (!table) return;
    
    const rows = table.querySelectorAll('tr');
    const csvContent = Array.from(rows).map(row => {
        const cells = row.querySelectorAll('th, td');
        return Array.from(cells).map(cell => {
            const text = cell.textContent.trim();
            return `"${text.replace(/"/g, '""')}"`;
        }).join(',');
    }).join('\n');
    
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    
    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    link.style.visibility = 'hidden';
    
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// 批量操作功能
function initBatchOperations() {
    const checkboxes = document.querySelectorAll('input[type="checkbox"][data-batch]');
    const batchActions = document.querySelector('.batch-actions');
    
    if (checkboxes.length === 0) return;
    
    checkboxes.forEach(checkbox => {
        checkbox.addEventListener('change', updateBatchActions);
    });
    
    function updateBatchActions() {
        const checkedBoxes = document.querySelectorAll('input[type="checkbox"][data-batch]:checked');
        if (batchActions) {
            batchActions.style.display = checkedBoxes.length > 0 ? 'block' : 'none';
        }
    }
}

// 自动保存功能
function initAutoSave(formSelector, interval = 30000) {
    const form = document.querySelector(formSelector);
    if (!form) return;
    
    let autoSaveTimer;
    const inputs = form.querySelectorAll('input, textarea, select');
    
    inputs.forEach(input => {
        input.addEventListener('input', function() {
            clearTimeout(autoSaveTimer);
            autoSaveTimer = setTimeout(() => {
                saveFormData(form);
            }, interval);
        });
    });
    
    function saveFormData(form) {
        const formData = new FormData(form);
        const data = Object.fromEntries(formData.entries());
        
        // 保存到localStorage
        localStorage.setItem(`autosave_${form.id}`, JSON.stringify(data));
        
        // 显示自动保存提示
        showNotification('表单已自动保存', 'info');
    }
    
    // 页面加载时恢复数据
    function restoreFormData(form) {
        const savedData = localStorage.getItem(`autosave_${form.id}`);
        if (savedData) {
            const data = JSON.parse(savedData);
            Object.keys(data).forEach(key => {
                const input = form.querySelector(`[name="${key}"]`);
                if (input) {
                    input.value = data[key];
                }
            });
        }
    }
    
    restoreFormData(form);
}

// 初始化所有增强功能
document.addEventListener('DOMContentLoaded', function() {
    // 增强表格
    enhanceTable('.table-custom table');
    
    // 初始化批量操作
    initBatchOperations();
    
    // 为表单启用自动保存
    const forms = document.querySelectorAll('form[data-autosave]');
    forms.forEach(form => {
        initAutoSave(`#${form.id}`);
    });
});

// 工具函数：格式化文件大小
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 工具函数：格式化时间
function formatTime(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    if (hours > 0) {
        return `${hours}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }
    return `${minutes}:${secs.toString().padStart(2, '0')}`;
}

// 工具函数：防抖
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// 工具函数：节流
function throttle(func, limit) {
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
}