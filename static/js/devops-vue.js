(function () {
    if (!window.Vue) {
        document.getElementById('devops-vue-root').innerHTML = '<div class="vue-error">Vue 加载失败，请检查本地 Vue 静态文件。</div>';
        return;
    }

    const { createApp } = window.Vue;

    function csrfToken() {
        const match = document.cookie.match(/(?:^|; )csrftoken=([^;]+)/);
        return match ? decodeURIComponent(match[1]) : '';
    }

    async function apiFetch(url, options) {
        const response = await fetch(url, Object.assign({
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken(),
            },
        }, options || {}));
        const payload = await response.json();
        if (!response.ok || payload.ok === false) {
            throw new Error(payload.message || `HTTP ${response.status}`);
        }
        return payload;
    }

    createApp({
        delimiters: ['[[', ']]'],
        data() {
            return {
                loading: true,
                refreshing: false,
                activeTab: 'dashboard',
                error: '',
                notice: '',
                bootstrap: {
                    user: { id: '', name: '-', role: '-' },
                    permissions: {},
                    counts: {},
                },
                dashboard: {
                    counts: {},
                    recent_commands: [],
                    host_metrics: [],
                },
                hosts: [],
                commands: [],
                tasks: [],
                approvals: [],
                deployments: [],
                files: [],
                notifications: { channels: [], logs: [] },
                metrics: null,
                refreshTimer: null,
                commandForm: { host_id: '', command: '' },
                taskForm: { name: '', host_ids: [], command: '' },
                metricFilters: { host: '', range: '24h' },
                tabs: [
                    { key: 'dashboard', label: '概览', icon: 'fas fa-gauge-high' },
                    { key: 'hosts', label: '主机', icon: 'fas fa-server' },
                    { key: 'commands', label: '命令', icon: 'fas fa-terminal', permission: 'command' },
                    { key: 'tasks', label: '任务', icon: 'fas fa-layer-group', permission: 'task' },
                    { key: 'metrics', label: '指标', icon: 'fas fa-chart-line', permission: 'metric' },
                    { key: 'approvals', label: '审批', icon: 'fas fa-shield-alt', permission: 'approval' },
                    { key: 'deployments', label: '发布', icon: 'fas fa-rocket', permission: 'deployment' },
                    { key: 'files', label: '文件', icon: 'fas fa-file-arrow-up', permission: 'file' },
                    { key: 'notifications', label: '通知', icon: 'fas fa-bullhorn', permission: 'notification' },
                ],
            };
        },
        computed: {
            counts() {
                return (this.dashboard && this.dashboard.counts) || (this.bootstrap && this.bootstrap.counts) || {};
            },
            recentCommands() {
                return (this.dashboard && this.dashboard.recent_commands) || [];
            },
            hostMetrics() {
                return (this.dashboard && this.dashboard.host_metrics) || [];
            },
            canRunCommand() {
                return this.bootstrap && this.bootstrap.permissions && this.bootstrap.permissions.command;
            },
            canRunTask() {
                return this.bootstrap && this.bootstrap.permissions && this.bootstrap.permissions.task;
            },
            visibleTabs() {
                const permissions = (this.bootstrap && this.bootstrap.permissions) || {};
                return this.tabs.filter((tab) => !tab.permission || permissions[tab.permission]);
            },
            hasRunningWork() {
                const activeStates = ['pending', 'running'];
                return [this.commands, this.tasks, this.deployments, this.files].some((items) => {
                    return (items || []).some((item) => activeStates.indexOf(item.status) !== -1);
                });
            },
            selectedMetricSummary() {
                if (!this.metrics || !this.metrics.series) return { cpu: null, memory: null, disk: null };
                const latest = {};
                ['cpu', 'memory', 'disk'].forEach((name) => {
                    const values = this.metrics.series[name] || [];
                    const present = values.filter((value) => value !== null && value !== undefined);
                    latest[name] = present.length ? present[present.length - 1] : null;
                });
                return latest;
            },
            metricPolyline() {
                if (!this.metrics || !this.metrics.labels || !this.metrics.labels.length) return '';
                const values = this.metrics.series.cpu || [];
                const points = [];
                const width = 720;
                const height = 220;
                const pad = 24;
                values.forEach((value, index) => {
                    if (value === null || value === undefined) return;
                    const x = values.length === 1 ? pad : pad + (index / (values.length - 1)) * (width - pad * 2);
                    const y = height - pad - (Math.max(0, Math.min(100, value)) / 100) * (height - pad * 2);
                    points.push(`${x.toFixed(1)},${y.toFixed(1)}`);
                });
                return points.join(' ');
            },
        },
        methods: {
            async loadAll() {
                this.loading = true;
                this.error = '';
                try {
                    const [bootstrap, dashboard, hosts, commands, tasks, approvals, deployments, files, notifications] = await Promise.all([
                        apiFetch('/devops/api/bootstrap/'),
                        apiFetch('/devops/api/dashboard/'),
                        apiFetch('/devops/api/hosts/'),
                        apiFetch('/devops/api/commands/?limit=20'),
                        apiFetch('/devops/api/tasks/?limit=20'),
                        apiFetch('/devops/api/approvals/?limit=50'),
                        apiFetch('/devops/api/deployments/?limit=20'),
                        apiFetch('/devops/api/files/?limit=20'),
                        apiFetch('/devops/api/notifications/'),
                    ]);
                    this.bootstrap = bootstrap;
                    this.dashboard = dashboard;
                    this.hosts = hosts.results || [];
                    this.commands = commands.results || [];
                    this.tasks = tasks.results || [];
                    this.approvals = approvals.results || [];
                    this.deployments = deployments.results || [];
                    this.files = files.results || [];
                    this.notifications = notifications || { channels: [], logs: [] };
                    if (!this.visibleTabs.some((tab) => tab.key === this.activeTab)) this.activeTab = 'dashboard';
                    if (!this.commandForm.host_id && this.hosts.length) this.commandForm.host_id = this.hosts[0].id;
                    if (!this.taskForm.host_ids.length && this.hosts.length) this.taskForm.host_ids = [this.hosts[0].id];
                    if (!this.metricFilters.host && this.hosts.length) this.metricFilters.host = this.hosts[0].id;
                    await this.loadMetrics();
                    this.scheduleStatusRefresh();
                } catch (error) {
                    this.error = error.message;
                } finally {
                    this.loading = false;
                }
            },
            async refresh() {
                this.refreshing = true;
                this.notice = '';
                await this.loadAll();
                this.refreshing = false;
            },
            async loadMetrics() {
                if (!this.metricFilters.host) return;
                const query = new URLSearchParams({
                    host: this.metricFilters.host,
                    range: this.metricFilters.range,
                });
                this.metrics = await apiFetch(`/devops/api/metrics/?${query.toString()}`);
            },
            scheduleStatusRefresh() {
                if (this.refreshTimer) {
                    clearTimeout(this.refreshTimer);
                    this.refreshTimer = null;
                }
                if (!this.hasRunningWork) return;
                this.refreshTimer = setTimeout(async () => {
                    this.refreshTimer = null;
                    await this.refresh();
                }, 5000);
            },
            async submitCommand() {
                this.error = '';
                this.notice = '';
                if (!this.commandForm.host_id || !this.commandForm.command.trim()) {
                    this.error = '请选择主机并输入命令';
                    return;
                }
                try {
                    const payload = await apiFetch('/devops/api/commands/', {
                        method: 'POST',
                        body: JSON.stringify({
                            host_id: Number(this.commandForm.host_id),
                            command: this.commandForm.command.trim(),
                        }),
                    });
                    this.notice = payload.requires_approval ? `命令已转入审批：${payload.approval.title}` : `命令已提交：#${payload.record.id}`;
                    this.commandForm.command = '';
                    await this.reloadCommands();
                } catch (error) {
                    this.error = error.message;
                }
            },
            async submitTask() {
                this.error = '';
                this.notice = '';
                if (!this.taskForm.name.trim() || !this.taskForm.command.trim() || !this.taskForm.host_ids.length) {
                    this.error = '请填写任务名称、目标主机和命令';
                    return;
                }
                try {
                    const payload = await apiFetch('/devops/api/tasks/', {
                        method: 'POST',
                        body: JSON.stringify({
                            name: this.taskForm.name.trim(),
                            host_ids: this.taskForm.host_ids.map(Number),
                            command: this.taskForm.command.trim(),
                        }),
                    });
                    this.notice = `批量任务已提交：#${payload.task.id}`;
                    this.taskForm.name = '';
                    this.taskForm.command = '';
                    await this.reloadTasks();
                } catch (error) {
                    this.error = error.message;
                }
            },
            async reloadCommands() {
                const payload = await apiFetch('/devops/api/commands/?limit=20');
                this.commands = payload.results || [];
            },
            async reloadTasks() {
                const payload = await apiFetch('/devops/api/tasks/?limit=20');
                this.tasks = payload.results || [];
            },
            setActiveTab(key, event) {
                this.activeTab = key;
                this.$nextTick(() => {
                    if (event && event.currentTarget && event.currentTarget.scrollIntoView) {
                        event.currentTarget.scrollIntoView({ behavior: 'smooth', inline: 'center', block: 'nearest' });
                    }
                });
            },
            statusClass(status) {
                return status || '';
            },
            statusIcon(status) {
                const iconMap = {
                    pending: 'fas fa-clock',
                    running: 'fas fa-spinner fa-spin',
                    success: 'fas fa-check-circle',
                    partial: 'fas fa-adjust',
                    failed: 'fas fa-times-circle',
                    blocked: 'fas fa-ban',
                    approved: 'fas fa-check',
                    rejected: 'fas fa-xmark',
                    executed: 'fas fa-bolt',
                    rolled_back: 'fas fa-rotate-left',
                };
                return iconMap[status] || 'fas fa-circle';
            },
            tabCount(key) {
                const countMap = {
                    hosts: this.hosts.length,
                    commands: this.commands.length,
                    tasks: this.tasks.length,
                    approvals: this.approvals.length,
                    deployments: this.deployments.length,
                    files: this.files.length,
                    notifications: (this.notifications.channels || []).length,
                };
                return countMap[key] || '';
            },
            metricForHost(hostId) {
                return this.hostMetrics.find((item) => item.host && item.host.id === hostId) || {};
            },
            metricWidth(value) {
                if (value === null || value === undefined) return '0%';
                return `${Math.max(0, Math.min(100, Number(value))).toFixed(1)}%`;
            },
            metricTone(value) {
                if (value === null || value === undefined) return 'muted';
                const number = Number(value);
                if (number >= 90) return 'danger';
                if (number >= 75) return 'warning';
                return 'success';
            },
            percent(value) {
                if (value === null || value === undefined) return '-';
                return `${Number(value).toFixed(1)}%`;
            },
            shortText(value, length) {
                value = value || '-';
                return value.length > length ? `${value.slice(0, length)}...` : value;
            },
        },
        mounted() {
            this.loadAll();
        },
        template: `
            <div v-if="loading" class="vue-loading">
                <div class="spinner-border text-primary" role="status"></div>
                <span>加载 DevOps 控制台...</span>
            </div>
            <div v-else class="devops-vue-shell">
                <div class="vue-topbar">
                    <div>
                        <h1 class="vue-title">DevOps 控制台</h1>
                        <p class="vue-subtitle">[[ hosts.length ]] 台主机 · [[ commands.length ]] 条命令 · [[ approvals.length ]] 条审批</p>
                        <div class="vue-user-line">
                            <span class="vue-avatar">[[ (bootstrap.user.name || '-').slice(0, 1).toUpperCase() ]]</span>
                            <span>[[ bootstrap.user.name ]]</span>
                            <span class="vue-role-pill">[[ bootstrap.user.role ]]</span>
                        </div>
                    </div>
                    <div class="vue-topbar-actions">
                        <a class="btn btn-outline-primary" href="/devops/legacy/"><i class="fas fa-table-columns me-1"></i>旧版入口</a>
                        <button class="btn btn-primary" type="button" :disabled="refreshing" @click="refresh">
                            <i class="fas fa-sync-alt me-1"></i>刷新
                        </button>
                    </div>
                </div>

                <div v-if="error" class="vue-error">[[ error ]]</div>
                <div v-if="notice" class="alert alert-info py-2 mb-0">[[ notice ]]</div>

                <div class="vue-tabs">
                    <button v-for="tab in visibleTabs" :key="tab.key" class="vue-tab" :class="{active: activeTab === tab.key}" @click="setActiveTab(tab.key, $event)">
                        <i :class="tab.icon"></i>
                        <span>[[ tab.label ]]</span>
                        <em v-if="tabCount(tab.key)">[[ tabCount(tab.key) ]]</em>
                    </button>
                </div>

                <section v-if="activeTab === 'dashboard'">
                    <div class="vue-stat-grid">
                        <div class="vue-stat-card"><div class="vue-stat-icon"><i class="fas fa-server"></i></div><div><div class="vue-stat-label">主机资产</div><div class="vue-stat-value">[[ counts.hosts || 0 ]]</div><div class="vue-stat-note">可访问范围内服务器</div></div></div>
                        <div class="vue-stat-card"><div class="vue-stat-icon info"><i class="fas fa-sitemap"></i></div><div><div class="vue-stat-label">主机分组</div><div class="vue-stat-value">[[ counts.groups || 0 ]]</div><div class="vue-stat-note">用于权限和批量操作</div></div></div>
                        <div class="vue-stat-card"><div class="vue-stat-icon danger"><i class="fas fa-bell"></i></div><div><div class="vue-stat-label">未处理告警</div><div class="vue-stat-value">[[ counts.open_alerts || 0 ]]</div><div class="vue-stat-note">需要关注的异常事件</div></div></div>
                        <div class="vue-stat-card"><div class="vue-stat-icon success"><i class="fas fa-layer-group"></i></div><div><div class="vue-stat-label">批量任务</div><div class="vue-stat-value">[[ counts.tasks || 0 ]]</div><div class="vue-stat-note">自动化执行记录</div></div></div>
                    </div>
                    <div class="vue-grid mt-3">
                        <div class="vue-panel">
                            <div class="vue-panel-header"><h2 class="vue-panel-title"><i class="fas fa-terminal"></i>最近命令</h2><span class="vue-panel-count">[[ recentCommands.length ]] 条</span></div>
                            <div class="vue-panel-body">
                                <div class="vue-command-list" v-if="recentCommands.length">
                                    <div class="vue-command-row" v-for="item in recentCommands" :key="item.id">
                                        <div class="vue-row-main"><div class="vue-row-title">[[ item.host ? item.host.name : '-' ]]</div><div class="vue-row-meta"><span>[[ item.created_at || '-' ]]</span><span>[[ item.created_by || '-' ]]</span></div><code>[[ shortText(item.command, 70) ]]</code></div>
                                        <span class="vue-status" :class="statusClass(item.status)"><i :class="statusIcon(item.status)"></i>[[ item.status_label ]]</span>
                                    </div>
                                </div>
                                <div class="vue-empty" v-else>暂无命令记录</div>
                            </div>
                        </div>
                        <div class="vue-panel">
                            <div class="vue-panel-header"><h2 class="vue-panel-title"><i class="fas fa-chart-simple"></i>主机指标</h2><span class="vue-panel-count">[[ hostMetrics.length ]] 台</span></div>
                            <div class="vue-panel-body">
                                <div class="vue-host-list" v-if="hostMetrics.length">
                                    <div class="vue-host-row" v-for="item in hostMetrics" :key="item.host.id">
                                        <div class="vue-row-main">
                                            <div class="vue-row-title">[[ item.host.name ]]</div>
                                            <div class="vue-metric-mini">
                                                <span>CPU [[ percent(item.cpu) ]]</span><span>内存 [[ percent(item.memory) ]]</span><span>磁盘 [[ percent(item.disk) ]]</span>
                                            </div>
                                            <div class="vue-progress-line"><span :class="metricTone(item.cpu)" :style="{width: metricWidth(item.cpu)}"></span></div>
                                        </div>
                                    </div>
                                </div>
                                <div class="vue-empty" v-else>暂无指标数据</div>
                            </div>
                        </div>
                    </div>
                </section>

                <section v-if="activeTab === 'hosts'" class="vue-panel">
                    <div class="vue-panel-header"><h2 class="vue-panel-title"><i class="fas fa-server"></i>主机列表</h2><span class="vue-panel-count">[[ hosts.length ]] 台</span></div>
                    <div class="vue-panel-body">
                        <div class="vue-host-card-grid" v-if="hosts.length">
                            <div class="vue-host-card" v-for="host in hosts" :key="host.id">
                                <div class="vue-host-card-head">
                                    <div class="vue-host-avatar"><i class="fas fa-server"></i></div>
                                    <div><div class="vue-row-title">[[ host.name ]]</div><div class="vue-row-meta">[[ host.hostname || '未采集主机名' ]]</div></div>
                                </div>
                                <div class="vue-host-kv"><span>IP</span><strong>[[ host.ip ]]</strong></div>
                                <div class="vue-host-kv"><span>端口</span><strong>[[ host.port || '-' ]]</strong></div>
                                <div class="vue-host-kv"><span>用户</span><strong>[[ host.user || '-' ]]</strong></div>
                                <div class="vue-host-kv"><span>应用</span><strong>[[ host.app || '-' ]]</strong></div>
                                <div class="vue-host-meter">
                                    <div><span>CPU</span><strong>[[ percent(metricForHost(host.id).cpu) ]]</strong></div>
                                    <div class="vue-progress-line"><span :class="metricTone(metricForHost(host.id).cpu)" :style="{width: metricWidth(metricForHost(host.id).cpu)}"></span></div>
                                </div>
                                <a class="btn btn-sm btn-outline-primary vue-card-action" :href="'/list_detail/' + host.id + '/'"><i class="fas fa-arrow-up-right-from-square me-1"></i>详情</a>
                            </div>
                        </div>
                        <div class="vue-empty" v-else>暂无可访问主机</div>
                    </div>
                </section>

                <section v-if="activeTab === 'commands'" class="vue-grid">
                    <div class="vue-panel">
                        <div class="vue-panel-header"><h2 class="vue-panel-title"><i class="fas fa-terminal"></i>提交命令</h2></div>
                        <div class="vue-panel-body">
                            <form class="vue-form-grid" @submit.prevent="submitCommand">
                                <div><label class="form-label">目标主机</label><select class="form-control" v-model="commandForm.host_id" :disabled="!canRunCommand"><option v-for="host in hosts" :key="host.id" :value="host.id">[[ host.name ]] · [[ host.ip ]]</option></select></div>
                                <div><label class="form-label">命令</label><textarea class="form-control" rows="4" v-model="commandForm.command" :disabled="!canRunCommand" placeholder="例如：uptime"></textarea></div>
                                <button class="btn btn-primary" type="submit" :disabled="!canRunCommand"><i class="fas fa-play me-1"></i>提交执行</button>
                                <div v-if="!canRunCommand" class="text-muted small">当前用户没有命令执行权限。</div>
                            </form>
                        </div>
                    </div>
                    <div class="vue-panel">
                        <div class="vue-panel-header"><h2 class="vue-panel-title"><i class="fas fa-list-check"></i>命令记录</h2><span class="vue-panel-count">[[ commands.length ]] 条</span></div>
                        <div class="vue-panel-body">
                            <div class="vue-command-list" v-if="commands.length">
                                <div class="vue-command-row" v-for="item in commands" :key="item.id">
                                    <div class="vue-row-main"><div class="vue-row-title"># [[ item.id ]] · [[ item.host ? item.host.name : '-' ]]</div><div class="vue-row-meta"><span>[[ item.created_at || '-' ]]</span><span>耗时 [[ item.duration_ms || 0 ]] ms</span></div><code>[[ shortText(item.command, 80) ]]</code></div>
                                    <span class="vue-status" :class="statusClass(item.status)"><i :class="statusIcon(item.status)"></i>[[ item.status_label ]]</span>
                                </div>
                            </div>
                            <div class="vue-empty" v-else>暂无命令记录</div>
                        </div>
                    </div>
                </section>

                <section v-if="activeTab === 'tasks'" class="vue-grid">
                    <div class="vue-panel">
                        <div class="vue-panel-header"><h2 class="vue-panel-title"><i class="fas fa-layer-group"></i>提交批量任务</h2></div>
                        <div class="vue-panel-body">
                            <form class="vue-form-grid" @submit.prevent="submitTask">
                                <div><label class="form-label">任务名称</label><input class="form-control" v-model="taskForm.name" :disabled="!canRunTask" placeholder="例如：检查 uptime"></div>
                                <div><label class="form-label">目标主机</label><select class="form-control" multiple v-model="taskForm.host_ids" :disabled="!canRunTask"><option v-for="host in hosts" :key="host.id" :value="host.id">[[ host.name ]] · [[ host.ip ]]</option></select></div>
                                <div><label class="form-label">命令</label><textarea class="form-control" rows="4" v-model="taskForm.command" :disabled="!canRunTask" placeholder="例如：uptime"></textarea></div>
                                <button class="btn btn-primary" type="submit" :disabled="!canRunTask"><i class="fas fa-paper-plane me-1"></i>提交任务</button>
                            </form>
                        </div>
                    </div>
                    <div class="vue-panel">
                        <div class="vue-panel-header"><h2 class="vue-panel-title"><i class="fas fa-bars-progress"></i>任务记录</h2><span class="vue-panel-count">[[ tasks.length ]] 条</span></div>
                        <div class="vue-panel-body">
                            <div class="vue-command-list" v-if="tasks.length">
                                <div class="vue-command-row" v-for="task in tasks" :key="task.id">
                                    <div class="vue-row-main"><div class="vue-row-title"># [[ task.id ]] · [[ task.name ]]</div><div class="vue-row-meta"><span>[[ task.host_count ]] 台主机</span><span>[[ task.created_at || '-' ]]</span></div><code>[[ shortText(task.command, 70) ]]</code><div class="vue-row-note">[[ task.summary || '等待执行结果回写' ]]</div></div>
                                    <span class="vue-status" :class="statusClass(task.status)"><i :class="statusIcon(task.status)"></i>[[ task.status_label ]]</span>
                                </div>
                            </div>
                            <div class="vue-empty" v-else>暂无批量任务</div>
                        </div>
                    </div>
                </section>

                <section v-if="activeTab === 'metrics'" class="vue-panel">
                    <div class="vue-panel-header">
                        <h2 class="vue-panel-title"><i class="fas fa-chart-line"></i>监控指标</h2>
                        <div class="vue-filter-row">
                            <select class="form-control form-control-sm" v-model="metricFilters.host" @change="loadMetrics">
                                <option v-for="host in hosts" :key="host.id" :value="host.id">[[ host.name ]]</option>
                            </select>
                            <select class="form-control form-control-sm" v-model="metricFilters.range" @change="loadMetrics">
                                <option value="6h">最近 6 小时</option><option value="24h">最近 24 小时</option><option value="7d">最近 7 天</option><option value="30d">最近 30 天</option>
                            </select>
                        </div>
                    </div>
                    <div class="vue-panel-body">
                        <div class="vue-metric-summary">
                            <div><span>CPU</span><strong>[[ percent(selectedMetricSummary.cpu) ]]</strong><div class="vue-progress-line"><span :class="metricTone(selectedMetricSummary.cpu)" :style="{width: metricWidth(selectedMetricSummary.cpu)}"></span></div></div>
                            <div><span>内存</span><strong>[[ percent(selectedMetricSummary.memory) ]]</strong><div class="vue-progress-line"><span :class="metricTone(selectedMetricSummary.memory)" :style="{width: metricWidth(selectedMetricSummary.memory)}"></span></div></div>
                            <div><span>磁盘</span><strong>[[ percent(selectedMetricSummary.disk) ]]</strong><div class="vue-progress-line"><span :class="metricTone(selectedMetricSummary.disk)" :style="{width: metricWidth(selectedMetricSummary.disk)}"></span></div></div>
                        </div>
                        <div class="vue-chart-wrap">
                            <svg class="vue-metric-chart" viewBox="0 0 720 220" role="img" aria-label="CPU趋势图">
                                <line x1="24" y1="196" x2="696" y2="196" stroke="#e2e8f0"></line>
                                <line x1="24" y1="110" x2="696" y2="110" stroke="#e2e8f0"></line>
                                <line x1="24" y1="24" x2="696" y2="24" stroke="#e2e8f0"></line>
                                <polyline v-if="metricPolyline" :points="metricPolyline" fill="none" stroke="#2563eb" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"></polyline>
                                <text v-if="!metricPolyline" x="360" y="112" text-anchor="middle" fill="#64748b">当前范围暂无 CPU 趋势数据</text>
                            </svg>
                        </div>
                        <div class="vue-row-meta mt-2">当前主机：[[ metrics && metrics.host ? metrics.host.name : '-' ]] · 样本数：[[ metrics ? metrics.labels.length : 0 ]]</div>
                    </div>
                </section>

                <section v-if="activeTab === 'approvals'" class="vue-panel">
                    <div class="vue-panel-header"><h2 class="vue-panel-title"><i class="fas fa-shield-alt"></i>审批列表</h2><span class="vue-panel-count">[[ approvals.length ]] 条</span></div>
                    <div class="vue-panel-body">
                        <div class="vue-command-list" v-if="approvals.length">
                            <div class="vue-command-row" v-for="item in approvals" :key="item.id">
                                <div class="vue-row-main"><div class="vue-row-title"># [[ item.id ]] · [[ item.title ]]</div><div class="vue-row-meta"><span>[[ item.request_type_label ]]</span><span>申请人 [[ item.requester || '-' ]]</span><span>[[ item.created_at || '-' ]]</span></div><div class="vue-row-note">[[ item.reason || '-' ]]</div></div>
                                <span class="vue-status" :class="statusClass(item.status)"><i :class="statusIcon(item.status)"></i>[[ item.status_label ]]</span>
                            </div>
                        </div>
                        <div class="vue-empty" v-else>暂无审批</div>
                    </div>
                </section>

                <section v-if="activeTab === 'deployments'" class="vue-panel">
                    <div class="vue-panel-header"><h2 class="vue-panel-title"><i class="fas fa-rocket"></i>发布记录</h2><span class="vue-panel-count">[[ deployments.length ]] 条</span></div>
                    <div class="vue-panel-body">
                        <div class="vue-command-list" v-if="deployments.length">
                            <div class="vue-command-row" v-for="item in deployments" :key="item.id">
                                <div class="vue-row-main"><div class="vue-row-title"># [[ item.id ]] · [[ item.app.name ]] [[ item.version ]]</div><div class="vue-row-meta"><span>[[ item.host_count ]] 台主机</span><span>[[ item.created_by || '-' ]]</span><span>[[ item.created_at || '-' ]]</span></div><div class="vue-row-note">[[ item.summary || item.description || '-' ]]</div></div>
                                <span class="vue-status" :class="statusClass(item.status)"><i :class="statusIcon(item.status)"></i>[[ item.status_label ]]</span>
                            </div>
                        </div>
                        <div class="vue-empty" v-else>暂无发布记录</div>
                    </div>
                </section>

                <section v-if="activeTab === 'files'" class="vue-panel">
                    <div class="vue-panel-header"><h2 class="vue-panel-title"><i class="fas fa-file-arrow-up"></i>文件分发</h2><span class="vue-panel-count">[[ files.length ]] 条</span></div>
                    <div class="vue-panel-body">
                        <div class="vue-command-list" v-if="files.length">
                            <div class="vue-command-row" v-for="item in files" :key="item.id">
                                <div class="vue-row-main"><div class="vue-row-title"># [[ item.id ]] · [[ item.name ]]</div><div class="vue-row-meta"><span>[[ item.host_count ]] 台主机</span><span>[[ item.created_by || '-' ]]</span><span>[[ item.created_at || '-' ]]</span></div><code>[[ item.remote_path || '-' ]]</code><div class="vue-row-note">[[ item.summary || '等待执行结果回写' ]]</div></div>
                                <span class="vue-status" :class="statusClass(item.status)"><i :class="statusIcon(item.status)"></i>[[ item.status_label ]]</span>
                            </div>
                        </div>
                        <div class="vue-empty" v-else>暂无文件分发记录</div>
                    </div>
                </section>

                <section v-if="activeTab === 'notifications'" class="vue-grid">
                    <div class="vue-panel">
                        <div class="vue-panel-header"><h2 class="vue-panel-title"><i class="fas fa-bullhorn"></i>通知渠道</h2><span class="vue-panel-count">[[ notifications.channels.length ]] 个</span></div>
                        <div class="vue-panel-body">
                            <div class="vue-command-list" v-if="notifications.channels.length">
                                <div class="vue-command-row" v-for="channel in notifications.channels" :key="channel.id">
                                    <div class="vue-row-main"><div class="vue-row-title">[[ channel.name ]]</div><div class="vue-row-meta"><span>[[ channel.channel_type_label ]]</span><span>告警 [[ channel.notify_alert ? '开启' : '关闭' ]]</span><span>审批 [[ channel.notify_approval ? '开启' : '关闭' ]]</span><span>发布 [[ channel.notify_deployment ? '开启' : '关闭' ]]</span></div></div>
                                    <span class="vue-status" :class="channel.enabled ? 'success' : 'blocked'"><i :class="channel.enabled ? 'fas fa-check-circle' : 'fas fa-ban'"></i>[[ channel.enabled ? '启用' : '停用' ]]</span>
                                </div>
                            </div>
                            <div class="vue-empty" v-else>暂无通知渠道</div>
                        </div>
                    </div>
                    <div class="vue-panel">
                        <div class="vue-panel-header"><h2 class="vue-panel-title"><i class="fas fa-clock-rotate-left"></i>通知日志</h2><span class="vue-panel-count">[[ notifications.logs.length ]] 条</span></div>
                        <div class="vue-panel-body">
                            <div class="vue-command-list" v-if="notifications.logs.length">
                                <div class="vue-command-row" v-for="log in notifications.logs" :key="log.id">
                                    <div class="vue-row-main"><div class="vue-row-title">[[ log.title ]]</div><div class="vue-row-meta"><span>[[ log.channel || '-' ]]</span><span>[[ log.event_type_label ]]</span><span>[[ log.created_at || '-' ]]</span></div><div class="vue-row-note">[[ shortText(log.response || '-', 90) ]]</div></div>
                                    <span class="vue-status" :class="statusClass(log.status)"><i :class="statusIcon(log.status)"></i>[[ log.status_label ]]</span>
                                </div>
                            </div>
                            <div class="vue-empty" v-else>暂无通知日志</div>
                        </div>
                    </div>
                </section>
            </div>
        `,
    }).mount('#devops-vue-root');
})();
