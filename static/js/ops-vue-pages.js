(function () {
    const root = document.getElementById('ops-vue-root');
    const payloadNode = document.getElementById('ops-vue-payload');
    if (!root || !payloadNode) return;
    if (!window.Vue) {
        root.innerHTML = '<div class="vue-error">Vue 加载失败，请检查本地静态文件。</div>';
        return;
    }

    const payload = JSON.parse(payloadNode.textContent || '{}');
    const { createApp } = window.Vue;

    function csrfToken() {
        const match = document.cookie.match(/(?:^|; )csrftoken=([^;]+)/);
        return match ? decodeURIComponent(match[1]) : '';
    }

    function emptyMetricTable() {
        return {
            result_type: '',
            label_columns: [],
            rows: [],
            total_rows: 0,
            truncated: false,
        };
    }

    function normalizeMetricTable(table) {
        if (!table || typeof table !== 'object') return emptyMetricTable();
        return {
            result_type: table.result_type || '',
            label_columns: Array.isArray(table.label_columns) ? table.label_columns : [],
            rows: Array.isArray(table.rows) ? table.rows : [],
            total_rows: Number.isFinite(Number(table.total_rows)) ? Number(table.total_rows) : 0,
            truncated: Boolean(table.truncated),
        };
    }

    function metricQueryPanel(id, query, table, error) {
        return {
            id,
            query: query || '',
            table: normalizeMetricTable(table),
            error: error || '',
            loading: false,
            hasExecuted: Boolean(query || error),
        };
    }

    createApp({
        delimiters: ['[[', ']]'],
        data() {
            const pageData = payload.data || {};
            return {
                kind: payload.kind,
                title: payload.title,
                data: pageData,
                reveal: {},
                revealError: '',
                queryPanels: [metricQueryPanel(1, pageData.query, pageData.table, pageData.error)],
                nextQueryPanelId: 2,
            };
        },
        computed: {
            pageTitle() {
                if (this.kind === 'monitor') return '告警设置';
                return this.title;
            },
            errors() {
                return this.data.errors || [];
            },
            monitorIntegrations() {
                return Array.isArray(this.data.integrations) ? this.data.integrations : [];
            },
            prometheusForm() {
                return this.data.prometheus_form || { values: {} };
            },
            prometheusValues() {
                return this.prometheusForm.values || {};
            },
            alertmanagerForm() {
                return this.data.alertmanager_form || { values: {} };
            },
            alertmanagerValues() {
                return this.alertmanagerForm.values || {};
            },
            alertProviders() {
                const notifications = this.data.notifications || {};
                return [
                    { key: 'feishu', label: '飞书', icon: 'paper-plane', config: notifications.feishu || {} },
                    { key: 'wecom', label: '企业微信', icon: 'comments', config: notifications.wecom || {} },
                ];
            },
        },
        methods: {
            submitForm(event) {
                return true;
            },
            confirmDelete(event, integration) {
                const name = integration && (integration.name || integration.kind_label);
                if (window.confirm('确定删除“' + (name || '该监控对接') + '”吗？')) return true;
                if (event) event.preventDefault();
                return false;
            },
            async revealPassword(item) {
                this.revealError = '';
                try {
                    const response = await fetch(item.reveal_url, {
                        method: 'POST',
                        credentials: 'same-origin',
                        headers: { 'X-CSRFToken': csrfToken() },
                    });
                    const body = await response.json();
                    if (!response.ok) throw new Error(body.message || '查看失败');
                    this.reveal[item.id] = body.password;
                } catch (error) {
                    this.revealError = error.message;
                }
            },
            metric(value) {
                if (value === null || value === undefined || value === '') return '-';
                return value;
            },
            addMetricQueryPanel() {
                const panel = metricQueryPanel(this.nextQueryPanelId, '', null, '');
                this.nextQueryPanelId += 1;
                this.queryPanels.push(panel);
                this.$nextTick(() => {
                    const input = document.getElementById('metric-query-' + panel.id);
                    if (input) input.focus();
                });
            },
            removeMetricQueryPanel(panelId) {
                if (this.queryPanels.length <= 1) return;
                this.queryPanels = this.queryPanels.filter((panel) => panel.id !== panelId);
            },
            async executeMetricQuery(panel) {
                panel.loading = true;
                panel.error = '';
                panel.hasExecuted = true;
                const form = new URLSearchParams();
                form.set('query', panel.query || '');
                try {
                    const response = await fetch(this.data.execute_url, {
                        method: 'POST',
                        credentials: 'same-origin',
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
                            'X-CSRFToken': this.data.csrf || csrfToken(),
                        },
                        body: form.toString(),
                    });
                    let body = {};
                    try {
                        body = await response.json();
                    } catch (error) {
                        throw new Error('指标查询响应格式异常');
                    }
                    if (!response.ok || !body.ok) throw new Error(body.message || '指标查询失败');
                    panel.query = body.query || panel.query;
                    panel.table = normalizeMetricTable(body.table);
                } catch (error) {
                    panel.table = emptyMetricTable();
                    panel.error = error.message || '指标查询失败';
                } finally {
                    panel.loading = false;
                }
            },
            formatMetricTimestamp(value) {
                const timestamp = Number(value);
                if (!Number.isFinite(timestamp)) return this.metric(value);
                const date = new Date(timestamp * 1000);
                if (Number.isNaN(date.getTime())) return this.metric(value);
                return date.toLocaleString('zh-CN', { hour12: false });
            },
        },
        template: `
            <div>
                <div class="ops-page-head">
                    <div>
                        <h1 class="ops-title">[[ pageTitle ]]</h1>
                        <div class="ops-subtitle" v-if="data.subtitle">[[ data.subtitle ]]</div>
                    </div>
                    <div class="ops-actions">
                        <a v-for="action in data.actions || []" :key="action.url + action.label" class="btn btn-sm" :class="action.class || 'btn-outline-primary'" :href="action.url">[[ action.label ]]</a>
                    </div>
                </div>

                <div v-if="errors.length" class="alert alert-danger">
                    <strong>[[ data.error_heading || '提交失败，请检查以下内容' ]]</strong>
                    <ul class="ops-error-list"><li v-for="error in errors" :key="error">[[ error ]]</li></ul>
                </div>
                <div v-if="data.message" class="alert" :class="data.message_ok === true ? 'alert-success' : (data.message_ok === false ? 'alert-danger' : 'alert-info')">[[ data.message ]]</div>

                <section v-if="kind === 'auth-login'" class="ops-panel">
                    <form class="ops-form" method="post" action="/login/" @submit="submitForm">
                        <input type="hidden" name="csrfmiddlewaretoken" :value="data.csrf">
                        <div><label class="form-label">用户名</label><input class="form-control" name="user" autocomplete="username" :value="data.form && data.form.user || ''"></div>
                        <div><label class="form-label">密码</label><input class="form-control" name="pwd" type="password" autocomplete="current-password"></div>
                        <button class="btn btn-primary" type="submit">登录</button>
                        <a href="/register/">注册账号</a>
                    </form>
                </section>

                <section v-else-if="kind === 'auth-register'" class="ops-panel">
                    <form class="ops-form" method="post" action="/register/" @submit="submitForm">
                        <input type="hidden" name="csrfmiddlewaretoken" :value="data.csrf">
                        <div><label class="form-label">用户名</label><input class="form-control" name="user" autocomplete="username" :value="data.form && data.form.user || ''"></div>
                        <div><label class="form-label">邮箱</label><input class="form-control" name="email" type="email" autocomplete="email" :value="data.form && data.form.email || ''"></div>
                        <div><label class="form-label">密码</label><input class="form-control" name="password" type="password" autocomplete="new-password"></div>
                        <div><label class="form-label">确认密码</label><input class="form-control" name="confirm_pwd" type="password" autocomplete="new-password"></div>
                        <button class="btn btn-primary" type="submit">注册</button>
                        <a href="/login/">返回登录</a>
                    </form>
                </section>

                <section v-else-if="kind === 'dashboard'">
                    <div class="ops-grid">
                        <div class="ops-card"><div class="ops-card-label">资产</div><div class="ops-card-value">[[ data.counts.hosts ]]</div></div>
                        <div class="ops-card"><div class="ops-card-label">凭据记录</div><div class="ops-card-value">[[ data.counts.passwords ]]</div></div>
                        <div class="ops-card"><div class="ops-card-label">DevOps</div><div class="ops-card-value">Vue</div></div>
                        <div class="ops-card"><div class="ops-card-label">监控</div><div class="ops-card-value">可用</div></div>
                    </div>
                </section>

                <section v-else-if="kind === 'local-linux'" class="ops-grid three">
                    <div class="ops-card" v-for="item in data.items" :key="item.label"><div class="ops-card-label">[[ item.label ]]</div><div class="ops-card-value">[[ item.value ]]</div></div>
                </section>

                <section v-else-if="kind === 'host-list'" class="ops-panel">
                    <form class="ops-search-bar mb-3" method="get" :action="data.search_action || '/detail/'">
                        <input class="form-control form-control-sm" name="search" :value="data.keyword || ''" placeholder="搜索名称、IP、主机名、应用">
                        <button class="btn btn-sm btn-primary">搜索</button>
                        <a v-if="data.keyword" class="btn btn-sm btn-outline-secondary" href="/detail/">清空</a>
                    </form>
                    <div class="ops-list-summary">[[ data.keyword ? ('搜索“' + data.keyword + '”，共 ' + (data.total || 0) + ' 条') : ('共 ' + (data.total || 0) + ' 台服务器') ]]</div>
                    <div v-if="!data.hosts || data.hosts.length === 0" class="ops-empty">没有找到匹配的服务器</div>
                    <div v-else class="ops-list">
                        <div class="ops-row" v-for="host in data.hosts" :key="host.id">
                            <div><div class="ops-row-title">[[ host.linux_name || host.linux_ip ]]</div><div class="ops-row-meta"><span>[[ host.linux_ip ]]</span><span>[[ host.linux_hostname || '-' ]]</span><span>[[ host.linux_app || '-' ]]</span></div></div>
                            <div class="ops-actions"><a class="btn btn-sm btn-outline-primary" :href="'/list_detail/' + host.id + '/'">详情</a><a class="btn btn-sm btn-outline-secondary" :href="'/linux_update/' + host.id + '/'">编辑</a><a class="btn btn-sm btn-outline-dark" :href="'/connect/' + host.id + '/'">WebSSH</a></div>
                        </div>
                    </div>
                    <div v-if="data.pagination && data.pagination.total > 1" class="ops-pagination">
                        <a class="btn btn-sm btn-outline-secondary" :class="{ disabled: !data.pagination.has_previous }" :href="data.pagination.previous_url || '#'">上一页</a>
                        <span>[[ data.pagination.current ]] / [[ data.pagination.total ]]</span>
                        <a class="btn btn-sm btn-outline-secondary" :class="{ disabled: !data.pagination.has_next }" :href="data.pagination.next_url || '#'">下一页</a>
                    </div>
                </section>

                <section v-else-if="kind === 'host-form'" class="ops-panel">
                    <form class="ops-form" method="post" :action="data.action" @submit="submitForm">
                        <input type="hidden" name="csrfmiddlewaretoken" :value="data.csrf">
                        <div><label class="form-label">名称</label><input class="form-control" name="linux_name" :value="data.host.linux_name || ''"></div>
                        <div><label class="form-label">IP</label><input class="form-control" name="linux_ip" :value="data.host.linux_ip || ''" required></div>
                        <div><label class="form-label">主机名</label><input class="form-control" name="linux_hostname" :value="data.host.linux_hostname || ''"></div>
                        <div><label class="form-label">端口</label><input class="form-control" name="linux_port" :value="data.host.linux_port || '22'" required></div>
                        <div><label class="form-label">用户</label><input class="form-control" name="linux_user" :value="data.host.linux_user || ''" required></div>
                        <div><label class="form-label">认证方式</label><select class="form-control" name="linux_auth_type"><option value="password" :selected="data.host.linux_auth_type !== 'key'">密码</option><option value="key" :selected="data.host.linux_auth_type === 'key'">SSH Key</option></select></div>
                        <div><label class="form-label">SSH 密码</label><input class="form-control" name="linux_passwd" type="password" placeholder="留空则保持原密码不变"></div>
                        <div><label class="form-label">SSH 私钥</label><textarea class="form-control" name="linux_private_key" placeholder="留空则保持原私钥不变"></textarea></div>
                        <div><label class="form-label">私钥口令</label><input class="form-control" name="linux_private_key_passphrase" type="password"></div>
                        <div><label class="form-label">应用说明</label><textarea class="form-control" name="linux_app">[[ data.host.linux_app || '' ]]</textarea></div>
                        <button class="btn btn-primary" type="submit">保存</button>
                    </form>
                </section>

                <section v-else-if="kind === 'host-import'" class="ops-panel">
                    <form class="ops-form" method="post" :action="data.action" enctype="multipart/form-data" @submit="submitForm">
                        <input type="hidden" name="csrfmiddlewaretoken" :value="data.csrf">
                        <div>
                            <label class="form-label">CSV 文件</label>
                            <input class="form-control" name="file" type="file" accept=".csv,text/csv" required>
                        </div>
                        <div class="ops-muted">字段：[[ data.fields ]]</div>
                        <div class="ops-muted">也支持中文表头：名称、IP、主机名、端口、用户、密码、认证方式、私钥、私钥口令、应用说明。</div>
                        <button class="btn btn-primary" type="submit">导入</button>
                    </form>
                </section>

                <section v-else-if="kind === 'host-detail'" class="ops-grid three">
                    <div class="ops-card" v-for="item in data.items" :key="item.label"><div class="ops-card-label">[[ item.label ]]</div><div class="ops-card-value">[[ metric(item.value) ]]</div></div>
                </section>

                <section v-else-if="kind === 'monitor-home'">
                    <div class="ops-grid">
                        <div class="ops-card" v-for="card in data.cards || []" :key="card.label">
                            <div class="ops-card-label">[[ card.label ]]</div>
                            <div class="ops-card-value">[[ metric(card.value) ]]</div>
                            <div class="ops-card-meta" v-if="card.meta">[[ card.meta ]]</div>
                        </div>
                    </div>
                    <div class="ops-panel mt-3">
                        <div class="ops-section-head">
                            <div class="ops-section-title">监控对接</div>
                            <div class="ops-actions">
                                <a v-if="data.integration_url" class="btn btn-sm btn-outline-primary" :href="data.integration_url"><i class="fas fa-plug" aria-hidden="true"></i> 管理对接</a>
                                <a v-if="data.query_url" class="btn btn-sm btn-outline-secondary" :href="data.query_url">指标查询</a>
                                <a v-if="data.alert_settings_url" class="btn btn-sm btn-outline-dark" :href="data.alert_settings_url">告警设置</a>
                            </div>
                        </div>
                        <div v-if="!monitorIntegrations.length" class="ops-empty">暂无监控对接</div>
                        <div v-else class="table-responsive ops-integration-table-wrap">
                            <table class="table table-sm ops-integration-table mb-0">
                                <thead><tr><th scope="col">类型</th><th scope="col">名称</th><th scope="col">基础地址</th><th scope="col">状态</th><th v-if="data.can_manage_integrations" scope="col">操作</th></tr></thead>
                                <tbody>
                                    <tr v-for="integration in monitorIntegrations" :key="integration.kind + '-' + integration.id">
                                        <td><span class="ops-kind-label">[[ integration.kind_label || integration.kind ]]</span></td>
                                        <td><strong>[[ integration.name ]]</strong><span v-if="integration.updated_at" class="ops-cell-meta">更新于 [[ integration.updated_at ]]</span></td>
                                        <td><span class="ops-integration-url" :title="integration.url">[[ integration.url ]]</span></td>
                                        <td><span class="ops-badge" :class="{ 'ops-badge-muted': !integration.enabled }">[[ integration.enabled ? '已启用' : '已停用' ]]</span></td>
                                        <td v-if="data.can_manage_integrations" class="ops-integration-actions">
                                            <div class="ops-actions">
                                                <a class="btn btn-sm btn-outline-primary" :href="integration.edit_url"><i class="fas fa-edit" aria-hidden="true"></i> 更新</a>
                                                <form class="ops-inline-form" method="post" :action="integration.delete_url" @submit="confirmDelete($event, integration)">
                                                    <input type="hidden" name="csrfmiddlewaretoken" :value="data.csrf">
                                                    <button class="btn btn-sm btn-outline-danger" type="submit"><i class="fas fa-trash" aria-hidden="true"></i> 删除</button>
                                                </form>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </section>

                <div v-else-if="kind === 'monitor-integrations'" class="ops-integration-page">
                    <section v-if="data.can_manage_integrations" class="ops-panel">
                        <div class="ops-section-title"><i class="fas fa-chart-line" aria-hidden="true"></i>[[ prometheusForm.editing ? '更新 Prometheus 对接' : '新增 Prometheus 对接' ]]</div>
                        <form class="ops-form ops-integration-form" method="post" :action="prometheusForm.action" @submit="submitForm">
                            <input type="hidden" name="csrfmiddlewaretoken" :value="data.csrf">
                            <input v-if="prometheusValues.id" type="hidden" name="id" :value="prometheusValues.id">
                            <div>
                                <label class="form-label">名称</label>
                                <input class="form-control" name="name" :value="prometheusValues.name || ''" placeholder="生产 Prometheus" autocomplete="off" required>
                            </div>
                            <div>
                                <label class="form-label">Prometheus URL</label>
                                <input class="form-control" name="prometheus_url" type="url" :value="prometheusValues.prometheus_url || ''" placeholder="http://prometheus.example:9090" autocomplete="off" required>
                            </div>
                            <label class="ops-check-row ops-form-full">
                                <input type="checkbox" name="enabled" value="1" :checked="prometheusValues.enabled">
                                <span>启用 Prometheus 对接</span>
                            </label>
                            <div class="ops-actions ops-form-full">
                                <button class="btn btn-primary" type="submit"><i class="fas fa-save" aria-hidden="true"></i> [[ prometheusForm.editing ? '更新' : '保存' ]]</button>
                                <button class="btn btn-outline-secondary" type="submit" :formaction="prometheusForm.test_action"><i class="fas fa-plug" aria-hidden="true"></i> 测试连接</button>
                            </div>
                        </form>
                    </section>

                    <section v-if="data.can_manage_integrations" class="ops-panel">
                        <div class="ops-section-title"><i class="fas fa-bell" aria-hidden="true"></i>[[ alertmanagerForm.editing ? '更新 Alertmanager 对接' : '新增 Alertmanager 对接' ]]</div>
                        <form class="ops-form ops-integration-form" method="post" :action="alertmanagerForm.action" @submit="submitForm">
                            <input type="hidden" name="csrfmiddlewaretoken" :value="data.csrf">
                            <input v-if="alertmanagerValues.id" type="hidden" name="id" :value="alertmanagerValues.id">
                            <div>
                                <label class="form-label">名称</label>
                                <input class="form-control" name="name" :value="alertmanagerValues.name || ''" placeholder="生产 Alertmanager" autocomplete="off" required>
                            </div>
                            <div>
                                <label class="form-label">Alertmanager URL</label>
                                <input class="form-control" name="alertmanager_url" type="url" :value="alertmanagerValues.alertmanager_url || ''" placeholder="http://alertmanager.example:9093" autocomplete="off" required>
                            </div>
                            <label class="ops-check-row ops-form-full">
                                <input type="checkbox" name="enabled" value="1" :checked="alertmanagerValues.enabled">
                                <span>启用 Alertmanager 对接</span>
                            </label>
                            <div class="ops-actions ops-form-full">
                                <button class="btn btn-primary" type="submit"><i class="fas fa-save" aria-hidden="true"></i> [[ alertmanagerForm.editing ? '更新' : '保存' ]]</button>
                                <button class="btn btn-outline-secondary" type="submit" :formaction="alertmanagerForm.test_action"><i class="fas fa-plug" aria-hidden="true"></i> 测试连接</button>
                            </div>
                        </form>
                    </section>

                    <section class="ops-panel">
                        <div class="ops-section-title">当前对接</div>
                        <div v-if="!monitorIntegrations.length" class="ops-empty">暂无监控对接</div>
                        <div v-else class="table-responsive ops-integration-table-wrap">
                            <table class="table table-sm ops-integration-table mb-0">
                                <thead><tr><th scope="col">类型</th><th scope="col">名称</th><th scope="col">基础地址</th><th scope="col">状态</th><th v-if="data.can_manage_integrations" scope="col">操作</th></tr></thead>
                                <tbody>
                                    <tr v-for="integration in monitorIntegrations" :key="integration.kind + '-' + integration.id">
                                        <td><span class="ops-kind-label">[[ integration.kind_label || integration.kind ]]</span></td>
                                        <td><strong>[[ integration.name ]]</strong><span v-if="integration.updated_at" class="ops-cell-meta">更新于 [[ integration.updated_at ]]</span></td>
                                        <td><span class="ops-integration-url" :title="integration.url">[[ integration.url ]]</span></td>
                                        <td><span class="ops-badge" :class="{ 'ops-badge-muted': !integration.enabled }">[[ integration.enabled ? '已启用' : '已停用' ]]</span></td>
                                        <td v-if="data.can_manage_integrations" class="ops-integration-actions">
                                            <div class="ops-actions">
                                                <a class="btn btn-sm btn-outline-primary" :href="integration.edit_url"><i class="fas fa-edit" aria-hidden="true"></i> 更新</a>
                                                <form class="ops-inline-form" method="post" :action="integration.delete_url" @submit="confirmDelete($event, integration)">
                                                    <input type="hidden" name="csrfmiddlewaretoken" :value="data.csrf">
                                                    <button class="btn btn-sm btn-outline-danger" type="submit"><i class="fas fa-trash" aria-hidden="true"></i> 删除</button>
                                                </form>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </section>
                </div>

                <section v-else-if="kind === 'alert-query'" class="ops-query-page">
                    <div v-if="!data.prometheus_configured" class="alert alert-warning">Prometheus 尚未配置或未启用。</div>
                    <div class="ops-query-toolbar">
                        <button class="btn btn-sm btn-outline-primary" type="button" @click="addMetricQueryPanel">
                            <i class="fas fa-plus" aria-hidden="true"></i> 新增查询
                        </button>
                    </div>
                    <article class="ops-panel ops-query-panel" v-for="(panel, panelIndex) in queryPanels" :key="panel.id">
                        <div class="ops-query-panel-head">
                            <div class="ops-query-panel-title">查询 [[ panelIndex + 1 ]]</div>
                            <button class="btn btn-sm btn-outline-danger ops-icon-button" type="button"
                                    :disabled="queryPanels.length === 1" title="删除此查询" aria-label="删除此查询"
                                    @click="removeMetricQueryPanel(panel.id)">
                                <i class="fas fa-trash" aria-hidden="true"></i>
                            </button>
                        </div>
                        <form class="ops-query-form" @submit.prevent="executeMetricQuery(panel)">
                            <div class="ops-query-field">
                                <label class="form-label" :for="'metric-query-' + panel.id">PromQL</label>
                                <textarea class="form-control ops-query-input" :id="'metric-query-' + panel.id"
                                          v-model="panel.query" name="query" rows="2" maxlength="2000"
                                          placeholder="up" autocomplete="off"></textarea>
                            </div>
                            <button class="btn btn-sm btn-primary ops-query-submit" type="submit" :disabled="panel.loading">
                                <i class="fas" :class="panel.loading ? 'fa-spinner fa-spin' : 'fa-search'" aria-hidden="true"></i>
                                [[ panel.loading ? '查询中' : '查询' ]]
                            </button>
                        </form>
                        <div v-if="panel.error" class="alert alert-danger ops-query-error">[[ panel.error ]]</div>
                        <div v-if="panel.hasExecuted && !panel.error" class="ops-query-result">
                            <div class="ops-query-result-head">
                                <div class="ops-section-title">查询结果</div>
                                <div class="ops-query-summary">
                                    <span v-if="panel.table.result_type">类型：[[ panel.table.result_type ]]</span>
                                    <span>[[ panel.table.total_rows ]] 行</span>
                                    <span v-if="panel.table.truncated" class="ops-query-truncated">仅展示前 [[ panel.table.rows.length ]] 行</span>
                                </div>
                            </div>
                            <div v-if="panel.table.rows.length" class="table-responsive ops-query-table-wrap">
                                <table class="table table-sm ops-query-table mb-0">
                                    <thead>
                                        <tr>
                                            <th v-for="column in panel.table.label_columns" :key="column" scope="col">[[ column ]]</th>
                                            <th class="ops-query-time-column" scope="col">时间</th>
                                            <th class="ops-query-value-column" scope="col">值</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr v-for="(row, rowIndex) in panel.table.rows" :key="rowIndex">
                                            <td v-for="column in panel.table.label_columns" :key="column"><code>[[ metric(row.labels && row.labels[column]) ]]</code></td>
                                            <td class="ops-query-time-cell" :title="row.timestamp">[[ formatMetricTimestamp(row.timestamp) ]]</td>
                                            <td class="ops-query-value-cell"><code>[[ metric(row.value) ]]</code></td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                            <div v-else class="ops-empty">查询结果为空</div>
                        </div>
                    </article>
                </section>

                <section v-else-if="kind === 'monitor'" class="ops-panel">
                    <form class="ops-form" method="post" :action="data.action" @submit="submitForm">
                        <input type="hidden" name="csrfmiddlewaretoken" :value="data.csrf">
                        <div><label class="form-label">告警邮箱</label><input class="form-control" name="monitor_email" type="email" :value="data.monitor.monitor_email || ''"></div>
                        <div><label class="form-label">CPU 阈值</label><input class="form-control" name="monitor_cpu" :value="data.monitor.monitor_cpu || ''"></div>
                        <div><label class="form-label">内存阈值</label><input class="form-control" name="monitor_men" :value="data.monitor.monitor_men || ''"></div>
                        <div><label class="form-label">磁盘阈值</label><input class="form-control" name="monitor_disk" :value="data.monitor.monitor_disk || ''"></div>
                        <button class="btn btn-primary" type="submit">保存</button>
                    </form>
                    <div class="ops-muted mt-3">当前未处理告警：[[ data.open_alert_count || 0 ]]</div>
                </section>

                <section v-else-if="kind === 'alert-notifications'">
                    <div v-if="data.test_message" class="alert alert-info">[[ data.test_message ]]</div>
                    <div class="ops-grid two">
                        <div class="ops-card ops-notification-card" v-for="provider in alertProviders" :key="provider.key">
                            <form class="ops-form compact" method="post" :action="data.action" @submit="submitForm">
                                <input type="hidden" name="csrfmiddlewaretoken" :value="data.csrf">
                                <input type="hidden" name="provider" :value="provider.key">
                                <div class="ops-notification-head">
                                    <div>
                                        <div class="ops-section-title"><i class="fas" :class="'fa-' + provider.icon"></i> [[ provider.label ]]</div>
                                        <div class="ops-muted">[[ provider.config.enabled ? '已启用' : '未启用' ]]</div>
                                    </div>
                                    <label class="ops-check-row">
                                        <input type="checkbox" :name="provider.key + '_enabled'" value="1" :checked="provider.config.enabled">
                                        <span>启用</span>
                                    </label>
                                </div>
                                <div>
                                    <label class="form-label">名称</label>
                                    <input class="form-control" :name="provider.key + '_name'" :value="provider.config.name || provider.label" autocomplete="off">
                                </div>
                                <div>
                                    <label class="form-label">Webhook</label>
                                    <input class="form-control" :name="provider.key + '_webhook_url'" type="password" placeholder="留空则保持现有 Webhook 不变" autocomplete="new-password">
                                    <div v-if="provider.config.has_webhook" class="form-text">当前：[[ provider.config.webhook_display || '已保存' ]]</div>
                                </div>
                                <div class="ops-actions">
                                    <button class="btn btn-primary" type="submit">保存</button>
                                    <button class="btn btn-outline-secondary" type="submit" :formaction="data.test_action" name="provider" :value="provider.key">测试[[ provider.label ]]</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </section>

                <section v-else-if="kind === 'password-list'" class="ops-panel">
                    <form class="ops-actions mb-3" method="get" action="/password/password_search/"><input class="form-control form-control-sm" name="search" :value="data.keyword || ''" placeholder="搜索系统、账号、备注"><button class="btn btn-sm btn-primary">搜索</button></form>
                    <div v-if="revealError" class="alert alert-danger">[[ revealError ]]</div>
                    <div class="ops-list">
                        <div class="ops-row" v-for="item in data.passwords" :key="item.id" :data-system-name="item.system_name">
                            <div><div class="ops-row-title">[[ item.system_name ]]</div><div class="ops-row-meta"><span>[[ item.account ]]</span><span>[[ item.remark || '-' ]]</span><span class="ops-secret">[[ reveal[item.id] || '••••••••' ]]</span></div></div>
                            <div class="ops-actions"><button class="btn btn-sm btn-outline-primary" type="button" @click="revealPassword(item)">查看</button><a class="btn btn-sm btn-outline-secondary" :href="item.update_url">编辑</a></div>
                        </div>
                    </div>
                </section>

                <section v-else-if="kind === 'password-form'" class="ops-panel">
                    <form class="ops-form" method="post" :action="data.action" @submit="submitForm">
                        <input type="hidden" name="csrfmiddlewaretoken" :value="data.csrf">
                        <div><label class="form-label">系统名称</label><input class="form-control" name="system_name" :value="data.password.system_name || ''" required></div>
                        <div><label class="form-label">账号</label><input class="form-control" name="account" :value="data.password.account || ''" required></div>
                        <div><label class="form-label">密码</label><input class="form-control" name="password" type="password" :placeholder="data.keep_hint || ''"></div>
                        <div><label class="form-label">备注</label><input class="form-control" name="remark" :value="data.password.remark || ''"></div>
                        <button class="btn btn-primary" type="submit">保存</button>
                    </form>
                </section>

                <section v-else-if="kind === 'webssh'" class="ops-panel">
                    <div id="terminal" class="ops-terminal"></div>
                </section>

                <section v-else class="ops-panel">页面已切换为 Vue 渲染。</section>
            </div>
        `,
        mounted() {
            if (this.kind === 'webssh' && window.Terminal) {
                const terminal = new window.Terminal({ convertEol: true, cursorBlink: true, fontSize: 18, theme: { foreground: 'yellow', background: '#060101' } });
                terminal.open(document.getElementById('terminal'));
                terminal.writeln('正在打开 WebSSH 会话...');
                const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
                const sock = new WebSocket(protocol + window.location.host + this.data.ws_url);
                sock.addEventListener('message', (event) => terminal.write(event.data));
                terminal.on('data', (value) => sock.send(value));
            }
        },
    }).mount(root);
})();
