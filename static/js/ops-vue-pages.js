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
        if (!table || typeof table !== 'object' || Array.isArray(table)) return emptyMetricTable();
        const rows = Array.isArray(table.rows) ? table.rows : [];
        const rawTotalRows = table.total_rows;
        return {
            result_type: typeof table.result_type === 'string' ? table.result_type : '',
            label_columns: Array.isArray(table.label_columns)
                ? table.label_columns.filter((column) => typeof column === 'string')
                : [],
            rows,
            total_rows: rawTotalRows !== null && rawTotalRows !== undefined && Number.isFinite(Number(rawTotalRows))
                ? Number(rawTotalRows)
                : rows.length,
            truncated: Boolean(table.truncated),
        };
    }

    function metricQueryPanel(id, query, table, error) {
        const normalizedTable = normalizeMetricTable(table);
        return {
            id,
            query: typeof query === 'string' ? query : '',
            table: normalizedTable,
            error: typeof error === 'string' ? error : '',
            loading: false,
            hasExecuted: Boolean(query || error || normalizedTable.result_type || normalizedTable.rows.length),
            durationMs: null,
        };
    }

    function normalizeMetricPrometheusId(value) {
        const id = Number(value);
        return Number.isSafeInteger(id) && id > 0 ? String(id) : '';
    }

    function normalizeMetricPrometheusConfigs(configs) {
        if (!Array.isArray(configs)) return [];
        const seen = {};
        return configs.reduce((items, config) => {
            const id = normalizeMetricPrometheusId(config && config.id);
            const name = config && typeof config.name === 'string' ? config.name.trim() : '';
            if (!id || !name || seen[id]) return items;
            seen[id] = true;
            items.push({ id, name });
            return items;
        }, []);
    }

    function safeMetricResourceText(value, maxLength) {
        if (typeof value !== 'string') return '';
        const text = value.trim();
        if (!text) return '';
        if (text.length <= maxLength) return text;
        return maxLength > 3 ? text.slice(0, maxLength - 3) + '...' : text.slice(0, maxLength);
    }

    function safeMetricResourceCount(value, fallback) {
        if (value === null || value === undefined || value === '' || typeof value === 'boolean') return fallback;
        const count = Number(value);
        return Number.isSafeInteger(count) && count >= 0 ? count : fallback;
    }

    function safeMetricResourceSeconds(value) {
        if (value === null || value === undefined || value === '' || typeof value === 'boolean') return null;
        const seconds = Number(value);
        return Number.isFinite(seconds) && seconds >= 0 ? seconds : null;
    }

    function isSensitiveMetricLabelKey(value) {
        const normalized = value.replace(/([a-z0-9])([A-Z])/g, '$1_$2')
            .toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
        if (!normalized) return false;
        const sensitiveParts = [
            'token', 'password', 'passwd', 'secret', 'apikey', 'credential', 'credentials',
            'authorization', 'auth', 'webhook', 'key',
        ];
        const parts = normalized.split('_');
        const compact = parts.join('');
        return sensitiveParts.some((sensitive) => parts.indexOf(sensitive) !== -1)
            || normalized.indexOf('api_key') !== -1
            || sensitiveParts.some((sensitive) => compact.endsWith(sensitive));
    }

    function isSensitiveMetricLabelValue(value) {
        if (typeof value !== 'string') return false;
        const text = value.trim();
        if (!text) return false;
        if (/(?:^|[?&#;\s])(?:api[_-]?key|apikey|token|password|passwd|secret|credential|credentials|authorization|auth|webhook|access[_-]?key|client[_-]?secret)\s*=/i.test(text)) {
            return true;
        }
        if (!/^(?:https?:)?\/\//i.test(text)) return false;
        const withoutScheme = text.replace(/^(?:https?:)?\/\//i, '');
        const authority = withoutScheme.split(/[/?#]/, 1)[0];
        return authority.indexOf('@') !== -1 || text.indexOf('?') !== -1 || text.indexOf('#') !== -1;
    }

    function normalizeMetricResourceLabels(labels) {
        if (!labels || typeof labels !== 'object' || Array.isArray(labels)) return [];
        return Object.keys(labels).sort().reduce((items, key) => {
            if (items.length >= 24 || isSensitiveMetricLabelKey(key)
                    || isSensitiveMetricLabelValue(labels[key])) return items;
            const name = safeMetricResourceText(key, 120);
            const value = safeMetricResourceText(labels[key], 500);
            if (name && value) items.push({ name, value });
            return items;
        }, []);
    }

    function emptyMetricResourceData(kind) {
        return {
            rows: [],
            summary: kind === 'targets'
                ? { total: 0, up: 0, down: 0, unknown: 0, with_errors: 0 }
                : { total: 0, alerting: 0, recording: 0, unhealthy: 0, firing: 0, pending: 0 },
            totalRows: 0,
            truncated: false,
        };
    }

    function normalizeMetricTargets(resource) {
        const empty = emptyMetricResourceData('targets');
        if (!resource || typeof resource !== 'object' || Array.isArray(resource)) return empty;
        const rawRows = Array.isArray(resource.rows) ? resource.rows : [];
        const rows = rawRows.filter((row) => (
            row && typeof row === 'object' && !Array.isArray(row)
        )).slice(0, 500).map((row) => ({
            instance: safeMetricResourceText(row.instance, 240),
            job: safeMetricResourceText(row.job, 160),
            scrapePool: safeMetricResourceText(row.scrape_pool, 160),
            health: safeMetricResourceText(row.health, 32),
            lastScrape: safeMetricResourceText(row.last_scrape, 80),
            lastScrapeDuration: safeMetricResourceSeconds(row.last_scrape_duration),
            labels: normalizeMetricResourceLabels(row.labels),
            hasError: row.has_error === true,
        }));
        const rawSummary = resource.summary && typeof resource.summary === 'object' && !Array.isArray(resource.summary)
            ? resource.summary
            : {};
        const totalRows = safeMetricResourceCount(resource.total_rows, rawRows.length);
        return {
            rows,
            summary: {
                total: safeMetricResourceCount(rawSummary.total, totalRows),
                up: safeMetricResourceCount(rawSummary.up, 0),
                down: safeMetricResourceCount(rawSummary.down, 0),
                unknown: safeMetricResourceCount(rawSummary.unknown, 0),
                with_errors: safeMetricResourceCount(rawSummary.with_errors, 0),
            },
            totalRows,
            truncated: Boolean(resource.truncated || rawRows.length > rows.length || totalRows > rows.length),
        };
    }

    function normalizeMetricRules(resource) {
        const empty = emptyMetricResourceData('rules');
        if (!resource || typeof resource !== 'object' || Array.isArray(resource)) return empty;
        const rawRows = Array.isArray(resource.rows) ? resource.rows : [];
        const rows = rawRows.filter((row) => (
            row && typeof row === 'object' && !Array.isArray(row)
        )).slice(0, 500).map((row) => ({
            group: safeMetricResourceText(row.group, 240),
            name: safeMetricResourceText(row.name, 240),
            type: safeMetricResourceText(row.type, 32),
            health: safeMetricResourceText(row.health, 32),
            state: safeMetricResourceText(row.state, 32),
            query: safeMetricResourceText(row.query, 2000),
            duration: safeMetricResourceSeconds(row.duration),
            labels: normalizeMetricResourceLabels(row.labels),
            lastEvaluation: safeMetricResourceText(row.last_evaluation, 80),
            evaluationTime: safeMetricResourceSeconds(row.evaluation_time),
            activeAlerts: safeMetricResourceCount(row.active_alerts, 0),
            hasError: row.has_error === true,
        }));
        const rawSummary = resource.summary && typeof resource.summary === 'object' && !Array.isArray(resource.summary)
            ? resource.summary
            : {};
        const totalRows = safeMetricResourceCount(resource.total_rows, rawRows.length);
        return {
            rows,
            summary: {
                total: safeMetricResourceCount(rawSummary.total, totalRows),
                alerting: safeMetricResourceCount(rawSummary.alerting, 0),
                recording: safeMetricResourceCount(rawSummary.recording, 0),
                unhealthy: safeMetricResourceCount(rawSummary.unhealthy, 0),
                firing: safeMetricResourceCount(rawSummary.firing, 0),
                pending: safeMetricResourceCount(rawSummary.pending, 0),
            },
            totalRows,
            truncated: Boolean(resource.truncated || rawRows.length > rows.length || totalRows > rows.length),
        };
    }

    function metricResourceState(kind) {
        return Object.assign(emptyMetricResourceData(kind), {
            loading: false,
            loaded: false,
            error: '',
            durationMs: null,
            requestVersion: 0,
        });
    }

    function normalizeMonitorIntegrationList(integrations, expectedKind) {
        if (!Array.isArray(integrations)) return [];
        const seen = {};
        const items = integrations.reduce((normalized, integration) => {
            if (!integration || typeof integration !== 'object' || Array.isArray(integration)) return normalized;
            const id = normalizeMetricPrometheusId(integration.id);
            const kind = typeof integration.kind === 'string' ? integration.kind : expectedKind;
            if (!id || seen[id] || kind !== expectedKind) return normalized;
            const fallbackName = expectedKind === 'prometheus' ? 'Prometheus' : 'Alertmanager';
            const name = typeof integration.name === 'string' && integration.name.trim()
                ? integration.name.trim()
                : fallbackName;
            seen[id] = true;
            normalized.push({
                id,
                kind,
                kindLabel: expectedKind === 'prometheus' ? 'Prometheus' : 'Alertmanager',
                name,
                enabled: Boolean(integration.enabled),
                updatedAt: typeof integration.updated_at === 'string' ? integration.updated_at : '',
                editUrl: typeof integration.edit_url === 'string' ? integration.edit_url : '',
                deleteUrl: typeof integration.delete_url === 'string' ? integration.delete_url : '',
            });
            return normalized;
        }, []);
        const nameCounts = items.reduce((counts, integration) => {
            counts[integration.name] = (counts[integration.name] || 0) + 1;
            return counts;
        }, {});
        return items.map((integration) => Object.assign({}, integration, {
            displayName: nameCounts[integration.name] > 1
                ? integration.name + ' (#' + integration.id + ')'
                : integration.name,
        }));
    }

    function monitorIntegrationList(pageData, key, kind) {
        const classified = Array.isArray(pageData[key])
            ? pageData[key]
            : (Array.isArray(pageData.integrations)
                ? pageData.integrations.filter((integration) => integration && integration.kind === kind)
                : []);
        return normalizeMonitorIntegrationList(classified, kind);
    }

    function normalizeAlertNotificationIntegrations(integrations) {
        if (!Array.isArray(integrations)) return [];
        const seen = {};
        return integrations.reduce((items, integration) => {
            if (!integration || typeof integration !== 'object' || Array.isArray(integration)) return items;
            const provider = typeof integration.provider === 'string' ? integration.provider.trim() : '';
            const name = typeof integration.name === 'string' ? integration.name.trim() : '';
            if (!provider || !name || seen[provider]) return items;
            seen[provider] = true;
            items.push({
                provider,
                providerLabel: typeof integration.provider_label === 'string' && integration.provider_label.trim()
                    ? integration.provider_label.trim()
                    : provider,
                name,
                enabled: Boolean(integration.enabled),
                configured: Boolean(integration.configured),
                updatedAt: typeof integration.updated_at === 'string' ? integration.updated_at : '',
                configureUrl: typeof integration.configure_url === 'string' ? integration.configure_url : '',
            });
            return items;
        }, []);
    }

    createApp({
        delimiters: ['[[', ']]'],
        data() {
            const pageData = payload.data || {};
            const metricPrometheusConfigs = normalizeMetricPrometheusConfigs(pageData.prometheus_configs);
            const requestedPrometheusId = normalizeMetricPrometheusId(pageData.selected_prometheus_id);
            const selectedMetricPrometheusId = metricPrometheusConfigs.some(
                (config) => config.id === requestedPrometheusId
            ) ? requestedPrometheusId : '';
            const monitorPrometheusIntegrations = monitorIntegrationList(
                pageData, 'prometheus_integrations', 'prometheus'
            );
            const monitorAlertmanagerIntegrations = monitorIntegrationList(
                pageData, 'alertmanager_integrations', 'alertmanager'
            );
            const activePrometheusId = normalizeMetricPrometheusId(
                pageData.prometheus_form && pageData.prometheus_form.values
                    ? pageData.prometheus_form.values.id
                    : null
            );
            const activeAlertmanagerId = normalizeMetricPrometheusId(
                pageData.alertmanager_form && pageData.alertmanager_form.values
                    ? pageData.alertmanager_form.values.id
                    : null
            );
            return {
                kind: payload.kind,
                title: payload.title,
                data: pageData,
                reveal: {},
                revealError: '',
                queryPanels: [metricQueryPanel(1, pageData.query, pageData.table, pageData.error)],
                nextQueryPanelId: 2,
                metricView: 'promql',
                metricResources: {
                    targets: metricResourceState('targets'),
                    rules: metricResourceState('rules'),
                },
                metricPrometheusConfigs,
                selectedMetricPrometheusId,
                monitorPrometheusIntegrations,
                monitorAlertmanagerIntegrations,
                monitorIntegrationSelections: {
                    prometheus: monitorPrometheusIntegrations.some((item) => item.id === activePrometheusId)
                        ? activePrometheusId
                        : (monitorPrometheusIntegrations[0] ? monitorPrometheusIntegrations[0].id : ''),
                    alertmanager: monitorAlertmanagerIntegrations.some((item) => item.id === activeAlertmanagerId)
                        ? activeAlertmanagerId
                        : (monitorAlertmanagerIntegrations[0] ? monitorAlertmanagerIntegrations[0].id : ''),
                },
                alertNotificationIntegrations: normalizeAlertNotificationIntegrations(
                    pageData.notification_integrations
                ),
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
            monitorIntegrationGroups() {
                return [
                    {
                        key: 'prometheus',
                        label: 'Prometheus',
                        icon: 'fa-chart-line',
                        description: '指标采集与查询连接',
                        items: this.monitorPrometheusIntegrations,
                    },
                    {
                        key: 'alertmanager',
                        label: 'Alertmanager',
                        icon: 'fa-bell',
                        description: '告警路由与分发连接',
                        items: this.monitorAlertmanagerIntegrations,
                    },
                ];
            },
            canConfigureNotifications() {
                if (this.data.can_manage_notifications !== undefined) {
                    return Boolean(this.data.can_manage_notifications);
                }
                return Boolean(this.data.configure_url);
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
            selectedMetricPrometheus() {
                return this.metricPrometheusConfigs.find(
                    (config) => config.id === this.selectedMetricPrometheusId
                ) || null;
            },
            metricQueryLoading() {
                return this.queryPanels.some((panel) => panel.loading);
            },
            metricResourceLoading() {
                return this.metricResources.targets.loading || this.metricResources.rules.loading;
            },
            metricSourceLocked() {
                return this.metricQueryLoading || this.metricResourceLoading;
            },
            canExecuteMetricQuery() {
                return Boolean(this.data.prometheus_configured && this.selectedMetricPrometheus);
            },
        },
        methods: {
            submitForm(event) {
                return true;
            },
            confirmDelete(event, integration) {
                const name = integration && (
                    integration.displayName || integration.name || integration.kindLabel || integration.kind_label
                );
                if (window.confirm('确定删除“' + (name || '该监控对接') + '”吗？')) return true;
                if (event) event.preventDefault();
                return false;
            },
            selectedMonitorIntegration(kind) {
                const items = kind === 'prometheus'
                    ? this.monitorPrometheusIntegrations
                    : this.monitorAlertmanagerIntegrations;
                return items.find((integration) => (
                    integration.id === this.monitorIntegrationSelections[kind]
                )) || null;
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
            clearMetricQueryResult(panel) {
                panel.table = emptyMetricTable();
                panel.error = '';
                panel.durationMs = null;
                panel.hasExecuted = false;
            },
            resetMetricQueryResult(panel) {
                if (panel.loading) return;
                this.clearMetricQueryResult(panel);
            },
            clearMetricResource(kind) {
                const state = this.metricResources[kind];
                if (!state) return;
                const requestVersion = state.requestVersion + 1;
                Object.assign(state, emptyMetricResourceData(kind), {
                    loading: false,
                    loaded: false,
                    error: '',
                    durationMs: null,
                    requestVersion,
                });
            },
            changeMetricView(view) {
                if (['promql', 'targets', 'rules'].indexOf(view) === -1) return;
                this.metricView = view;
                if (view !== 'promql' && !this.metricResources[view].loaded
                        && !this.metricResources[view].loading) {
                    this.loadMetricResource(view);
                }
            },
            handleMetricTabKeydown(event, currentView) {
                if (!event) return;
                const views = ['promql', 'targets', 'rules'];
                const currentIndex = views.indexOf(currentView);
                if (currentIndex === -1) return;
                let nextIndex = null;
                if (event.key === 'ArrowRight') nextIndex = (currentIndex + 1) % views.length;
                if (event.key === 'ArrowLeft') nextIndex = (currentIndex + views.length - 1) % views.length;
                if (event.key === 'Home') nextIndex = 0;
                if (event.key === 'End') nextIndex = views.length - 1;
                if (nextIndex === null) return;
                event.preventDefault();
                const nextView = views[nextIndex];
                this.changeMetricView(nextView);
                this.$nextTick(() => {
                    const tab = document.getElementById('metric-tab-' + nextView);
                    if (tab) tab.focus();
                });
            },
            changeMetricPrometheus() {
                const selectedId = normalizeMetricPrometheusId(this.selectedMetricPrometheusId);
                this.selectedMetricPrometheusId = this.metricPrometheusConfigs.some(
                    (config) => config.id === selectedId
                ) ? selectedId : '';
                this.queryPanels.forEach((panel) => this.clearMetricQueryResult(panel));
                this.clearMetricResource('targets');
                this.clearMetricResource('rules');
                if (this.metricView !== 'promql' && this.selectedMetricPrometheus) {
                    this.loadMetricResource(this.metricView, true);
                }
            },
            async fetchMetricJson(url, form, context) {
                const queryContext = context === 'query';
                const messages = queryContext ? {
                    missing: '指标查询接口不可用，请刷新页面后重试',
                    forbidden: '当前账号无权执行指标查询',
                    format: '指标查询响应格式异常，请稍后重试',
                    unavailable: '指标查询服务暂时不可用，请稍后重试',
                    failed: '指标查询失败',
                } : {
                    missing: '指标资源接口不可用，请刷新页面后重试',
                    forbidden: '当前账号无权查看指标资源',
                    format: '指标资源响应格式异常，请稍后重试',
                    unavailable: '指标资源服务暂时不可用，请稍后重试',
                    failed: '指标资源请求失败',
                };
                if (typeof url !== 'string' || !url) {
                    throw new Error(messages.missing);
                }
                const response = await fetch(url, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
                        'X-CSRFToken': this.data.csrf || csrfToken(),
                    },
                    body: form.toString(),
                });
                const contentType = (response.headers.get('content-type') || '').toLowerCase();
                if (response.redirected && contentType.indexOf('application/json') === -1) {
                    throw new Error('登录状态已失效，请重新登录后再试');
                }
                if (contentType.indexOf('application/json') === -1) {
                    if (response.status === 401) throw new Error('登录状态已失效，请重新登录后再试');
                    if (response.status === 403) throw new Error(messages.forbidden);
                    throw new Error(response.ok
                        ? messages.format
                        : messages.unavailable);
                }

                let body;
                try {
                    body = await response.json();
                } catch (error) {
                    throw new Error(messages.format);
                }
                if (!body || typeof body !== 'object' || Array.isArray(body)) {
                    throw new Error(messages.format);
                }
                const responseMessage = safeMetricResourceText(body.message, 500);
                if (!response.ok || body.ok !== true) {
                    if (response.status === 401) throw new Error('登录状态已失效，请重新登录后再试');
                    if (response.status === 403) throw new Error(messages.forbidden);
                    throw new Error(responseMessage || messages.failed);
                }
                return body;
            },
            metricResponseSourceIsCurrent(body, requestedPrometheusId) {
                const returnedPrometheusId = normalizeMetricPrometheusId(body && body.prometheus_id);
                return Boolean(
                    returnedPrometheusId
                    && returnedPrometheusId === requestedPrometheusId
                    && this.selectedMetricPrometheusId === requestedPrometheusId
                    && this.metricPrometheusConfigs.some((config) => config.id === returnedPrometheusId)
                );
            },
            async loadMetricResource(kind, force) {
                if (kind !== 'targets' && kind !== 'rules') return;
                const state = this.metricResources[kind];
                if (state.loading || (state.loaded && !force)) return;
                const selectedPrometheus = this.selectedMetricPrometheus;
                const empty = emptyMetricResourceData(kind);
                if (!this.data.prometheus_configured || !this.metricPrometheusConfigs.length) {
                    Object.assign(state, empty, {
                        loaded: true,
                        error: '请先配置并启用 Prometheus 对接',
                        durationMs: null,
                    });
                    return;
                }
                if (!selectedPrometheus) {
                    Object.assign(state, empty, {
                        loaded: true,
                        error: '请选择 Prometheus 连接',
                        durationMs: null,
                    });
                    return;
                }

                const endpoint = kind === 'targets' ? this.data.targets_url : this.data.rules_url;
                const requestedPrometheusId = selectedPrometheus.id;
                const requestVersion = state.requestVersion + 1;
                const startedAt = Date.now();
                Object.assign(state, empty, {
                    loading: true,
                    loaded: false,
                    error: '',
                    durationMs: null,
                    requestVersion,
                });
                const form = new URLSearchParams();
                form.set('prometheus_id', requestedPrometheusId);
                try {
                    const body = await this.fetchMetricJson(endpoint, form, 'resource');
                    if (state.requestVersion !== requestVersion) return;
                    if (!this.metricResponseSourceIsCurrent(body, requestedPrometheusId)) {
                        throw new Error('指标资源来源不一致，请重新加载');
                    }
                    const normalized = kind === 'targets'
                        ? normalizeMetricTargets(body.targets)
                        : normalizeMetricRules(body.rules);
                    Object.assign(state, normalized, { loaded: true, error: '' });
                } catch (error) {
                    if (state.requestVersion !== requestVersion) return;
                    Object.assign(state, empty, {
                        loaded: true,
                        error: error instanceof TypeError
                            ? '无法连接指标资源服务，请检查网络后重试'
                            : (safeMetricResourceText(error.message, 500) || '指标资源加载失败'),
                    });
                } finally {
                    if (state.requestVersion === requestVersion) {
                        state.durationMs = Date.now() - startedAt;
                        state.loading = false;
                    }
                }
            },
            async executeMetricQuery(panel) {
                if (panel.loading) return;
                const query = (panel.query || '').trim();
                panel.query = query;
                panel.hasExecuted = true;
                panel.error = '';
                panel.durationMs = null;
                if (!query) {
                    panel.table = emptyMetricTable();
                    panel.error = '请输入 PromQL 查询语句';
                    return;
                }
                if (!this.data.prometheus_configured || !this.metricPrometheusConfigs.length) {
                    panel.table = emptyMetricTable();
                    panel.error = '请先配置并启用 Prometheus 对接';
                    return;
                }
                const selectedPrometheus = this.selectedMetricPrometheus;
                if (!selectedPrometheus) {
                    panel.table = emptyMetricTable();
                    panel.error = '请选择 Prometheus 连接';
                    return;
                }

                panel.loading = true;
                const startedAt = Date.now();
                const requestedPrometheusId = selectedPrometheus.id;
                const form = new URLSearchParams();
                form.set('query', query);
                form.set('prometheus_id', requestedPrometheusId);
                try {
                    const body = await this.fetchMetricJson(this.data.execute_url, form, 'query');
                    if (!this.metricResponseSourceIsCurrent(body, requestedPrometheusId)) {
                        throw new Error('指标查询来源不一致，请重新查询');
                    }
                    panel.query = typeof body.query === 'string' ? body.query : panel.query;
                    panel.table = normalizeMetricTable(body.table);
                } catch (error) {
                    panel.table = emptyMetricTable();
                    panel.error = error instanceof TypeError
                        ? '无法连接指标查询服务，请检查网络后重试'
                        : (error.message || '指标查询失败');
                } finally {
                    panel.durationMs = Date.now() - startedAt;
                    panel.loading = false;
                }
            },
            metricQueryStatus(panel) {
                if (panel.loading) return { key: 'loading', label: '查询中', icon: 'fa-spinner fa-spin' };
                if (panel.error) return { key: 'error', label: '查询失败', icon: 'fa-exclamation-circle' };
                if (!panel.hasExecuted) return { key: 'idle', label: '待查询', icon: 'fa-clock' };
                if (!panel.table.rows.length) return { key: 'empty', label: '无结果', icon: 'fa-minus-circle' };
                return { key: 'success', label: '已完成', icon: 'fa-check-circle' };
            },
            formatMetricDuration(value) {
                const milliseconds = Number(value);
                if (!Number.isFinite(milliseconds) || milliseconds < 0) return '-';
                if (milliseconds < 1000) return milliseconds + ' ms';
                return (milliseconds / 1000).toFixed(milliseconds < 10000 ? 2 : 1) + ' s';
            },
            formatMetricSeconds(value) {
                if (value === null || value === undefined || value === '' || typeof value === 'boolean') return '-';
                const seconds = Number(value);
                if (!Number.isFinite(seconds) || seconds < 0) return '-';
                if (seconds < 1) return Math.round(seconds * 1000) + ' ms';
                if (seconds < 60) return seconds.toFixed(seconds < 10 ? 2 : 1).replace(/\.0+$/, '') + ' s';
                if (seconds < 3600) return (seconds / 60).toFixed(1).replace(/\.0$/, '') + ' min';
                return (seconds / 3600).toFixed(1).replace(/\.0$/, '') + ' h';
            },
            metricResourceStatusClass(value) {
                const status = typeof value === 'string' ? value.toLowerCase() : '';
                if (['up', 'ok', 'healthy'].indexOf(status) !== -1) return 'is-success';
                if (['down', 'error', 'err', 'unhealthy', 'firing'].indexOf(status) !== -1) return 'is-danger';
                if (['pending', 'unknown'].indexOf(status) !== -1) return 'is-warning';
                return 'is-muted';
            },
            formatMetricTimestamp(value) {
                const timestamp = Number(value);
                if (!Number.isFinite(timestamp)) return this.metric(value);
                const date = new Date(timestamp * 1000);
                if (Number.isNaN(date.getTime())) return this.metric(value);
                return date.toLocaleString('zh-CN', { hour12: false });
            },
            formatDisplayDate(value) {
                if (typeof value !== 'string' || !value.trim()) return '';
                const text = value.trim();
                if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(?::\d{2})?$/.test(text)) return text;
                const date = new Date(text);
                if (Number.isNaN(date.getTime())) return '-';
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
                    <div class="ops-monitor-summary-grid">
                        <div class="ops-card" v-for="card in data.cards || []" :key="card.label">
                            <div class="ops-card-label">[[ card.label ]]</div>
                            <div class="ops-card-value">[[ metric(card.value) ]]</div>
                            <div class="ops-card-meta" v-if="card.meta">[[ card.meta ]]</div>
                        </div>
                    </div>
                    <div class="ops-integration-overview mt-3">
                        <div class="ops-section-head">
                            <div class="ops-section-title">监控对接</div>
                            <div class="ops-actions">
                                <a v-if="data.integration_url" class="btn btn-sm btn-outline-primary" :href="data.integration_url"><i class="fas fa-plug" aria-hidden="true"></i> 管理对接</a>
                                <a v-if="data.query_url" class="btn btn-sm btn-outline-secondary" :href="data.query_url">指标查询</a>
                                <a v-if="data.alert_settings_url" class="btn btn-sm btn-outline-dark" :href="data.alert_settings_url">告警设置</a>
                            </div>
                        </div>
                        <div class="ops-integration-picker-grid">
                            <article class="ops-integration-picker" v-for="group in monitorIntegrationGroups" :key="group.key">
                                <div class="ops-integration-picker-head">
                                    <div>
                                        <div class="ops-integration-picker-title">
                                            <i class="fas" :class="group.icon" aria-hidden="true"></i> [[ group.label ]]
                                        </div>
                                        <div class="ops-muted">[[ group.description ]]</div>
                                    </div>
                                    <span class="ops-integration-picker-count">[[ group.items.length ]] 个</span>
                                </div>
                                <label class="form-label" :for="'monitor-home-' + group.key + '-selector'">已配置连接</label>
                                <div class="ops-integration-picker-control">
                                    <select class="form-control form-control-sm" :id="'monitor-home-' + group.key + '-selector'"
                                            v-model="monitorIntegrationSelections[group.key]" :disabled="!group.items.length">
                                        <option value="" disabled>[[ group.items.length ? ('选择 ' + group.label + ' 连接') : ('暂无 ' + group.label + ' 连接') ]]</option>
                                        <option v-for="integration in group.items" :key="integration.id" :value="integration.id">
                                            [[ integration.displayName ]] · [[ integration.enabled ? '已启用' : '已停用' ]]
                                        </option>
                                    </select>
                                    <a v-if="data.can_manage_integrations && selectedMonitorIntegration(group.key) && selectedMonitorIntegration(group.key).editUrl"
                                       class="btn btn-sm btn-outline-primary ops-integration-picker-action"
                                       :href="selectedMonitorIntegration(group.key).editUrl"
                                       :title="'编辑 ' + selectedMonitorIntegration(group.key).displayName"
                                       :aria-label="'编辑 ' + selectedMonitorIntegration(group.key).displayName">
                                        <i class="fas fa-edit" aria-hidden="true"></i>
                                    </a>
                                    <form v-if="data.can_manage_integrations && selectedMonitorIntegration(group.key) && selectedMonitorIntegration(group.key).deleteUrl"
                                          class="ops-inline-form" method="post" :action="selectedMonitorIntegration(group.key).deleteUrl"
                                          @submit="confirmDelete($event, selectedMonitorIntegration(group.key))">
                                        <input type="hidden" name="csrfmiddlewaretoken" :value="data.csrf">
                                        <button class="btn btn-sm btn-outline-danger ops-integration-picker-action" type="submit"
                                                :title="'删除 ' + selectedMonitorIntegration(group.key).displayName"
                                                :aria-label="'删除 ' + selectedMonitorIntegration(group.key).displayName">
                                            <i class="fas fa-trash" aria-hidden="true"></i>
                                        </button>
                                    </form>
                                </div>
                                <div v-if="selectedMonitorIntegration(group.key)" class="ops-integration-picker-meta" role="status">
                                    <span class="ops-badge" :class="{ 'ops-badge-muted': !selectedMonitorIntegration(group.key).enabled }">
                                        [[ selectedMonitorIntegration(group.key).enabled ? '已启用' : '已停用' ]]
                                    </span>
                                    <span v-if="selectedMonitorIntegration(group.key).updatedAt">更新于 [[ formatDisplayDate(selectedMonitorIntegration(group.key).updatedAt) ]]</span>
                                </div>
                                <div v-else class="ops-integration-picker-empty">尚未配置</div>
                            </article>
                        </div>
                    </div>
                </section>

                <div v-else-if="kind === 'monitor-integrations'" class="ops-integration-page">
                    <div class="ops-integration-picker-grid">
                        <article class="ops-integration-picker" v-for="group in monitorIntegrationGroups" :key="group.key">
                            <div class="ops-integration-picker-head">
                                <div>
                                    <div class="ops-integration-picker-title">
                                        <i class="fas" :class="group.icon" aria-hidden="true"></i> [[ group.label ]]
                                    </div>
                                    <div class="ops-muted">[[ group.description ]]</div>
                                </div>
                                <span class="ops-integration-picker-count">[[ group.items.length ]] 个</span>
                            </div>
                            <label class="form-label" :for="'monitor-integrations-' + group.key + '-selector'">已配置连接</label>
                            <div class="ops-integration-picker-control">
                                <select class="form-control form-control-sm" :id="'monitor-integrations-' + group.key + '-selector'"
                                        v-model="monitorIntegrationSelections[group.key]" :disabled="!group.items.length">
                                    <option value="" disabled>[[ group.items.length ? ('选择 ' + group.label + ' 连接') : ('暂无 ' + group.label + ' 连接') ]]</option>
                                    <option v-for="integration in group.items" :key="integration.id" :value="integration.id">
                                        [[ integration.displayName ]] · [[ integration.enabled ? '已启用' : '已停用' ]]
                                    </option>
                                </select>
                                <a v-if="data.can_manage_integrations && selectedMonitorIntegration(group.key) && selectedMonitorIntegration(group.key).editUrl"
                                   class="btn btn-sm btn-outline-primary ops-integration-picker-action"
                                   :href="selectedMonitorIntegration(group.key).editUrl"
                                   :title="'编辑 ' + selectedMonitorIntegration(group.key).displayName"
                                   :aria-label="'编辑 ' + selectedMonitorIntegration(group.key).displayName">
                                    <i class="fas fa-edit" aria-hidden="true"></i>
                                </a>
                                <form v-if="data.can_manage_integrations && selectedMonitorIntegration(group.key) && selectedMonitorIntegration(group.key).deleteUrl"
                                      class="ops-inline-form" method="post" :action="selectedMonitorIntegration(group.key).deleteUrl"
                                      @submit="confirmDelete($event, selectedMonitorIntegration(group.key))">
                                    <input type="hidden" name="csrfmiddlewaretoken" :value="data.csrf">
                                    <button class="btn btn-sm btn-outline-danger ops-integration-picker-action" type="submit"
                                            :title="'删除 ' + selectedMonitorIntegration(group.key).displayName"
                                            :aria-label="'删除 ' + selectedMonitorIntegration(group.key).displayName">
                                        <i class="fas fa-trash" aria-hidden="true"></i>
                                    </button>
                                </form>
                            </div>
                            <div v-if="selectedMonitorIntegration(group.key)" class="ops-integration-picker-meta" role="status">
                                <span class="ops-badge" :class="{ 'ops-badge-muted': !selectedMonitorIntegration(group.key).enabled }">
                                    [[ selectedMonitorIntegration(group.key).enabled ? '已启用' : '已停用' ]]
                                </span>
                                <span v-if="selectedMonitorIntegration(group.key).updatedAt">更新于 [[ formatDisplayDate(selectedMonitorIntegration(group.key).updatedAt) ]]</span>
                            </div>
                            <div v-else class="ops-integration-picker-empty">尚未配置</div>
                        </article>
                    </div>

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

                </div>

                <section v-else-if="kind === 'alert-query'" class="ops-query-page">
                    <div class="ops-query-toolbar">
                        <div class="ops-query-view-tabs" role="tablist" aria-label="指标查询视图">
                            <button id="metric-tab-promql" type="button" role="tab"
                                    :class="{ active: metricView === 'promql' }"
                                    :aria-selected="metricView === 'promql' ? 'true' : 'false'"
                                    :tabindex="metricView === 'promql' ? 0 : -1"
                                    aria-controls="metric-view-promql"
                                    @click="changeMetricView('promql')"
                                    @keydown="handleMetricTabKeydown($event, 'promql')">
                                <i class="fas fa-terminal" aria-hidden="true"></i> PromQL
                            </button>
                            <button id="metric-tab-targets" type="button" role="tab"
                                    :class="{ active: metricView === 'targets' }"
                                    :aria-selected="metricView === 'targets' ? 'true' : 'false'"
                                    :tabindex="metricView === 'targets' ? 0 : -1"
                                    aria-controls="metric-view-targets"
                                    @click="changeMetricView('targets')"
                                    @keydown="handleMetricTabKeydown($event, 'targets')">
                                <i class="fas fa-bullseye" aria-hidden="true"></i> Targets
                            </button>
                            <button id="metric-tab-rules" type="button" role="tab"
                                    :class="{ active: metricView === 'rules' }"
                                    :aria-selected="metricView === 'rules' ? 'true' : 'false'"
                                    :tabindex="metricView === 'rules' ? 0 : -1"
                                    aria-controls="metric-view-rules"
                                    @click="changeMetricView('rules')"
                                    @keydown="handleMetricTabKeydown($event, 'rules')">
                                <i class="fas fa-list-alt" aria-hidden="true"></i> Rules
                            </button>
                        </div>
                        <div class="ops-query-source">
                            <label class="ops-query-source-label" for="metric-prometheus-source">
                                <i class="fas fa-server" aria-hidden="true"></i>
                                Prometheus
                            </label>
                            <select id="metric-prometheus-source"
                                    class="form-control form-control-sm ops-query-source-select"
                                    v-model="selectedMetricPrometheusId"
                                    :disabled="metricSourceLocked || !data.prometheus_configured || !metricPrometheusConfigs.length"
                                    :title="selectedMetricPrometheus ? selectedMetricPrometheus.name : '选择 Prometheus 连接'"
                                    @change="changeMetricPrometheus">
                                <option value="" disabled>[[ metricPrometheusConfigs.length ? '请选择连接' : '暂无可用连接' ]]</option>
                                <option v-for="config in metricPrometheusConfigs" :key="config.id"
                                        :value="config.id" :title="config.name">[[ config.name ]]</option>
                            </select>
                        </div>
                    </div>

                    <div v-if="metricView === 'promql'" id="metric-view-promql" class="ops-query-promql-view"
                         role="tabpanel" aria-labelledby="metric-tab-promql">
                        <div class="ops-query-promql-toolbar">
                            <span class="ops-query-count">[[ queryPanels.length ]] 个查询</span>
                            <button class="btn btn-sm btn-outline-primary" type="button" @click="addMetricQueryPanel">
                                <i class="fas fa-plus" aria-hidden="true"></i> 新增查询
                            </button>
                        </div>
                        <article class="ops-query-panel" v-for="(panel, panelIndex) in queryPanels" :key="panel.id">
                            <div class="ops-query-panel-head">
                                <strong class="ops-query-panel-title">查询 [[ panelIndex + 1 ]]</strong>
                                <span class="ops-query-panel-state" :class="'is-' + metricQueryStatus(panel).key">
                                    [[ metricQueryStatus(panel).label ]]
                                </span>
                                <button class="ops-query-remove-button" type="button"
                                        :disabled="queryPanels.length === 1 || panel.loading" title="删除此查询" aria-label="删除此查询"
                                        @click="removeMetricQueryPanel(panel.id)">
                                    <i class="fas fa-trash" aria-hidden="true"></i>
                                </button>
                            </div>
                            <form class="ops-query-form" :aria-busy="panel.loading ? 'true' : 'false'" @submit.prevent="executeMetricQuery(panel)">
                                <div class="ops-query-field">
                                    <div class="ops-query-field-head">
                                        <label class="form-label" :for="'metric-query-' + panel.id">PromQL</label>
                                        <span class="ops-query-counter" :class="{ 'is-near-limit': panel.query.length >= 1800 }">[[ panel.query.length ]]/2000</span>
                                    </div>
                                    <textarea class="form-control ops-query-input" :id="'metric-query-' + panel.id"
                                              v-model="panel.query" name="query" rows="2" maxlength="2000"
                                              placeholder="up" autocomplete="off" spellcheck="false" :disabled="panel.loading"
                                              :aria-invalid="panel.error ? 'true' : 'false'"
                                              @input="resetMetricQueryResult(panel)"
                                              @keydown.ctrl.enter.prevent="executeMetricQuery(panel)"
                                              @keydown.meta.enter.prevent="executeMetricQuery(panel)"></textarea>
                                </div>
                                <button class="btn btn-sm btn-primary ops-query-submit" type="submit"
                                        :disabled="panel.loading || !canExecuteMetricQuery"
                                        :title="canExecuteMetricQuery ? '执行查询' : (metricPrometheusConfigs.length ? '请选择 Prometheus 连接' : 'Prometheus 尚不可用')">
                                    <i class="fas" :class="panel.loading ? 'fa-spinner fa-spin' : 'fa-search'" aria-hidden="true"></i>
                                    [[ panel.loading ? '查询中' : '运行' ]]
                                </button>
                            </form>
                            <div v-if="panel.loading" class="ops-query-message is-loading" role="status" aria-live="polite">
                                <i class="fas fa-spinner fa-spin" aria-hidden="true"></i>
                                <span>正在等待 Prometheus 返回结果</span>
                            </div>
                            <div v-else-if="panel.error" class="ops-query-message is-error" role="alert">
                                <i class="fas fa-exclamation-circle" aria-hidden="true"></i>
                                <span>[[ panel.error ]]</span>
                            </div>
                            <div v-else-if="panel.hasExecuted && panel.table.rows.length">
                                <div class="ops-query-result-head">
                                    <div class="ops-query-summary">
                                        <span class="text-success"><i class="fas fa-check-circle mr-1" aria-hidden="true"></i>返回 <strong>[[ panel.table.rows.length ]]</strong> 行</span>
                                        <span>类型 <strong>[[ panel.table.result_type || '-' ]]</strong></span>
                                        <span>标签 <strong>[[ panel.table.label_columns.length ]]</strong></span>
                                        <span v-if="panel.durationMs !== null">耗时 <strong>[[ formatMetricDuration(panel.durationMs) ]]</strong></span>
                                        <span v-if="panel.table.truncated" class="ops-query-truncated">
                                            <i class="fas fa-exclamation-circle mr-1" aria-hidden="true"></i>已截断，共 [[ panel.table.total_rows ]] 行
                                        </span>
                                    </div>
                                </div>
                                <div class="table-responsive ops-query-table-wrap">
                                    <table class="table table-sm ops-query-table mb-0">
                                        <caption class="sr-only">PromQL 查询结果</caption>
                                        <thead>
                                            <tr>
                                                <th class="ops-query-row-number" scope="col">#</th>
                                                <th v-for="column in panel.table.label_columns" :key="column" scope="col">[[ column ]]</th>
                                                <th class="ops-query-time-column" scope="col">时间</th>
                                                <th class="ops-query-value-column" scope="col">值</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr v-for="(row, rowIndex) in panel.table.rows" :key="rowIndex">
                                                <th class="ops-query-row-number" scope="row">[[ rowIndex + 1 ]]</th>
                                                <td v-for="column in panel.table.label_columns" :key="column"><code>[[ metric(row.labels && row.labels[column]) ]]</code></td>
                                                <td class="ops-query-time-cell" :title="row.timestamp">[[ formatMetricTimestamp(row.timestamp) ]]</td>
                                                <td class="ops-query-value-cell"><code>[[ metric(row.value) ]]</code></td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                            <div v-else-if="panel.hasExecuted" class="ops-query-message is-empty" role="status">
                                <i class="fas fa-info-circle" aria-hidden="true"></i>
                                <span>查询完成，未返回匹配结果</span>
                                <span v-if="panel.durationMs !== null" class="ops-query-message-meta">[[ formatMetricDuration(panel.durationMs) ]]</span>
                            </div>
                        </article>
                    </div>

                    <div v-else-if="metricView === 'targets'" id="metric-view-targets" class="ops-metric-resource"
                         role="tabpanel" aria-labelledby="metric-tab-targets" :aria-busy="metricResources.targets.loading ? 'true' : 'false'">
                        <div class="ops-metric-resource-head">
                            <div class="ops-metric-resource-summary">
                                <strong>Targets</strong>
                                <span>总计 <b>[[ metricResources.targets.summary.total ]]</b></span>
                                <span class="is-success">Up <b>[[ metricResources.targets.summary.up ]]</b></span>
                                <span class="is-danger">Down <b>[[ metricResources.targets.summary.down ]]</b></span>
                                <span>未知 <b>[[ metricResources.targets.summary.unknown ]]</b></span>
                                <span v-if="metricResources.targets.summary.with_errors" class="is-warning">异常 <b>[[ metricResources.targets.summary.with_errors ]]</b></span>
                                <span v-if="metricResources.targets.durationMs !== null">刷新耗时 [[ formatMetricDuration(metricResources.targets.durationMs) ]]</span>
                                <span v-if="metricResources.targets.truncated" class="is-warning">已截断，共 [[ metricResources.targets.totalRows ]] 条</span>
                            </div>
                            <button class="btn btn-sm btn-outline-secondary ops-metric-resource-refresh" type="button"
                                    :disabled="metricResources.targets.loading || !canExecuteMetricQuery"
                                    title="刷新 Targets" aria-label="刷新 Targets" @click="loadMetricResource('targets', true)">
                                <i class="fas" :class="metricResources.targets.loading ? 'fa-spinner fa-spin' : 'fa-sync-alt'" aria-hidden="true"></i>
                            </button>
                        </div>
                        <div v-if="metricResources.targets.loading" class="ops-metric-resource-state" role="status" aria-live="polite">
                            <i class="fas fa-spinner fa-spin" aria-hidden="true"></i><span>正在加载 Targets</span>
                        </div>
                        <div v-else-if="metricResources.targets.error" class="ops-metric-resource-state is-error" role="alert">
                            <i class="fas fa-exclamation-circle" aria-hidden="true"></i><span>[[ metricResources.targets.error ]]</span>
                        </div>
                        <div v-else-if="metricResources.targets.rows.length" class="table-responsive ops-metric-resource-table-wrap">
                            <table class="table table-sm ops-metric-resource-table ops-targets-table mb-0">
                                <caption class="sr-only">Prometheus Targets</caption>
                                <thead><tr><th scope="col">#</th><th scope="col">健康状态</th><th scope="col">Instance</th><th scope="col">Job</th><th scope="col">Scrape Pool</th><th scope="col">最后抓取</th><th scope="col">耗时</th><th scope="col">Labels</th></tr></thead>
                                <tbody>
                                    <tr v-for="(row, rowIndex) in metricResources.targets.rows" :key="rowIndex">
                                        <th scope="row">[[ rowIndex + 1 ]]</th>
                                        <td>
                                            <span class="ops-metric-resource-status" :class="metricResourceStatusClass(row.health)">[[ row.health || 'unknown' ]]</span>
                                            <i v-if="row.hasError" class="fas fa-exclamation-circle ops-metric-row-error" title="目标存在抓取错误" aria-label="目标存在抓取错误"></i>
                                        </td>
                                        <td><code>[[ row.instance || '-' ]]</code></td>
                                        <td>[[ row.job || '-' ]]</td>
                                        <td>[[ row.scrapePool || '-' ]]</td>
                                        <td class="ops-metric-resource-time">[[ row.lastScrape ? formatDisplayDate(row.lastScrape) : '-' ]]</td>
                                        <td class="ops-metric-resource-duration">[[ formatMetricSeconds(row.lastScrapeDuration) ]]</td>
                                        <td><div v-if="row.labels.length" class="ops-metric-labels"><span v-for="label in row.labels" :key="label.name"><b>[[ label.name ]]</b>=<code>[[ label.value ]]</code></span></div><span v-else>-</span></td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                        <div v-else class="ops-metric-resource-state is-empty" role="status">
                            <i class="fas fa-info-circle" aria-hidden="true"></i><span>当前连接没有可展示的 Targets</span>
                        </div>
                    </div>

                    <div v-else id="metric-view-rules" class="ops-metric-resource"
                         role="tabpanel" aria-labelledby="metric-tab-rules" :aria-busy="metricResources.rules.loading ? 'true' : 'false'">
                        <div class="ops-metric-resource-head">
                            <div class="ops-metric-resource-summary">
                                <strong>Rules</strong>
                                <span>总计 <b>[[ metricResources.rules.summary.total ]]</b></span>
                                <span>告警 <b>[[ metricResources.rules.summary.alerting ]]</b></span>
                                <span>记录 <b>[[ metricResources.rules.summary.recording ]]</b></span>
                                <span v-if="metricResources.rules.summary.unhealthy" class="is-danger">异常 <b>[[ metricResources.rules.summary.unhealthy ]]</b></span>
                                <span v-if="metricResources.rules.summary.firing" class="is-danger">Firing <b>[[ metricResources.rules.summary.firing ]]</b></span>
                                <span v-if="metricResources.rules.summary.pending" class="is-warning">Pending <b>[[ metricResources.rules.summary.pending ]]</b></span>
                                <span v-if="metricResources.rules.durationMs !== null">刷新耗时 [[ formatMetricDuration(metricResources.rules.durationMs) ]]</span>
                                <span v-if="metricResources.rules.truncated" class="is-warning">已截断，共 [[ metricResources.rules.totalRows ]] 条</span>
                            </div>
                            <button class="btn btn-sm btn-outline-secondary ops-metric-resource-refresh" type="button"
                                    :disabled="metricResources.rules.loading || !canExecuteMetricQuery"
                                    title="刷新 Rules" aria-label="刷新 Rules" @click="loadMetricResource('rules', true)">
                                <i class="fas" :class="metricResources.rules.loading ? 'fa-spinner fa-spin' : 'fa-sync-alt'" aria-hidden="true"></i>
                            </button>
                        </div>
                        <div v-if="metricResources.rules.loading" class="ops-metric-resource-state" role="status" aria-live="polite">
                            <i class="fas fa-spinner fa-spin" aria-hidden="true"></i><span>正在加载 Rules</span>
                        </div>
                        <div v-else-if="metricResources.rules.error" class="ops-metric-resource-state is-error" role="alert">
                            <i class="fas fa-exclamation-circle" aria-hidden="true"></i><span>[[ metricResources.rules.error ]]</span>
                        </div>
                        <div v-else-if="metricResources.rules.rows.length" class="table-responsive ops-metric-resource-table-wrap">
                            <table class="table table-sm ops-metric-resource-table ops-rules-table mb-0">
                                <caption class="sr-only">Prometheus Rules</caption>
                                <thead><tr><th scope="col">#</th><th scope="col">规则</th><th scope="col">类型 / 状态</th><th scope="col">健康状态</th><th scope="col">表达式</th><th scope="col">持续时间</th><th scope="col">最近评估</th><th scope="col">活动告警</th><th scope="col">Labels</th></tr></thead>
                                <tbody>
                                    <tr v-for="(row, rowIndex) in metricResources.rules.rows" :key="rowIndex">
                                        <th scope="row">[[ rowIndex + 1 ]]</th>
                                        <td><strong>[[ row.name || '-' ]]</strong><span class="ops-cell-meta">[[ row.group || '-' ]]</span></td>
                                        <td><span>[[ row.type || '-' ]]</span><span v-if="row.state" class="ops-metric-resource-status" :class="metricResourceStatusClass(row.state)">[[ row.state ]]</span></td>
                                        <td>
                                            <span class="ops-metric-resource-status" :class="metricResourceStatusClass(row.health)">[[ row.health || 'unknown' ]]</span>
                                            <i v-if="row.hasError" class="fas fa-exclamation-circle ops-metric-row-error" title="规则存在评估错误" aria-label="规则存在评估错误"></i>
                                        </td>
                                        <td class="ops-metric-rule-query"><code>[[ row.query || '-' ]]</code></td>
                                        <td class="ops-metric-resource-duration">[[ formatMetricSeconds(row.duration) ]]</td>
                                        <td class="ops-metric-resource-time"><span>[[ row.lastEvaluation ? formatDisplayDate(row.lastEvaluation) : '-' ]]</span><span class="ops-cell-meta">耗时 [[ formatMetricSeconds(row.evaluationTime) ]]</span></td>
                                        <td class="ops-metric-active-alerts">[[ row.activeAlerts ]]</td>
                                        <td><div v-if="row.labels.length" class="ops-metric-labels"><span v-for="label in row.labels" :key="label.name"><b>[[ label.name ]]</b>=<code>[[ label.value ]]</code></span></div><span v-else>-</span></td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                        <div v-else class="ops-metric-resource-state is-empty" role="status">
                            <i class="fas fa-info-circle" aria-hidden="true"></i><span>当前连接没有可展示的 Rules</span>
                        </div>
                    </div>
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

                <section v-else-if="kind === 'alert-notification-list'" class="ops-notification-list-page">
                    <div class="ops-section-head">
                        <div>
                            <div class="ops-section-title">已配置通知渠道</div>
                            <div class="ops-muted">[[ alertNotificationIntegrations.length ]] 个渠道</div>
                        </div>
                        <a v-if="canConfigureNotifications && data.configure_url" class="btn btn-sm btn-primary" :href="data.configure_url">
                            <i class="fas fa-cog" aria-hidden="true"></i> 配置通知
                        </a>
                    </div>
                    <div v-if="!alertNotificationIntegrations.length" class="ops-empty ops-notification-list-empty">
                        <span>暂无已配置通知渠道</span>
                        <a v-if="canConfigureNotifications && data.configure_url" class="btn btn-sm btn-outline-primary" :href="data.configure_url">前往配置</a>
                    </div>
                    <div v-else class="table-responsive ops-notification-list-table-wrap">
                        <table class="table table-sm ops-notification-list-table mb-0">
                            <caption class="sr-only">已配置告警通知渠道</caption>
                            <thead>
                                <tr>
                                    <th scope="col">名称</th>
                                    <th scope="col">类型</th>
                                    <th scope="col">启用状态</th>
                                    <th scope="col">配置状态</th>
                                    <th scope="col">更新时间</th>
                                    <th v-if="canConfigureNotifications" scope="col">操作</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr v-for="integration in alertNotificationIntegrations" :key="integration.provider">
                                    <td><strong>[[ integration.name ]]</strong></td>
                                    <td><span class="ops-kind-label">[[ integration.providerLabel ]]</span></td>
                                    <td>
                                        <span class="ops-badge" :class="{ 'ops-badge-muted': !integration.enabled }">
                                            [[ integration.enabled ? '已启用' : '已停用' ]]
                                        </span>
                                    </td>
                                    <td>
                                        <span class="ops-badge" :class="integration.configured ? 'ops-badge-success' : 'ops-badge-muted'">
                                            [[ integration.configured ? '已配置' : '未配置' ]]
                                        </span>
                                    </td>
                                    <td class="ops-notification-list-time">[[ integration.updatedAt || '-' ]]</td>
                                    <td v-if="canConfigureNotifications">
                                        <a v-if="integration.configureUrl" class="btn btn-sm btn-outline-primary" :href="integration.configureUrl">
                                            <i class="fas fa-cog" aria-hidden="true"></i> 配置
                                        </a>
                                        <span v-else>-</span>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </section>

                <section v-else-if="kind === 'alert-notifications'">
                    <div v-if="data.test_message" class="alert alert-info">[[ data.test_message ]]</div>
                    <div v-if="!canConfigureNotifications" class="alert alert-secondary py-2" role="status">
                        当前账号仅有查看权限。
                    </div>
                    <div class="ops-grid two">
                        <div class="ops-card ops-notification-card" v-for="provider in alertProviders" :key="provider.key">
                            <form v-if="canConfigureNotifications" class="ops-form compact" method="post" :action="data.action" @submit="submitForm">
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
                                    <div v-if="provider.config.has_webhook" class="form-text">当前：已保存</div>
                                </div>
                                <div class="ops-actions">
                                    <button class="btn btn-primary" type="submit">保存</button>
                                    <button class="btn btn-outline-secondary" type="submit" :formaction="data.test_action" name="provider" :value="provider.key">测试[[ provider.label ]]</button>
                                </div>
                            </form>
                            <div v-else class="ops-notification-readonly">
                                <div class="ops-notification-head">
                                    <div>
                                        <div class="ops-section-title"><i class="fas" :class="'fa-' + provider.icon"></i> [[ provider.label ]]</div>
                                        <div class="ops-notification-readonly-name">[[ provider.config.name || provider.label ]]</div>
                                    </div>
                                    <span class="ops-badge ops-badge-muted">仅查看</span>
                                </div>
                                <div class="ops-notification-readonly-status">
                                    <span class="ops-badge" :class="{ 'ops-badge-muted': !provider.config.enabled }">
                                        [[ provider.config.enabled ? '已启用' : '已停用' ]]
                                    </span>
                                    <span class="ops-badge" :class="provider.config.configured ? 'ops-badge-success' : 'ops-badge-muted'">
                                        [[ provider.config.configured ? 'Webhook 已配置' : 'Webhook 未配置' ]]
                                    </span>
                                </div>
                            </div>
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
