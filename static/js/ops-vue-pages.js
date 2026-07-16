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

    const promqlFunctionNames = [
        'abs', 'absent', 'avg', 'ceil', 'changes', 'clamp', 'clamp_max', 'clamp_min', 'count',
        'delta', 'deriv', 'floor', 'histogram_quantile', 'holt_winters', 'idelta', 'increase',
        'irate', 'label_join', 'label_replace', 'max', 'min', 'predict_linear', 'quantile', 'rate',
        'resets', 'round', 'scalar', 'sort', 'sort_desc', 'sum', 'time', 'vector',
    ];
    const promqlFunctionSuggestions = promqlFunctionNames.map((name) => ({
        kind: 'function', label: '函数', query: name,
    }));

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
            suggestions: [],
            suggestionsVisible: false,
            suggestionIndex: -1,
            metricSuggestionKeyword: '',
            metricSuggestionLoading: false,
            metricSuggestionError: '',
            metricSuggestionTotal: 0,
            metricSuggestionShown: 0,
            metricSuggestionTruncated: false,
            metricSuggestionRequestVersion: 0,
            metricSuggestionTimer: null,
            table: normalizedTable,
            error: typeof error === 'string' ? error : '',
            loading: false,
            hasExecuted: Boolean(query || error || normalizedTable.result_type || normalizedTable.rows.length),
            durationMs: null,
            stickyScrollbarVisible: false,
            stickyScrollbarWidth: 0,
            stickyScrollbarLeft: 0,
            stickyScrollbarViewportWidth: 0,
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
            name: safeMetricResourceText(row.name, 240),
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
                url: typeof integration.url === 'string' ? integration.url.trim() : '',
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
        return integrations.reduce((items, integration) => {
            if (!integration || typeof integration !== 'object' || Array.isArray(integration)) return items;
            const provider = typeof integration.provider === 'string' ? integration.provider.trim() : '';
            const name = typeof integration.name === 'string' ? integration.name.trim() : '';
            const id = Number(integration.id);
            if (!provider || !name) return items;
            items.push({
                id: Number.isSafeInteger(id) && id > 0 ? String(id) : provider + '-' + items.length,
                provider,
                providerLabel: typeof integration.provider_label === 'string' && integration.provider_label.trim()
                    ? integration.provider_label.trim()
                    : provider,
                name,
                alertName: typeof integration.alert_name === 'string' ? integration.alert_name.trim() : '',
                alertType: typeof integration.alert_type === 'string' ? integration.alert_type.trim() : '',
                createdAt: typeof integration.created_at === 'string' ? integration.created_at : '',
                createdBy: typeof integration.created_by === 'string' ? integration.created_by.trim() : '',
                alertmanagerId: integration.alertmanager_id ? String(integration.alertmanager_id) : '',
                alertmanagerName: typeof integration.alertmanager_name === 'string' ? integration.alertmanager_name.trim() : '',
                enabled: Boolean(integration.enabled),
                configured: Boolean(integration.configured),
                updatedAt: typeof integration.updated_at === 'string' ? integration.updated_at : '',
                configureUrl: typeof integration.configure_url === 'string' ? integration.configure_url : '',
                editUrl: typeof integration.edit_url === 'string' ? integration.edit_url : '',
                deleteUrl: typeof integration.delete_url === 'string' ? integration.delete_url : '',
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
            const initialIntegrationKind = monitorPrometheusIntegrations.length || !monitorAlertmanagerIntegrations.length
                ? 'prometheus'
                : 'alertmanager';
            const alertNotificationIntegrations = normalizeAlertNotificationIntegrations(
                pageData.notification_integrations
            );
            return {
                kind: payload.kind,
                title: payload.title,
                data: pageData,
                reveal: {},
                revealError: '',
                queryPanels: [metricQueryPanel(1, pageData.query, pageData.table, pageData.error)],
                metricMetadataCache: {},
                metricMetadataRequests: {},
                metricSearchCache: {},
                nextQueryPanelId: 2,
                metricView: 'promql',
                metricResources: {
                    targets: metricResourceState('targets'),
                    rules: metricResourceState('rules'),
                },
                metricResourceFilters: { targets: '', rules: '' },
                expandedTargetCells: { name: [], instance: [], job: [], scrapePool: [], labels: [] },
                expandedRuleCells: { query: [], labels: [] },
                metricPrometheusConfigs,
                selectedMetricPrometheusId,
                monitorPrometheusIntegrations,
                monitorAlertmanagerIntegrations,
                monitorIntegrationKind: initialIntegrationKind,
                monitorIntegrationQuery: '',
                monitorIntegrationSelections: {
                    prometheus: monitorPrometheusIntegrations.some((item) => item.id === activePrometheusId)
                        ? activePrometheusId
                        : (monitorPrometheusIntegrations[0] ? monitorPrometheusIntegrations[0].id : ''),
                    alertmanager: monitorAlertmanagerIntegrations.some((item) => item.id === activeAlertmanagerId)
                        ? activeAlertmanagerId
                        : (monitorAlertmanagerIntegrations[0] ? monitorAlertmanagerIntegrations[0].id : ''),
                },
                alertNotificationIntegrations,
                alertNotificationProvider: alertNotificationIntegrations.some((item) => item.provider === 'feishu')
                    ? 'feishu'
                    : 'wecom',
                alertNotificationQuery: '',
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
            activeMonitorIntegrationGroup() {
                return this.monitorIntegrationGroups.find((group) => (
                    group.key === this.monitorIntegrationKind
                )) || this.monitorIntegrationGroups[0];
            },
            filteredMonitorIntegrationItems() {
                const group = this.activeMonitorIntegrationGroup || { items: [] };
                const query = typeof this.monitorIntegrationQuery === 'string'
                    ? this.monitorIntegrationQuery.trim().toLowerCase()
                    : '';
                if (!query) return group.items;
                return group.items.filter((integration) => {
                    const enabledText = integration.enabled ? '已启用 enabled' : '已停用 disabled';
                    return [
                        integration.displayName,
                        integration.name,
                        integration.url,
                        integration.kindLabel,
                        enabledText,
                    ].some((value) => String(value || '').toLowerCase().indexOf(query) !== -1);
                });
            },
            canConfigureNotifications() {
                if (this.data.can_manage_notifications !== undefined) {
                    return Boolean(this.data.can_manage_notifications);
                }
                return Boolean(this.data.configure_url);
            },
            alertNotificationGroups() {
                const providers = [
                    { key: 'feishu', label: '飞书', icon: 'fa-paper-plane' },
                    { key: 'wecom', label: '企业微信', icon: 'fa-comments' },
                ];
                return providers.map((provider) => Object.assign({}, provider, {
                    items: this.alertNotificationIntegrations.filter((item) => item.provider === provider.key),
                }));
            },
            activeAlertNotificationGroup() {
                return this.alertNotificationGroups.find((group) => (
                    group.key === this.alertNotificationProvider
                )) || this.alertNotificationGroups[0];
            },
            filteredAlertNotificationIntegrations() {
                const group = this.activeAlertNotificationGroup || { items: [] };
                const query = typeof this.alertNotificationQuery === 'string'
                    ? this.alertNotificationQuery.trim().toLowerCase()
                    : '';
                if (!query) return group.items;
                return group.items.filter((integration) => {
                    const enabledText = integration.enabled ? '已启用 enabled' : '已停用 disabled';
                    const configuredText = integration.configured ? '已配置 configured' : '未配置 unconfigured';
                    return [
                        integration.name,
                        integration.alertName,
                        integration.alertType,
                        integration.alertmanagerName,
                        integration.createdAt,
                        integration.createdBy,
                        integration.providerLabel,
                        enabledText,
                        configuredText,
                        integration.updatedAt,
                    ].some((value) => String(value || '').toLowerCase().indexOf(query) !== -1);
                });
            },
            alertNotificationEnabledCount() {
                return this.alertNotificationIntegrations.filter((integration) => integration.enabled).length;
            },
            alertNotificationConfiguredCount() {
                return this.alertNotificationIntegrations.filter((integration) => integration.configured).length;
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
                const providers = [
                    { key: 'feishu', label: '飞书', icon: 'paper-plane', config: notifications.feishu || {} },
                    { key: 'wecom', label: '企业微信', icon: 'comments', config: notifications.wecom || {} },
                ];
                if (this.data.editing_provider) {
                    return providers.filter((provider) => provider.key === this.data.editing_provider);
                }
                return providers;
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
            filteredMetricTargets() {
                return this.filterMetricResourceRows('targets', this.metricResources.targets.rows);
            },
            filteredMetricRules() {
                return this.filterMetricResourceRows('rules', this.metricResources.rules.rows);
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
                    this.measureQueryStickyBars();
                    const input = document.getElementById('metric-query-' + panel.id);
                    if (input) input.focus();
                });
            },
            removeMetricQueryPanel(panelId) {
                if (this.queryPanels.length <= 1) return;
                const panel = this.queryPanels.find((item) => item.id === panelId);
                if (panel && panel.metricSuggestionTimer) window.clearTimeout(panel.metricSuggestionTimer);
                this.queryPanels = this.queryPanels.filter((panel) => panel.id !== panelId);
                this.$nextTick(this.measureQueryStickyBars);
            },
            clearMetricQueryResult(panel) {
                panel.table = emptyMetricTable();
                panel.error = '';
                panel.durationMs = null;
                panel.hasExecuted = false;
                panel.stickyScrollbarVisible = false;
                panel.stickyScrollbarWidth = 0;
                panel.stickyScrollbarLeft = 0;
                panel.stickyScrollbarViewportWidth = 0;
            },
            queryTableWrap(panelId) {
                return document.getElementById('metric-query-table-' + panelId);
            },
            queryStickyBar(panelId) {
                return document.getElementById('metric-query-sticky-scroll-' + panelId);
            },
            syncQueryStickyScroll(panelId) {
                const tableWrap = this.queryTableWrap(panelId);
                const stickyBar = this.queryStickyBar(panelId);
                if (tableWrap && stickyBar && stickyBar.scrollLeft !== tableWrap.scrollLeft) {
                    stickyBar.scrollLeft = tableWrap.scrollLeft;
                }
            },
            measureQueryStickyBars() {
                if (this.kind !== 'alert-query') return;
                const viewportHeight = window.innerHeight || document.documentElement.clientHeight;
                this.queryPanels.forEach((panel) => {
                    const tableWrap = this.queryTableWrap(panel.id);
                    if (!tableWrap || !panel.hasExecuted || panel.error || !panel.table.rows.length) {
                        panel.stickyScrollbarVisible = false;
                        panel.stickyScrollbarWidth = 0;
                        panel.stickyScrollbarViewportWidth = 0;
                        return;
                    }
                    const rect = tableWrap.getBoundingClientRect();
                    const hasHorizontalOverflow = tableWrap.scrollWidth > tableWrap.clientWidth + 1;
                    panel.stickyScrollbarWidth = hasHorizontalOverflow ? tableWrap.scrollWidth : 0;
                    panel.stickyScrollbarLeft = rect.left;
                    panel.stickyScrollbarViewportWidth = rect.width;
                    const wasVisible = panel.stickyScrollbarVisible;
                    panel.stickyScrollbarVisible = Boolean(
                        hasHorizontalOverflow && rect.top < viewportHeight && rect.bottom > viewportHeight
                    );
                    if (panel.stickyScrollbarVisible && !wasVisible) {
                        this.$nextTick(() => this.syncQueryStickyScroll(panel.id));
                    } else {
                        this.syncQueryStickyScroll(panel.id);
                    }
                });
            },
            mirrorQueryTableScroll(panelId, event) {
                const stickyBar = this.queryStickyBar(panelId);
                const tableWrap = event && event.currentTarget;
                if (stickyBar && tableWrap && stickyBar.scrollLeft !== tableWrap.scrollLeft) {
                    stickyBar.scrollLeft = tableWrap.scrollLeft;
                }
            },
            mirrorQueryStickyScroll(panelId, event) {
                const tableWrap = this.queryTableWrap(panelId);
                const stickyBar = event && event.currentTarget;
                if (tableWrap && stickyBar && tableWrap.scrollLeft !== stickyBar.scrollLeft) {
                    tableWrap.scrollLeft = stickyBar.scrollLeft;
                }
            },
            resetMetricQueryResult(panel) {
                if (panel.loading) return;
                this.clearMetricQueryResult(panel);
            },
            metricQueryToken(input) {
                const cursor = Number.isInteger(input.selectionStart) ? input.selectionStart : input.value.length;
                const beforeCursor = input.value.slice(0, cursor);
                const match = beforeCursor.match(/[a-zA-Z_:][a-zA-Z0-9_:]*$/);
                return { value: match ? match[0] : beforeCursor.trim(), start: match ? cursor - match[0].length : 0, end: cursor };
            },
            metricMetadataState(prometheusId) {
                const id = normalizeMetricPrometheusId(prometheusId);
                return id ? this.metricMetadataCache[id] : null;
            },
            metricSuggestionCatalog(metrics, token) {
                const state = this.metricMetadataState(this.selectedMetricPrometheusId);
                const labels = state && Array.isArray(state.labels) ? state.labels : [];
                const normalizedToken = typeof token === 'string' ? token.toLowerCase() : '';
                const matches = (item) => !normalizedToken
                    || item.query.toLowerCase().indexOf(normalizedToken) !== -1;
                const metricSuggestions = (Array.isArray(metrics) ? metrics : [])
                    .map((name) => ({ kind: 'metric', label: '指标', query: name }));
                const supportingSuggestions = labels
                    .map((name) => ({ kind: 'label', label: '标签', query: name }))
                    .concat(promqlFunctionSuggestions)
                    .filter(matches);
                return metricSuggestions.slice(0, 50).concat(supportingSuggestions);
            },
            async loadMetricMetadata() {
                const selectedPrometheus = this.selectedMetricPrometheus;
                if (!selectedPrometheus) return;
                const id = selectedPrometheus.id;
                const existing = this.metricMetadataState(id);
                if (existing && existing.loaded) return;
                if (existing && existing.loading) return this.metricMetadataRequests[id];
                const state = { loading: true, loaded: false, metrics: [], labels: [], error: '' };
                this.metricMetadataCache[id] = state;
                const form = new URLSearchParams();
                form.set('prometheus_id', id);
                const request = (async () => {
                    try {
                        const body = await this.fetchMetricJson(this.data.metadata_url, form, 'metadata');
                        if (!this.metricResponseSourceIsCurrent(body, id)) return;
                        const uniqueNames = (values) => Array.from(new Set(
                            (Array.isArray(values) ? values : [])
                                .filter((value) => typeof value === 'string' && /^[a-zA-Z_:][a-zA-Z0-9_:]*$/.test(value))
                        )).sort();
                        const metadata = body.metadata && typeof body.metadata === 'object' ? body.metadata : {};
                        state.metrics = uniqueNames(body.metrics || body.metric_names || metadata.metrics || metadata.metric_names);
                        state.labels = uniqueNames(body.labels || body.label_names || metadata.labels || metadata.label_names);
                        state.loaded = true;
                    } catch (error) {
                        state.error = error instanceof TypeError
                            ? '无法加载当前 Prometheus 的提示数据'
                            : (safeMetricResourceText(error.message, 200) || '提示数据加载失败');
                    } finally {
                        state.loading = false;
                        delete this.metricMetadataRequests[id];
                    }
                })();
                this.metricMetadataRequests[id] = request;
                return request;
            },
            applyMetricQuerySuggestions(panel, token, metrics) {
                panel.suggestions = this.metricSuggestionCatalog(metrics, token);
                panel.suggestionsVisible = panel.suggestions.length > 0
                    || panel.metricSuggestionLoading
                    || Boolean(panel.metricSuggestionError);
                panel.suggestionIndex = panel.suggestions.length ? 0 : -1;
            },
            metricSearchCacheKey(prometheusId, keyword) {
                return normalizeMetricPrometheusId(prometheusId) + ':' + keyword.toLowerCase();
            },
            async searchMetricNames(panel, prometheusId, keyword, requestVersion) {
                const cacheKey = this.metricSearchCacheKey(prometheusId, keyword);
                let result = this.metricSearchCache[cacheKey];
                try {
                    if (!result) {
                        const form = new URLSearchParams();
                        form.set('prometheus_id', prometheusId);
                        form.set('keyword', keyword);
                        const body = await this.fetchMetricJson(this.data.metadata_url, form, 'metadata');
                        if (!this.metricResponseSourceIsCurrent(body, prometheusId)) return;
                        const metadata = body.metadata && typeof body.metadata === 'object' ? body.metadata : {};
                        const values = body.metrics || body.metric_names || metadata.metrics || metadata.metric_names;
                        const metrics = Array.from(new Set(
                            (Array.isArray(values) ? values : []).filter(
                                (value) => typeof value === 'string' && /^[a-zA-Z_:][a-zA-Z0-9_:]*$/.test(value)
                            )
                        )).slice(0, 50);
                        const rawTotal = body.metric_total !== undefined ? body.metric_total : metadata.metric_total;
                        const parsedTotal = Number(rawTotal);
                        result = {
                            metrics,
                            total: Number.isFinite(parsedTotal) && parsedTotal >= metrics.length
                                ? parsedTotal : metrics.length,
                            truncated: Boolean(
                                body.metric_truncated !== undefined
                                    ? body.metric_truncated : metadata.metric_truncated
                            ),
                        };
                        this.metricSearchCache[cacheKey] = result;
                    }
                    if (panel.metricSuggestionRequestVersion !== requestVersion
                            || this.selectedMetricPrometheusId !== prometheusId
                            || panel.metricSuggestionKeyword !== keyword) return;
                    panel.metricSuggestionTotal = result.total;
                    panel.metricSuggestionShown = result.metrics.length;
                    panel.metricSuggestionTruncated = result.truncated || result.total > result.metrics.length;
                    this.applyMetricQuerySuggestions(panel, keyword, result.metrics);
                } catch (error) {
                    if (panel.metricSuggestionRequestVersion !== requestVersion
                            || this.selectedMetricPrometheusId !== prometheusId
                            || panel.metricSuggestionKeyword !== keyword) return;
                    panel.metricSuggestionError = error instanceof TypeError
                        ? '无法搜索当前 Prometheus 的指标'
                        : (safeMetricResourceText(error.message, 200) || '指标搜索失败');
                    this.applyMetricQuerySuggestions(panel, keyword, []);
                } finally {
                    if (panel.metricSuggestionRequestVersion === requestVersion
                            && this.selectedMetricPrometheusId === prometheusId
                            && panel.metricSuggestionKeyword === keyword) {
                        panel.metricSuggestionLoading = false;
                        this.applyMetricQuerySuggestions(
                            panel, keyword, result && Array.isArray(result.metrics) ? result.metrics : []
                        );
                    }
                }
            },
            updateMetricQuerySuggestions(panel, event) {
                if (panel.loading) return;
                const input = event && event.target ? event.target : document.getElementById('metric-query-' + panel.id);
                if (!input) return;
                const token = this.metricQueryToken(input).value.toLowerCase();
                const prometheusId = normalizeMetricPrometheusId(this.selectedMetricPrometheusId);
                if (panel.metricSuggestionTimer) window.clearTimeout(panel.metricSuggestionTimer);
                panel.metricSuggestionRequestVersion += 1;
                panel.metricSuggestionKeyword = token;
                panel.metricSuggestionLoading = false;
                panel.metricSuggestionError = '';
                panel.metricSuggestionTotal = 0;
                panel.metricSuggestionShown = 0;
                panel.metricSuggestionTruncated = false;
                this.applyMetricQuerySuggestions(panel, token, []);
                this.loadMetricMetadata().then(() => {
                    if (panel.metricSuggestionKeyword === token
                            && this.selectedMetricPrometheusId === prometheusId) {
                        const cachedResult = token
                            ? this.metricSearchCache[this.metricSearchCacheKey(prometheusId, token)]
                            : null;
                        this.applyMetricQuerySuggestions(
                            panel, token, cachedResult && Array.isArray(cachedResult.metrics)
                                ? cachedResult.metrics : []
                        );
                    }
                });
                if (!token || !prometheusId) return;
                const cacheKey = this.metricSearchCacheKey(prometheusId, token);
                const cached = this.metricSearchCache[cacheKey];
                if (cached) {
                    panel.metricSuggestionTotal = cached.total;
                    panel.metricSuggestionShown = cached.metrics.length;
                    panel.metricSuggestionTruncated = cached.truncated || cached.total > cached.metrics.length;
                    this.applyMetricQuerySuggestions(panel, token, cached.metrics);
                    return;
                }
                const requestVersion = panel.metricSuggestionRequestVersion;
                panel.metricSuggestionLoading = true;
                this.applyMetricQuerySuggestions(panel, token, []);
                panel.metricSuggestionTimer = window.setTimeout(() => {
                    panel.metricSuggestionTimer = null;
                    this.searchMetricNames(panel, prometheusId, token, requestVersion);
                }, 200);
            },
            hideMetricQuerySuggestions(panel) {
                window.setTimeout(() => {
                    panel.suggestionsVisible = false;
                    panel.suggestionIndex = -1;
                }, 120);
            },
            selectMetricQuerySuggestion(panel, suggestion) {
                if (!suggestion || panel.loading) return;
                const input = document.getElementById('metric-query-' + panel.id);
                if (!input) return;
                const token = this.metricQueryToken(input);
                const functionSuggestion = suggestion.kind === 'function';
                const replacement = suggestion.query + (functionSuggestion ? '()' : '');
                panel.query = input.value.slice(0, token.start) + replacement + input.value.slice(token.end);
                this.resetMetricQueryResult(panel);
                panel.suggestionsVisible = false;
                panel.suggestionIndex = -1;
                this.$nextTick(() => {
                    const cursor = token.start + replacement.length - (functionSuggestion ? 1 : 0);
                    input.focus();
                    input.setSelectionRange(cursor, cursor);
                });
            },
            handleMetricQueryKeydown(event, panel) {
                if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
                    event.preventDefault();
                    panel.suggestionsVisible = false;
                    this.executeMetricQuery(panel);
                    return;
                }
                if (!panel.suggestionsVisible || !panel.suggestions.length) return;
                if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
                    event.preventDefault();
                    const direction = event.key === 'ArrowDown' ? 1 : -1;
                    panel.suggestionIndex = (panel.suggestionIndex + direction + panel.suggestions.length) % panel.suggestions.length;
                } else if (event.key === 'Enter') {
                    event.preventDefault();
                    this.selectMetricQuerySuggestion(panel, panel.suggestions[panel.suggestionIndex]);
                } else if (event.key === 'Escape') {
                    event.preventDefault();
                    panel.suggestionsVisible = false;
                    panel.suggestionIndex = -1;
                }
            },
            clearMetricResource(kind) {
                const state = this.metricResources[kind];
                if (!state) return;
                this.resetMetricResourceUi(kind);
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
                this.metricSearchCache = {};
                this.queryPanels.forEach((panel) => {
                    if (panel.metricSuggestionTimer) window.clearTimeout(panel.metricSuggestionTimer);
                    panel.metricSuggestionTimer = null;
                    panel.metricSuggestionRequestVersion += 1;
                    this.clearMetricQueryResult(panel);
                    panel.suggestions = [];
                    panel.suggestionsVisible = false;
                    panel.suggestionIndex = -1;
                    panel.metricSuggestionKeyword = '';
                    panel.metricSuggestionLoading = false;
                    panel.metricSuggestionError = '';
                    panel.metricSuggestionTotal = 0;
                    panel.metricSuggestionShown = 0;
                    panel.metricSuggestionTruncated = false;
                });
                this.clearMetricResource('targets');
                this.clearMetricResource('rules');
                if (this.metricView !== 'promql' && this.selectedMetricPrometheus) {
                    this.loadMetricResource(this.metricView, true);
                }
            },
            async fetchMetricJson(url, form, context) {
                const queryContext = context === 'query';
                const metadataContext = context === 'metadata';
                const messages = queryContext ? {
                    missing: '指标查询接口不可用，请刷新页面后重试',
                    forbidden: '当前账号无权执行指标查询',
                    format: '指标查询响应格式异常，请稍后重试',
                    unavailable: '指标查询服务暂时不可用，请稍后重试',
                    failed: '指标查询失败',
                } : metadataContext ? {
                    missing: '指标提示接口不可用，仍可手工输入查询',
                    forbidden: '当前账号无权加载指标提示',
                    format: '指标提示响应格式异常',
                    unavailable: '指标提示服务暂时不可用',
                    failed: '指标提示加载失败',
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
                if (force) this.resetMetricResourceUi(kind);
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
                    this.$nextTick(this.measureQueryStickyBars);
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
            resetMetricResourceUi(kind) {
                if (this.metricResourceFilters[kind] !== undefined) this.metricResourceFilters[kind] = '';
                if (kind === 'targets') {
                    this.expandedTargetCells.name = [];
                    this.expandedTargetCells.instance = [];
                    this.expandedTargetCells.job = [];
                    this.expandedTargetCells.scrapePool = [];
                    this.expandedTargetCells.labels = [];
                }
                if (kind === 'rules') {
                    this.expandedRuleCells.query = [];
                    this.expandedRuleCells.labels = [];
                }
            },
            metricResourceSearchText(kind, row) {
                const labels = Array.isArray(row.labels)
                    ? row.labels.map((label) => label.name + '=' + label.value).join(' ')
                    : '';
                const fields = kind === 'targets'
                    ? [row.name, row.instance, row.job, row.scrapePool, row.health, labels]
                    : [row.group, row.name, row.type, row.state, row.health, row.query, labels];
                return fields.map((value) => value || '').join(' ').toLocaleLowerCase();
            },
            filterMetricResourceRows(kind, rows) {
                const query = (this.metricResourceFilters[kind] || '').trim().toLocaleLowerCase();
                if (!query) return rows;
                return rows.filter((row) => this.metricResourceSearchText(kind, row).indexOf(query) !== -1);
            },
            formatMetricLabelsSummary(labels) {
                if (!Array.isArray(labels) || !labels.length) return '-';
                return labels.map((label) => label.name + '=' + label.value).join('  ');
            },
            isRuleCellExpanded(row, cell) {
                const expanded = this.expandedRuleCells[cell];
                return Array.isArray(expanded) && expanded.indexOf(row) !== -1;
            },
            toggleRuleCell(row, cell) {
                const expanded = this.expandedRuleCells[cell];
                if (!Array.isArray(expanded)) return;
                const index = expanded.indexOf(row);
                if (index === -1) expanded.push(row);
                else expanded.splice(index, 1);
            },
            handleRuleCellKeydown(event, row, cell) {
                if (!event || (event.key !== 'Enter' && event.key !== ' ')) return;
                event.preventDefault();
                this.toggleRuleCell(row, cell);
            },
            isTargetCellExpanded(row, cell) {
                const expanded = this.expandedTargetCells[cell];
                return Array.isArray(expanded) && expanded.indexOf(row) !== -1;
            },
            toggleTargetCell(row, cell) {
                const expanded = this.expandedTargetCells[cell];
                if (!Array.isArray(expanded)) return;
                const index = expanded.indexOf(row);
                if (index === -1) expanded.push(row);
                else expanded.splice(index, 1);
            },
            handleTargetCellKeydown(event, row, cell) {
                if (!event || (event.key !== 'Enter' && event.key !== ' ')) return;
                event.preventDefault();
                this.toggleTargetCell(row, cell);
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
                            <div class="ops-section-title">监控对接列表</div>
                            <div class="ops-actions">
                                <a v-if="data.integration_url" class="btn btn-sm btn-outline-primary" :href="data.integration_url"><i class="fas fa-plug" aria-hidden="true"></i> 管理对接</a>
                                <a v-if="data.query_url" class="btn btn-sm btn-outline-secondary" :href="data.query_url">指标查询</a>
                                <a v-if="data.alert_settings_url" class="btn btn-sm btn-outline-dark" :href="data.alert_settings_url">告警设置</a>
                            </div>
                        </div>
                        <div class="ops-integration-filter">
                            <div class="ops-integration-filter-kind">
                                <label class="form-label" for="monitor-home-integration-kind">对接类型</label>
                                <select id="monitor-home-integration-kind" class="form-control form-control-sm"
                                        v-model="monitorIntegrationKind">
                                    <option v-for="group in monitorIntegrationGroups" :key="group.key" :value="group.key">
                                        [[ group.label ]]
                                    </option>
                                </select>
                            </div>
                            <div class="ops-integration-filter-query">
                                <div class="ops-integration-query-control">
                                    <i class="fas fa-search" aria-hidden="true"></i>
                                    <input id="monitor-home-integration-query" class="form-control form-control-sm"
                                           v-model.trim="monitorIntegrationQuery" aria-label="查询监控对接">
                                </div>
                            </div>
                        </div>
                        <div class="ops-integration-picker-grid">
                            <article class="ops-integration-picker">
                                <div class="ops-integration-picker-head">
                                    <div>
                                        <div class="ops-integration-picker-title">
                                            <i class="fas" :class="activeMonitorIntegrationGroup.icon" aria-hidden="true"></i> [[ activeMonitorIntegrationGroup.label ]]
                                        </div>
                                        <div class="ops-muted">[[ activeMonitorIntegrationGroup.description ]]</div>
                                    </div>
                                    <span class="ops-integration-picker-count">[[ filteredMonitorIntegrationItems.length ]] / [[ activeMonitorIntegrationGroup.items.length ]] 个</span>
                                </div>
                                <div v-if="filteredMonitorIntegrationItems.length" class="ops-integration-list">
                                    <div class="ops-integration-list-row" v-for="integration in filteredMonitorIntegrationItems" :key="integration.id">
                                        <div class="ops-integration-list-main">
                                            <strong>[[ integration.displayName ]]</strong>
                                            <code v-if="integration.url" class="ops-integration-address">[[ integration.url ]]</code>
                                            <span v-if="integration.updatedAt">更新于 [[ formatDisplayDate(integration.updatedAt) ]]</span>
                                        </div>
                                        <div class="ops-integration-list-side">
                                            <span class="ops-badge" :class="{ 'ops-badge-muted': !integration.enabled }">
                                                [[ integration.enabled ? '已启用' : '已停用' ]]
                                            </span>
                                            <a v-if="data.can_manage_integrations && integration.editUrl"
                                               class="btn btn-sm btn-outline-primary ops-integration-picker-action"
                                               :href="integration.editUrl"
                                               :title="'编辑 ' + integration.displayName"
                                               :aria-label="'编辑 ' + integration.displayName">
                                                <i class="fas fa-edit" aria-hidden="true"></i>
                                            </a>
                                            <form v-if="data.can_manage_integrations && integration.deleteUrl"
                                                  class="ops-inline-form" method="post" :action="integration.deleteUrl"
                                                  @submit="confirmDelete($event, integration)">
                                                <input type="hidden" name="csrfmiddlewaretoken" :value="data.csrf">
                                                <button class="btn btn-sm btn-outline-danger ops-integration-picker-action" type="submit"
                                                        :title="'删除 ' + integration.displayName"
                                                        :aria-label="'删除 ' + integration.displayName">
                                                    <i class="fas fa-trash" aria-hidden="true"></i>
                                                </button>
                                            </form>
                                        </div>
                                    </div>
                                </div>
                                <div v-else class="ops-integration-picker-empty">[[ activeMonitorIntegrationGroup.items.length ? '未找到匹配的对接' : '尚未配置' ]]</div>
                            </article>
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
                                    <div class="ops-query-input-shell">
                                        <textarea class="form-control ops-query-input" :id="'metric-query-' + panel.id"
                                                  v-model="panel.query" name="query" rows="2" maxlength="2000"
                                                  placeholder="输入指标名或函数，例如 rate" autocomplete="off" spellcheck="false" :disabled="panel.loading"
                                                  :aria-invalid="panel.error ? 'true' : 'false'"
                                                  :aria-expanded="panel.suggestionsVisible ? 'true' : 'false'"
                                                  :aria-controls="'metric-query-suggestions-' + panel.id"
                                                  aria-autocomplete="list"
                                                  @focus="updateMetricQuerySuggestions(panel, $event)"
                                                  @input="resetMetricQueryResult(panel); updateMetricQuerySuggestions(panel, $event)"
                                                  @blur="hideMetricQuerySuggestions(panel)"
                                                  @keydown="handleMetricQueryKeydown($event, panel)"></textarea>
                                        <div v-if="panel.suggestionsVisible" class="ops-query-suggestions"
                                             :id="'metric-query-suggestions-' + panel.id" role="listbox" aria-label="PromQL 指标、标签和函数提示">
                                            <button v-for="(suggestion, suggestionIndex) in panel.suggestions"
                                                    :key="suggestion.label + suggestion.query" type="button" role="option"
                                                    :aria-selected="panel.suggestionIndex === suggestionIndex ? 'true' : 'false'"
                                                    :class="{ 'is-active': panel.suggestionIndex === suggestionIndex }"
                                                    @mousedown.prevent="selectMetricQuerySuggestion(panel, suggestion)">
                                                <span class="ops-query-suggestion-kind" :class="'is-' + suggestion.kind">[[ suggestion.label ]]</span>
                                                <code>[[ suggestion.query ]][[ suggestion.kind === 'function' ? '()' : '' ]]</code>
                                            </button>
                                            <div v-if="panel.metricSuggestionLoading" class="ops-query-suggestion-status" role="status">
                                                正在搜索当前 Prometheus 的真实指标...
                                            </div>
                                            <div v-else-if="panel.metricSuggestionError" class="ops-query-suggestion-status is-error" role="status">
                                                [[ panel.metricSuggestionError ]]，仍可手工输入。
                                            </div>
                                            <div v-else-if="panel.metricSuggestionTruncated" class="ops-query-suggestion-status is-warning" role="status">
                                                共匹配 [[ panel.metricSuggestionTotal ]] 个指标，当前展示 [[ panel.metricSuggestionShown ]] 个，请继续缩小关键词。
                                            </div>
                                        </div>
                                    </div>
                                    <div v-if="metricMetadataState(selectedMetricPrometheusId) && metricMetadataState(selectedMetricPrometheusId).loading"
                                         class="ops-query-hint" role="status">正在加载当前 Prometheus 的指标和标签...</div>
                                    <div v-else-if="metricMetadataState(selectedMetricPrometheusId) && metricMetadataState(selectedMetricPrometheusId).error"
                                         class="ops-query-hint is-error" role="status">
                                        [[ metricMetadataState(selectedMetricPrometheusId).error ]]，仍可手工输入 PromQL。
                                    </div>
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
                                <div class="ops-query-table-wrap" :id="'metric-query-table-' + panel.id"
                                     @scroll="mirrorQueryTableScroll(panel.id, $event)">
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
                                <div v-show="panel.stickyScrollbarVisible" class="ops-query-sticky-scroll"
                                     :id="'metric-query-sticky-scroll-' + panel.id" aria-hidden="true"
                                     :style="{ left: panel.stickyScrollbarLeft + 'px', width: panel.stickyScrollbarViewportWidth + 'px' }"
                                     @scroll="mirrorQueryStickyScroll(panel.id, $event)">
                                    <div class="ops-query-sticky-scroll-width"
                                         :style="{ width: panel.stickyScrollbarWidth + 'px' }"></div>
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
                        <div class="ops-metric-resource-filter">
                            <label class="sr-only" for="metric-targets-filter">查询 Targets</label>
                            <i class="fas fa-search" aria-hidden="true"></i>
                            <input id="metric-targets-filter" v-model="metricResourceFilters.targets" class="form-control form-control-sm"
                                   type="search" placeholder="查询名称、Instance、Job、Scrape Pool、状态或 Labels" autocomplete="off">
                            <span class="ops-metric-resource-filter-count">匹配 [[ filteredMetricTargets.length ]] / 已加载 [[ metricResources.targets.rows.length ]]</span>
                        </div>
                        <div v-if="metricResources.targets.loading" class="ops-metric-resource-state" role="status" aria-live="polite">
                            <i class="fas fa-spinner fa-spin" aria-hidden="true"></i><span>正在加载 Targets</span>
                        </div>
                        <div v-else-if="metricResources.targets.error" class="ops-metric-resource-state is-error" role="alert">
                            <i class="fas fa-exclamation-circle" aria-hidden="true"></i><span>[[ metricResources.targets.error ]]</span>
                        </div>
                        <div v-else-if="filteredMetricTargets.length" class="table-responsive ops-metric-resource-table-wrap">
                            <table class="table table-sm ops-metric-resource-table ops-targets-table mb-0">
                                <caption class="sr-only">Prometheus Targets</caption>
                                <thead><tr><th scope="col">#</th><th scope="col">健康状态</th><th scope="col">名称</th><th scope="col">Instance</th><th scope="col">Job</th><th scope="col">Scrape Pool</th><th scope="col">最后抓取</th><th scope="col">耗时</th><th scope="col">Labels</th></tr></thead>
                                <tbody>
                                    <tr v-for="(row, rowIndex) in filteredMetricTargets" :key="rowIndex">
                                        <th scope="row">[[ rowIndex + 1 ]]</th>
                                        <td>
                                            <span class="ops-metric-resource-status" :class="metricResourceStatusClass(row.health)">[[ row.health || 'unknown' ]]</span>
                                            <i v-if="row.hasError" class="fas fa-exclamation-circle ops-metric-row-error" title="目标存在抓取错误" aria-label="目标存在抓取错误"></i>
                                        </td>
                                        <td class="ops-metric-target-text-cell ops-metric-expandable-cell" tabindex="0" role="button"
                                            :class="{ 'is-expanded': isTargetCellExpanded(row, 'name') }"
                                            :aria-expanded="isTargetCellExpanded(row, 'name') ? 'true' : 'false'"
                                            @dblclick="toggleTargetCell(row, 'name')" @keydown="handleTargetCellKeydown($event, row, 'name')"><span>[[ row.name || '-' ]]</span></td>
                                        <td class="ops-metric-target-text-cell ops-metric-expandable-cell" tabindex="0" role="button"
                                            :class="{ 'is-expanded': isTargetCellExpanded(row, 'instance') }"
                                            :aria-expanded="isTargetCellExpanded(row, 'instance') ? 'true' : 'false'"
                                            @dblclick="toggleTargetCell(row, 'instance')" @keydown="handleTargetCellKeydown($event, row, 'instance')"><code>[[ row.instance || '-' ]]</code></td>
                                        <td class="ops-metric-target-text-cell ops-metric-expandable-cell" tabindex="0" role="button"
                                            :class="{ 'is-expanded': isTargetCellExpanded(row, 'job') }"
                                            :aria-expanded="isTargetCellExpanded(row, 'job') ? 'true' : 'false'"
                                            @dblclick="toggleTargetCell(row, 'job')" @keydown="handleTargetCellKeydown($event, row, 'job')"><span>[[ row.job || '-' ]]</span></td>
                                        <td class="ops-metric-target-text-cell ops-metric-expandable-cell" tabindex="0" role="button"
                                            :class="{ 'is-expanded': isTargetCellExpanded(row, 'scrapePool') }"
                                            :aria-expanded="isTargetCellExpanded(row, 'scrapePool') ? 'true' : 'false'"
                                            @dblclick="toggleTargetCell(row, 'scrapePool')" @keydown="handleTargetCellKeydown($event, row, 'scrapePool')"><span>[[ row.scrapePool || '-' ]]</span></td>
                                        <td class="ops-metric-resource-time">[[ row.lastScrape ? formatDisplayDate(row.lastScrape) : '-' ]]</td>
                                        <td class="ops-metric-resource-duration">[[ formatMetricSeconds(row.lastScrapeDuration) ]]</td>
                                        <td class="ops-metric-target-label-cell ops-metric-expandable-cell" tabindex="0" role="button"
                                            :class="{ 'is-expanded': isTargetCellExpanded(row, 'labels') }"
                                            :aria-expanded="isTargetCellExpanded(row, 'labels') ? 'true' : 'false'"
                                            @dblclick="toggleTargetCell(row, 'labels')" @keydown="handleTargetCellKeydown($event, row, 'labels')"><div v-if="isTargetCellExpanded(row, 'labels') && row.labels.length" class="ops-metric-labels"><span v-for="label in row.labels" :key="label.name"><b>[[ label.name ]]</b>=<code>[[ label.value ]]</code></span></div><span v-else class="ops-metric-label-summary">[[ formatMetricLabelsSummary(row.labels) ]]</span></td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                        <div v-else class="ops-metric-resource-state is-empty" role="status">
                            <i class="fas fa-info-circle" aria-hidden="true"></i><span>[[ metricResources.targets.rows.length ? '没有匹配的 Targets' : '当前连接没有可展示的 Targets' ]]</span>
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
                        <div class="ops-metric-resource-filter">
                            <label class="sr-only" for="metric-rules-filter">查询 Rules</label>
                            <i class="fas fa-search" aria-hidden="true"></i>
                            <input id="metric-rules-filter" v-model="metricResourceFilters.rules" class="form-control form-control-sm"
                                   type="search" placeholder="查询规则、类型、状态、表达式或 Labels" autocomplete="off">
                            <span class="ops-metric-resource-filter-count">匹配 [[ filteredMetricRules.length ]] / 已加载 [[ metricResources.rules.rows.length ]]</span>
                        </div>
                        <div v-if="metricResources.rules.loading" class="ops-metric-resource-state" role="status" aria-live="polite">
                            <i class="fas fa-spinner fa-spin" aria-hidden="true"></i><span>正在加载 Rules</span>
                        </div>
                        <div v-else-if="metricResources.rules.error" class="ops-metric-resource-state is-error" role="alert">
                            <i class="fas fa-exclamation-circle" aria-hidden="true"></i><span>[[ metricResources.rules.error ]]</span>
                        </div>
                        <div v-else-if="filteredMetricRules.length" class="table-responsive ops-metric-resource-table-wrap">
                            <table class="table table-sm ops-metric-resource-table ops-rules-table mb-0">
                                <caption class="sr-only">Prometheus Rules</caption>
                                <thead><tr><th scope="col">#</th><th scope="col">规则</th><th scope="col">类型 / 状态</th><th scope="col">健康状态</th><th scope="col">表达式</th><th scope="col">持续时间</th><th scope="col">最近评估</th><th scope="col">活动告警</th><th scope="col">Labels</th></tr></thead>
                                <tbody>
                                    <tr v-for="(row, rowIndex) in filteredMetricRules" :key="rowIndex">
                                        <th scope="row">[[ rowIndex + 1 ]]</th>
                                        <td><strong>[[ row.name || '-' ]]</strong><span class="ops-cell-meta">[[ row.group || '-' ]]</span></td>
                                        <td><span>[[ row.type || '-' ]]</span><span v-if="row.state" class="ops-metric-resource-status" :class="metricResourceStatusClass(row.state)">[[ row.state ]]</span></td>
                                        <td>
                                            <span class="ops-metric-resource-status" :class="metricResourceStatusClass(row.health)">[[ row.health || 'unknown' ]]</span>
                                            <i v-if="row.hasError" class="fas fa-exclamation-circle ops-metric-row-error" title="规则存在评估错误" aria-label="规则存在评估错误"></i>
                                        </td>
                                        <td class="ops-metric-rule-query ops-metric-expandable-cell" tabindex="0" role="button"
                                            :class="{ 'is-expanded': isRuleCellExpanded(row, 'query') }"
                                            :aria-expanded="isRuleCellExpanded(row, 'query') ? 'true' : 'false'"
                                            @dblclick="toggleRuleCell(row, 'query')" @keydown="handleRuleCellKeydown($event, row, 'query')"><code>[[ row.query || '-' ]]</code></td>
                                        <td class="ops-metric-resource-duration">[[ formatMetricSeconds(row.duration) ]]</td>
                                        <td class="ops-metric-resource-time"><span>[[ row.lastEvaluation ? formatDisplayDate(row.lastEvaluation) : '-' ]]</span><span class="ops-cell-meta">耗时 [[ formatMetricSeconds(row.evaluationTime) ]]</span></td>
                                        <td class="ops-metric-active-alerts">[[ row.activeAlerts ]]</td>
                                        <td class="ops-metric-rule-label-cell ops-metric-expandable-cell" tabindex="0" role="button"
                                            :class="{ 'is-expanded': isRuleCellExpanded(row, 'labels') }"
                                            :aria-expanded="isRuleCellExpanded(row, 'labels') ? 'true' : 'false'"
                                            @dblclick="toggleRuleCell(row, 'labels')" @keydown="handleRuleCellKeydown($event, row, 'labels')"><div v-if="isRuleCellExpanded(row, 'labels') && row.labels.length" class="ops-metric-labels"><span v-for="label in row.labels" :key="label.name"><b>[[ label.name ]]</b>=<code>[[ label.value ]]</code></span></div><span v-else class="ops-metric-label-summary">[[ formatMetricLabelsSummary(row.labels) ]]</span></td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                        <div v-else class="ops-metric-resource-state is-empty" role="status">
                            <i class="fas fa-info-circle" aria-hidden="true"></i><span>[[ metricResources.rules.rows.length ? '没有匹配的 Rules' : '当前连接没有可展示的 Rules' ]]</span>
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
                    <section class="ops-notification-list-summary" aria-label="告警通知状态">
                        <span><strong>[[ alertNotificationIntegrations.length ]]</strong> 渠道</span>
                        <span class="is-enabled"><i class="fas fa-circle" aria-hidden="true"></i>[[ alertNotificationEnabledCount ]] 已启用</span>
                        <span class="is-configured"><i class="fas fa-circle" aria-hidden="true"></i>[[ alertNotificationConfiguredCount ]] 已配置</span>
                        <span class="is-current"><i class="fas fa-circle" aria-hidden="true"></i>[[ filteredAlertNotificationIntegrations.length ]] 当前显示</span>
                    </section>
                    <div class="ops-notification-filter">
                        <div class="ops-notification-filter-kind">
                            <label class="form-label" for="alert-notification-provider">通知类型</label>
                            <select id="alert-notification-provider" class="form-control form-control-sm"
                                    v-model="alertNotificationProvider">
                                <option v-for="group in alertNotificationGroups" :key="group.key" :value="group.key">
                                    [[ group.label ]]
                                </option>
                            </select>
                        </div>
                        <div class="ops-notification-filter-query">
                            <div class="ops-notification-query-control">
                                <input id="alert-notification-query" class="form-control form-control-sm"
                                       v-model.trim="alertNotificationQuery" placeholder="查询告警名称、类型、创建人"
                                       aria-label="查询告警通知">
                                <button v-if="alertNotificationQuery" type="button"
                                        class="ops-notification-query-clear"
                                        aria-label="清空查询" @click="alertNotificationQuery = ''">
                                    <i class="fas fa-times" aria-hidden="true"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                    <section v-if="filteredAlertNotificationIntegrations.length" class="ops-notification-table-panel">
                        <div class="ops-notification-table-wrap">
                            <table class="ops-notification-table">
                                <thead>
                                    <tr>
                                        <th>告警名称</th>
                                        <th>告警类型</th>
                                        <th>Alertmanager 名称</th>
                                        <th>状态</th>
                                        <th>创建时间</th>
                                        <th>创建人员</th>
                                        <th><span class="visually-hidden">操作</span></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr v-for="integration in filteredAlertNotificationIntegrations" :key="integration.id">
                                        <td>
                                            <strong class="ops-notification-table-name">[[ integration.alertName || integration.name ]]</strong>
                                            <small>[[ integration.name ]]</small>
                                        </td>
                                        <td><code>[[ integration.alertType || integration.providerLabel ]]</code></td>
                                        <td><span class="ops-notification-table-text">[[ integration.alertmanagerName || '-' ]]</span></td>
                                        <td>
                                            <span class="ops-notification-list-status" :class="integration.enabled ? 'is-enabled' : 'is-disabled'">
                                                <i class="fas fa-circle" aria-hidden="true"></i>[[ integration.enabled ? '已启用' : '已停用' ]]
                                            </span>
                                        </td>
                                        <td class="ops-notification-table-time">[[ integration.createdAt || '-' ]]</td>
                                        <td><span class="ops-notification-table-text">[[ integration.createdBy || '-' ]]</span></td>
                                        <td>
                                            <div class="ops-notification-list-actions">
                                                <a v-if="canConfigureNotifications && integration.editUrl"
                                                   class="ops-notification-icon-action"
                                                   :href="integration.editUrl"
                                                   :title="'配置 ' + (integration.alertName || integration.name)"
                                                   :aria-label="'配置 ' + (integration.alertName || integration.name)">
                                                    <i class="fas fa-cog" aria-hidden="true"></i>
                                                </a>
                                                <form v-if="canConfigureNotifications && integration.deleteUrl"
                                                      class="ops-inline-form" method="post" :action="integration.deleteUrl"
                                                      @submit="confirmDelete($event, integration)">
                                                    <input type="hidden" name="csrfmiddlewaretoken" :value="data.csrf">
                                                    <button class="ops-notification-icon-action is-delete" type="submit"
                                                            :title="'删除 ' + (integration.alertName || integration.name)"
                                                            :aria-label="'删除 ' + (integration.alertName || integration.name)">
                                                        <i class="fas fa-trash" aria-hidden="true"></i>
                                                    </button>
                                                </form>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </section>
                    <div v-else class="ops-empty ops-notification-list-empty">
                        <span>[[ activeAlertNotificationGroup.items.length ? '没有匹配的通知渠道' : '暂无已配置通知渠道' ]]</span>
                        <a v-if="canConfigureNotifications && data.configure_url" class="btn btn-sm btn-outline-primary" :href="data.configure_url">前往配置</a>
                    </div>
                </section>

                <section v-else-if="kind === 'alert-notifications'">
                    <div v-if="data.save_message" class="alert" :class="data.save_ok ? 'alert-success' : 'alert-danger'">[[ data.save_message ]]</div>
                    <div v-if="data.test_message" class="alert alert-info">[[ data.test_message ]]</div>
                    <div v-if="!canConfigureNotifications" class="alert alert-secondary py-2" role="status">
                        当前账号仅有查看权限。
                    </div>
                    <div class="ops-grid two">
                        <div class="ops-card ops-notification-card" v-for="provider in alertProviders" :key="provider.key">
                            <form v-if="canConfigureNotifications" class="ops-form compact" method="post" :action="provider.config.action || data.action" @submit="submitForm">
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
                                    <label class="form-label">告警名称</label>
                                    <input class="form-control" :name="provider.key + '_alert_name'" :value="provider.config.alert_name || ''" autocomplete="off">
                                </div>
                                <div>
                                    <label class="form-label">Alertmanager</label>
                                    <select class="form-control" :name="provider.key + '_alertmanager_id'" :value="provider.config.alertmanager_id || ''">
                                        <option value="">请选择 Alertmanager 对接</option>
                                        <option v-for="item in data.alertmanager_options || []" :key="item.id" :value="String(item.id)">
                                            [[ item.name ]]
                                        </option>
                                    </select>
                                </div>
                                <div>
                                    <label class="form-label">Webhook</label>
                                    <input class="form-control" :name="provider.key + '_webhook_url'" type="text" :value="provider.config.webhook_url || ''" :placeholder="provider.config.editing ? '留空保持现有 Webhook 不变' : '填写 Webhook 地址'" autocomplete="off">
                                    <div v-if="provider.config.has_webhook" class="form-text">当前：[[ provider.config.webhook_display || '已保存' ]]</div>
                                </div>
                                <div class="ops-actions">
                                    <button class="btn btn-primary" type="submit">[[ provider.config.editing ? '更新' : '保存' ]]</button>
                                    <button v-if="!provider.config.editing" class="btn btn-outline-secondary" type="submit" :formaction="data.test_action" name="provider" :value="provider.key">测试[[ provider.label ]]</button>
                                    <a v-if="provider.config.editing" class="btn btn-outline-secondary" :href="data.list_url">取消</a>
                                </div>
                            </form>
                            <div v-else class="ops-notification-readonly">
                                <div class="ops-notification-head">
                                    <div>
                                        <div class="ops-section-title"><i class="fas" :class="'fa-' + provider.icon"></i> [[ provider.label ]]</div>
                                        <div class="ops-notification-readonly-name">[[ provider.config.name || provider.label ]]</div>
                                        <div class="ops-muted">告警名称：[[ provider.config.alert_name || '-' ]]</div>
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
            this.handleQueryViewportChange = () => this.measureQueryStickyBars();
            window.addEventListener('scroll', this.handleQueryViewportChange, { passive: true });
            window.addEventListener('resize', this.handleQueryViewportChange, { passive: true });
            this.$nextTick(this.measureQueryStickyBars);
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
        beforeUnmount() {
            this.queryPanels.forEach((panel) => {
                if (panel.metricSuggestionTimer) window.clearTimeout(panel.metricSuggestionTimer);
            });
            window.removeEventListener('scroll', this.handleQueryViewportChange);
            window.removeEventListener('resize', this.handleQueryViewportChange);
        },
    }).mount(root);
})();
