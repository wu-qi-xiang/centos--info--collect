(function () {
    const root = document.getElementById('aiops-vue-root');
    const payloadNode = document.getElementById('aiops-payload');
    if (!root || !payloadNode) return;
    if (!window.Vue) {
        root.innerHTML = '<div class="vue-error">Vue 加载失败，请检查本地静态文件。</div>';
        return;
    }

    const payload = JSON.parse(payloadNode.textContent || '{}');
    const { createApp } = window.Vue;

    createApp({
        delimiters: ['[[', ']]'],
        data() {
            return {
                active: 'overview',
                data: payload,
				diagnostic: {
					hostId: '',
					window: '24h',
					loading: false,
					error: '',
					result: null,
				},
				alertGroups: {
					window: '24h',
					loading: false,
					error: '',
					results: null,
				},
				signalFreshness: {
					window: '24h',
					loading: false,
					error: '',
					results: null,
				},
				serviceImpacts: {
					window: '24h',
					loading: false,
					error: '',
					results: null,
				},
				serviceWorkbench: {
					serviceId: '',
					window: '24h',
					loading: false,
					error: '',
					result: null,
				},
				serviceReliability: {
					window: '24h',
					requestId: 0,
					loading: false,
					error: '',
					results: [],
					summary: null,
				},
				alertQuality: {
					loading: false,
					error: '',
					results: [],
					summary: null,
				},
				capacitySimulation: {
					cpu: 0,
					memory: 0,
					instances: 0,
					loading: false,
					error: '',
					result: null,
				},
				investigations: {
					loading: false, saving: false, error: '', results: [], selected: null, requestId: 0,
					filter: 'all',
					feedback: { loading: false, saving: false, error: '', results: [], form: { classification: 'effective', note: '' } },
					form: { title: '', hostId: '', serviceId: '', windowKey: '24h', start: '', end: '' },
				},
				k8sAnalyzer: { clusterId: '', namespace: 'default', loading: false, refreshing: false, error: '', result: null },
				operatorScan: { loading: false, error: '', result: null, window: '24h' },
				runbookRecommendations: { loading: false, initiating: false, error: '', results: [], outcome: null, outcomeLoading: false },
                tabs: [
                    { key: 'overview', label: '总览', icon: 'fas fa-gauge-high', group: 'analysis' },
                    { key: 'anomaly', label: '异常检测', icon: 'fas fa-wave-square', group: 'analysis' },
                    { key: 'correlation', label: '事件关联', icon: 'fas fa-project-diagram', group: 'analysis' },
                    { key: 'impact', label: '变更影响', icon: 'fas fa-code-branch', group: 'analysis' },
                    { key: 'quality', label: '告警质量', icon: 'fas fa-sliders', group: 'analysis' },
					...(payload.alert_groups_endpoint ? [{ key: 'alert-groups', label: '告警分组', icon: 'fas fa-layer-group', group: 'analysis' }] : []),
					...(payload.signal_freshness_endpoint ? [{ key: 'signal-freshness', label: '信号新鲜度', icon: 'fas fa-signal', group: 'analysis' }] : []),
					...(payload.service_impacts_endpoint ? [{ key: 'service-impacts', label: '服务影响', icon: 'fas fa-sitemap', group: 'analysis' }] : []),
					...(payload.service_reliability_endpoint ? [{ key: 'service-reliability', label: '可靠性评分', icon: 'fas fa-shield-halved', group: 'analysis' }] : []),
					...(payload.service_workbench_endpoint_template ? [{ key: 'service-workbench', label: '服务事件', icon: 'fas fa-table-list', group: 'analysis' }] : []),
                    { key: 'rca', label: '根因分析', icon: 'fas fa-magnifying-glass-chart', group: 'analysis' },
                    { key: 'capacity', label: '容量预测', icon: 'fas fa-chart-area', group: 'analysis' },
                    { key: 'investigation', label: '事件研判', icon: 'fas fa-timeline', group: 'investigation' },
					...(payload.operator_scan_endpoint ? [{ key: 'operator-scan', label: '主动巡检', icon: 'fas fa-stethoscope', group: 'investigation' }] : []),
					...(payload.k8s_analyzer_endpoint_template ? [{ key: 'k8s-analyzer', label: 'Kubernetes 分析', icon: 'fas fa-cubes', group: 'investigation' }] : []),
					{ key: 'diagnostic', label: '诊断证据', icon: 'fas fa-clipboard-list', group: 'investigation' },
                    { key: 'runbook', label: '运行手册', icon: 'fas fa-book-open', group: 'investigation' },
                    { key: 'ingest', label: '告警接入', icon: 'fas fa-bell', group: 'investigation' },
                ],
            };
        },
        methods: {
            selectTab(key) {
                this.active = key;
            },
            tabGroups() {
                return [
                    { key: 'analysis', label: '运维分析', detail: '信号、影响与可靠性洞察' },
                    { key: 'investigation', label: '事件调查', detail: '巡检、证据与处置建议' },
                ].map((group) => ({ ...group, tabs: this.tabs.filter((tab) => tab.group === group.key) }));
            },
            tabIndex(tab) {
                return this.tabs.findIndex((item) => item.key === tab.key);
            },
            onTabKeydown(event, index) {
                const keys = this.tabs.map((tab) => tab.key);
                let target = index;
                if (event.key === 'ArrowRight') target = (index + 1) % keys.length;
                else if (event.key === 'ArrowLeft') target = (index - 1 + keys.length) % keys.length;
                else if (event.key === 'Home') target = 0;
                else if (event.key === 'End') target = keys.length - 1;
                else return;
                event.preventDefault();
                this.selectTab(keys[target]);
            },
            levelClass(level) {
                if (level === 'critical') return 'danger';
                if (level === 'warning') return 'warning';
                return 'info';
            },
            metricBar(value) {
                const number = Number(value || 0);
                return Math.max(0, Math.min(100, number)) + '%';
            },
				items(value) {
				return Array.isArray(value) ? value : [];
			},
			investigationResults() {
				const results = this.items(this.investigations.results);
				if (this.investigations.filter === 'critical') return results.filter((item) => item.risk === 'critical');
				if (this.investigations.filter === 'partial') return results.filter((item) => item.status === 'partial');
				if (this.investigations.filter === 'completed') return results.filter((item) => item.status === 'completed');
				return results;
			},
			changeImpactCount() {
				const count = Number(this.data.counts && this.data.counts.change_impacts);
				return Number.isFinite(count) ? count : this.items(this.data.change_impacts).length;
			},
			riskLabel(state) {
				return { critical: '高风险', warning: '需关注', degraded: '已降级', healthy: '健康', normal: '正常', unknown: '未知' }[state] || state || '未知';
			},
			riskClass(state) {
				return { critical: 'danger', warning: 'warning', degraded: 'warning', healthy: 'success', normal: 'success', unknown: 'info' }[state] || 'info';
			},
			reliabilityStateLabel(state) {
				return { healthy: '健康', good: '良好', warning: '需关注', degraded: '已降级', critical: '高风险', unknown: '未知' }[state] || state || '未知';
			},
			reliabilityStateClass(state) {
				return { healthy: 'success', good: 'success', warning: 'warning', degraded: 'warning', critical: 'danger', unknown: 'info' }[state] || 'info';
			},
            evidenceLabel(kind) {
                const labels = {
                    open_alert: '未恢复告警',
                    failed_command: '失败执行',
                    deployment: '发布变更',
                    deployment_health: '发布健康评估',
                    incident: '事件工单',
                    alert: '告警',
                    alert_quality_feedback: '告警质量反馈',
					metric_state: '指标状态',
					ci_delivery: 'CI 发布状态',
                    prometheus_rule_revision: '监控规则变更',
                    audit: '审计记录',
                };
                return labels[kind] || kind || '关联证据';
            },
			async loadDiagnosticEvidence() {
				const config = this.data.diagnostic_evidence || {};
				if (!config.endpoint || !this.diagnostic.hostId) return;
				this.diagnostic.loading = true;
				this.diagnostic.error = '';
				this.diagnostic.result = null;
				try {
					const query = new URLSearchParams({
						host_id: String(this.diagnostic.hostId),
						window: this.diagnostic.window,
					});
					const response = await fetch(config.endpoint + '?' + query.toString(), {
						credentials: 'same-origin',
					});
					const result = await response.json();
					if (!response.ok || !result.ok) throw new Error(result.message || '诊断证据加载失败');
					this.diagnostic.result = result;
				} catch (error) {
					this.diagnostic.error = error.message || '诊断证据加载失败';
				} finally {
					this.diagnostic.loading = false;
				}
			},
			async loadAlertGroups() {
				const endpoint = this.data.alert_groups_endpoint;
				if (!endpoint) return;
				this.alertGroups.loading = true;
				this.alertGroups.error = '';
				this.alertGroups.results = null;
				try {
					const response = await fetch(endpoint + '?window=' + encodeURIComponent(this.alertGroups.window), {
						credentials: 'same-origin',
					});
					const result = await response.json();
					if (!response.ok || !result.ok) throw new Error(result.message || '告警分组加载失败');
					this.alertGroups.results = this.items(result.results);
				} catch (error) {
					this.alertGroups.error = error.message || '告警分组加载失败';
				} finally {
					this.alertGroups.loading = false;
				}
			},
				async loadSignalFreshness() {
				const endpoint = this.data.signal_freshness_endpoint;
				if (!endpoint) return;
				this.signalFreshness.loading = true;
				this.signalFreshness.error = '';
				this.signalFreshness.results = null;
				try {
					const response = await fetch(endpoint + '?window=' + encodeURIComponent(this.signalFreshness.window), {
						credentials: 'same-origin',
					});
					const result = await response.json();
					if (!response.ok || !result.ok) throw new Error(result.message || '信号新鲜度加载失败');
					this.signalFreshness.results = this.items(result.results);
				} catch (error) {
					this.signalFreshness.error = error.message || '信号新鲜度加载失败';
				} finally {
					this.signalFreshness.loading = false;
				}
				},
			async loadServiceImpacts() {
					const endpoint = this.data.service_impacts_endpoint;
					if (!endpoint) return;
					this.serviceImpacts.loading = true;
					this.serviceImpacts.error = '';
					this.serviceImpacts.results = null;
					try {
						const response = await fetch(endpoint + '?window=' + encodeURIComponent(this.serviceImpacts.window), {
							credentials: 'same-origin',
						});
						const result = await response.json();
						if (!response.ok || !result.ok) throw new Error(result.message || '服务影响加载失败');
						this.serviceImpacts.results = this.items(result.results);
					} catch (error) {
						this.serviceImpacts.error = error.message || '服务影响加载失败';
					} finally {
						this.serviceImpacts.loading = false;
					}
				},
				async loadServiceReliability() {
					const endpoint = this.data.service_reliability_endpoint;
					if (!endpoint) return;
					const requestId = ++this.serviceReliability.requestId;
					const requestedWindow = this.serviceReliability.window;
					this.serviceReliability.loading = true;
					this.serviceReliability.error = '';
					try {
						const query = new URLSearchParams({ window: requestedWindow });
						const response = await fetch(endpoint + '?' + query.toString(), { credentials: 'same-origin' });
						const result = await response.json();
						if (!response.ok || !result.ok) throw new Error(result.message || '服务可靠性评分加载失败');
						if (requestId !== this.serviceReliability.requestId) return;
						this.serviceReliability.summary = result.summary || null;
						this.serviceReliability.results = this.items(result.results || result.services || result.reliability);
					} catch (error) {
						if (requestId !== this.serviceReliability.requestId) return;
						this.serviceReliability.error = error.message || '服务可靠性评分加载失败';
					} finally {
						if (requestId === this.serviceReliability.requestId) this.serviceReliability.loading = false;
					}
				},
			async loadServiceWorkbench() {
					const template = this.data.service_workbench_endpoint_template;
					if (!template || !this.serviceWorkbench.serviceId) return;
					this.serviceWorkbench.loading = true;
					this.serviceWorkbench.error = '';
					this.serviceWorkbench.result = null;
					try {
						const endpoint = template.replace('{service_id}', encodeURIComponent(this.serviceWorkbench.serviceId));
						const response = await fetch(endpoint + '?window=' + encodeURIComponent(this.serviceWorkbench.window), {
							credentials: 'same-origin',
						});
						const result = await response.json();
						if (!response.ok || !result.ok) throw new Error(result.message || '服务事件加载失败');
						this.serviceWorkbench.result = result;
					} catch (error) {
						this.serviceWorkbench.error = error.message || '服务事件加载失败';
					} finally {
						this.serviceWorkbench.loading = false;
					}
				},
				async loadAlertQualityGovernance() {
					const endpoint = this.data.alert_quality_governance_endpoint;
					if (!endpoint) return;
					this.alertQuality.loading = true;
					this.alertQuality.error = '';
					try {
						const response = await fetch(endpoint, { credentials: 'same-origin' });
						const result = await response.json();
						if (!response.ok || !result.ok) throw new Error(result.message || '告警质量治理加载失败');
						this.alertQuality.results = this.items(result.suggestions);
						this.alertQuality.summary = result.summary || null;
					} catch (error) {
						this.alertQuality.error = error.message || '告警质量治理加载失败';
					} finally {
						this.alertQuality.loading = false;
					}
				},
				async runCapacitySimulation() {
					const endpoint = this.data.capacity_cost_simulation_endpoint;
					if (!endpoint) return;
					this.capacitySimulation.loading = true;
					this.capacitySimulation.error = '';
					try {
						const response = await fetch(endpoint, {
							method: 'POST', credentials: 'same-origin',
							headers: {
								'Content-Type': 'application/json',
								'X-CSRFToken': (this.data.integration && this.data.integration.csrf) || '',
							},
							body: JSON.stringify({
								cpu_delta_percent: Number(this.capacitySimulation.cpu),
								memory_delta_percent: Number(this.capacitySimulation.memory),
								instance_delta: Number(this.capacitySimulation.instances),
							}),
						});
						const result = await response.json();
						if (!response.ok || !result.ok) throw new Error(result.message || '容量仿真失败');
						this.capacitySimulation.result = result;
					} catch (error) {
						this.capacitySimulation.error = error.message || '容量仿真失败';
					} finally {
						this.capacitySimulation.loading = false;
					}
				},
				qualityStatusLabel(status) {
					return { open: '待审核', accepted: '已接受', rejected: '已拒绝', implemented: '已实施' }[status] || status || '-';
				},
				qualityStatusClass(status) {
					return { open: 'warning', accepted: 'info', rejected: 'danger', implemented: 'success' }[status] || 'info';
				},
			async reviewAlertQuality(item, status) {
					const template = this.data.alert_quality_governance_review_endpoint_template;
					if (!template || !item || !item.suggestion_key) return;
					item.reviewing = true;
					try {
						const endpoint = template.replace('{suggestion_key}', encodeURIComponent(item.suggestion_key));
						const response = await fetch(endpoint, {
							method: 'POST', credentials: 'same-origin',
							headers: {
								'Content-Type': 'application/json',
								'X-CSRFToken': (this.data.integration && this.data.integration.csrf) || '',
							},
							body: JSON.stringify({ status: status }),
						});
						const result = await response.json();
						if (!response.ok || !result.ok) throw new Error(result.message || '审核状态更新失败');
						item.review = result.review;
					} catch (error) {
						this.alertQuality.error = error.message || '审核状态更新失败';
					} finally {
						item.reviewing = false;
					}
				},
				async loadInvestigations() {
					const endpoint = this.data.investigations_endpoint;
					if (!endpoint) return;
					const requestId = ++this.investigations.requestId;
					this.investigations.loading = true; this.investigations.error = '';
					try {
						const response = await fetch(endpoint, { credentials: 'same-origin' });
						const result = await response.json();
						if (!response.ok || !result.ok) throw new Error(result.message || '调查列表加载失败');
						if (requestId !== this.investigations.requestId) return;
						this.investigations.results = this.items(result.results);
					} catch (error) {
						if (requestId === this.investigations.requestId) this.investigations.error = error.message || '调查列表加载失败';
					} finally {
						if (requestId === this.investigations.requestId) this.investigations.loading = false;
					}
				},
				async loadK8sAnalyzer(forceRefresh) {
					const state = this.k8sAnalyzer; const template = this.data.k8s_analyzer_endpoint_template;
					if (!template || !state.clusterId) return;
					state.refreshing = Boolean(forceRefresh && this.canRefreshK8sAnalyzer());
					state.loading = true; state.error = '';
					try { const endpoint = template.replace('{cluster_id}', encodeURIComponent(state.clusterId));
						const query = new URLSearchParams({ namespace: state.namespace || 'default' });
						if (state.refreshing) query.set('refresh', '1');
						const response = await fetch(endpoint + '?' + query.toString(), { credentials: 'same-origin' });
						const result = await response.json(); if (!response.ok || !result.ok) throw new Error(result.message || 'Kubernetes 分析失败'); state.result = result.result;
					} catch (error) { state.error = error.message || 'Kubernetes 分析失败'; } finally { state.loading = false; state.refreshing = false; }
				},
				refreshK8sAnalyzer() {
					if (!this.canRefreshK8sAnalyzer()) return;
					this.loadK8sAnalyzer(true);
				},
				canRefreshK8sAnalyzer() {
					return Boolean(this.data.k8s_analyzer_can_refresh || this.data.k8s_analyzer_refresh_allowed);
				},
				async loadOperatorScan() {
					const state = this.operatorScan; if (!this.data.operator_scan_endpoint) return; state.loading = true; state.error = '';
					try { const response = await fetch(this.data.operator_scan_endpoint + '?window=' + encodeURIComponent(state.window), { credentials: 'same-origin' }); const result = await response.json(); if (!response.ok || !result.ok) throw new Error(result.message || '主动巡检失败'); state.result = result.result; } catch (error) { state.error = error.message || '主动巡检失败'; } finally { state.loading = false; }
				},
				async loadRunbookRecommendations() {
					const endpoint = this.data.runbook_recommendations_endpoint; if (!endpoint) return;
					this.runbookRecommendations.loading = true; this.runbookRecommendations.error = '';
					try { const response = await fetch(endpoint, { credentials: 'same-origin' }); const result = await response.json(); if (!response.ok || !result.ok) throw new Error(result.message || '运行手册建议加载失败'); this.runbookRecommendations.results = this.items(result.results); } catch (error) { this.runbookRecommendations.error = error.message || '运行手册建议加载失败'; } finally { this.runbookRecommendations.loading = false; }
				},
				async loadRunbookOutcome(item) {
					if (!item || !this.data.runbook_recommendations_endpoint) return;
					this.runbookRecommendations.outcomeLoading = true; this.runbookRecommendations.error = '';
					try { const response = await fetch(this.data.runbook_recommendations_endpoint + item.id + '/outcome/', { credentials: 'same-origin' }); const result = await response.json(); if (!response.ok || !result.ok) throw new Error(result.message || '结果加载失败'); this.runbookRecommendations.outcome = result.outcome; } catch (error) { this.runbookRecommendations.error = error.message || '结果加载失败'; } finally { this.runbookRecommendations.outcomeLoading = false; }
				},
				async initiateRunbookRecommendation(item) {
					const template = this.data.runbook_recommendation_initiate_endpoint_template;
					if (!item || !template || this.runbookRecommendations.initiating) return;
					this.runbookRecommendations.initiating = true; this.runbookRecommendations.error = '';
					try {
						const endpoint = template.replace('{recommendation_id}', encodeURIComponent(item.id));
						const response = await fetch(endpoint, { method: 'POST', credentials: 'same-origin',
							headers: { 'Content-Type': 'application/json', 'X-CSRFToken': (this.data.integration || {}).csrf || '' },
							body: JSON.stringify({}), });
						const result = await response.json();
						if (!response.ok || !result.ok) throw new Error(result.message || '提交审批失败');
						if (result.recommendation) Object.assign(item, result.recommendation);
						await this.loadRunbookOutcome(item);
					} catch (error) { this.runbookRecommendations.error = error.message || '提交审批失败'; }
					finally { this.runbookRecommendations.initiating = false; }
				},
				async createInvestigation() {
					const state = this.investigations; const endpoint = this.data.investigations_endpoint;
					if (!endpoint || !state.form.title || !state.form.hostId || !state.form.start || !state.form.end) return;
					state.saving = true; state.error = '';
					try {
						const body = { title: state.form.title, window_key: state.form.windowKey,
							host_ids: [Number(state.form.hostId)], service_ids: state.form.serviceId ? [Number(state.form.serviceId)] : [],
							window_start: new Date(state.form.start).toISOString(), window_end: new Date(state.form.end).toISOString() };
						const response = await fetch(endpoint, { method: 'POST', credentials: 'same-origin',
							headers: { 'Content-Type': 'application/json', 'X-CSRFToken': (this.data.integration || {}).csrf || '' }, body: JSON.stringify(body) });
						const result = await response.json();
						if (!response.ok || !result.ok) throw new Error(result.message || '调查创建失败');
						state.selected = result.investigation; state.results.unshift(result.investigation); state.form.title = '';
					} catch (error) { state.error = error.message || '调查创建失败'; }
					finally { state.saving = false; }
				},
				formatInvestigationDateTime(value) {
					const date = new Date(value);
					const pad = (number) => String(number).padStart(2, '0');
					return date.getFullYear() + '-' + pad(date.getMonth() + 1) + '-' + pad(date.getDate())
						+ 'T' + pad(date.getHours()) + ':' + pad(date.getMinutes());
				},
				setInvestigationWindow() {
					const hours = { '1h': 1, '6h': 6, '24h': 24, '7d': 24 * 7 };
					const end = new Date();
					const start = new Date(end.getTime() - (hours[this.investigations.form.windowKey] || 24) * 3600000);
					this.investigations.form.start = this.formatInvestigationDateTime(start);
					this.investigations.form.end = this.formatInvestigationDateTime(end);
				},
				async loadInvestigationDetail(item) {
					if (!item || !this.data.investigations_endpoint) return;
					const requestId = ++this.investigations.requestId;
					this.investigations.loading = true; this.investigations.error = '';
					try {
						const response = await fetch(this.data.investigations_endpoint + item.id + '/', { credentials: 'same-origin' });
						const result = await response.json();
						if (!response.ok || !result.ok) throw new Error(result.message || '调查详情加载失败');
						if (requestId !== this.investigations.requestId) return;
						this.investigations.selected = result.investigation;
						this.investigations.feedback.form.note = '';
						this.investigations.feedback.error = '';
						this.investigations.feedback.results = [];
						await this.loadInvestigationFeedback(result.investigation.id);
					} catch (error) {
						if (requestId === this.investigations.requestId) this.investigations.error = error.message || '调查详情加载失败';
					} finally {
						if (requestId === this.investigations.requestId) this.investigations.loading = false;
					}
				},
				async loadInvestigationFeedback(investigationId) {
					const template = this.data.investigation_feedback_endpoint_template;
					if (!template || !investigationId) return;
					const state = this.investigations.feedback;
					state.loading = true; state.error = '';
					try {
						const endpoint = template.replace('{investigation_id}', encodeURIComponent(investigationId));
						const response = await fetch(endpoint, { credentials: 'same-origin' });
						const result = await response.json();
						if (!response.ok || !result.ok) throw new Error(result.message || '反馈加载失败');
						state.results = this.items(result.results);
					} catch (error) { state.error = error.message || '反馈加载失败'; }
					finally { state.loading = false; }
				},
				async submitInvestigationFeedback() {
					const selected = this.investigations.selected;
					const state = this.investigations.feedback;
					const template = this.data.investigation_feedback_endpoint_template;
					if (!selected || !template || state.saving) return;
					state.saving = true; state.error = '';
					try {
						const endpoint = template.replace('{investigation_id}', encodeURIComponent(selected.id));
						const response = await fetch(endpoint, {
							method: 'POST', credentials: 'same-origin',
							headers: { 'Content-Type': 'application/json', 'X-CSRFToken': (this.data.integration || {}).csrf || '' },
							body: JSON.stringify({ classification: state.form.classification, note: state.form.note || '' }),
						});
						const result = await response.json();
						if (!response.ok || !result.ok) throw new Error(result.message || '反馈提交失败');
						state.results.unshift(result.feedback);
						state.form.note = '';
					} catch (error) { state.error = error.message || '反馈提交失败'; }
					finally { state.saving = false; }
				},
				feedbackLabel(classification) {
					return { effective: '有效', partial: '部分有效', ineffective: '无效' }[classification] || classification || '-';
				},
				feedbackClass(classification) {
					return { effective: 'success', partial: 'warning', ineffective: 'danger' }[classification] || 'info';
				},
        },
		mounted() {
			const hashTabs = { analysis: 'anomaly', investigation: 'investigation', diagnostic: 'diagnostic' };
			const requestedTab = hashTabs[(window.location.hash || '').replace(/^#/, '')];
			if (requestedTab && this.tabs.some((tab) => tab.key === requestedTab)) this.active = requestedTab;
			this.setInvestigationWindow();
			this.loadAlertQualityGovernance();
			if (this.data.service_impacts_endpoint) this.loadServiceImpacts();
			if (this.data.service_reliability_endpoint) this.loadServiceReliability();
			if (this.data.runbook_recommendations_endpoint) this.loadRunbookRecommendations();
			if (this.data.investigations_endpoint) this.loadInvestigations();
		},
        template: `
            <div>
                <div class="aiops-head">
                    <div>
                        <h1>AIOps</h1>
                        <p>智能运维分析、事件关联、根因定位和自动处置建议</p>
                    </div>
                    <div class="aiops-updated">更新时间 [[ data.updated_at ]]</div>
                </div>

                <div class="aiops-tabs" role="tablist" aria-label="AIOps 工作区">
                    <section v-for="group in tabGroups()" :key="group.key" class="aiops-tab-group" :class="'aiops-tab-group-' + group.key">
                        <div class="aiops-tab-group-heading"><strong>[[ group.label ]]</strong><span>[[ group.detail ]]</span></div>
                        <div class="aiops-tab-group-items">
                            <button v-for="tab in group.tabs" :key="tab.key" type="button" role="tab" :id="'aiops-tab-' + tab.key" :aria-selected="active === tab.key" :tabindex="active === tab.key ? 0 : -1" :class="{ active: active === tab.key }" @click="selectTab(tab.key)" @keydown="onTabKeydown($event, tabIndex(tab))">
                                <i :class="tab.icon" aria-hidden="true"></i><span>[[ tab.label ]]</span>
                            </button>
                        </div>
                    </section>
                </div>

                <section v-if="active === 'overview'">
                    <div class="aiops-kpis">
                        <div class="aiops-card"><span>主机</span><strong>[[ data.counts.hosts ]]</strong></div>
                        <div class="aiops-card"><span>未恢复告警</span><strong>[[ data.counts.open_alerts ]]</strong></div>
                        <div class="aiops-card"><span>异常信号</span><strong>[[ data.counts.anomalies ]]</strong></div>
                        <div class="aiops-card"><span>事件簇</span><strong>[[ data.counts.correlations ]]</strong></div>
                        <div class="aiops-card"><span>失败命令</span><strong>[[ data.counts.failed_commands ]]</strong></div>
                        <div class="aiops-card"><span>变更影响</span><strong>[[ changeImpactCount() ]]</strong></div>
                        <div class="aiops-card"><span>通知失败</span><strong>[[ data.counts.notification_failures ]]</strong></div>
                    </div>
					<div class="aiops-grid two">
                        <div class="aiops-panel">
                            <h2>能力地图</h2>
                            <div class="aiops-capability" v-for="item in data.capabilities" :key="item.name">
                                <strong>[[ item.name ]]</strong>
                                <span>[[ item.detail ]]</span>
                            </div>
                        </div>
                        <div class="aiops-panel">
                            <h2>近期变更</h2>
                            <div v-if="!data.recent_changes.length" class="aiops-empty">暂无审计变更</div>
                            <div class="aiops-row compact" v-for="item in data.recent_changes" :key="item.created_at + item.action">
                                <div><strong>[[ item.action ]]</strong><span>[[ item.target || '-' ]] · [[ item.detail || '-' ]]</span></div>
                                <em>[[ item.created_at ]]</em>
                            </div>
                        </div>
                    </div>
                </section>

                <section v-if="active === 'anomaly'" class="aiops-panel">
                    <h2>异常检测</h2>
                    <div v-if="!data.anomalies.length" class="aiops-empty">当前没有明显异常信号</div>
                    <div class="aiops-row" v-for="item in data.anomalies" :key="item.host + item.metric + item.reason">
                        <div>
                            <strong>[[ item.host ]]</strong>
                            <span>[[ item.reason ]]</span>
                            <small>建议：[[ item.action ]]</small>
                        </div>
                        <b :class="'aiops-badge ' + levelClass(item.level)">[[ item.metric ]] [[ item.value ]]</b>
                    </div>
                </section>

                <section v-if="active === 'correlation'" class="aiops-panel">
                    <h2>事件关联</h2>
                    <div v-if="!data.correlations.length" class="aiops-empty">暂无可关联事件</div>
                    <div class="aiops-row" v-for="item in data.correlations" :key="item.title">
                        <div>
                            <strong>[[ item.title ]]</strong>
                            <span>[[ item.summary ]]</span>
                        </div>
                        <b class="aiops-score">[[ item.score ]]</b>
                    </div>
                </section>

                <section v-if="active === 'impact'" class="aiops-panel aiops-impact-panel">
                    <div class="aiops-panel-heading">
                        <div>
                            <h2>变更影响分析</h2>
                            <p class="aiops-muted">按时间窗口关联告警、失败执行与已发布变更，仅供人工研判。</p>
                        </div>
                        <b class="aiops-score">[[ changeImpactCount() ]] 条</b>
                    </div>
                    <div v-if="!items(data.change_impacts).length" class="aiops-empty">当前时间窗口内没有可确认的变更影响证据</div>
                    <article class="aiops-impact" v-for="item in items(data.change_impacts)" :key="item.target + item.observed_at">
                        <div class="aiops-impact-main">
                            <div class="aiops-impact-title">
                                <strong>[[ item.target || '变更影响记录' ]]</strong>
                                <b class="aiops-score">[[ item.score ]]</b>
                            </div>
                            <div class="aiops-impact-meta">
                                <span>观测时间：[[ item.observed_at ]]</span>
                            </div>
                        </div>
                        <ol v-if="items(item.evidence).length" class="aiops-impact-timeline">
                            <li v-for="evidence in items(item.evidence)" :key="evidence.kind + evidence.observed_at + evidence.summary">
                                <div>
                                    <strong>[[ evidenceLabel(evidence.kind) ]]</strong>
                                    <span>[[ evidence.summary ]]<template v-if="evidence.kind === 'deployment_health'"> · [[ evidence.status === 'healthy' ? '健康' : '不健康' ]] · [[ evidence.score ]] 分</template></span>
                                    <small>[[ evidence.observed_at ]]</small>
                                </div>
                                <a v-if="evidence.url" class="aiops-evidence-link" :href="evidence.url">查看记录</a>
                            </li>
                        </ol>
                    </article>
                </section>

                <section v-if="active === 'rca'" class="aiops-panel">
                    <h2>根因分析</h2>
                    <div v-if="!data.root_causes.length" class="aiops-empty">暂无足够证据生成根因判断</div>
                    <div class="aiops-row" v-for="item in data.root_causes" :key="item.host + item.cause">
                        <div>
                            <strong>[[ item.host ]] · [[ item.cause ]]</strong>
                            <span>证据：[[ item.evidence ]]</span>
                        </div>
                        <b class="aiops-score">[[ item.confidence ]]%</b>
                    </div>
                </section>

				<section v-if="active === 'quality'" class="aiops-panel">
					<div class="aiops-panel-heading">
						<div><h2>告警质量治理</h2><p class="aiops-muted">建议仅供人工审核，不会自动修改监控规则。</p></div>
						<button v-if="data.alert_quality_governance_endpoint" class="btn btn-outline-primary btn-sm" type="button" :disabled="alertQuality.loading" @click="loadAlertQualityGovernance">[[ alertQuality.loading ? '加载中' : '刷新建议' ]]</button>
					</div>
					<div v-if="alertQuality.error" class="aiops-empty aiops-error">[[ alertQuality.error ]]</div>
					<div v-else-if="alertQuality.loading && !alertQuality.results.length" class="aiops-empty">正在加载治理建议…</div>
					<div v-else-if="!alertQuality.results.length" class="aiops-empty">暂无需要复核的告警质量建议</div>
					<div class="aiops-row aiops-quality-row" v-for="item in alertQuality.results" :key="item.suggestion_key">
						<div><strong>[[ item.metric ]] · [[ item.action_label ]]</strong><span>反馈 [[ item.feedback_count ]] 条 · 覆盖 [[ item.host_count ]] 台主机</span></div>
						<div class="aiops-quality-actions">
							<b :class="'aiops-badge ' + qualityStatusClass(item.review && item.review.status)">[[ qualityStatusLabel(item.review && item.review.status) ]]</b>
							<button v-if="data.alert_quality_governance_review_endpoint_template && (!item.review || item.review.status === 'open')" class="btn btn-sm btn-primary" type="button" :disabled="item.reviewing" @click="reviewAlertQuality(item, 'accepted')">接受</button>
							<button v-if="data.alert_quality_governance_review_endpoint_template && item.review && item.review.status === 'open'" class="btn btn-sm btn-outline-danger" type="button" :disabled="item.reviewing" @click="reviewAlertQuality(item, 'rejected')">驳回</button>
							<button v-if="data.alert_quality_governance_review_endpoint_template && item.review && item.review.status === 'accepted'" class="btn btn-sm btn-outline-success" type="button" :disabled="item.reviewing" @click="reviewAlertQuality(item, 'implemented')">标记已实施</button>
						</div>
					</div>
					<div v-if="data.service_impacts_endpoint" class="aiops-panel aiops-release-risk-panel">
						<div class="aiops-panel-heading">
							<div><h2>发布与服务风险</h2><p class="aiops-muted">基于当前授权范围内的告警、事件、SLO、发布和 CI 信号。</p></div>
							<div class="aiops-panel-actions">
								<b v-if="serviceImpacts.results" class="aiops-score">[[ serviceImpacts.results.length ]] 项服务</b>
								<button class="btn btn-outline-primary btn-sm" type="button" :disabled="serviceImpacts.loading" @click="loadServiceImpacts">[[ serviceImpacts.loading ? '加载中' : (serviceImpacts.results ? '刷新风险' : '加载风险') ]]</button>
								<button v-if="serviceImpacts.results" class="btn btn-link btn-sm" type="button" @click="selectTab('service-impacts')">查看详情</button>
							</div>
						</div>
						<div v-if="serviceImpacts.error" class="aiops-empty aiops-error">[[ serviceImpacts.error ]]</div>
						<div v-else-if="serviceImpacts.loading && !serviceImpacts.results" class="aiops-empty">正在加载服务风险…</div>
						<div v-else-if="serviceImpacts.results && !serviceImpacts.results.length" class="aiops-empty">当前主机范围没有可查看的服务风险信号</div>
						<div v-else-if="serviceImpacts.results" class="aiops-release-risk-list">
							<div v-for="item in serviceImpacts.results.slice(0, 6)" :key="item.service.id" class="aiops-row aiops-release-risk-row">
								<div><strong>[[ item.service.name ]]</strong><span>告警 [[ item.evidence_counts.active_alerts ]] · 事件 [[ item.evidence_counts.open_incidents ]] · SLO [[ item.evidence_counts.exhausted_slos ]] · 发布 [[ item.evidence_counts.unhealthy_deployments ]] · CI [[ item.evidence_counts.failed_ci_deliveries ]]</span></div>
								<b :class="'aiops-badge ' + riskClass(item.state)">[[ riskLabel(item.state) ]]</b>
							</div>
						</div>
					</div>
				</section>

                <section v-if="active === 'investigation'" class="aiops-panel">
                    <div class="aiops-panel-heading"><div><h2>调查工作台</h2><p class="aiops-muted">按授权主机和服务生成只读调查结果。</p></div><div class="aiops-panel-actions"><select v-if="data.investigations_endpoint" class="form-control form-control-sm" v-model="investigations.filter" aria-label="调查筛选"><option value="all">全部调查</option><option value="critical">高风险</option><option value="partial">部分结果</option><option value="completed">已完成</option></select><button v-if="data.investigations_endpoint" class="btn btn-outline-primary btn-sm" type="button" :disabled="investigations.loading" @click="loadInvestigations">刷新调查</button></div></div>
                    <div v-if="!data.investigations_endpoint" class="aiops-empty aiops-error">当前账号没有完整的调查证据查看权限</div>
                    <form v-else class="aiops-form aiops-investigation-form" @submit.prevent="createInvestigation">
                        <label><span>标题</span><input class="form-control" maxlength="200" v-model.trim="investigations.form.title" required></label>
                        <label><span>主机</span><select class="form-control" v-model="investigations.form.hostId" required><option value="">选择主机</option><option v-for="host in items(data.investigation_scope.hosts)" :key="host.id" :value="host.id">[[ host.name ]]</option></select></label>
                        <label><span>服务</span><select class="form-control" v-model="investigations.form.serviceId"><option value="">全部可见服务</option><option v-for="service in items(data.investigation_scope.services)" :key="service.id" :value="service.id">[[ service.name ]]</option></select></label>
						<label><span>窗口</span><select class="form-control" v-model="investigations.form.windowKey" @change="setInvestigationWindow"><option value="1h">近 1 小时</option><option value="6h">近 6 小时</option><option value="24h">近 24 小时</option><option value="7d">近 7 天</option></select></label>
                        <label><span>开始</span><input class="form-control" type="datetime-local" v-model="investigations.form.start" required></label><label><span>结束</span><input class="form-control" type="datetime-local" v-model="investigations.form.end" required></label>
                        <button class="btn btn-primary" type="submit" :disabled="investigations.saving">[[ investigations.saving ? '创建中' : '创建调查' ]]</button>
                    </form>
                    <div v-if="investigations.error" class="aiops-empty aiops-error">[[ investigations.error ]]</div>
                    <div v-else-if="investigations.loading && !investigations.results.length" class="aiops-empty">正在加载调查…</div>
                    <div v-else-if="!investigations.results.length" class="aiops-empty">暂无调查记录</div>
                    <div v-else-if="!investigationResults().length" class="aiops-empty">当前筛选条件没有匹配的调查</div>
                    <div v-else class="aiops-investigation-list"><button v-for="item in investigationResults()" :key="item.id" type="button" class="aiops-row aiops-investigation-item" @click="loadInvestigationDetail(item)"><span><strong>[[ item.title ]]</strong><small>[[ item.window.key ]] · [[ item.status ]] · 主机 [[ item.scope.host_count ]]</small></span><b class="aiops-score">[[ item.confidence ]]%</b></button></div>
                    <article v-if="investigations.selected" class="aiops-investigation-detail"><div class="aiops-panel-heading"><h3>[[ investigations.selected.title ]]</h3><button class="btn btn-sm btn-outline-primary" type="button" @click="loadInvestigationDetail(investigations.selected)">刷新详情</button></div><p>[[ investigations.selected.summary ]]</p><div v-if="investigations.selected.partial" class="aiops-empty aiops-warning">部分数据源不可用：[[ items(investigations.selected.errors).map(error => error.source).join('、') ]]</div><h3>根因候选</h3><div v-if="!items(investigations.selected.root_causes).length" class="aiops-empty">暂无足够证据</div><div v-for="cause in items(investigations.selected.root_causes)" :key="cause.key" class="aiops-row"><span><strong>[[ cause.summary ]]</strong><small>下一步：[[ cause.next_action ]]</small></span><b class="aiops-score">[[ cause.confidence ]]%</b></div><h3>证据时间线</h3><ol class="aiops-impact-timeline"><li v-for="entry in items(investigations.selected.timeline)" :key="entry.kind + entry.ref_id"><div><strong>[[ evidenceLabel(entry.kind) ]]</strong><span>[[ entry.summary ]]</span><small>[[ entry.occurred_at ]]</small></div></li></ol><div v-if="data.investigation_feedback_endpoint_template" class="aiops-investigation-feedback"><div class="aiops-feedback-heading"><h3>调查结论反馈</h3><span class="aiops-muted">仅用于质量评估</span></div><form class="aiops-feedback-form" @submit.prevent="submitInvestigationFeedback"><label><span>结论</span><select class="form-control" v-model="investigations.feedback.form.classification"><option value="effective">有效</option><option value="partial">部分有效</option><option value="ineffective">无效</option></select></label><label><span>备注 <small>（可选，最多 300 字）</small></span><textarea class="form-control" maxlength="300" rows="2" v-model.trim="investigations.feedback.form.note" placeholder="记录证据质量或改进建议"></textarea></label><button class="btn btn-primary btn-sm" type="submit" :disabled="investigations.feedback.saving">[[ investigations.feedback.saving ? '提交中' : '提交反馈' ]]</button></form><div v-if="investigations.feedback.error" class="aiops-empty aiops-error">[[ investigations.feedback.error ]]</div><div v-else-if="investigations.feedback.loading && !investigations.feedback.results.length" class="aiops-empty">正在加载反馈…</div><div v-else-if="!investigations.feedback.results.length" class="aiops-empty">暂无反馈记录</div><div v-else class="aiops-feedback-list"><div v-for="feedback in investigations.feedback.results" :key="feedback.created_at + feedback.created_by" class="aiops-feedback-item"><span><b :class="'aiops-badge ' + feedbackClass(feedback.classification)">[[ feedbackLabel(feedback.classification) ]]</b><small>[[ feedback.created_by || '匿名' ]] · [[ feedback.created_at ]]</small></span><em v-if="feedback.note_present">有备注</em></div></div></div></article>
                    <h2>事件研判时间线</h2>
                    <div v-if="!items(data.investigation_timelines).length" class="aiops-empty">暂无可关联的安全证据</div>
                    <article class="aiops-impact" v-for="timeline in items(data.investigation_timelines)" :key="timeline.host">
                        <strong>[[ timeline.host ]]</strong>
                        <ol class="aiops-impact-timeline"><li v-for="item in items(timeline.entries)" :key="item.kind + item.observed_at + item.summary"><div><strong>[[ evidenceLabel(item.kind) ]]</strong><span>[[ item.summary ]]</span><small>[[ item.observed_at ]]</small></div></li></ol>
                    </article>
                </section>

				<section v-if="active === 'k8s-analyzer'" class="aiops-panel"><div class="aiops-panel-heading"><div><h2>Kubernetes Analyzer</h2><p class="aiops-muted">只读检查授权服务关联的集群。</p></div><button v-if="canRefreshK8sAnalyzer()" class="btn btn-outline-primary btn-sm" type="button" :disabled="!k8sAnalyzer.clusterId || k8sAnalyzer.loading" @click="refreshK8sAnalyzer">[[ k8sAnalyzer.refreshing ? '刷新中' : '刷新' ]]</button></div><div class="aiops-form"><label><span>集群</span><select class="form-control" v-model="k8sAnalyzer.clusterId"><option value="">选择集群</option><option v-for="cluster in items(data.k8s_clusters)" :key="cluster.id" :value="cluster.id">[[ cluster.name ]]</option></select></label><label><span>命名空间</span><input class="form-control" maxlength="63" v-model.trim="k8sAnalyzer.namespace"></label><button class="btn btn-primary" type="button" :disabled="!k8sAnalyzer.clusterId || k8sAnalyzer.loading" @click="loadK8sAnalyzer">[[ k8sAnalyzer.loading ? '加载中' : '开始分析' ]]</button></div><div v-if="k8sAnalyzer.error" class="aiops-empty aiops-error">[[ k8sAnalyzer.error ]]</div><div v-else-if="k8sAnalyzer.loading" class="aiops-empty">正在读取集群信息…</div><div v-else-if="!k8sAnalyzer.result" class="aiops-empty">选择集群和命名空间开始分析</div><div v-else><div v-if="k8sAnalyzer.result.partial" class="aiops-empty aiops-warning">部分资源源不可用，结果可能不完整。</div><div v-if="!k8sAnalyzer.result.findings.length" class="aiops-empty">当前命名空间未发现异常</div><div v-for="finding in k8sAnalyzer.result.findings" :key="finding.kind + finding.namespace + finding.name" class="aiops-row"><span><strong>[[ finding.kind ]] / [[ finding.name ]]</strong><small>[[ finding.reason ]] · [[ finding.detail ]]</small></span><b class="aiops-badge danger">[[ finding.status ]]</b></div></div></section>
				<section v-if="active === 'operator-scan'" class="aiops-panel"><div class="aiops-panel-heading"><div><h2>主动巡检</h2><p class="aiops-muted">基于本地授权数据生成只读巡检摘要。</p></div><button class="btn btn-outline-primary btn-sm" type="button" :disabled="operatorScan.loading" @click="loadOperatorScan">刷新</button></div><div class="aiops-form"><label><span>时间窗</span><select class="form-control" v-model="operatorScan.window"><option value="6h">近 6 小时</option><option value="24h">近 24 小时</option><option value="7d">近 7 天</option></select></label><button class="btn btn-primary" type="button" :disabled="operatorScan.loading" @click="loadOperatorScan">[[ operatorScan.loading ? '巡检中' : '开始巡检' ]]</button></div><div v-if="operatorScan.error" class="aiops-empty aiops-error">[[ operatorScan.error ]]</div><div v-else-if="operatorScan.loading" class="aiops-empty">正在执行只读巡检…</div><div v-else-if="!operatorScan.result" class="aiops-empty">点击开始巡检</div><div v-else><div v-if="operatorScan.result.partial" class="aiops-empty aiops-warning">部分数据源不可用</div><div v-if="!operatorScan.result.findings.length" class="aiops-empty">未发现需要关注的信号</div><div v-for="finding in operatorScan.result.findings" :key="finding.kind + finding.resource + finding.occurred_at" class="aiops-row"><span><strong>[[ finding.kind ]] · [[ finding.resource ]]</strong><small>[[ finding.summary ]] · [[ finding.occurred_at || '-' ]]</small></span><b class="aiops-badge danger">[[ finding.severity ]]</b></div></div></section>
				<section v-if="active === 'diagnostic'" class="aiops-panel">
					<h2>诊断证据包</h2>
					<div class="aiops-form">
						<label><span>主机</span><select class="form-control" v-model="diagnostic.hostId"><option value="">选择主机</option><option v-for="host in items(data.diagnostic_evidence && data.diagnostic_evidence.hosts)" :key="host.id" :value="host.id">[[ host.name ]]</option></select></label>
						<label><span>时间窗</span><select class="form-control" v-model="diagnostic.window"><option value="6h">近 6 小时</option><option value="24h">近 24 小时</option></select></label>
						<button class="btn btn-primary" type="button" :disabled="!diagnostic.hostId || diagnostic.loading" @click="loadDiagnosticEvidence">[[ diagnostic.loading ? '加载中' : '加载证据' ]]</button>
					</div>
					<div v-if="diagnostic.error" class="aiops-empty">[[ diagnostic.error ]]</div>
					<div v-else-if="diagnostic.result && !items(diagnostic.result.evidence).length" class="aiops-empty">当前时间窗没有可查看的诊断证据</div>
					<ol v-else-if="diagnostic.result" class="aiops-impact-timeline"><li v-for="item in items(diagnostic.result.evidence)" :key="item.kind + item.id + item.observed_at"><div><strong>[[ evidenceLabel(item.kind) ]]</strong><span>[[ item.metric || item.status || item.level || item.provider || item.state || '-' ]]</span><small>[[ item.observed_at ]]</small></div></li></ol>
				</section>

				<section v-if="active === 'alert-groups'" class="aiops-panel">
					<h2>告警分组</h2>
					<div class="aiops-form">
						<label><span>时间窗</span><select class="form-control" v-model="alertGroups.window"><option value="6h">近 6 小时</option><option value="24h">近 24 小时</option></select></label>
						<button class="btn btn-primary" type="button" :disabled="alertGroups.loading" @click="loadAlertGroups">[[ alertGroups.loading ? '加载中' : '加载分组' ]]</button>
					</div>
					<div v-if="alertGroups.error" class="aiops-empty">[[ alertGroups.error ]]</div>
					<div v-else-if="alertGroups.results && !alertGroups.results.length" class="aiops-empty">当前时间窗没有活动或静默告警</div>
					<div v-else-if="alertGroups.results" class="aiops-row" v-for="group in alertGroups.results" :key="group.key">
						<div><strong>[[ group.metric ]] · [[ group.level ]]</strong><span>主机 [[ group.host_count ]] · 活动 [[ group.active_count ]] · 静默 [[ group.silenced_count ]] · 重复 [[ group.repeat_count ]] · 事件 [[ items(group.incident_statuses).join('、') || '无' ]]</span><small>[[ group.recommendation ]]</small></div>
					</div>
				</section>

					<section v-if="active === 'signal-freshness'" class="aiops-panel">
					<h2>信号新鲜度</h2>
					<div class="aiops-form">
						<label><span>时间窗</span><select class="form-control" v-model="signalFreshness.window"><option value="6h">近 6 小时</option><option value="24h">近 24 小时</option></select></label>
						<button class="btn btn-primary" type="button" :disabled="signalFreshness.loading" @click="loadSignalFreshness">[[ signalFreshness.loading ? '加载中' : '加载状态' ]]</button>
					</div>
					<div v-if="signalFreshness.error" class="aiops-empty">[[ signalFreshness.error ]]</div>
					<div v-else-if="signalFreshness.results && !signalFreshness.results.length" class="aiops-empty">当前主机范围没有可查看的监控信号</div>
					<div v-else-if="signalFreshness.results" class="aiops-row" v-for="item in signalFreshness.results" :key="item.host_id">
						<div><strong>[[ item.host_name ]] · [[ item.state ]]</strong><span>新鲜 [[ item.fresh_count ]] · 过期 [[ item.stale_count ]] · 缺失 [[ item.missing_count ]]</span><small>CPU [[ item.metric_states.cpu ]] · 内存 [[ item.metric_states.memory ]] · 磁盘 [[ item.metric_states.disk ]]</small></div>
					</div>
					</section>

					<section v-if="active === 'service-impacts'" class="aiops-panel">
						<h2>服务影响</h2>
						<div class="aiops-form">
							<label><span>时间窗</span><select class="form-control" v-model="serviceImpacts.window"><option value="6h">近 6 小时</option><option value="24h">近 24 小时</option></select></label>
							<button class="btn btn-primary" type="button" :disabled="serviceImpacts.loading" @click="loadServiceImpacts">[[ serviceImpacts.loading ? '加载中' : '加载服务影响' ]]</button>
						</div>
						<div v-if="serviceImpacts.error" class="aiops-empty">[[ serviceImpacts.error ]]</div>
						<div v-else-if="serviceImpacts.results && !serviceImpacts.results.length" class="aiops-empty">当前主机范围没有可查看的服务影响信号</div>
						<div v-else-if="serviceImpacts.results" class="aiops-row" v-for="item in serviceImpacts.results" :key="item.service.id">
							<div><strong>[[ item.service.name ]] · [[ item.state ]]</strong><span>关键等级 [[ item.criticality ]] · 可见主机 [[ item.host_count ]] · 受影响主机 [[ item.affected_host_count ]] · 上游依赖 [[ item.dependency_count ]]</span><small>告警 [[ item.evidence_counts.active_alerts ]] · 事件 [[ item.evidence_counts.open_incidents ]] · SLO [[ item.evidence_counts.exhausted_slos ]] · 发布 [[ item.evidence_counts.unhealthy_deployments ]] · CI [[ item.evidence_counts.failed_ci_deliveries ]]</small><small>[[ item.recommendation ]]</small></div>
							<b :class="'aiops-badge ' + levelClass(item.state === 'critical' ? 'critical' : 'info')">[[ item.state ]]</b>
						</div>
					</section>

					<section v-if="active === 'service-reliability'" class="aiops-panel aiops-reliability-panel">
						<div class="aiops-panel-heading">
							<div><h2>服务可靠性评分</h2><p class="aiops-muted">基于当前授权范围的告警、事件、发布与 SLO 证据。</p></div>
							<div class="aiops-reliability-actions">
								<label class="aiops-inline-control"><span>时间窗</span><select class="form-control form-control-sm" v-model="serviceReliability.window" @change="loadServiceReliability"><option value="24h">近 24 小时</option><option value="7d">近 7 天</option><option value="30d">近 30 天</option></select></label>
								<button class="btn btn-sm btn-outline-primary" type="button" :disabled="serviceReliability.loading" @click="loadServiceReliability">[[ serviceReliability.loading ? '加载中' : '刷新评分' ]]</button>
							</div>
						</div>
						<div v-if="serviceReliability.error" class="aiops-empty aiops-error">[[ serviceReliability.error ]]</div>
						<div v-else-if="serviceReliability.loading && !serviceReliability.results.length" class="aiops-empty">正在计算服务可靠性…</div>
						<div v-else-if="!serviceReliability.results.length" class="aiops-empty">当前主机范围暂无服务可靠性评分</div>
						<div v-else class="aiops-reliability-list">
							<article v-for="item in serviceReliability.results" :key="(item.service && item.service.id) || item.service_id || item.id || item.name" class="aiops-reliability-row">
								<div class="aiops-reliability-main"><strong>[[ (item.service && item.service.name) || item.service_name || item.name || '未命名服务' ]]</strong><span v-if="item.recommendation">[[ item.recommendation ]]</span></div>
								<div class="aiops-reliability-score"><b>[[ Math.max(0, Math.min(100, Number(item.score || 0))) ]]</b><small>/ 100</small></div>
								<div class="aiops-reliability-track"><i :class="'state-' + reliabilityStateClass(item.state)" :style="{ width: Math.max(0, Math.min(100, Number(item.score || 0))) + '%' }"></i></div>
								<span :class="'aiops-badge ' + reliabilityStateClass(item.state)">[[ reliabilityStateLabel(item.state) ]]</span>
								<div class="aiops-reliability-evidence"><span>告警 [[ (item.evidence_counts || {}).active_alerts || 0 ]]</span><span>事件 [[ (item.evidence_counts || {}).open_incidents || 0 ]]</span><span>SLO [[ (item.evidence_counts || {}).exhausted_slos || 0 ]]</span><span>发布 [[ (item.evidence_counts || {}).unhealthy_deployments || 0 ]]</span></div>
								<small v-if="item.review_count !== undefined" class="aiops-muted">复核 [[ item.review_count ]] 次</small>
							</article>
						</div>
					</section>

					<section v-if="active === 'service-workbench'" class="aiops-panel">
						<h2>服务事件工作区</h2>
						<div class="aiops-form">
							<label><span>服务</span><select class="form-control" v-model="serviceWorkbench.serviceId"><option value="">先加载服务影响后选择服务</option><option v-for="item in items(serviceImpacts.results)" :key="item.service.id" :value="item.service.id">[[ item.service.name ]]</option></select></label>
							<label><span>时间窗</span><select class="form-control" v-model="serviceWorkbench.window"><option value="6h">近 6 小时</option><option value="24h">近 24 小时</option></select></label>
							<button class="btn btn-primary" type="button" :disabled="!serviceWorkbench.serviceId || serviceWorkbench.loading" @click="loadServiceWorkbench">[[ serviceWorkbench.loading ? '加载中' : '加载工作区' ]]</button>
						</div>
						<div v-if="serviceWorkbench.error" class="aiops-empty">[[ serviceWorkbench.error ]]</div>
						<div v-else-if="serviceWorkbench.result && !serviceWorkbench.result.incidents.length && !serviceWorkbench.result.releases.length" class="aiops-empty">当前时间窗没有可查看的事件或发布记录</div>
						<div v-else-if="serviceWorkbench.result" class="aiops-row"><div><strong>[[ serviceWorkbench.result.service.name ]] · [[ serviceWorkbench.result.state ]]</strong><span>告警 [[ serviceWorkbench.result.counts.active_alerts ]] · 事件 [[ serviceWorkbench.result.counts.open_incidents ]] · 发布 [[ serviceWorkbench.result.counts.unhealthy_deployments ]] · CI [[ serviceWorkbench.result.counts.failed_ci_deliveries ]]</span></div></div>
						<div v-for="incident in items(serviceWorkbench.result && serviceWorkbench.result.incidents)" :key="'incident-' + incident.id" class="aiops-row"><div><strong>事件 #[[ incident.id ]] · [[ incident.status ]]</strong><span>负责人 [[ incident.owner || '-' ]] · SLA [[ incident.sla_due_at || '-' ]]</span></div></div>
						<div v-for="release in items(serviceWorkbench.result && serviceWorkbench.result.releases)" :key="'release-' + release.id" class="aiops-row"><div><strong>发布 #[[ release.id ]] · [[ release.status ]]</strong><span>健康 [[ release.health_state ]] · 观测 [[ release.observed_at ]]</span></div></div>
					</section>

                <section v-if="active === 'capacity'" class="aiops-panel">
                    <h2>容量预测</h2>
                    <div v-if="!data.capacity.length" class="aiops-empty">暂无指标样本，采集后会生成容量判断</div>
                    <div class="aiops-capacity" v-for="item in data.capacity" :key="item.host + item.metric">
                        <div>
                            <strong>[[ item.host ]] · [[ item.metric ]]</strong>
                            <span>[[ item.trend ]] · [[ item.advice ]] · 样本 [[ item.points ]]</span>
                        </div>
                        <div class="aiops-bar"><i :style="{ width: metricBar(item.average) }"></i></div>
                        <b>[[ item.average ]]%</b>
                    </div>
					<div v-if="data.capacity_cost_simulation_endpoint" class="aiops-capacity-simulation">
						<div class="aiops-panel-heading"><div><h3>容量与成本仿真</h3><p class="aiops-muted">仅基于当前授权范围的本地数据计算，不会修改资源。</p></div></div>
						<div class="aiops-form aiops-simulation-form">
							<label><span>CPU 变化 (%)</span><input class="form-control" type="number" min="-50" max="100" v-model.number="capacitySimulation.cpu"></label>
							<label><span>内存变化 (%)</span><input class="form-control" type="number" min="-50" max="100" v-model.number="capacitySimulation.memory"></label>
							<label><span>实例变化</span><input class="form-control" type="number" min="-10" max="20" v-model.number="capacitySimulation.instances"></label>
							<button class="btn btn-primary" type="button" :disabled="capacitySimulation.loading" @click="runCapacitySimulation">[[ capacitySimulation.loading ? '计算中' : '运行仿真' ]]</button>
						</div>
						<div v-if="capacitySimulation.error" class="aiops-empty aiops-error">[[ capacitySimulation.error ]]</div>
						<div v-if="capacitySimulation.result" class="aiops-row aiops-simulation-result"><div><strong>基线风险 [[ capacitySimulation.result.capacity.baseline_risk ]] · 预测风险 [[ capacitySimulation.result.capacity.projected_risk ]]</strong><span v-for="cost in items(capacitySimulation.result.costs)" :key="cost.currency">[[ cost.currency ]] 成本变化 [[ cost.delta_daily ]]</span></div></div>
					</div>
                </section>

                <section v-if="active === 'runbook'" class="aiops-panel">
                    <h2>运行手册</h2>
					<div v-if="data.runbook_recommendations_endpoint" class="aiops-runbook-outcomes"><div class="aiops-panel-heading"><h3>建议结果</h3><button class="btn btn-sm btn-outline-primary" type="button" :disabled="runbookRecommendations.loading" @click="loadRunbookRecommendations">刷新</button></div><div v-if="runbookRecommendations.error" class="aiops-empty aiops-error">[[ runbookRecommendations.error ]]</div><div v-else-if="runbookRecommendations.loading && !runbookRecommendations.results.length" class="aiops-empty">正在加载建议…</div><div v-else-if="!runbookRecommendations.results.length" class="aiops-empty">暂无运行手册建议</div><div v-for="item in runbookRecommendations.results" :key="item.id" class="aiops-row"><span><strong>建议 #[[ item.id ]]</strong><small>状态：[[ item.status ]] · 审批：[[ item.approval_id || '未提交' ]]</small></span><button v-if="data.runbook_recommendation_initiate_endpoint_template && item.status === 'recommended'" class="btn btn-sm btn-primary" type="button" :disabled="runbookRecommendations.initiating" @click="initiateRunbookRecommendation(item)">[[ runbookRecommendations.initiating ? '提交中' : '发起审批' ]]</button><button class="btn btn-sm btn-outline-primary" type="button" :disabled="runbookRecommendations.outcomeLoading" @click="loadRunbookOutcome(item)">查看结果</button></div><div v-if="runbookRecommendations.outcome" class="aiops-row aiops-outcome-summary"><span><strong>审批 [[ runbookRecommendations.outcome.approval ? runbookRecommendations.outcome.approval.status : '未提交' ]]</strong><small>执行 [[ runbookRecommendations.outcome.execution ? runbookRecommendations.outcome.execution.status : '无' ]] · 健康 [[ runbookRecommendations.outcome.health_verification ? runbookRecommendations.outcome.health_verification.status : '无' ]] · 反馈 [[ items(runbookRecommendations.outcome.effectiveness_feedback).map(item => item.classification).join('、') || '无' ]]</small></span></div></div></div>
                    <div v-if="items(data.runbook_effectiveness_suggestions).length" class="aiops-panel-heading"><div><h2>效果排序</h2></div></div>
                    <div class="aiops-row" v-for="book in items(data.runbook_effectiveness_suggestions)" :key="'effectiveness-' + book.id">
                        <div><strong>[[ book.name ]]</strong><span>有效 [[ book.effective_count ]] · 部分有效 [[ book.partial_count ]] · 无效 [[ book.ineffective_count ]]</span></div>
                        <b class="aiops-score">[[ book.effectiveness_score ]] 分</b>
                    </div>
                    <div class="aiops-runbook" v-for="book in data.runbooks" :key="book.id">
                        <div>
                            <strong>[[ book.name ]]</strong>
                            <span>版本：[[ book.version ]]</span>
                        </div>
                        <a class="btn btn-outline-primary btn-sm" :href="book.initiate_url">查看并发起审批</a>
                    </div>
                </section>

                <section v-if="active === 'ingest'" class="aiops-grid two">
                    <div class="aiops-panel">
                        <h2>告警接入配置</h2>
                        <form v-if="data.integration.can_manage" class="aiops-form" method="post">
                            <input type="hidden" name="csrfmiddlewaretoken" :value="data.integration.csrf">
                            <label>
                                <span>Alertmanager 地址</span>
                                <input class="form-control" name="alertmanager_url" type="url" placeholder="留空保持已有配置" autocomplete="off">
                            </label>
                            <label>
                                <span>大模型地址</span>
                                <input class="form-control" name="llm_url" type="url" placeholder="留空保持已有配置" autocomplete="off">
                            </label>
                            <label>
                                <span>模型名称</span>
                                <input class="form-control" name="llm_model" placeholder="留空保持已有配置" autocomplete="off">
                            </label>
                            <label>
                                <span>API Key</span>
                                <input class="form-control" name="llm_api_key" type="password" :placeholder="data.integration.llm_api_key_set ? '已配置，留空保持不变' : '可选'">
                            </label>
                            <label class="aiops-check">
                                <input name="enabled" type="checkbox" :checked="data.integration.enabled">
                                <span>启用告警接入</span>
                            </label>
                            <button class="btn btn-primary" type="submit">保存配置</button>
                        </form>
                        <div v-else class="aiops-empty">当前账号没有接入配置管理权限，仅可查看状态。</div>
                    </div>
                    <div class="aiops-panel">
                        <h2>接入状态</h2>
                        <div class="aiops-row compact"><div><strong>Alertmanager</strong></div><b>[[ data.integration.alertmanager_configured ? '已配置' : '未配置' ]]</b></div>
                        <div class="aiops-row compact"><div><strong>大模型连接</strong></div><b>[[ data.integration.llm_configured ? '已配置' : '未配置' ]]</b></div>
                        <div class="aiops-row compact"><div><strong>访问密钥</strong></div><b>[[ data.integration.llm_api_key_set ? '已配置' : '未配置' ]]</b></div>
                        <div class="aiops-row compact"><div><strong>告警接入</strong></div><b>[[ data.integration.enabled ? '已启用' : '未启用' ]]</b></div>
                    </div>
                    <div class="aiops-panel aiops-wide">
                        <h2>最近告警分析</h2>
                        <div v-if="!data.alert_analyses.length" class="aiops-empty">暂无 Alertmanager 告警分析记录</div>
                        <div class="aiops-row" v-for="item in data.alert_analyses" :key="item.id">
                            <div>
                                <strong>[[ item.alert_name ]] · [[ item.instance ]]</strong>
                                <span>[[ item.summary ]]</span>
                                <small>建议：[[ item.suggestion ]]</small>
                                <small v-if="item.error">错误：[[ item.error ]]</small>
                            </div>
                            <b :class="'aiops-badge ' + levelClass(item.severity)">[[ item.status ]]</b>
                        </div>
                    </div>
                </section>
            </div>
        `,
    }).mount(root);
})();
