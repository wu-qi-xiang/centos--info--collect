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
                tabs: [
                    { key: 'overview', label: '总览', icon: 'fas fa-gauge-high' },
                    { key: 'anomaly', label: '异常检测', icon: 'fas fa-wave-square' },
                    { key: 'correlation', label: '事件关联', icon: 'fas fa-project-diagram' },
                    { key: 'impact', label: '变更影响', icon: 'fas fa-code-branch' },
                    { key: 'quality', label: '告警质量', icon: 'fas fa-sliders' },
                    { key: 'investigation', label: '事件研判', icon: 'fas fa-timeline' },
					{ key: 'diagnostic', label: '诊断证据', icon: 'fas fa-clipboard-list' },
					...(payload.alert_groups_endpoint ? [{ key: 'alert-groups', label: '告警分组', icon: 'fas fa-layer-group' }] : []),
					...(payload.signal_freshness_endpoint ? [{ key: 'signal-freshness', label: '信号新鲜度', icon: 'fas fa-signal' }] : []),
					...(payload.service_impacts_endpoint ? [{ key: 'service-impacts', label: '服务影响', icon: 'fas fa-sitemap' }] : []),
					...(payload.service_workbench_endpoint_template ? [{ key: 'service-workbench', label: '服务事件', icon: 'fas fa-table-list' }] : []),
                    { key: 'rca', label: '根因分析', icon: 'fas fa-magnifying-glass-chart' },
                    { key: 'capacity', label: '容量预测', icon: 'fas fa-chart-area' },
                    { key: 'runbook', label: '运行手册', icon: 'fas fa-book-open' },
                    { key: 'ingest', label: '告警接入', icon: 'fas fa-bell' },
                ],
            };
        },
        methods: {
            selectTab(key) {
                this.active = key;
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
            changeImpactCount() {
                const count = Number(this.data.counts && this.data.counts.change_impacts);
                return Number.isFinite(count) ? count : this.items(this.data.change_impacts).length;
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
                    <button v-for="(tab, index) in tabs" :key="tab.key" type="button" role="tab" :id="'aiops-tab-' + tab.key" :aria-selected="active === tab.key" :tabindex="active === tab.key ? 0 : -1" :class="{ active: active === tab.key }" @click="selectTab(tab.key)" @keydown="onTabKeydown($event, index)">
                        <i :class="tab.icon" aria-hidden="true"></i><span>[[ tab.label ]]</span>
                    </button>
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
                    <h2>告警质量建议</h2>
                    <div v-if="!items(data.alert_quality_suggestions).length" class="aiops-empty">暂无需要复核的告警质量反馈</div>
                    <div class="aiops-row" v-for="item in items(data.alert_quality_suggestions)" :key="item.metric + item.action">
                        <div><strong>[[ item.metric ]]</strong><span>[[ item.summary ]]</span></div>
                        <b class="aiops-score">[[ item.feedback_count ]] 条</b>
                    </div>
                </section>

                <section v-if="active === 'investigation'" class="aiops-panel">
                    <h2>事件研判时间线</h2>
                    <div v-if="!items(data.investigation_timelines).length" class="aiops-empty">暂无可关联的安全证据</div>
                    <article class="aiops-impact" v-for="timeline in items(data.investigation_timelines)" :key="timeline.host">
                        <strong>[[ timeline.host ]]</strong>
                        <ol class="aiops-impact-timeline"><li v-for="item in items(timeline.entries)" :key="item.kind + item.observed_at + item.summary"><div><strong>[[ evidenceLabel(item.kind) ]]</strong><span>[[ item.summary ]]</span><small>[[ item.observed_at ]]</small></div></li></ol>
                    </article>
                </section>

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
                </section>

                <section v-if="active === 'runbook'" class="aiops-panel">
                    <h2>运行手册</h2>
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
                        <form class="aiops-form" method="post">
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
