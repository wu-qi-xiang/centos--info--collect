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
                tabs: [
                    { key: 'overview', label: '总览', icon: 'fas fa-gauge-high' },
                    { key: 'anomaly', label: '异常检测', icon: 'fas fa-wave-square' },
                    { key: 'correlation', label: '事件关联', icon: 'fas fa-project-diagram' },
                    { key: 'rca', label: '根因分析', icon: 'fas fa-magnifying-glass-chart' },
                    { key: 'capacity', label: '容量预测', icon: 'fas fa-chart-area' },
                    { key: 'runbook', label: '运行手册', icon: 'fas fa-book-open' },
                    { key: 'ingest', label: '告警接入', icon: 'fas fa-bell' },
                ],
            };
        },
        methods: {
            levelClass(level) {
                if (level === 'critical') return 'danger';
                if (level === 'warning') return 'warning';
                return 'info';
            },
            metricBar(value) {
                const number = Number(value || 0);
                return Math.max(0, Math.min(100, number)) + '%';
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

                <div class="aiops-tabs">
                    <button v-for="tab in tabs" :key="tab.key" type="button" :class="{ active: active === tab.key }" @click="active = tab.key">
                        <i :class="tab.icon"></i><span>[[ tab.label ]]</span>
                    </button>
                </div>

                <section v-if="active === 'overview'">
                    <div class="aiops-kpis">
                        <div class="aiops-card"><span>主机</span><strong>[[ data.counts.hosts ]]</strong></div>
                        <div class="aiops-card"><span>未恢复告警</span><strong>[[ data.counts.open_alerts ]]</strong></div>
                        <div class="aiops-card"><span>异常信号</span><strong>[[ data.counts.anomalies ]]</strong></div>
                        <div class="aiops-card"><span>事件簇</span><strong>[[ data.counts.correlations ]]</strong></div>
                        <div class="aiops-card"><span>失败命令</span><strong>[[ data.counts.failed_commands ]]</strong></div>
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
                    <div class="aiops-runbook" v-for="book in data.runbooks" :key="book.title">
                        <div>
                            <strong>[[ book.title ]]</strong>
                            <span>触发：[[ book.trigger ]]</span>
                        </div>
                        <ol><li v-for="step in book.steps" :key="step">[[ step ]]</li></ol>
                    </div>
                </section>

                <section v-if="active === 'ingest'" class="aiops-grid two">
                    <div class="aiops-panel">
                        <h2>告警接入配置</h2>
                        <form class="aiops-form" method="post" :action="data.integration.config_url">
                            <input type="hidden" name="csrfmiddlewaretoken" :value="data.integration.csrf">
                            <label>
                                <span>Alertmanager 地址</span>
                                <input class="form-control" name="alertmanager_url" :value="data.integration.alertmanager_url || ''" placeholder="http://alertmanager:9093">
                            </label>
                            <label>
                                <span>大模型地址</span>
                                <input class="form-control" name="llm_url" :value="data.integration.llm_url || ''" placeholder="http://llm-gateway:8000 或完整 /v1/chat/completions">
                            </label>
                            <label>
                                <span>模型名称</span>
                                <input class="form-control" name="llm_model" :value="data.integration.llm_model || 'gpt-4o-mini'">
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
                        <h2>Alertmanager Webhook</h2>
                        <div class="aiops-webhook">[[ data.integration.webhook_url ]]</div>
                        <div class="aiops-muted">在 Alertmanager receiver 的 webhook_configs.url 中填写该地址。收到告警后会保存原始内容，并调用大模型生成处理建议。</div>
                        <div class="aiops-example">
                            <strong>receiver 示例</strong>
                            <pre>receivers:
  - name: aiops
    webhook_configs:
      - url: [[ data.integration.webhook_url ]]</pre>
                        </div>
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
