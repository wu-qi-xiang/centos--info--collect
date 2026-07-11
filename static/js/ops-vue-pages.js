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

    createApp({
        delimiters: ['[[', ']]'],
        data() {
            return {
                kind: payload.kind,
                title: payload.title,
                data: payload.data || {},
                reveal: {},
                revealError: '',
            };
        },
        computed: {
            errors() {
                return this.data.errors || [];
            },
        },
        methods: {
            submitForm(event) {
                return true;
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
                return value || '-';
            },
        },
        template: `
            <div>
                <div class="ops-page-head">
                    <div>
                        <h1 class="ops-title">[[ title ]]</h1>
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
                <div v-if="data.message" class="alert alert-info">[[ data.message ]]</div>

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
