# 外部认证配置

平台保留现有本地账号密码登录。OIDC 和 LDAP/AD 是可选身份来源，可以分别启用，也可以同时启用；一个来源的变量全部为空时保持禁用，部分配置会阻止应用启动。外部认证成功后，平台仅接受配置了组映射的用户，并把匹配到的组映射为既有 DevOps `viewer`、`operator` 或 `admin` 角色。

不要将客户端密钥、LDAP 绑定密码或供应商端点提交到仓库、日志、审计记录或浏览器响应中。使用部署系统的密钥注入能力提供这些环境变量。

## 角色映射

`EXTERNAL_AUTH_ROLE_MAP` 是 JSON 对象。键为身份提供方返回的精确组名，值只能是 `viewer`、`operator` 或 `admin`。例如：

```text
EXTERNAL_AUTH_ROLE_MAP={"<external-group-viewers>":"viewer","<external-group-operators>":"operator","<external-group-admins>":"admin"}
```

启用 OIDC 或 LDAP 后必须至少配置一个映射。没有匹配组的外部身份不得获得平台访问权限。

## OIDC

OIDC 仅支持一个来源。全部变量为空时禁用；只填写部分变量会阻止应用启动：

```text
OIDC_DISCOVERY_URL=https://<identity-provider>/.well-known/openid-configuration
OIDC_CLIENT_ID=<oidc-client-id>
OIDC_CLIENT_SECRET=<oidc-client-secret>
OIDC_REDIRECT_URI=https://<platform-host>/userprofile/external/oidc/callback/
```

生产环境要求 discovery URL 和 redirect URI 都为不含用户信息、查询参数或片段的 HTTPS 绝对地址。回调主机必须精确列在 `DJANGO_ALLOWED_HOSTS`，并在身份提供方控制台登记相同的回调地址。

## LDAP / Active Directory

LDAP/AD 仅支持一个来源。全部变量为空时禁用；启用时以下变量必须全部设置：

```text
LDAP_SERVER_URI=ldaps://<ldap-host>:636
LDAP_BIND_DN=<service-account-distinguished-name>
LDAP_BIND_PASSWORD=<service-account-password>
LDAP_BASE_DN=<directory-search-base-distinguished-name>
LDAP_USER_FILTER=(&(objectClass=person)(uid={username}))
LDAP_GROUP_ATTRIBUTE=memberOf
LDAP_STARTTLS=True
```

`LDAP_USER_FILTER` 必须且只能使用一次 `{username}` 占位符。平台会在查询前对用户名进行 LDAP 转义；不要在过滤器中拼接其他用户输入。`LDAP_GROUP_ATTRIBUTE` 只能是目录属性名。

生产环境必须使用 `ldaps://`，或使用 `ldap://` 并设置 `LDAP_STARTTLS=True`。绑定账户应为只读、只具备所需目录搜索范围的服务账户。

## 上线检查

部署前执行：

```bash
.venv/bin/python manage.py check --deploy
```

该检查会阻止不完整来源、无效角色、OIDC 非 HTTPS、未登记回调主机，以及未启用 LDAPS/StartTLS 的 LDAP 配置。检查输出不会包含客户端密钥或 LDAP 绑定密码。
