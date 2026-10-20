# Lynx_PatchWatch —— Magento 后台注入页设计

> 本期**只做设计**，不随 `lynx-patch-watch`（lpw）一起发布代码。
> 本文档描述一个独立的 Magento 2 模块 `Lynx_PatchWatch`，它读取 lpw 产出的补丁状态，
> 在后台展示 Adobe Commerce 安全公告的修复情况，并在后台首页给出风险提示条。

---

## 1. 目标与范围

- 让运营 / 安全人员**无需登录 lpw 看板**，就能在 Magento 后台看到「这个项目有没有把关键补丁装上」。
- 数据只读：模块不写 lpw 数据库，也不触发扫描；它只是状态的**消费者**。
- 两种数据来源二选一（见 §4），部署方按网络可达性决定：
  - **(a) 在线**：调用 lpw 的 `GET /api/projects/{id}/status`，带只读 token，结果缓存 1 小时。
  - **(b) 离线**：读取 `var/lynx_patch_status.json`，由 CI / 部署流程运行 `lpw export-status` 写入。

---

## 2. 模块结构

```
app/code/Lynx/PatchWatch/
├── registration.php
├── composer.json
├── etc/
│   ├── module.xml
│   ├── acl.xml                 # ACL 资源 Lynx_PatchWatch::view
│   ├── adminhtml/
│   │   ├── menu.xml            # 系统 → 安全补丁状态
│   │   └── routes.xml          # adminhtml 路由 /admin/lynx_patchwatch/*
│   └── config.xml              # 默认配置（缓存 TTL、数据来源）
├── Model/
│   ├── Config.php              # 读取 store 配置（URL / token / 来源 / 缓存 TTL）
│   ├── StatusFetcher.php       # 来源 (a)：HTTP 拉取 + 1h 缓存
│   ├── JsonFileSource.php      # 来源 (b)：读 var/lynx_patch_status.json
│   └── StatusCache.php         # 基于 Core Cache 的 1 小时缓存
├── Block/Adminhtml/
│   ├── Status.php              # 公告状态列表 Block
│   └── DashboardBar.php        # 后台首页提示条 Block
├── Controller/Adminhtml/
│   ├── Status/
│   │   └── Index.php           # 系统 → 安全补丁状态 页面
│   └── Dashboard/
│       └── Bar.php             # 提示条内容（ajax 或直接渲染）
├── Observer/
│   └── AdminhtmlDashboardBar.php  # 向后台首页注入提示条
├── view/adminhtml/
│   ├── layout/
│   │   ├── lynx_patchwatch_status_index.xml
│   │   └── admin_dashboard_index.xml
│   ├── templates/
│   │   ├── status.phtml
│   │   └── dashboard_bar.phtml
│   └── requirejs-config.js     # 若用到远程资源，登记 CSP
└── etc/csp_whitelist.xml       # CSP 白名单（仅在 (a) 跨域拉取时需要）
```

---

## 3. ACL 资源

`etc/acl.xml` 中声明一个资源，挂在后台「系统」区域下：

```xml
<config>
  <acl>
    <resources>
      <resource id="Magento_Backend::admin" title="Admin">
        <resource id="Magento_Backend::stores" title="Stores">
          <resource id="Lynx_PatchWatch::view"
                    title="查看安全补丁状态"
                    sortOrder="100" />
        </resource>
      </resource>
    </resources>
  </acl>
</config>
```

- 只有被授予 `Lynx_PatchWatch::view` 的角色才能访问「系统 → 安全补丁状态」页面与提示条。
- 控制器 `Status\Index` 与 `Dashboard\Bar` 均通过 `_isAllowed()` 校验该 ACL 资源。

---

## 4. 数据来源（二选一）

两种来源产出的 JSON 结构完全一致（见 §6），模块内部统一映射成一个 `AdvisoryStatus[]`。

### 来源 (a)：在线 API

配置项（`Stores → Configuration → Lynx PatchWatch`）：

| 配置 | 说明 |
|---|---|
| `lynx_patchwatch/general/enabled` | 是否启用模块 |
| `lynx_patchwatch/source/mode` | `api` 或 `json_file` |
| `lynx_patchwatch/api/base_url` | lpw 部署地址，如 `https://lpw.internal` |
| `lynx_patchwatch/api/project_id` | 对应本项目的 lpw project id |
| `lynx_patchwatch/api/token` | 只读 token（见 §5） |
| `lynx_patchwatch/api/cache_ttl` | 缓存秒数，默认 3600（1 小时） |

`StatusFetcher` 行为：

1. 拼接 `GET {base_url}/api/projects/{project_id}/status?token={token}`。
2. 校验 HTTP 200 与 `project` 字段匹配；否则记录 `warning` 并回退到上一次缓存（若有）。
3. 将响应写入 Magento 的 `core_cache`（key 含 project_id），TTL = `cache_ttl`。
4. 下一次读取命中缓存，避免频繁打扰 lpw。

> lpw 侧：`/api/projects/{id}/status` 只接受 `?token=`，token 错误返回 403，项目不存在返回 404。
> 生成 token 的命令是 `lpw api-token`（详见 README）；lpw 只存储其 SHA-256 哈希。

### 来源 (b)：离线 JSON 文件

| 配置 | 说明 |
|---|---|
| `lynx_patchwatch/json/file_path` | `var/lynx_patch_status.json` 的绝对路径 |
| `lynx_patchwatch/json/cache_ttl` | 文件 mtime 校验周期，默认 3600 |

`JsonFileSource` 行为：

1. 读取 `file_path`；文件缺失 / 解析失败时记录 `warning` 并回退缓存。
2. 用文件里的 `generated_at` 判断新鲜度；超过 `cache_ttl` 给出「数据可能过期」的视觉提示（不报错）。
3. 部署方在 CI 或发布脚本里运行：

   ```bash
   lpw export-status --project <project_id> --out var/lynx_patch_status.json
   ```

   再随代码 / 部署包发布到 Magento 的 `var/` 目录。

---

## 5. Token 存放方式

- **绝不**把 token 写死在 PHP 源码或提交到版本库。
- 优先：Magento **Encrypted Config**（`<system>` 字段加 `<backend_model>Magento\Config\Model\Config\Backend\Encrypted</backend_model>`），由 `core_config_data` 的加密列存储，明文只在运行时由 `Model/Config.php` 解密。
- 备选：通过环境变量 `LYNX_PATCHWATCH_API_TOKEN` 注入（容器 / 部署平台秘钥管理），`Model/Config` 优先读环境变量，缺省再回落到 store 配置。
- lpw 端只保存 token 的哈希（`sha256`），即使 lpw 数据库泄露也无法还原 token；泄露后通过 `lpw api-token --rotate` 立即轮换。

---

## 6. 数据结构（两种来源一致）

lpw 产出的 JSON（`/api/...` 与 `export-status` 完全相同）：

```json
{
  "project": "shop-acme",
  "generated_at": "2026-10-17T08:23:11+00:00",
  "advisories": {
    "APSB26-146": "vulnerable",
    "APSB26-73":  "fixed",
    "APSB26-51":  "unknown"
  }
}
```

`advisories` 的值是公告级汇总状态，取值与中文标签如下（与 lpw 看板一致）：

| 状态值 | 中文 | 含义 |
|---|---|---|
| `fixed` | 已修复 | 所有适用项均验证已修复 |
| `vulnerable` | 存在漏洞 | 任一适用项存在漏洞或冲突待复核 |
| `declared` | 已声明补丁 | 仅发现补丁声明，未验证 |
| `unknown` | 未知 | 尚无明确证据（未扫描 / 证据不足） |
| `not_applicable` | 不适用 | 该项目不在受影响范围内 |

> 注：`conflict`（冲突待复核）在公告级会被聚合为 `vulnerable`，因为冲突项按「未修」处理（见 lpw 结论合并规则）。

---

## 7. 后台页面与提示条

### 7.1 「系统 → 安全补丁状态」页

- 菜单注册在 `etc/adminhtml/menu.xml`，父节点为 `Magento_Backend::system`（系统），标题「安全补丁状态」。
- 页面表格列：公告 ID、标题、优先级、发布时间、修复状态（着色）、首次发现 / 修复时间（可选）。
- 着色逻辑复用上面的状态 → 中文标签映射，并配背景色（`vulnerable` 红、`fixed` 绿、`declared` 灰、`unknown` 浅灰）。
- 若数据来自来源 (a) 且最近一次拉取失败，页面顶部显示黄色提示「状态数据可能过期，上次成功：{time}」。

### 7.2 后台首页提示条

- 通过 `Observer` 监听 `adminhtml_block_html_before`（或 `controller_action_predispatch_adminhtml_dashboard_index`），
  向 `adminhtml_dashboard_index.xml` 指定的容器注入 `DashboardBar` Block。
- 提示条只在「存在 vulnerable / unknown 公告」时出现，文案示例：
  - 有漏洞：`⚠ 发现 N 个未修复的安全公告（如 APSB26-146），请尽快处理。`
  - 全部已修：不显示或显示绿色「✓ 已安装全部已跟踪安全补丁」。
- 提示条只读取缓存，不主动发起网络请求，避免拖慢后台首页。

---

## 8. CSP 白名单

- **来源 (b)**：模块只读取本地文件，不产生任何跨域请求，**无需** CSP 配置。
- **来源 (a)**：若 `StatusFetcher` 通过浏览器侧（fetch / requirejs）直接拉取 lpw，则需在
  `etc/csp_whitelist.xml` 中把 lpw 的 host 加入 `connect-src`（以及 `img-src` / `style-src`，若该 host 提供图标或样式）。
  推荐改为**服务端 PHP 拉取 + Magento 缓存**，这样前端零跨域请求，CSP 保持最严。
- 不论哪种模式，模块自身不引入第三方 CDN，默认 CSP 模式 `store` 即可满足。

```xml
<!-- 仅在 (a) 且确需前端跨域拉取时才需要 -->
<config>
  <csp_whitelist xmlns:xsi="..." xsi:noNamespaceSchemaLocation="...">
    <policies>
      <policy id="connect-src">
        <value id="lynx_patchwatch_api" type="host">https://lpw.internal</value>
      </policy>
    </policies>
  </csp_whitelist>
</config>
```

---

## 9. 部署与运维

1. 安装模块：`composer require lynx/patchwatch` 或放入 `app/code/Lynx/PatchWatch` 后 `bin/magento setup:upgrade`。
2. 选择来源：
   - (a) 在线：在后台配置 `base_url` / `project_id` / `token`（加密），并保证 Magento 能访问 lpw 的 `/api`。
   - (b) 离线：在发布流程中加入 `lpw export-status --project … --out var/lynx_patch_status.json`。
3. 生成 token：`lpw api-token`（lpw 端），把输出填入模块配置或环境变量。
4. 轮换 token：lpw 端 `lpw api-token --rotate`，再更新模块配置；旧 token 立即失效。
5. 缓存：来源 (a) 默认 1 小时；来源 (b) 以文件 `generated_at` 为准。需要即时刷新时清 `lynx_patchwatch` 缓存。

---

## 10. 安全要点（ checklist ）

- [ ] token 使用 Magento Encrypted Config 或环境变量，未进入版本库。
- [ ] lpw 的 `/api` 仅暴露只读状态，且强制 token；lpw 数据库只存 token 哈希。
- [ ] 后台页面与提示条均经 ACL `Lynx_PatchWatch::view` 校验。
- [ ] 来源 (a) 使用服务端拉取 + 缓存，前端无跨域请求（CSP 保持最严）；确需前端跨域时登记 `csp_whitelist.xml`。
- [ ] 拉取失败有降级（回退缓存 + 过期提示），不会让后台首页崩溃。
- [ ] 模块对 lpw 数据库零写权限，仅消费状态 JSON。
