# lynx-patch-watch (`lpw`)

补丁安装检查 + 多项目看板 + 项目管理工具，首期适配 **Magento / Adobe Commerce**。

它回答一个 msw（`magento-security-watcher`）回答不了的问题：**某个项目到底有没有把某个安全修复装上？**
在 msw 的「公告采集 + 版本比对」之上，新增了：

- **git 提交检查**：修复 commit 是否为祖先、按 message 搜索、上游 `.patch` 路径映射比对。
- **补丁声明识别**：`m2-hotfixes`、`cweagans/composer-patches`、`vaimo`、Quality Patches (QPT)。
- **自定义规则**：YAML 组合 `all / any / not` 原子条件，按 `applies_to`（类型 / 版本 / edition）生效。
- **历史时间线与增量扫描**：从第一次扫描起就写入只追加账本；commit / 规则集 / 公告未变时跳过。
- **项目类型识别**：`detect` 自动判断 Magento 版本与 Edition（CE / EE / B2B）。
- **可编辑的项目管理 + Excel 导入导出**：项目清单、人工确认结果、4 张导出表。
- **带认证的 Web 看板**：看板 / 矩阵 / 历史 / 公告 / 规则 / Excel，单管理员 + CSRF + IP 白名单。
- **只读 API**：`/api/projects/{id}/status`，供 Magento 后台模块消费（见 `docs/magento-module-design.md`）。

> 数据模型与采集逻辑从仓库内未提交的 `magento-security-watcher`（msw）**移植**，移植处注明出处；
> **lpw 不修改 msw**。

---

## 目录结构

```
lynx-patch-watch/
├── pyproject.toml              # 包名 lynx_patch_watch，CLI 入口 lpw
├── .env.example                # 复制为 .env（存秘钥，勿提交）
├── config/
│   └── settings.yaml.example    # 复制为 config/settings.yaml 后调整
├── rules/magento/              # 检查规则（内置示例 + 用户自定义）
├── src/lynx_patch_watch/
│   ├── config.py store.py models.py cli.py
│   ├── detect/                 # 项目类型识别
│   ├── adapters/magento/       # 公告源、版本比较、Magento 路径映射
│   ├── checkers/               # 可插拔检查器
│   ├── engine/                 # 扫描编排、结论合并、扫描任务队列
│   ├── excel/                  # 模板、导入、导出
│   └── web/                    # FastAPI + Jinja2（带登录）
├── tests/fixtures/             # chimera collection.json 片段、Magento 工作区样例
└── docs/magento-module-design.md
```

---

## 环境要求

- Python **≥ 3.10**
- 依赖：`fastapi`、`uvicorn`、`jinja2`、`python-multipart`、`openpyxl`、`argon2-cffi`、`itsdangerous`、`pydantic`、`pydantic-settings`、`httpx`、`pyyaml`、`click`

---

## 安装

```bash
cd lynx-patch-watch
python -m venv .venv && source .venv/bin/activate
pip install -e .
lpw --help
```

---

## 配置

1. `cp config/settings.yaml.example config/settings.yaml`，按需调整（chimera URL、扫描目录、端口等）。
2. `cp .env.example .env`，至少填写管理员密码哈希：

   ```bash
   lpw hash-password          # 交互输入密码，输出 argon2 哈希
   # 把输出写入 .env：
   # LPW_ADMIN_PASSWORD_HASH=$argon2id$v=19$m=...
   ```

3. （可选）凭据引用：项目 `git_url` 里可写 `https://${LPW_GIT_USER}:${LPW_GIT_TOKEN}@host/repo.git`，
   lpw 在 clone 时展开 `${ENV}`，日志中自动脱敏。

---

## CLI 用法

```
lpw ingest [--from-html F] [--fixture-dir D] [--full]   # 抓取 Adobe 公告入库
lpw import-msw --db PATH                                # 从 msw 数据库导入公告+风险项（不含 findings）
lpw detect PATH                                         # 识别工作区类型/版本/Edition
lpw scan [--project ID ...] [--local-workspace DIR] [--full]   # 扫描项目并记录结论
lpw projects list | import-yaml FILE                    # 项目管理（import-yaml 会剥离凭据）
lpw excel template FILE | export FILE | import FILE [--dry-run]   # Excel 模板/导出/导入
lpw export-status --project ID --out FILE               # 导出某项目状态 JSON（供 Magento 模块）
lpw api-token [--rotate]                                # 创建/轮换只读 API token
lpw serve [--host H] [--port P]                         # 启动 Web 看板（含后台扫描 worker）
lpw hash-password                                        # 生成管理员密码哈希
```

### 典型端到端流程

```bash
# 1. 采集公告（离线 fixture 或联网）
lpw ingest --fixture-dir tests/fixtures
# 2. 登记一个本地 Magento 工作区，立即扫描
lpw scan --local-workspace /path/to/magento
# 3. 生成只读 token，供 Magento 后台模块使用
lpw api-token
# 4. 导出状态 JSON
lpw export-status --project <id> --out var/lynx_patch_status.json
# 5. 启动看板
lpw serve
```

---

## Web 看板

`lpw serve` 启动 FastAPI 应用（默认 `127.0.0.1:8080`）：

- **所有页面都需要登录**（仅一个管理员账号，密码哈希由 `.env` 配置）。
- 会话为 `itsdangerous` 签名的 `HttpOnly` + `SameSite=Strict` Cookie；登录失败有速率限制；表单带 CSRF token。
- IP 白名单中间件：默认仅回环；在 `settings.yaml` 的 `web.allowed_cidrs` 放开。
- 页面：`/`（看板）、`/projects`、`/matrix`、`/history`、`/advisories`、`/rules`、`/excel`。
- 后台 worker 串行执行网页入队的扫描任务。

---

## 只读 API（给 Magento 模块）

```
GET /api/projects/{id}/status?token=<read_only_token>
```

返回（与 `export-status` 一致）：

```json
{
  "project": "shop-acme",
  "generated_at": "2026-10-17T08:23:11+00:00",
  "advisories": { "APSB26-146": "vulnerable", "APSB26-73": "fixed" }
}
```

- token 由 `lpw api-token` 生成；lpw 只存储其 SHA-256 哈希，泄露可 `lpw api-token --rotate` 立即轮换。
- 错误 token → `403`，未知项目 → `404`。
- Magento 端的消费 / 展示 / ACL / CSP 设计见 **`docs/magento-module-design.md`**。

---

## Excel 导入 / 导出

- **模板**：`lpw excel template lpw-template.xlsx` —— 含「说明」「项目」「人工确认」三张表，数字 ID 列强制文本格式（防止纯数字 ID 被 Excel 转成数字 / 丢精度）。
- **导入**：`lpw excel import FILE [--dry-run]`。先预览（新增 / 更新 / 无变化 / 逐行错误）；有错误则中止、不写入。
  - 脱敏值 `***` 与空 Git 地址视为「不修改」。
  - 含明文凭据的 Git 地址**拒绝**该行。
  - 拒绝 `.xlsm`、限制 5MB、使用 `read_only` 模式读取。
- **导出**：`lpw excel export FILE` 生成 4 张表：
  1. `项目清单`（列与导入一致，可改完再导回；Git 地址脱敏为 `***`）
  2. `项目×公告矩阵`（状态中文 + 条件填色）
  3. `问题明细`（每行一个 project × item：状态、判定来源、置信度、证据摘要、人工状态…）
  4. `统计`（各项目维护率）
  - 以 `= + - @` 开头的单元格加前导单引号，防止公式注入。

---

## 结论状态词汇表

| 状态 | 含义 |
|---|---|
| `fixed` 已修复 | 有正向证据（内容匹配 / 补丁已验证 / lock 版本已修 / 修复 commit 是祖先 / 规则命中） |
| `vulnerable` 存在漏洞 | 内容证据为漏洞（部署树有 vendor 且版本层显示已修时另标 `conflict`） |
| `conflict` 冲突待复核 | 正向证据与漏洞证据并存，按「未修」处理，需人工复核 |
| `declared` 已声明补丁 | 仅发现补丁声明，未经验证（不计入已验证修复率） |
| `not_applicable` 不适用 | 不在受影响范围 |
| `unknown` 未知 | 证据不足 / 尚未扫描 |
| `error` 检查出错 | 某个检查器异常 |

人工确认（`confirmed_fixed` / `confirmed_vulnerable` / `ignored` / `false_positive`）会覆盖自动结论，
但证据变化后会将确认标记为「过期」提示复核；`ignored` / `false_positive` 从分母中剔除、不计为已修。

---

## 测试

```bash
python -m pytest -q   # 需从仓库根目录运行：测试通过 `from tests.conftest import ...` 导入，直接 `pytest` 会报 ModuleNotFoundError
```

- 移植自 msw 的测试全部保留。
- 新增覆盖：chimera 3 位公告编号与 Commerce 过滤、各检查器、结论合并、项目识别、Excel 往返与注入防护、Web 认证与 CRUD、API token、CLI。

---

## 安全与数据说明

- **不修改 msw**：lpw 从 msw 移植可复用代码并注明出处，二者目录共存、互不改动。
- 密码哈希（argon2）与 API token 哈希（sha256）只存派生值，不存明文。
- Git 凭据用 `${ENV}` 占位，运行期展开、日志脱敏；导入含明文凭据的 URL 会被拒绝并提示轮换。
- `import-msw` 只导入公告与风险项，**不导入 msw 的 findings**，避免假的首现时间污染历史账本。

---

## 已知限制（本期）

- 仅实现 Magento 一种项目类型识别与检查。
- 上游修复 commit 不做自动发现，只在规则里显式写 sha / patch URL 时生效。
- QPT 只识别补丁声明与文件，不执行 `magento-patches status`。
- APSB26-146 的示例规则特征为占位，需拿到真实 hotfix 补丁后补全（见规则文件内 `TODO`）。
- 未包含：企微通知、LLM 分析、alert_state（留待后续）。
