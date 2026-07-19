# LLM Filter Sidecar

[English](README.md)

一个位于 OpenAI 兼容上游之前的过滤边车：先不可逆地脱敏 PII/密钥，再按需调用语义安全审核，最后以不缓冲 SSE 的方式转发请求。

```text
客户端 / nginx
      |
      v
llm-filter-sidecar ----> privacy-filter（脱敏）
      |
      +---------------> 可选的 OpenAI 兼容审核模型
      |
      v
任意 OpenAI 兼容上游
```

它不接管账号、计费、模型路由、数据库或响应存储，因此可以放在任意兼容上游之前。

## 核心能力

- 精确处理 `POST /v1/chat/completions` 与 `POST /v1/responses`。
- 通过 [packyme/privacy-filter](https://github.com/packyme/privacy-filter) 脱敏；示例 Compose 固定到明确提交。
- 脱敏或审核不可用时，对目标路由 fail-closed。
- 语义审核默认关闭；启用后只接收已经脱敏的 user 文本。
- 无状态开放段审核：最后一条 assistant 消息之后的所有 user 消息共同参与判定。
- 模型列表精确、区分大小写，并显式选择 `allow` 或 `audit` 模式。
- 使用带密钥的 HMAC-SHA256 指纹比较重试，不记录原始 prompt。
- 保留上游流式/SSE 响应；非目标路由原样透传。
- Go 网关只依赖标准库；容器默认非 root、只读文件系统、丢弃 Linux capabilities。

## 覆盖范围

| 路由 | 会脱敏的字段 |
| --- | --- |
| Chat Completions | 消息文本、旧版/工具函数调用参数、函数描述、嵌套 JSON Schema 描述 |
| Responses | `instructions`、字符串/数组 `input`、content/output 文本、函数参数、函数描述、嵌套 JSON Schema 描述 |

图片、音频和上传文件的二进制内容不在过滤范围内。可能被上游规范化为目标路由的路径别名会直接拒绝，避免绕过。

## 快速启动

需要 Docker Engine、Compose v2，以及构建固定版本 `privacy-filter` 所需的出网能力。

```bash
cp .env.example .env
# 编辑 UPSTREAM_URL；该地址必须能从 sidecar 容器访问。
docker compose config --quiet
docker compose up -d --build --wait --wait-timeout 240
./scripts/verify.sh http://127.0.0.1:8080 401
```

`verify.sh` 的第二个参数是上游面对脚本假 API Key 时的确定状态码。请传入真实预期值，不要用宽泛状态码范围掩盖异常。

默认只监听 `127.0.0.1:8080`。宿主机上游可使用 `http://host.docker.internal:<端口>`；另一个 Compose 项目中的上游应与 sidecar 接入同一个 Docker 网络。

## 启用语义审核

```bash
./scripts/prepare-audit-secrets.sh
# 安全写入 secrets/audit_api_key，不要把密钥放在命令行。
# Linux 上将 .env 的 SIDECAR_UID/SIDECAR_GID 设置为 `id -u`/`id -g`。
# 在 .env 中设置 AUDIT_URL 与 AUDIT_MODEL。
docker compose -f compose.yaml -f compose.audit.yaml config --quiet
docker compose -f compose.yaml -f compose.audit.yaml up -d --build --wait --wait-timeout 240
./scripts/verify.sh http://127.0.0.1:8080 401
```

审核地址默认必须是 HTTPS。只有在明确受信的私有网络里，才应显式设置 `AUDIT_ALLOW_INSECURE_HTTP=true`。

[`audit-model-list.txt`](audit-model-list.txt) 的解释方式：

- `allow`：列表内模型跳过语义审核，列表外审核；空列表表示审核所有合法模型。
- `audit`：仅列表内模型审核，列表外跳过；空列表表示不审核任何合法模型。
- 缺失或非字符串 model 在两种模式下都必须审核。

模型选择永远不会绕过隐私脱敏。

本地 Docker Compose 会把文件型 secrets 作为 bind mount。示例因此以 `SIDECAR_UID:SIDECAR_GID`（默认 `1000:1000`）运行非 root sidecar，使部署用户持有的 `0600` 密钥无需放宽为全局可读；Linux 部署时应把两项改成 `id -u` 与 `id -g` 的结果。直接运行镜像时仍默认使用专用 UID/GID 65532。

## 安全边界

- 目标路由 fail-closed；非目标路由明确不属于过滤范围。
- 不主动记录请求体、prompt、Authorization、密钥或审核服务原始响应。
- 审核日志只有元数据、短原因和带密钥指纹。
- 审核先于上游、后于脱敏；审核方看不到原始的已选 user 文本。
- 客户端删掉或改写的历史消息无法由无状态网关恢复。
- 内置审核 prompt 是可部署基线，不是概率模型绝不误判/漏判的保证；启用前必须用自己的模型做成对策略测试。

完整配置见 [`skills/llm-filter-sidecar-deploy/references/configuration.md`](skills/llm-filter-sidecar-deploy/references/configuration.md)，生产切换和回滚见公开部署 skill：[`skills/llm-filter-sidecar-deploy`](skills/llm-filter-sidecar-deploy)。暴露到 loopback 之外前请阅读 [SECURITY.md](SECURITY.md)。

## 开发验证

```bash
gofmt -w main.go main_test.go
go test ./...
go vet ./...
go build ./...
```

项目采用 Apache-2.0；Compose 单独构建的 `packyme/privacy-filter` 采用 MIT 许可证。
