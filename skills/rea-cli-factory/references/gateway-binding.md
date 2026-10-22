# 通用 IPC 入口到窄业务命令

任意通道转发器不是可用业务 CLI。`discover_modules.mjs` 将它保留为 `gateways`，状态为 `gateway-unbound`；只有 renderer 的调用证据能证明具体通道时，`bind_gateway.mjs` 才生成可选候选。

## 自动流程

`analyze_electron.mjs` 先分析 preload；存在 gateway 时，从同一 ASAR 的 HTML 本地 script src 选择 renderer 入口，运行第二次真实 REA，再调用 `bindGateways(sources, contract, evidence)`。原包摘要必须一致；两阶段原始证据、覆盖范围与耗时分别保存。

当前绑定器只接受一种有限结构：未被替换的内建 Proxy，两个空目标对象及纯 get trap，依次取得命名空间和方法名，构造 `${namespace}.${method}`，通过既有 gateway 原样转发 rest 参数。分析的是 AST，不运行代理或发布包代码。两处构造器都必须通过词法作用域检查；可见的内建 Proxy 替换、遮蔽、工厂逃逸、动态业务路径与冲突参数数量会拒绝。

固定业务调用例如 `client.settings.read(key)` 可形成 `settings.read` 命令；调用点数量只确定 arity，不能推定参数类型。支持不可重新绑定的 ESM const 导出，但不推断未分析的外部消费者。整个代理逃逸会拒绝；单个命名空间逃逸时排除该命名空间。无关可用性判断不视为业务调用。

## 配置与运行边界

- `apiPath`：从业务调用恢复的命令标识。
- `targetPath`：已证实的原始 preload gateway 路径。
- `boundArgs`：恰好一个固定 channel；必须与候选 channel 相同。
- `params` / `arity`：调用者提供的业务参数，最多 16 个；不包含 channel。
- `availability`：条件暴露来源；运行器再次检查原路径可用，缺失立即失败。

生成器仍要求显式选择少量任务方法。CLI 不提供 channel 参数、任意表达式或动态方法选择；调用原 gateway，保留其转发行为。业务语义、隔离启动、页面协议、独立结果验证由适配器工作流负责。

## 证据与局限

Preload 的 IPC 源码范围与 REA 操作必须匹配；renderer 的完整输入摘要必须有真实 REA artifact 观察支持。保留 factoryRange、callRanges、gatewayRange 和两阶段 Evidence ID。

`channelResolution: static-proxy-call` 与 `reaResolution: artifact-only` 明确表示通道由有限静态推导获得，不能写成 REA 已直接解析业务通道。第二阶段 coverage 单独记录；精选入口不代表整应用分析。候选仍为 candidate，真实调用 returned 仍为 verified:false，只有独立比较实际结果才能验证窄任务。

绑定器最多 16 文件、每个 8 MiB、合计 16 MiB；每个 AST 索引最多 2,500,000 节点、深度 1,024。不支持任意 Proxy、RPC 框架、拼接规则、跨 chunk 消费者或复杂参数变换。0 个绑定结果按 blocked/unbound 保留，不能用手填映射改成自动成功。
