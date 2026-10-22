# 从静态桥接到候选 CLI

此流程减少重复抄写方法与参数，适用于支持子集内的 Electron preload。它不会判断业务授权、自动启动任意应用，或自动证明任务完成。先按具体任务确认已有 CLI/API 不满足需要。

## 输入与依赖

Python 3、Node.js >=24.11，仓库根目录执行 `npm ci --ignore-scripts`，按锁文件安装 `@babel/parser`。只分析应用发布包中选定的 preload，保留对应的完整 REA JavaScript JSON 和安装包来源关系；提取源码及证据保持私有。提取器验证源码摘要和 IPC 源码位置对应所给 REA 观察，不验证 Evidence 密码学完整性，也不自动证明这些精选源码来自给定安装包。

```sh
node skills/rea-cli-factory/scripts/discover_bridge.mjs \
  --source /private/selected/preload.js --source-name preload.js \
  --evidence /private/rea-evidence.json --out /private/bridge-contract.json
```

提取器不执行输入代码。支持顶层 CommonJS `require('electron')` 的命名空间或解构别名、对象字面量、函数声明/shorthand/简单箭头、字面量通道及直接 invoke/send 转发。输出方法路径、形参和数量、传输方式、通道、源码位置，统一标为 `candidate`。

动态通道、订阅回调、复杂函数、默认/rest 参数、未知作用域、绑定或属性突变、getter/spread、冲突暴露等保持 unsupported。保守拒绝可能漏掉可用接口；不能把未提取到视为应用没有该能力。候选数不等于运行时已支持数。

## 显式选择与生成

先检查任务含义、数据形状与副作用，仅选择必要方法。准备候选安装包清单，最终是否晋升固定已验证基线须由真实结果决定。固定应用主页面 URL：等待应用导航稳定后选择，不能把初始加载 URL 当成最终页面。

```sh
node skills/rea-cli-factory/scripts/generate_bridge_cli.mjs \
  --contract /private/bridge-contract.json \
  --baseline /private/app-inventory.json \
  --page-url 'file:///Applications/Selected.app/Contents/Resources/app.asar/index.html' \
  --select bridge.save,bridge.read \
  --out /private/new-adapter
```

生成器拒绝覆盖已有目录。产物包含通用运行器、固定基线、仅含显式选择方法的配置和 CLI 入口；这些实例属于应用专用适配器，默认不进入公开仓库。运行器调用原 preload 方法，不拼造 IPC channel 调用，不执行提取源码。

## 运行会话与结果

运行器不负责启动应用。适配器作者使用经过检查的启动方式建立自有测试 profile，并记录 `rea-cli-factory.local-session.v1` 描述：`appPath`、`profile`、`pid`、`port`、`owner`（UUID）、`targetId`、稳定的 `pageUrl`。macOS 启动参数须包含 `--user-data-dir=<profile>`，以 `--rea-cli-owner=<owner>` 结尾。此标记仅用于本机归属核对，不是身份认证机制。

```sh
node /private/new-adapter/cli.mjs list
node /private/new-adapter/cli.mjs call \
  --method bridge.read --args '[]' --session /private/session.json
```

调用前核对固定基线、兼容性、监听 PID、可执行文件、profile 启动参数、目标 ID 和页面 URL；执行表达式内再次核对 URL，防止查询目标后导航到别页。只连指定本机端口；不提供远程 CDP 或任意 JS 参数。此进程绑定实现仅支持 macOS，需要桌面应用运行，不是 headless。

参数由 JSON 数组传入，检查数量，不能从形参名推断类型或业务 schema。数据只作为原方法参数。`send` 返回 `dispatched`，`invoke` 返回 `returned`，二者始终 `verified:false`。另由任务工作流核对应用读回、独立产物和必要的重启读回。调用超时/断开可能已产生副作用，先检查状态，不能自动重试写入。

## 人工工作与验收指标

分别记录自动提取、显式选择、自动生成、实际运行和业务验证的数量/耗时。不要将手工选过的样本称作盲测，也不要把已有输入上的再生成时间说成从用户提出需求到交付的时长。

仍需人工或另一个经过验证的适配器负责：选择任务、确认源码/安装包归属、解释数据语义、检查启动隔离和清理、定义独立成功条件。动态枚举、复杂回调和 native 应用不属于本生成器支持范围。只有真实业务验证通过的窄任务可晋升 verified。
