# REA CLI Factory

**将应用分析证据转为 Agent 可调用、结果可验证的 CLI。**

A task-oriented agent skill for turning application analysis into verified CLI adapters. This repository publishes the reusable workflow and application inventory tools only; application-specific adapters are maintained separately.

结合 [REA](https://github.com/morluto/rea) 的发布包分析能力与 [CLI-Anything](https://github.com/HKUDS/CLI-Anything) 的真实软件后端、结构化输出和产物验证方法。先围绕具体任务寻找入口，再实现并验证适配器。静态发现不等于功能可用，也不意味着任意 GUI 都能自动转成 CLI。

## 开源范围

- [`skills/rea-cli-factory/SKILL.md`](skills/rea-cli-factory/SKILL.md)：面向 Agent 的通用开发工作流。
- [`references/adapter-contract.md`](skills/rea-cli-factory/references/adapter-contract.md)：目标身份、动作、结果、失败和验证契约。
- [`scripts/inventory_app.py`](skills/rea-cli-factory/scripts/inventory_app.py)：macOS 应用清单与摘要工具，只读取包身份，不启动应用或读取账号数据。
- [`scripts/probe_app.py`](skills/rea-cli-factory/scripts/probe_app.py)：只读入口候选探测与路由建议，不启动应用。
- [`scripts/summarize_rea.py`](skills/rea-cli-factory/scripts/summarize_rea.py)：离线筛选 REA 分析证据，保留覆盖范围与源位置。
- [`scripts/check_compatibility.py`](skills/rea-cli-factory/scripts/check_compatibility.py)：对固定已验证清单做只读兼容性门禁。
- [一次完成 ASAR 精选输入、REA 和接口提取](skills/rea-cli-factory/references/blind-evaluation.md)：冻结盲测输入、保留失败和人工介入边界。
- [静态桥接提取与候选 CLI 生成](skills/rea-cli-factory/references/bridge-generation.md)：从 REA 对应源码自动提取方法和形参，只生成显式选中的调用入口。
- [ESM、条件暴露与固定业务通道绑定](skills/rea-cli-factory/references/gateway-binding.md)。
- [重启与升级协议](skills/rea-cli-factory/references/maintenance-validation.md)。
- [多应用验证协议](skills/rea-cli-factory/references/multi-app-evaluation.md)、离线测试和 GitHub Actions。

**不包含任何应用专用 CLI、专用 Skill、逆向提取源码、运行收据或下载内容。** MCP 是可选扩展方向，目前没有实现 MCP server。

## 使用

基础清单/门禁需要 Python 3。静态桥接提取还需 Node.js >=24.11，并在仓库根目录执行 `npm ci --ignore-scripts`；生成运行器的进程绑定仅支持 macOS。应用清单面向 macOS .app；测试使用合成目录，可在 Linux 上运行。

```bash
git clone https://github.com/WeltPRICKETT/rea-cli-factory.git
cd rea-cli-factory
python3 skills/rea-cli-factory/scripts/inventory_app.py --app '/Applications/YourApp.app'
python3 skills/rea-cli-factory/scripts/probe_app.py --app '/Applications/YourApp.app'
```

已有 REA JavaScript JSON 时，可在本地读取紧凑摘要（不启动应用、不重新分析）：

```bash
python3 skills/rea-cli-factory/scripts/summarize_rea.py --input /private/path/evidence.json --query feature --limit 10
```

摘要用于开发定位，不验证 Evidence 的真实性；保留原始私有证据，不将输出当作自动脱敏发布材料。

清单输出包含包标识、版本、主程序与可选 app.asar 的 SHA-256；清单不是 REA 分析，也不是运行时验收。

将 Skill 目录交给支持 SKILL.md 的 Agent，或在仓库根目录创建链接（已有同名 Skill 时先比较，不覆盖）：

```bash
mkdir -p "$HOME/.codex/skills"
ln -s "$PWD/skills/rea-cli-factory" "$HOME/.codex/skills/rea-cli-factory"
```

然后向 Agent 指定应用和具体任务，例如：“使用 rea-cli-factory，为我安装的应用制作导出当前项目的 CLI，并验证导出结果。”

需要逆向分析时，自行安装和配置 REA 或对应 Skill，按实际版本的工具参数调用。REA 与 CLI-Anything 没有打包在本仓库中。

## 验证

```bash
python3 -m unittest discover -s skills/rea-cli-factory/scripts -p 'test_*.py'
npm ci --ignore-scripts
npm test
```

48 项 Python 与 108 项 Node 回归，共 156 项，覆盖身份摘要、升级失效、ASAR 有界选择、REA 证据关联、模块/工厂/ESM/条件暴露、固定业务通道、目标绑定与失败处理。测试本身不联网、不启动应用，不代表任意应用的自动适配能力。

## 多应用实测

已在三款应用完成原生命令行/脚本接口的真实产物验证，详见 [试验摘要](docs/generalization-2026-10-22.md)。随后在第四款应用完成了 [REA 辅助内部笔记接口试验](docs/rea-increment-2026-10-22.md)：两次真实导入、读回和导出通过。REA 提供候选位置，仍需代码检查与运行时验证；尚不是任意应用自动适配。后续 [维护试验](docs/maintenance-2026-10-23.md) 已通过两次真实重启读回和受控升级门禁演练；未执行真实应用升级。新增 [Hydrogen Music 生成试验](docs/bridge-generation-2026-10-23.md)，三个实测方法全部由提取器和生成器产生映射；业务语义与生命周期仍需人工确认。应用适配器和原始证据仍不公开。

## 项目状态

此前 [盲测记录](docs/blind-trial-2026-10-23.md) 保留 Miyo 筛选退出和 Tutti 首次失败。最新 [跨文件解析与新盲测](docs/module-resolution-2026-10-23.md) 已通过 Tutti 的生成 CLI 文本读取，随后冻结工具测试 Folo，保留其 ESM/条件暴露样本的首次失败。

最新 [ESM 与通道绑定试验](docs/esm-gateway-2026-10-23.md)：Folo 两个生成命令通过真实只读验证，但最终加固提取器因全局动态写入返回 blocked；Typeless 首次冻结盲测因混淆属性名返回 blocked。分别保留实测成功与自动提取失败，应用专用产物仍不公开。

实验性通用工具，面向希望将重复 GUI 任务交给 Agent 的个人开发者。当前公开范围是工作流、清单和候选生成工具；具体应用适配器独立维护。优先级是可验证结果与明确失败，下一里程碑是补充全局写入的执行顺序证明与有界混淆字符串恢复，并继续减少生命周期和验收的人工准备；不通过执行源码或手填映射绕过盲测失败。核心指标是正确性、人工介入次数、整体等待时间和维护成本；无可调用入口、结果不可验证或维护成本高于人工收益时停止该适配方向。

## 许可证与来源

使用 [MIT License](LICENSE)。REA 和 CLI-Anything 为独立项目；本项目借鉴方法，不声称获得官方背书或完整兼容其发布格式。
