# REA CLI Factory

**将应用分析证据转为 Agent 可调用、结果可验证的 CLI。**

A task-oriented agent skill for turning application analysis into verified CLI adapters. This repository publishes the reusable workflow and application inventory tools only; application-specific adapters are maintained separately.

结合 [REA](https://github.com/morluto/rea) 的发布包分析能力与 [CLI-Anything](https://github.com/HKUDS/CLI-Anything) 的真实软件后端、结构化输出和产物验证方法。先围绕具体任务寻找入口，再实现并验证适配器。静态发现不等于功能可用，也不意味着任意 GUI 都能自动转成 CLI。

## 开源范围

- [`skills/rea-cli-factory/SKILL.md`](skills/rea-cli-factory/SKILL.md)：面向 Agent 的通用开发工作流。
- [`references/adapter-contract.md`](skills/rea-cli-factory/references/adapter-contract.md)：目标身份、动作、结果、失败和验证契约。
- [`scripts/inventory_app.py`](skills/rea-cli-factory/scripts/inventory_app.py)：macOS 应用清单与摘要工具，只读取包身份，不启动应用或读取账号数据。
- 清单工具的离线测试和 GitHub Actions。

**不包含任何应用专用 CLI、专用 Skill、逆向提取源码、运行收据或下载内容。** MCP 是可选扩展方向，目前没有实现 MCP server。

## 使用

需要 Python 3。应用清单面向 macOS .app；测试使用合成目录，可在 Linux 上运行。

```bash
git clone https://github.com/WeltPRICKETT/rea-cli-factory.git
cd rea-cli-factory
python3 skills/rea-cli-factory/scripts/inventory_app.py --app '/Applications/YourApp.app'
```

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
```

6 项回归覆盖身份摘要、内容变化、应用名歧义、路径穿越、符号链接越界和缺失文件。测试不联网、不启动应用，不代表任意应用的自动适配能力。

## 项目状态

实验性通用工具，面向希望将重复 GUI 任务交给 Agent 的个人开发者。当前公开范围是工作流与应用清单工具；具体应用适配器独立维护。优先级是可验证结果与明确失败，下一里程碑是更多架构下的工作流验证。核心指标是正确性、人工介入次数、整体等待时间和维护成本；无可调用入口、结果不可验证或维护成本高于人工收益时停止该适配方向。

## 许可证与来源

使用 [MIT License](LICENSE)。REA 和 CLI-Anything 为独立项目；本项目借鉴方法，不声称获得官方背书或完整兼容其发布格式。
