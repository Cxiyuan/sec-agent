# skills/ — XDR 技能与角色模板

本目录存放**面向安全调查的 prompt 资产**（dsh skill 包），与代码插件（`agent/plugins/`）
分离：技能是模型按需取用的方法论，不是可执行逻辑。

## 目录约定

- 一个技能一个子目录，例如 `skills/investigation-sop/`（调查方法论）、
  `skills/role-forensics/`（取证深查员角色模板）。
- 角色 = 角色 prompt + 建议工具范围，只是模板；**安全边界不靠 prompt**，
  工具权限由插件注册范围（scope）与 approval 策略决定。
- 技能经 dsh 的 skill 机制注册（`ctx.skill`），主 agent 按需加载；
  多 agent 委派时作为 subagent spawn 的角色模板使用。

## 当前状态

尚未有技能落地。首批规划：调查方法论（P1）、取证/处置角色模板（P2）。
