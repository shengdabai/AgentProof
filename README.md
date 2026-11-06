# AgentProof

AI 辅助开发让“写出改动”越来越便宜，但验证、交接和误操作恢复仍然昂贵。AgentProof 是一个本地优先的窄 MVP：在 AI 动手前保存有界快照，完成后运行显式验收命令、检查交付物、标记敏感路径变化，并生成 JSON + HTML 证据包。

它不会上传项目内容；`.env`、密钥、凭据等默认只记录文件元数据，不读取、哈希或复制内容。恢复默认只预览，只有显式 `--yes` 才覆盖快照中有备份的文件；新增文件永不自动删除。

## 运行

```bash
cd 12-agentproof
python3 -m unittest discover -s tests -v

python3 agentproof.py snapshot \
  --project /path/to/project \
  --output /path/to/snapshot

python3 agentproof.py verify \
  --project /path/to/project \
  --baseline /path/to/snapshot \
  --config /path/to/checks.json \
  --output-dir /path/to/report

# 默认只显示恢复计划
python3 agentproof.py restore --project /path/to/project --baseline /path/to/snapshot --path src/app.py

# 明确执行单文件恢复
python3 agentproof.py restore --project /path/to/project --baseline /path/to/snapshot --path src/app.py --yes
```

配置只允许 JSON 中显式列出的命令，不自动猜测并执行项目脚本。示例见 [examples/complaint-radar.json](examples/complaint-radar.json)。

## 快照与恢复边界

- 自定义 `sensitive_patterns` 只增加保护规则，不会关闭内置规则。匹配不区分大小写，嵌套的凭据目录也受保护。
- 敏感文件只记录元数据。交付物检查同样拒绝读取或计算敏感文件的哈希，也拒绝指向敏感文件的符号链接。
- 命名管道等特殊文件只记录元数据，避免快照被阻塞。文件权限变化会计入变更；敏感文件权限变化会让验收失败。
- 恢复预览和执行均校验备份路径、文件类型、大小和 SHA-256。所选文件全部校验通过后，执行模式才开始写入。
- 恢复源和目标路径不允许符号链接。每个文件先写入临时副本并再次校验，再原子替换目标，避免通过硬链接覆盖其他文件。
- 清单和备份必须来自可信的本地快照。SHA-256 可检测备份与清单不符，不能证明同时被篡改的清单与备份可信。
- 多文件恢复不是事务。执行期间如果发生磁盘错误，之前已恢复的文件不会自动撤销；恢复期间应停止其他进程修改相关目录。

## MVP 验收口径

- Git 与非 Git 目录都能建立基线。
- 能发现新增、修改、删除和敏感路径变化。
- 能运行显式命令并记录退出码、耗时与脱敏输出尾部。
- 能验证文件存在、大小、SHA-256 以及 PNG/JPEG/GIF 尺寸。
- 能生成可读 HTML 与机器可读 JSON。
- 能预览或显式恢复有备份的基线文件，且不自动删除新增文件。

## 仍未证明

技术验收通过只证明 MVP 能覆盖指定工作流，不等于市场付费需求已经成立。商业门槛是：20 位目标用户触达、5 份真实仓库或失败 diff、3 次发现真实遗漏、1 次付费试跑。

