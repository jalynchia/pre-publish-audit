---
name: "pre-publish-audit"
description: "代码、Skills 上传发布或分享给其他人前的本地安全扫描 Skill，可以检测其中是否包含 API 密钥、密码、敏感个人信息等，以及是否缺少基础规范文件。"
version: 1.0.1
Update date: 2026-06-27
---

# 代码发布前安全审计

在把代码、Skills 公开、上传 GitHub 或发给其他人之前，可以先用这个 skill 扫描一下。
- 它能帮你找出不小心遗留的 API 密钥、密码、个人敏感信息（如邮箱、绝对路径等）；
- 检查项目里是否缺少常规的说明文件。

# 它能帮你检查什么

- **敏感凭证**：自动检测 AWS 密钥、大模型 API Key、数据库连接串、密码、JWT 等。
- **个人隐私**：识别邮箱地址、国内手机号、身份证号、内网 IP，以及会泄露系统用户名的绝对路径。
- **文件与结构**：检查项目里是不是漏掉了 `README.md`、`LICENSE`、`.gitignore` 或依赖声明文件（如 `requirements.txt`、`package.json`）。
- **可疑文件**：找出不该上传的 `.env`、`.DS_Store` 以及各种密钥文件（`.pem`、`.key` 等）。

# Dependencies 依赖

这个 skill 的扫描流程是通过 `audit_scanner.py` 来完成，这个脚本只用了 Python 3 标准库来实现，**没有任何第三方依赖**。
