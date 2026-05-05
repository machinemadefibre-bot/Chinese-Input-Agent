<p align="center">
  <img src="docs/banner.svg" alt="ChineseInputAgent banner" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/machinemadefibre-bot/ChineseInputAgent"><img alt="GitHub repo" src="https://img.shields.io/badge/GitHub-ChineseInputAgent-181717?logo=github"></a>
  <img alt="Windows" src="https://img.shields.io/badge/Windows-10%2F11-0078D4?logo=windows">
  <img alt="Native C" src="https://img.shields.io/badge/Native-C-00599C?logo=c">
  <img alt="llama.cpp" src="https://img.shields.io/badge/Runtime-llama.cpp-6B46C1">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-22C55E">
</p>

<h3 align="center">把加密消息伪装成一段普通中文长文的本地 Windows 小工具。</h3>

ChineseInputAgent 是一个原生 Win32 portable 应用，用来让两台电脑通过微信、QQ、Telegram、网页聊天框等第三方聊天软件交换加密后的自然中文文本。
它不依赖云端 API：本地模型只负责生成“看起来像文章”的载体，真正的隐私来自本地加密。

> 当前版本仍是实验性 demo。密码学实现和载体编码还没有经过第三方审计，不建议把它当成正式安全产品使用。

## Highlights

- **一次交换联系人包**：导入对方公开联系人包后，就可以用顶部 profile 选择收件人。
- **短密文优先**：使用椭圆曲线密钥交换 + 对称认证加密，不保留旧版 Signal 流程。
- **自然中文载体**：使用 Qwen3-4B-Instruct-2507 Q4_K_M GGUF + llama.cpp 本地生成正文。
- **Top-k token 编码**：把密文映射到受控 token 选择里，解码时通过同一模型 tokenizer 恢复。
- **离线可运行**：不需要 OpenAI、Gemini 或其他在线 API。
- **GPU 优先**：worker 优先尝试 CUDA，然后 Vulkan，最后 CPU。
- **Portable 数据目录**：默认把 profile、联系人、归档保存到 exe 同级 `data/`。
- **Windows Hello**：本地主密钥通过 Windows Hello 保护。

## Demo Flow

```text
明文 -> UTF-16LE -> AEAD 密文 -> top-k token 载体文章 -> 聊天软件发送
聊天软件复制 -> tokenizer 解码 -> AEAD 解密 -> 明文
```

## Quick Start

下载或构建后运行：

```text
ChineseInputAgent.exe
```

第一次启动会创建本机 profile，并通过 Windows Hello 保护本地密钥。两台电脑通信时，只需要先互相导入一次联系人包；之后主界面顶部选择联系人，输入主题和明文，点击加密即可生成可复制的中文载体。

## Build

### Requirements

- Windows 10/11
- MSYS2 UCRT64 MinGW-w64
- CMake + Ninja
- Python 3
- 可选：CUDA Toolkit 或 Vulkan SDK，用于 llama.cpp GPU backend

### Clone

```bash
git clone --recursive https://github.com/machinemadefibre-bot/ChineseInputAgent.git
cd ChineseInputAgent
```

如果你已经普通 clone 了仓库：

```bash
git submodule update --init --recursive
```

### Model

把 llama.cpp 兼容的 Qwen3-4B-Instruct-2507 Q4_K_M GGUF 放到：

```text
models/Qwen3-4B-Instruct-2507-Q4_K_M.gguf
```

模型文件太大，不会提交进 GitHub。详见 [models/README.md](models/README.md)。

### Package

```bat
build-mingw.bat
build-llama-worker.bat
package-installer-mingw.bat
```

输出：

```text
dist\ChineseInputAgentInstaller.exe
dist\ChineseInputAgent\
```

## Project Layout

```text
src/                         Win32 UI, local profile, crypto, installer stub
tools/payload_watermark/     llama.cpp worker and top-k payload codec
tools/packaging/             portable archive and installer payload helpers
third_party/curve25519-donna vendored X25519 implementation
third_party/llama.cpp        llama.cpp submodule
models/                      local GGUF model drop-in directory
```

## Security Notes

- 明文不会发送给第三方 LLM 服务。
- 载体文章不是安全边界；安全性来自加密层。
- 本地数据优先保存到 portable `data/`，并由本机主密钥保护。
- 联系人包只用于建立通信对象，不应该包含私钥。
- 当前 demo 没有做正式安全审计。

## Roadmap

- 更稳定的长文生成和更短的收尾。
- 更清晰的联系人指纹确认流程。
- 可替换模型配置和更小的下载包。
- 自动化端到端通信测试。

## License

MIT. Third-party components keep their own licenses.
