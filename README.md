<p align="center">
  <img src="docs/banner.svg" alt="ChineseInputAgent banner" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/machinemadefibre-bot/Chinese-Input-Agent"><img alt="GitHub repo" src="https://img.shields.io/badge/GitHub-Chinese--Input--Agent-181717?logo=github"></a>
  <img alt="Windows" src="https://img.shields.io/badge/Windows-10%2F11-0078D4?logo=windows">
  <img alt="Native C" src="https://img.shields.io/badge/Native-C-00599C?logo=c">
  <img alt="llama.cpp" src="https://img.shields.io/badge/Runtime-llama.cpp-6B46C1">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-22C55E">
</p>

<p align="center">
  简体中文 | <a href="README.en.md">English</a>
</p>

<h3 align="center">一个把密文写成文章的小工具。</h3>

ChineseInputAgent 是我做来测试一个想法的：两台电脑能不能不靠搭建服务器，只通过普通聊天软件，交换一段看起来像中文长文的加密消息。

它不是又一个重复造轮子的聊天软件，也不是另一个大而全的 AI 应用。它更像一个“翻译层”：把明文加密成二进制，再让本地模型把这些二进制藏进一篇自然中文里；对方复制这段文字，程序再从同一个 tokenizer 里把数据恢复出来并解密。

目前它还是实验项目。界面能用，链路能跑，但密码学和载体编码都还没有经过正式测试。

## 为什么做这个

我一直很喜欢互联网隐私，也和一些同样喜欢折腾隐私的朋友试过很多加密通信软件。问题是，真正聊天的时候，我们经常会在那些软件上叫不到人：有人没开代理连不上，有人不把它放在后台，有人没开通知。最后我们还是会退回到微信，因为微信几乎一直挂在后台，大家也都一定会看。

有时候甚至会变成这样：我先在微信里提醒对方“我在某个加密软件里发你消息了”，然后对方再切过去看。这个过程本身就有点别扭。于是我开始想，与其再做一个新的聊天软件，为什么不直接利用大家本来就在用的聊天软件，只把消息内容本身变成一段可以复制、可以发送、可以恢复的加密文本？

ChineseInputAgent 就是从这个想法开始的。它不想替代微信、QQ、Telegram 或任何现有平台，而是试着在这些平台之上加一层本地加密和文本载体，让两台电脑通过普通聊天窗口也能交换只有彼此能读懂的内容。

## 为什么不是直接发密文

直接把一段随机密文发出去当然最简单，但它也最突兀：一长串看不出意义的字符很容易把注意力集中到“这里有一段需要解开的东西”上。对我来说，这个项目有意思的地方不只是加密，而是让加密后的内容尽量保留普通文本的外观和使用方式。

现在 AI 生成内容已经很常见了，无论是在聊天窗口、论坛、博客。一段普通中文文章都比一段莫名其妙的编码更符合日常语境。ChineseInputAgent 尝试利用这一点，把密文变成一段看起来像正常文章的载体，让两个人或一组人可以通过已有的渠道交换内容，而不必额外约定“去另一个软件里看消息”。

注意：不要用它绕过任何审查、风控或平台规则。

## 它现在能做什么

- 在两台电脑之间交换一次联系人公钥包，之后按联系人加密消息。
- 使用椭圆曲线密钥交换和对称认证加密来保护正文，支持前向安全。
- 用本地 Qwen3-4b-2507 模型生成中文载体。
- 用 top-k token 编码承载密文；解码时通过同一模型 tokenizer 还原。
- 优先使用 CUDA，失败后尝试 Vulkan，再失败就落到 CPU。
- 加密存储明文聊天记录。
- 用 Windows Hello 保护本机主密钥。

## 它不是什么

- 不是端到端审计过的安全通信协议。
- 不是为了压缩到最短密文而牺牲可读性的隐写工具。
- 不是云服务；没有 OpenAI、Gemini 或其他在线 API 依赖。
- 也不是要替代你正在用的聊天软件。它只是生成一段你可以复制出去的文本。
- 不是绕过法律、平台规则或安全审查的保证工具。

## 使用方式

下载或构建后运行：

```text
ChineseInputAgent.exe
```

第一次启动会创建本机 profile，并要求 Windows Hello 解锁本地密钥。
如果是两台电脑通信，先在“导入/导出密钥”窗口互相交换联系人包；之后在主界面顶部选择联系人，输入明文，点击加密，复制生成的中文文章发给对方。

解密时直接复制对方发来的整段文字，点击解密。程序会按本地联系人尝试匹配和解密。

## 大致流程

```text
明文
  -> UTF-16LE bytes
  -> AEAD 密文
  -> top-k token 载体文章
  -> 复制到聊天软件
  -> 对方复制回来
  -> tokenizer 解码
  -> AEAD 解密
  -> 明文
```

## 构建

### 环境

- Windows 10/11
- MSYS2 UCRT64 MinGW-w64
- CMake + Ninja
- Python 3
- 可选：CUDA Toolkit 或 Vulkan SDK，用于 llama.cpp GPU 后端

### 拉取源码

```bash
git clone --recursive https://github.com/machinemadefibre-bot/Chinese-Input-Agent.git
cd Chinese-Input-Agent
```

如果你已经普通 clone 了仓库：

```bash
git submodule update --init --recursive
```

### 放入模型

仓库里不带模型文件。请把 llama.cpp 兼容的 Qwen3-4B-Instruct-2507 Q4_K_M GGUF 放到：

```text
models/Qwen3-4B-Instruct-2507-Q4_K_M.gguf
```

详见 [models/README.md](models/README.md)。

### 打包

```bat
build-mingw.bat
build-llama-worker.bat
package-installer-mingw.bat
```

输出会在：

```text
dist\ChineseInputAgentInstaller.exe
dist\ChineseInputAgent\
```

## 目录结构

```text
src/                         Win32 UI, 本地 profile, 加密, 安装器 stub
tools/payload_watermark/     llama.cpp worker 和 top-k payload codec
tools/packaging/             portable 包和安装器拼接脚本
third_party/curve25519-donna X25519 实现
third_party/llama.cpp        llama.cpp submodule
models/                      本地 GGUF 模型放置目录
```

## 安全边界

这个项目里，中文文章只是载体，不应该被当成安全层。真正保护消息的是加密层。

当前版本的设计目标是“能在普通聊天软件里复制、发送、恢复”，而不是抵抗所有分析、重写或主动攻击。第三方平台如果自动改写、摘要、翻译或清洗文本，解码可能会失败。


## 现在还粗糙的地方

- 长消息会比较慢，尤其是 CPU 推理。
- 载体文章有时会有小模型味，需要继续调 prompt 和生成策略。
- 安装包很大，因为模型文件本身很大。
- 还缺少完整的端到端自动化测试。

## License

MIT. Third-party components keep their own licenses.
