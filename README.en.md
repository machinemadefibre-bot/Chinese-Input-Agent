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
  <a href="README.md">简体中文</a> | English
</p>

<h3 align="center">A local Windows tool that turns encrypted messages into ordinary-looking Chinese articles.</h3>

ChineseInputAgent is a small experiment around one question: can two computers exchange encrypted messages through the chat apps people already keep open, without relying on a cloud API?

It is not a chat app, and it is not another all-in-one AI desktop client. It is closer to a translation layer. The app encrypts plaintext into bytes, then asks a local language model to carry those bytes inside a Chinese article. The receiver copies the article back into the app, and the app recovers the payload and decrypts it.

This is still an experimental project. The UI works and the end-to-end path is usable, but the cryptography and carrier encoding have not been formally audited. Treat it as a research prototype, not as a mature security product.

## Why I Built It

I have always been interested in information security, and I have tried many encrypted messengers with friends who share that interest. The practical problem was boring but real: when we actually wanted to talk, someone was often offline, had not opened the app, or missed the notification. So we kept falling back to WeChat, because it is always running in the background and everyone checks it.

Sometimes the workflow became absurd: I would send a message in WeChat saying, "I sent you something in that other encrypted app," and then wait for the other person to switch apps. At that point, I started wondering whether the better design was not another messenger at all. What if existing chat apps were just the transport, and the message content itself became encrypted, copyable, and recoverable text?

ChineseInputAgent came out of that idea. It does not try to replace WeChat, QQ, Telegram, or any other platform. It tries to add a local encryption and text-carrier layer on top of the tools people already use.

## Why Not Send Raw Ciphertext?

Sending raw ciphertext is simple, but it is also visually loud. A long block of random-looking characters immediately says, "this is something to decode." To me, the interesting part of this project is not only encryption; it is making encrypted content behave more like normal text in normal places.

AI-generated writing is everywhere now. In chat windows, forums, blogs, and other text-based spaces, an ordinary Chinese article is much less out of place than a mysterious encoded blob. ChineseInputAgent uses that social texture as a carrier: the encrypted payload becomes a readable article that can be copied through an existing text channel.

This does not mean the project can bypass moderation, platform rules, or legal processes. It only changes the form of the encrypted message from "obvious ciphertext" to "readable carrier text." The real security boundary is still the local encryption layer, not how natural the article looks.

## What It Can Do Today

- Exchange a contact public-key package once, then encrypt future messages to that contact.
- Create and join symmetric group chats. A group behaves like a selectable conversation object; v1 does not prevent impersonation by existing group members.
- Protect message content with a session transport and authenticated symmetric encryption; Double Ratchet-style forward secrecy is not implemented yet.
- Generate Chinese carrier text locally with a Qwen GGUF model through llama.cpp.
- Encode ciphertext with a top-k token carrier and recover it from the generated article.
- Try multiple tokenizer profiles during decode; the encryption layer decides which candidate is valid.
- Prefer CUDA, fall back to Vulkan, and then fall back to CPU.
- Store profiles, contacts, groups, and archives in the portable app's local `data/` directory.
- Protect the local master key with Windows Hello.

## What It Is Not

- It is not a formally audited end-to-end secure messaging protocol.
- It is not a cloud service. There is no OpenAI, Gemini, or other online API dependency.
- It is not trying to replace your existing chat app.
- It is not a guarantee against moderation, platform policy enforcement, or legal scrutiny.
- It is not optimized for the shortest possible ciphertext at the cost of readability.

## Quick Start

Download or build the app, then run:

```text
ChineseInputAgent.exe
```

On first launch, the app creates a local profile and asks Windows Hello to unlock the local key. For two-computer communication, exchange contact packages in the key-exchange view first. After that, choose a contact at the top of the main window, type plaintext, encrypt it, and send the generated Chinese article through any text channel you control.

Exchange text includes an 8-character base32 fingerprint for comparison through a trusted channel. It is not strong authentication by itself.

To decrypt a message, copy the whole article you received and click decrypt. The app will try the local contacts and decrypt the matching payload.

For group chat, use the key-exchange view's group mode to create or join a group. Each user sets a local group name and their own display nickname. Local remarks can override how another group member is shown on this machine.

## Rough Flow

```text
plaintext
  -> UTF-16LE bytes
  -> AEAD ciphertext
  -> top-k token carrier article
  -> copied into a chat app
  -> copied back by the receiver
  -> tokenizer decoding
  -> AEAD decryption
  -> plaintext
```

## Build

### Requirements

- Windows 10/11
- MSYS2 UCRT64 MinGW-w64
- CMake + Ninja
- Python 3
- Optional: CUDA Toolkit or Vulkan SDK for llama.cpp GPU backends

### Clone

```bash
git clone --recursive https://github.com/machinemadefibre-bot/Chinese-Input-Agent.git
cd Chinese-Input-Agent
```

If you cloned without submodules:

```bash
git submodule update --init --recursive
```

### Model

The repository does not include the model file. The installer produced by `package-installer-mingw.bat` downloads the Qwen3-4B-Instruct-2507 Q4_K_M GGUF model from Hugging Face during install, verifies its SHA-256, and writes it here:

```text
models/base_model.gguf
```

For portable zip-only or offline installs, place a llama.cpp-compatible Qwen GGUF at that path manually. See [models/README.md](models/README.md) for details.

Runtime worker configuration lives here:

```text
tools/payload_watermark/worker_config.txt
tools/payload_watermark/prompts/
```

### Package

```bat
build-mingw.bat
build-llama-worker.bat
package-installer-mingw.bat
```

Outputs:

```text
dist\ChineseInputAgentInstaller.exe
dist\ChineseInputAgent\
```

## Repository Layout

```text
src/                         Win32 UI, local profile, encryption, installer stub
tools/payload_watermark/     llama.cpp worker and top-k payload codec
tools/packaging/             portable package and installer assembly scripts
third_party/curve25519-donna X25519 implementation
third_party/llama.cpp        llama.cpp submodule
models/                      local GGUF model directory
```

## Security Boundary

The generated Chinese article is only a carrier. It should not be treated as the security layer. Message confidentiality and integrity come from the encryption layer.

The current session transport uses static identity keys plus one-time handshake material to establish sending chains, then derives a fresh message key for each message. It supports a limited amount of out-of-order delivery, but it is not Double Ratchet and it is not a complete Signal or Noise implementation. Do not treat it as full forward secrecy.

Group messages use a separate symmetric group transport. The v1 goal is confidentiality against non-members after each epoch change; it does not cryptographically prove which member sent a message.

The current design goal is to make copying, sending, and recovering text possible through ordinary chat software. It is not designed to resist all traffic analysis, text rewriting, summarization, translation, active attacks, or platform-side text cleanup. If a third-party platform rewrites the text, decoding may fail.

Contact packages should contain public information only. If exported content ever appears to contain private keys or recoverable private-key material, please open an issue immediately.

## Still Rough

- Long messages can be slow, especially on CPU.
- Carrier articles can still have a small-model feel.
- The current carrier is focused on Chinese text; English carrier text is planned for a future version.
- First install needs internet access to download the model, which can take a while on slow connections.
- End-to-end automated tests are still incomplete.

## License

MIT. Third-party components keep their own licenses.
