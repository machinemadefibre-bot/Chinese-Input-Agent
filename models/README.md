# Models

ChineseInputAgent uses a local GGUF model at runtime.

Expected installed file:

```text
models/base_model.gguf
```

The model file is intentionally not committed to Git because it is too large for
a normal GitHub repository. The installer downloads a llama.cpp-compatible
Q4_K_M GGUF build of Qwen3-4B-Instruct-2507 from Hugging Face and verifies:

```text
SHA256 3605803b982cb64aead44f6c1b2ae36e3acdb41d8e46c8a94c6533bc4c67e597
```

For portable zip-only or offline installs, download the same model manually and
place it at `models/base_model.gguf`.
