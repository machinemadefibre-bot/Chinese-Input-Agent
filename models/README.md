# Models

ChineseInputAgent uses a local GGUF model at package time.

Expected default file:

```text
models/Qwen3-4B-Instruct-2507-Q4_K_M.gguf
```

The model file is intentionally not committed to Git because it is too large for
a normal GitHub repository. Download a llama.cpp-compatible Q4_K_M GGUF build of
Qwen3-4B-Instruct-2507 and place it at the path above before running
`package-mingw.bat` or `package-installer-mingw.bat`.
