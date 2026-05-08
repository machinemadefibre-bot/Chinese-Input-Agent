ChineseInputAgent worker prompt templates.

These UTF-8 files are loaded by cia_llama_worker.exe at runtime. Editing them
does not require rebuilding the worker. Existing worker processes reload the
template file on the next encode request.

Files:
- default.txt: normal article/message carrier prompt.
- self_intro.txt: used when the topic contains "自我介绍" or "self-introduction".
- group_key.txt: group key-exchange carrier prompt.
- reject_phrases.txt: one rejected generated phrase per line.

Supported placeholders:
- {topic}
- {length_requirement}
- {min_chars}
- {max_chars}

Keep the Qwen chat markers if you still want the same non-thinking chat format.
