#include "llama.h"

#include "ggml-backend.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <filesystem>
#include <future>
#include <functional>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

static constexpr int DEFAULT_RADIX = 4;
static constexpr uintmax_t MAX_WORKER_FILE_BYTES = 128ull * 1024ull * 1024ull;
static const std::string DEFAULT_PROMPT_TEMPLATE =
    "<|im_start|>system\n"
    "你是简体中文正文写作器。你的唯一任务是输出正文。禁止对话、解释、道歉、标题、清单、Markdown、JSON 和思考过程。/no_think\n"
    "<|im_end|>\n"
    "<|im_start|>user\n"
    "写作任务：围绕以下主题写自然流畅的简体中文正文。\n"
    "主题：{topic}\n\n"
    "输出要求：\n"
    "1. 从第一个字开始就是正文，不要回应任务本身。\n"
    "2. 只输出简体中文正文，不要使用繁体字。\n"
    "3. 不要标题、提纲、编号、解释、Markdown、JSON 或思考过程。\n"
    "4. 不要输出 <think> 或 </think>。\n"
    "5. {length_requirement}\n"
    "6. 使用正常标点和完整句子。\n"
    "/no_think\n"
    "<|im_end|>\n"
    "<|im_start|>assistant\n";
static const std::string GROUP_KEY_PROMPT_TEMPLATE =
    "<|im_start|>system\n"
    "你是简体中文正文写作器。你的唯一任务是输出正文。禁止对话、解释、道歉、标题、清单、Markdown、JSON 和思考过程。/no_think\n"
    "<|im_end|>\n"
    "<|im_start|>user\n"
    "写作任务：写一段社团招新简介或社团介绍正文。\n"
    "主题：{topic}\n\n"
    "输出要求：\n"
    "1. 从第一个字开始就是正文，不要回应任务本身。\n"
    "2. 只输出简体中文正文，不要使用繁体字。\n"
    "3. 内容像社团招新简介或社团介绍，语气自然可信。\n"
    "4. 不要标题、提纲、编号、解释、Markdown、JSON 或思考过程。\n"
    "5. 不要输出 <think> 或 </think>。\n"
    "6. {length_requirement}\n"
    "7. 使用正常标点和完整句子。\n"
    "/no_think\n"
    "<|im_end|>\n"
    "<|im_start|>assistant\n";
static const std::string SELF_INTRO_PROMPT_TEMPLATE =
    "<|im_start|>system\n"
    "你是简体中文正文写作器。你的唯一任务是输出正文。禁止对话、解释、道歉、标题、清单、Markdown、JSON 和思考过程。/no_think\n"
    "<|im_end|>\n"
    "<|im_start|>user\n"
    "写作任务：写一段第一人称求职自我介绍正文。\n\n"
    "输出要求：\n"
    "1. 从第一个字开始就是正文，不要回应任务本身。\n"
    "2. 只输出简体中文正文，不要使用繁体字。\n"
    "3. 从头到尾保持第一人称自我介绍主题。\n"
    "4. 可以自然写身份、日常生活、学习、兴趣、性格和与人交流的方式。\n"
    "5. 不要标题、提纲、编号、解释、Markdown、JSON 或思考过程。\n"
    "6. 不要输出 <think> 或 </think>。\n"
    "7. {length_requirement}\n"
    "8. 使用正常标点和完整句子。\n"
    "/no_think\n"
    "<|im_end|>\n"
    "<|im_start|>assistant\n";

static const std::string OUTLINE_PROMPT_TEMPLATE =
    "<|im_start|>system\n"
    "You write a short Simplified Chinese planning outline. Output only the outline. /no_think\n"
    "<|im_end|>\n"
    "<|im_start|>user\n"
    "Write an internal outline for the final Chinese article.\n"
    "Template: {prompt_template}\n"
    "Topic: {topic}\n"
    "Length target: {length_requirement}\n"
    "Use 3 to 5 short lines. Do not write the final article. /no_think\n"
    "<|im_end|>\n"
    "<|im_start|>assistant\n";
static std::string ascii_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

static bool contains_ci(const std::string & haystack, const std::string & needle) {
    return ascii_lower(haystack).find(ascii_lower(needle)) != std::string::npos;
}

static std::string clean_prompt_topic(std::string topic) {
    for (char & c : topic) {
        if (c == '\r' || c == '\n' || c == '\t') c = ' ';
    }
    size_t start = 0;
    while (start < topic.size() && std::isspace(static_cast<unsigned char>(topic[start]))) ++start;
    size_t end = topic.size();
    while (end > start && std::isspace(static_cast<unsigned char>(topic[end - 1]))) --end;
    topic = topic.substr(start, end - start);
    if (topic.empty()) topic = "daily life";
    if (topic.size() > 240) topic.resize(240);
    return topic;
}

struct PromptLengthBounds {
    size_t lower_chars = 0;
    size_t upper_chars = 0;
};

struct PromptLengthConfig {
    int min_chars_floor = 48;
    float payload_digit_multiplier = 1.3333334f;
    int upper_tail_extra_chars = 160;
    float upper_lower_multiplier = 2.0f;
    int upper_extra_chars = 80;
};

static PromptLengthBounds prompt_length_bounds(size_t payload_digits,
                                               int tail_budget,
                                               const PromptLengthConfig & config) {
    PromptLengthBounds bounds;
    const double payload_scaled = std::ceil(static_cast<double>(payload_digits) *
                                            static_cast<double>(config.payload_digit_multiplier));
    bounds.lower_chars = std::max<size_t>(static_cast<size_t>(std::max(0, config.min_chars_floor)),
                                          static_cast<size_t>(std::max(0.0, payload_scaled)));
    bounds.upper_chars = bounds.lower_chars + static_cast<size_t>(std::max(0, tail_budget)) +
                         static_cast<size_t>(std::max(0, config.upper_tail_extra_chars));
    const double upper_scaled = std::ceil(static_cast<double>(bounds.lower_chars) *
                                          static_cast<double>(config.upper_lower_multiplier));
    bounds.upper_chars = std::max(bounds.upper_chars,
                                  static_cast<size_t>(std::max(0.0, upper_scaled)) +
                                  static_cast<size_t>(std::max(0, config.upper_extra_chars)));
    return bounds;
}

static std::string format_length_requirement(const PromptLengthBounds & bounds) {
    return "字数：至少 " + std::to_string(bounds.lower_chars) + " 个汉字，最多约 " +
           std::to_string(bounds.upper_chars) + " 个汉字。";
}

static void replace_all(std::string & text, const std::string & needle, const std::string & replacement) {
    if (needle.empty()) return;
    size_t pos = 0;
    while ((pos = text.find(needle, pos)) != std::string::npos) {
        text.replace(pos, needle.size(), replacement);
        pos += replacement.size();
    }
}

static std::string trim_ascii(std::string text) {
    auto is_ws = [](unsigned char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    while (!text.empty() && is_ws(static_cast<unsigned char>(text.front()))) text.erase(text.begin());
    while (!text.empty() && is_ws(static_cast<unsigned char>(text.back()))) text.pop_back();
    return text;
}

static std::vector<std::string> split_csv_list(const std::string & text) {
    std::vector<std::string> out;
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t comma = text.find(',', pos);
        std::string item = trim_ascii(comma == std::string::npos ? text.substr(pos) : text.substr(pos, comma - pos));
        if (!item.empty()) out.push_back(item);
        if (comma == std::string::npos) break;
        pos = comma + 1;
    }
    return out;
}

static bool append_unique_string(std::vector<std::string> & list, const std::string & value) {
    if (value.empty()) return false;
    if (std::find(list.begin(), list.end(), value) != list.end()) return false;
    list.push_back(value);
    return true;
}

static bool read_utf8_template_file(const fs::path & path, std::string & out) {
    out.clear();
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    file.seekg(0, std::ios::end);
    std::streamoff size = file.tellg();
    if (size <= 0 || size > 256 * 1024) return false;
    file.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    if (!file.read(&out[0], size)) {
        out.clear();
        return false;
    }
    if (out.size() >= 3 &&
        static_cast<unsigned char>(out[0]) == 0xef &&
        static_cast<unsigned char>(out[1]) == 0xbb &&
        static_cast<unsigned char>(out[2]) == 0xbf) {
        out.erase(0, 3);
    }
    return !out.empty();
}

static std::vector<std::string> read_line_list_file(const fs::path & path) {
    std::string text;
    std::vector<std::string> lines;
    if (!read_utf8_template_file(path, text)) return lines;
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t end = text.find('\n', pos);
        std::string line = trim_ascii(end == std::string::npos ? text.substr(pos) : text.substr(pos, end - pos));
        if (!line.empty() && line[0] != '#') lines.push_back(line);
        if (end == std::string::npos) break;
        pos = end + 1;
    }
    return lines;
}

static std::string sanitize_prompt_template_name(std::string name) {
    if (name.empty()) return "default";
    std::string sanitized;
    for (unsigned char c : name) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-') {
            sanitized.push_back(static_cast<char>(c));
        }
    }
    return sanitized.empty() ? "default" : sanitized;
}

static std::string load_prompt_template(const std::string & prompt_dir,
                                        const std::string & template_name,
                                        const std::string & fallback_template) {
    std::string loaded_template;
    if (!prompt_dir.empty() &&
        read_utf8_template_file(fs::path(prompt_dir) / (template_name + ".txt"), loaded_template)) {
        return loaded_template;
    }
    return fallback_template;
}

static const std::string & fallback_prompt_template(const std::string & template_name) {
    if (template_name == "self_intro") return SELF_INTRO_PROMPT_TEMPLATE;
    if (template_name == "group_key") return GROUP_KEY_PROMPT_TEMPLATE;
    return DEFAULT_PROMPT_TEMPLATE;
}

static std::string load_outline_prompt_template(const std::string & prompt_dir,
                                                const std::string & template_name) {
    std::string loaded_template;
    if (!prompt_dir.empty() &&
        read_utf8_template_file(fs::path(prompt_dir) / (template_name + "_outline.txt"), loaded_template)) {
        return loaded_template;
    }
    if (!prompt_dir.empty() &&
        read_utf8_template_file(fs::path(prompt_dir) / "outline.txt", loaded_template)) {
        return loaded_template;
    }
    return OUTLINE_PROMPT_TEMPLATE;
}

static void inject_outline_context(std::string & prompt, const std::string & outline) {
    if (outline.empty()) return;
    const std::string outline_block = "\nWriting outline reference. Do not output the outline:\n" + outline + "\n";
    const std::string assistant_marker = "\n<|im_end|>\n<|im_start|>assistant";
    size_t pos = prompt.rfind(assistant_marker);
    if (pos != std::string::npos) {
        prompt.insert(pos, outline_block);
    } else {
        prompt += outline_block;
    }
}

static std::string build_topk_prompt(const std::string & topic,
                                     size_t payload_digits,
                                     int tail_budget,
                                     const PromptLengthConfig & length_config,
                                     const std::string & prompt_dir,
                                     const std::string & prompt_template_name,
                                     const std::string & custom_prompt_template,
                                     const std::string & outline) {
    std::string clean = clean_prompt_topic(topic);
    PromptLengthBounds bounds = prompt_length_bounds(payload_digits, tail_budget, length_config);
    std::string template_name = sanitize_prompt_template_name(prompt_template_name);
    std::string prompt = custom_prompt_template.empty() ?
        load_prompt_template(prompt_dir, template_name, fallback_prompt_template(template_name)) :
        custom_prompt_template;
    const bool has_outline_placeholder = prompt.find("{outline}") != std::string::npos;
    replace_all(prompt, "{topic}", clean);
    replace_all(prompt, "{length_requirement}", format_length_requirement(bounds));
    replace_all(prompt, "{min_chars}", std::to_string(bounds.lower_chars));
    replace_all(prompt, "{max_chars}", std::to_string(bounds.upper_chars));
    replace_all(prompt, "{outline}", outline);
    if (!has_outline_placeholder) inject_outline_context(prompt, outline);
    return prompt;
}

static std::string build_outline_prompt(const std::string & topic,
                                        const std::string & prompt_template_name,
                                        const PromptLengthBounds & bounds,
                                        const std::string & prompt_dir) {
    std::string clean = clean_prompt_topic(topic);
    std::string template_name = sanitize_prompt_template_name(prompt_template_name);
    std::string prompt = load_outline_prompt_template(prompt_dir, template_name);
    replace_all(prompt, "{topic}", clean);
    replace_all(prompt, "{prompt_template}", template_name);
    replace_all(prompt, "{length_requirement}", format_length_requirement(bounds));
    replace_all(prompt, "{min_chars}", std::to_string(bounds.lower_chars));
    replace_all(prompt, "{max_chars}", std::to_string(bounds.upper_chars));
    return prompt;
}

struct Sha256 {
    uint32_t h[8];
    uint8_t block[64];
    uint64_t bytes = 0;
    size_t used = 0;

    static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    static uint32_t load_be(const uint8_t * p) {
        return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
    }
    static void store_be(uint8_t * p, uint32_t v) {
        p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16); p[2] = uint8_t(v >> 8); p[3] = uint8_t(v);
    }

    Sha256() { reset(); }
    void reset() {
        h[0] = 0x6a09e667u; h[1] = 0xbb67ae85u; h[2] = 0x3c6ef372u; h[3] = 0xa54ff53au;
        h[4] = 0x510e527fu; h[5] = 0x9b05688cu; h[6] = 0x1f83d9abu; h[7] = 0x5be0cd19u;
        bytes = 0; used = 0; std::memset(block, 0, sizeof(block));
    }
    void transform(const uint8_t * chunk) {
        static const uint32_t k[64] = {
            0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
            0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
            0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
            0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
            0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
            0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
            0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
            0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u };
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) w[i] = load_be(chunk + i * 4);
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
            uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0], b=h[1], c=h[2], d=h[3], e=h[4], f=h[5], g=h[6], hh=h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = hh + S1 + ch + k[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            hh = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    void update(const uint8_t * data, size_t len) {
        bytes += len;
        while (len > 0) {
            size_t take = std::min(len, sizeof(block) - used);
            std::memcpy(block + used, data, take);
            used += take; data += take; len -= take;
            if (used == sizeof(block)) { transform(block); used = 0; }
        }
    }
    void update(const std::string & s) { update(reinterpret_cast<const uint8_t *>(s.data()), s.size()); }
    std::array<uint8_t, 32> final() {
        uint64_t bit_len = bytes * 8;
        block[used++] = 0x80;
        if (used > 56) {
            while (used < 64) block[used++] = 0;
            transform(block); used = 0;
        }
        while (used < 56) block[used++] = 0;
        for (int i = 7; i >= 0; --i) block[used++] = uint8_t(bit_len >> (i * 8));
        transform(block);
        std::array<uint8_t, 32> out{};
        for (int i = 0; i < 8; ++i) store_be(out.data() + i * 4, h[i]);
        return out;
    }
};

static std::array<uint8_t, 32> sha256_bytes(const std::string & s) {
    Sha256 h; h.update(s); return h.final();
}

static std::array<uint8_t, 32> topk_generation_seed_digest(const std::string & seed,
                                                           const std::vector<uint8_t> & payload) {
    Sha256 h;
    h.update("ChineseInputAgent top-k generation seed v2");
    const uint8_t zero = 0;
    h.update(&zero, 1);
    h.update(seed);
    h.update(&zero, 1);
    if (!payload.empty()) h.update(payload.data(), payload.size());
    return h.final();
}

static std::vector<uint8_t> read_binary(const std::string & path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) throw std::runtime_error("无法打开输入文件：" + path);
    std::streampos end = f.tellg();
    if (end < 0) throw std::runtime_error("无法读取输入文件大小：" + path);
    uintmax_t size = static_cast<uintmax_t>(end);
    if (size > MAX_WORKER_FILE_BYTES) throw std::runtime_error("输入文件过大，已拒绝读取：" + path);
    if (size > static_cast<uintmax_t>(std::numeric_limits<std::streamsize>::max())) {
        throw std::runtime_error("输入文件超过当前运行时可读取范围：" + path);
    }
    std::vector<uint8_t> out(static_cast<size_t>(size));
    f.seekg(0, std::ios::beg);
    if (!out.empty() && !f.read(reinterpret_cast<char *>(out.data()), static_cast<std::streamsize>(out.size()))) {
        throw std::runtime_error("读取输入文件失败或文件被截断：" + path);
    }
    return out;
}

static std::string read_text(const std::string & path) {
    auto data = read_binary(path);
    return std::string(reinterpret_cast<const char *>(data.data()), data.size());
}

static void write_binary(const std::string & path, const std::vector<uint8_t> & data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("无法打开输出文件：" + path);
    if (data.size() > static_cast<size_t>(std::numeric_limits<std::streamsize>::max())) {
        throw std::runtime_error("输出文件过大：" + path);
    }
    if (!data.empty() && !f.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()))) {
        throw std::runtime_error("写入输出文件失败：" + path);
    }
}

static void write_text_file(const std::string & path, const std::string & text) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("无法打开输出文件：" + path);
    if (text.size() > static_cast<size_t>(std::numeric_limits<std::streamsize>::max())) {
        throw std::runtime_error("输出文本过大：" + path);
    }
    if (!text.empty() && !f.write(text.data(), static_cast<std::streamsize>(text.size()))) {
        throw std::runtime_error("写入输出文件失败：" + path);
    }
}

struct DecodeCandidate {
    std::string tokenizer_id;
    std::vector<uint8_t> payload;
};

static void append_u32_le(std::vector<uint8_t> & out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xffu));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xffu));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xffu));
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xffu));
}

static void write_decode_candidates_file(const std::string & path, const std::vector<DecodeCandidate> & candidates) {
    std::vector<uint8_t> data;
    data.insert(data.end(), {'C', 'I', 'A', 'T', 'K', 'M', '1', '\0'});
    append_u32_le(data, static_cast<uint32_t>(candidates.size()));
    for (const auto & candidate : candidates) {
        if (candidate.tokenizer_id.size() > 0xffffffffu || candidate.payload.size() > 0xffffffffu) {
            throw std::runtime_error("decode candidate output is too large");
        }
        append_u32_le(data, static_cast<uint32_t>(candidate.tokenizer_id.size()));
        data.insert(data.end(), candidate.tokenizer_id.begin(), candidate.tokenizer_id.end());
        append_u32_le(data, static_cast<uint32_t>(candidate.payload.size()));
        data.insert(data.end(), candidate.payload.begin(), candidate.payload.end());
    }
    write_binary(path, data);
}

static void append_utf8(std::string & out, uint32_t cp) {
    if (cp <= 0x7f) out.push_back(char(cp));
    else if (cp <= 0x7ff) { out.push_back(char(0xc0 | (cp >> 6))); out.push_back(char(0x80 | (cp & 0x3f))); }
    else if (cp <= 0xffff) { out.push_back(char(0xe0 | (cp >> 12))); out.push_back(char(0x80 | ((cp >> 6) & 0x3f))); out.push_back(char(0x80 | (cp & 0x3f))); }
    else { out.push_back(char(0xf0 | (cp >> 18))); out.push_back(char(0x80 | ((cp >> 12) & 0x3f))); out.push_back(char(0x80 | ((cp >> 6) & 0x3f))); out.push_back(char(0x80 | (cp & 0x3f))); }
}

static bool next_utf8(const std::string & s, size_t & i, uint32_t & cp) {
    if (i >= s.size()) return false;
    uint8_t c = uint8_t(s[i++]);
    if (c < 0x80) { cp = c; return true; }
    int need = 0; cp = 0;
    if ((c & 0xe0) == 0xc0) { need = 1; cp = c & 0x1f; }
    else if ((c & 0xf0) == 0xe0) { need = 2; cp = c & 0x0f; }
    else if ((c & 0xf8) == 0xf0) { need = 3; cp = c & 0x07; }
    else return false;
    if (i + size_t(need) > s.size()) return false;
    for (int j = 0; j < need; ++j) {
        uint8_t d = uint8_t(s[i++]);
        if ((d & 0xc0) != 0x80) return false;
        cp = (cp << 6) | (d & 0x3f);
    }
    return true;
}

static bool is_cjk(uint32_t cp) {
    return (cp >= 0x3400 && cp <= 0x4dbf) || (cp >= 0x4e00 && cp <= 0x9fff) || (cp >= 0xf900 && cp <= 0xfaff);
}

static bool is_chinese_punct(uint32_t cp) {
    return cp == 0xff0c || cp == 0x3002 || cp == 0xff01 || cp == 0xff1f || cp == 0xff1b || cp == 0xff1a || cp == 0x3001;
}

static bool is_any_punctuation(uint32_t cp) {
    if (is_chinese_punct(cp)) return true;
    if ((cp >= 0x21 && cp <= 0x2f) || (cp >= 0x3a && cp <= 0x40) ||
        (cp >= 0x5b && cp <= 0x60) || (cp >= 0x7b && cp <= 0x7e)) {
        return true;
    }
    if (cp >= 0x2000 && cp <= 0x206f) return true; // General Punctuation
    if (cp >= 0x3000 && cp <= 0x303f) return true; // CJK Symbols and Punctuation
    if (cp >= 0xfe10 && cp <= 0xfe1f) return true; // Vertical punctuation
    if (cp >= 0xfe30 && cp <= 0xfe4f) return true; // CJK compatibility forms
    if (cp >= 0xff01 && cp <= 0xff0f) return true; // Fullwidth ASCII punctuation
    if (cp >= 0xff1a && cp <= 0xff20) return true;
    if (cp >= 0xff3b && cp <= 0xff40) return true;
    if (cp >= 0xff5b && cp <= 0xff65) return true;
    return false;
}

static bool is_book_title_mark(uint32_t cp) {
    return cp == 0x3008 || cp == 0x3009 || cp == 0x300a || cp == 0x300b;
}

static bool is_bracket_char(uint32_t cp) {
    return cp == '(' || cp == ')' || cp == '[' || cp == ']' || cp == '{' || cp == '}' ||
           cp == '<' || cp == '>' || cp == 0xff08 || cp == 0xff09 ||
           cp == 0x3010 || cp == 0x3011 || cp == 0x3014 || cp == 0x3015 ||
           cp == 0x300c || cp == 0x300d || cp == 0x300e || cp == 0x300f ||
           cp == 0x3016 || cp == 0x3017 || cp == 0x3018 || cp == 0x3019 ||
           cp == 0x301a || cp == 0x301b || cp == 0xfe59 || cp == 0xfe5a ||
           cp == 0xfe5b || cp == 0xfe5c || cp == 0xfe5d || cp == 0xfe5e ||
           cp == 0xff3b || cp == 0xff3d || cp == 0xff5b || cp == 0xff5d ||
           cp == 0xff1c || cp == 0xff1e;
}

static bool contains_bracket(const std::string & text) {
    size_t i = 0; uint32_t cp = 0;
    while (next_utf8(text, i, cp)) if (is_bracket_char(cp)) return true;
    return false;
}

static bool is_social_stable_text(const std::string & text) {
    if (text.empty()) return false;
    bool has_cjk_char = false;
    size_t i = 0;
    while (i < text.size()) {
        uint32_t cp = 0;
        if (!next_utf8(text, i, cp)) return false;
        if (cp == 0xfffd || cp < 0x20 || cp == 0x200b || cp == 0x200c || cp == 0x200d || cp == 0xfeff) return false;
        if (cp == '\r' || cp == '\n' || cp == '\t' || cp == '`' || cp == '\\' || is_bracket_char(cp)) return false;
        if (!(is_cjk(cp) || is_chinese_punct(cp) || is_book_title_mark(cp))) return false;
        if (is_cjk(cp)) has_cjk_char = true;
    }
    return has_cjk_char;
}

static size_t cjk_count(const std::string & text) {
    size_t n = 0, i = 0; uint32_t cp = 0;
    while (next_utf8(text, i, cp)) if (is_cjk(cp)) ++n;
    return n;
}

static bool contains_sentence_break(const std::string & text) {
    size_t i = 0; uint32_t cp = 0;
    while (next_utf8(text, i, cp)) if (cp == 0x3002 || cp == 0xff01 || cp == 0xff1f) return true;
    return false;
}

static bool contains_punctuation(const std::string & text) {
    size_t i = 0; uint32_t cp = 0;
    while (next_utf8(text, i, cp)) if (is_any_punctuation(cp)) return true;
    return false;
}

static bool last_significant_codepoint(const std::string & text, uint32_t & out) {
    size_t i = 0;
    uint32_t cp = 0;
    bool found = false;
    while (next_utf8(text, i, cp)) {
        if (cp == ' ' || cp == '\r' || cp == '\n' || cp == '\t' || cp == 0x3000) continue;
        out = cp;
        found = true;
    }
    return found;
}

static bool is_sentence_terminal_punctuation(uint32_t cp) {
    return cp == 0x3002 || cp == 0xff01 || cp == 0xff1f ||
           cp == '.' || cp == '!' || cp == '?';
}

static bool is_clause_continuation_punctuation(uint32_t cp) {
    return cp == 0xff0c || cp == 0x3001 || cp == 0xff1b || cp == 0xff1a ||
           cp == ',' || cp == ';' || cp == ':';
}

static bool is_ignorable_token_prefix(uint32_t cp) {
    return cp == ' ' || cp == '\r' || cp == '\n' || cp == '\t' ||
           cp == 0x3000 || cp == 0x2581;
}

static bool disallowed_punctuation_transition(const std::string & generated_text,
                                              const std::string & piece) {
    uint32_t prev = 0;
    if (!last_significant_codepoint(generated_text, prev) ||
        !is_sentence_terminal_punctuation(prev)) return false;
    size_t i = 0;
    uint32_t cp = 0;
    while (next_utf8(piece, i, cp)) {
        if (is_ignorable_token_prefix(cp)) continue;
        if (is_clause_continuation_punctuation(cp)) return true;
        if (is_cjk(cp) || is_sentence_terminal_punctuation(cp)) return false;
        if (is_any_punctuation(cp)) return false;
    }
    return false;
}

static bool is_punctuation_only_text(const std::string & text) {
    if (text.empty()) return false;
    bool any = false;
    size_t i = 0; uint32_t cp = 0;
    while (next_utf8(text, i, cp)) {
        if (cp == 0xfffd || cp < 0x20 || cp == 0x200b || cp == 0x200c || cp == 0x200d || cp == 0xfeff) return false;
        if (!(is_chinese_punct(cp) || is_book_title_mark(cp))) return false;
        any = true;
    }
    return any;
}
static std::string json_escape(const std::string & s) {
    std::string out;
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8]; std::snprintf(buf, sizeof(buf), "\\u%04x", c); out += buf;
                } else out.push_back(char(c));
        }
    }
    return out;
}

static bool parse_hex4(const std::string & s, size_t pos, uint32_t & cp) {
    if (pos + 4 > s.size()) return false;
    cp = 0;
    for (size_t i = 0; i < 4; ++i) {
        char c = s[pos + i];
        cp <<= 4;
        if (c >= '0' && c <= '9') cp |= uint32_t(c - '0');
        else if (c >= 'a' && c <= 'f') cp |= uint32_t(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') cp |= uint32_t(c - 'A' + 10);
        else return false;
    }
    return true;
}

static bool json_get_string(const std::string & json, const std::string & key, std::string & out) {
    std::string pat = "\"" + key + "\"";
    size_t p = json.find(pat);
    if (p == std::string::npos) return false;
    p = json.find(':', p + pat.size());
    if (p == std::string::npos) return false;
    ++p;
    while (p < json.size() && std::isspace(static_cast<unsigned char>(json[p]))) ++p;
    if (p >= json.size() || json[p] != '"') return false;
    ++p;
    out.clear();
    while (p < json.size()) {
        char c = json[p++];
        if (c == '"') return true;
        if (c != '\\') { out.push_back(c); continue; }
        if (p >= json.size()) return false;
        char e = json[p++];
        switch (e) {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/': out.push_back('/'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case 'u': {
                uint32_t cp = 0;
                if (!parse_hex4(json, p, cp)) return false;
                p += 4;
                if (cp >= 0xd800 && cp <= 0xdbff && p + 6 <= json.size() && json[p] == '\\' && json[p + 1] == 'u') {
                    uint32_t lo = 0;
                    if (parse_hex4(json, p + 2, lo) && lo >= 0xdc00 && lo <= 0xdfff) {
                        cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                        p += 6;
                    }
                }
                append_utf8(out, cp);
                break;
            }
            default: return false;
        }
    }
    return false;
}

static bool json_has_key(const std::string & json, const std::string & key) {
    return json.find("\"" + key + "\"") != std::string::npos;
}

static bool json_get_int_strict(const std::string & json, const std::string & key, int & out) {
    std::string pat = "\"" + key + "\"";
    size_t p = json.find(pat);
    if (p == std::string::npos) return false;
    p = json.find(':', p + pat.size());
    if (p == std::string::npos) return false;
    ++p;
    while (p < json.size() && std::isspace(static_cast<unsigned char>(json[p]))) ++p;
    int sign = 1;
    if (p < json.size() && json[p] == '-') { sign = -1; ++p; }
    int64_t v = 0; bool any = false;
    const int64_t limit = sign < 0 ? int64_t(INT32_MAX) + 1 : int64_t(INT32_MAX);
    while (p < json.size() && std::isdigit(static_cast<unsigned char>(json[p]))) {
        any = true;
        int digit = json[p++] - '0';
        if (v > (limit - digit) / 10) return false;
        v = v * 10 + digit;
    }
    if (!any) return false;
    out = static_cast<int>(sign < 0 ? -v : v);
    return true;
}

static bool json_get_double_strict(const std::string & json, const std::string & key, double & out) {
    std::string pat = "\"" + key + "\"";
    size_t p = json.find(pat);
    if (p == std::string::npos) return false;
    p = json.find(':', p + pat.size());
    if (p == std::string::npos) return false;
    ++p;
    while (p < json.size() && std::isspace(static_cast<unsigned char>(json[p]))) ++p;
    const char * start = json.c_str() + p;
    char * end = nullptr;
    double value = std::strtod(start, &end);
    if (end == start) return false;
    out = value;
    return true;
}

static std::vector<int> tokenize(const llama_vocab * vocab, const std::string & text, bool add_special, bool parse_special) {
    int n = llama_tokenize(vocab, text.c_str(), static_cast<int32_t>(text.size()), nullptr, 0, add_special, parse_special);
    if (n == 0) return {};
    if (n > 0) throw std::runtime_error("tokenizer 返回了异常的长度探测结果");
    std::vector<int> out(static_cast<size_t>(-n));
    n = llama_tokenize(vocab, text.c_str(), static_cast<int32_t>(text.size()), out.data(), static_cast<int32_t>(out.size()), add_special, parse_special);
    if (n < 0) throw std::runtime_error("tokenizer 编码失败");
    out.resize(static_cast<size_t>(n));
    return out;
}

static std::string token_piece(const llama_vocab * vocab, int token) {
    std::array<char, 256> small{};
    int n = llama_token_to_piece(vocab, token, small.data(), static_cast<int32_t>(small.size()), 0, false);
    if (n >= 0) return std::string(small.data(), static_cast<size_t>(n));
    std::vector<char> buf(static_cast<size_t>(-n));
    n = llama_token_to_piece(vocab, token, buf.data(), static_cast<int32_t>(buf.size()), 0, false);
    if (n < 0) throw std::runtime_error("无法将 token 转换为文本片段");
    return std::string(buf.data(), static_cast<size_t>(n));
}

static std::string detokenize(const llama_vocab * vocab, const std::vector<int> & tokens) {
    if (tokens.empty()) return {};
    int n = llama_detokenize(vocab, tokens.data(), static_cast<int32_t>(tokens.size()), nullptr, 0, false, false);
    if (n == 0) return {};
    if (n > 0) throw std::runtime_error("detokenizer 返回了异常的长度探测结果");
    std::vector<char> buf(static_cast<size_t>(-n));
    n = llama_detokenize(vocab, tokens.data(), static_cast<int32_t>(tokens.size()), buf.data(), static_cast<int32_t>(buf.size()), false, false);
    if (n < 0) throw std::runtime_error("detokenizer 解码失败");
    return std::string(buf.data(), static_cast<size_t>(n));
}

struct Candidate {
    std::array<uint8_t, 32> digest{};
    int token = 0;
    std::string text;
};

struct TokenTable {
    int radix = DEFAULT_RADIX;
    std::vector<int> punctuation_tokens;
    std::vector<int> free_text_tokens;
    std::unordered_map<int, std::string> token_text;
};

static std::array<uint8_t, 32> token_digest(const std::string & seed, int token, const std::string & text) {
    Sha256 h;
    h.update(seed);
    const uint8_t zero = 0;
    h.update(&zero, 1);
    std::string id = std::to_string(token);
    h.update(id);
    h.update(&zero, 1);
    h.update(reinterpret_cast<const uint8_t *>(text.data()), text.size());
    return h.final();
}

static bool stable_token(const llama_vocab * vocab, int token, const std::string & text) {
    auto ids = tokenize(vocab, text, false, false);
    return ids.size() == 1 && ids[0] == token;
}

static TokenTable build_token_table(const llama_vocab * vocab, const std::string & seed, int radix) {
    const int n_vocab = llama_vocab_n_tokens(vocab);
    std::vector<Candidate> candidates;
    std::vector<Candidate> punctuation_candidates;
    candidates.reserve(static_cast<size_t>(n_vocab / 4));
    for (int token = 0; token < n_vocab; ++token) {
        if (llama_vocab_is_control(vocab, token) || llama_vocab_is_eog(vocab, token)) continue;
        std::string text;
        try { text = token_piece(vocab, token); } catch (const std::exception &) { continue; }
        if (text.find("<think") != std::string::npos || text.find("</think") != std::string::npos) continue;
        if (contains_bracket(text)) continue;
        try { if (!stable_token(vocab, token, text)) continue; } catch (const std::exception &) { continue; }
        if (!is_social_stable_text(text) && !is_punctuation_only_text(text)) continue;
        if (contains_punctuation(text)) {
            if (is_punctuation_only_text(text) || is_social_stable_text(text)) {
                punctuation_candidates.push_back({token_digest(seed + ":punctuation", token, text), token, text});
            }
            continue;
        }
        candidates.push_back({token_digest(seed, token, text), token, text});
    }
    std::sort(candidates.begin(), candidates.end(), [](const Candidate & a, const Candidate & b) {
        return a.digest < b.digest;
    });
    std::sort(punctuation_candidates.begin(), punctuation_candidates.end(), [](const Candidate & a, const Candidate & b) {
        return a.digest < b.digest;
    });
    if (static_cast<int>(candidates.size()) < radix * 64) {
        throw std::runtime_error("稳定 token 候选不足，无法构建 top-k 载体候选集");
    }
    TokenTable table;
    table.radix = radix;
    for (const auto & c : candidates) {
        table.free_text_tokens.push_back(c.token);
        table.token_text[c.token] = c.text;
    }
    for (const auto & c : punctuation_candidates) {
        table.punctuation_tokens.push_back(c.token);
        table.token_text[c.token] = c.text;
    }
    table.free_text_tokens.insert(table.free_text_tokens.end(), table.punctuation_tokens.begin(), table.punctuation_tokens.end());
    return table;
}

static int bits_per_digit(int radix) {
    if (radix == 2) return 1;
    if (radix == 4) return 2;
    if (radix == 8) return 3;
    if (radix == 16) return 4;
    throw std::runtime_error("top-k 载荷进制必须是 2、4、8 或 16");
}

static std::vector<int> bytes_to_base_digits(const std::vector<uint8_t> & data, int radix) {
    const int bits = bits_per_digit(radix);
    const int mask = radix - 1;
    uint32_t acc = 0;
    int bit_count = 0;
    std::vector<int> out;
    for (uint8_t byte : data) {
        acc = (acc << 8) | byte;
        bit_count += 8;
        while (bit_count >= bits) {
            bit_count -= bits;
            out.push_back((acc >> bit_count) & mask);
            acc &= bit_count ? ((1u << bit_count) - 1u) : 0u;
        }
    }
    if (bit_count) out.push_back((acc << (bits - bit_count)) & mask);
    return out;
}

static std::vector<uint8_t> base_digits_to_bytes(const std::vector<int> & digits, int radix) {
    const int bits = bits_per_digit(radix);
    uint32_t acc = 0;
    int bit_count = 0;
    std::vector<uint8_t> out;
    for (int d : digits) {
        if (d < 0 || d >= radix) throw std::runtime_error("载荷位超出当前 top-k 进制范围");
        acc = (acc << bits) | static_cast<uint32_t>(d);
        bit_count += bits;
        while (bit_count >= 8) {
            bit_count -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bit_count) & 0xffu));
            acc &= bit_count ? ((1u << bit_count) - 1u) : 0u;
        }
    }
    return out;
}

static bool is_power_of_two_radix(int radix) {
    return radix == 2 || radix == 4 || radix == 8 || radix == 16;
}

static void append_uvarint(std::vector<uint8_t> & out, uint32_t v) {
    while (v >= 0x80u) {
        out.push_back(uint8_t((v & 0x7fu) | 0x80u));
        v >>= 7;
    }
    out.push_back(uint8_t(v));
}

static bool read_uvarint(const std::vector<uint8_t> & d, size_t & pos, uint32_t & out) {
    out = 0;
    uint32_t shift = 0;
    for (int i = 0; i < 5; ++i) {
        if (pos >= d.size()) return false;
        uint8_t b = d[pos++];
        out |= uint32_t(b & 0x7fu) << shift;
        if ((b & 0x80u) == 0) return true;
        shift += 7;
    }
    return false;
}

static bool read_u32_le(const std::vector<uint8_t> & d, size_t & pos, uint32_t & out) {
    if (pos > d.size() || d.size() - pos < 4) return false;
    out = uint32_t(d[pos]) |
          (uint32_t(d[pos + 1]) << 8) |
          (uint32_t(d[pos + 2]) << 16) |
          (uint32_t(d[pos + 3]) << 24);
    pos += 4;
    return true;
}

static uint32_t crc32_bytes(const uint8_t * data, size_t len) {
    uint32_t crc = 0xffffffffu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
        }
    }
    return ~crc;
}

static uint8_t gf256_mul(uint8_t a, uint8_t b) {
    uint8_t out = 0;
    while (b) {
        if (b & 1u) out ^= a;
        bool carry = (a & 0x80u) != 0;
        a = uint8_t(a << 1);
        if (carry) a ^= 0x1du;
        b >>= 1;
    }
    return out;
}

static uint8_t gf256_inv(uint8_t value) {
    if (!value) return 0;
    for (int candidate = 1; candidate < 256; ++candidate) {
        if (gf256_mul(value, static_cast<uint8_t>(candidate)) == 1) {
            return static_cast<uint8_t>(candidate);
        }
    }
    return 0;
}

static int redundancy_block_size(int level) {
    if (level == 1) return 40;
    if (level == 2) return 20;
    if (level == 3) return 10;
    return 0;
}

static void append_redundancy_parity(std::vector<uint8_t> & out,
                                     const std::vector<uint8_t> & data,
                                     int block_size) {
    for (size_t offset = 0; offset < data.size(); offset += static_cast<size_t>(block_size)) {
        size_t len = std::min(static_cast<size_t>(block_size), data.size() - offset);
        uint8_t p0 = 0;
        uint8_t p1 = 0;
        for (size_t i = 0; i < len; ++i) {
            uint8_t value = data[offset + i];
            p0 ^= value;
            p1 ^= gf256_mul(value, static_cast<uint8_t>(i + 1));
        }
        out.push_back(p0);
        out.push_back(p1);
    }
}

static bool verify_redundancy_block(const std::vector<uint8_t> & data,
                                    size_t offset, size_t len,
                                    uint8_t expected_p0, uint8_t expected_p1) {
    uint8_t p0 = 0;
    uint8_t p1 = 0;
    for (size_t i = 0; i < len; ++i) {
        uint8_t value = data[offset + i];
        p0 ^= value;
        p1 ^= gf256_mul(value, static_cast<uint8_t>(i + 1));
    }
    return p0 == expected_p0 && p1 == expected_p1;
}

static bool repair_redundancy_block(std::vector<uint8_t> & data,
                                    size_t offset, size_t len,
                                    uint8_t expected_p0, uint8_t expected_p1) {
    uint8_t p0 = 0;
    uint8_t p1 = 0;
    for (size_t i = 0; i < len; ++i) {
        uint8_t value = data[offset + i];
        p0 ^= value;
        p1 ^= gf256_mul(value, static_cast<uint8_t>(i + 1));
    }
    uint8_t s0 = p0 ^ expected_p0;
    uint8_t s1 = p1 ^ expected_p1;
    if (!s0 && !s1) return true;
    if (!s0 || !s1) return true; // one parity byte may be damaged; CRC still verifies the frame.
    uint8_t pos = gf256_mul(s1, gf256_inv(s0));
    if (pos == 0 || pos > len) return false;
    data[offset + static_cast<size_t>(pos - 1)] ^= s0;
    return verify_redundancy_block(data, offset, len, expected_p0, expected_p1);
}

static std::vector<uint8_t> frame_payload_legacy(const std::vector<uint8_t> & payload, int radix) {
    (void)radix;
    std::vector<uint8_t> out;
    if (payload.size() > 0xffffffffu) throw std::runtime_error("top-k 载荷过大，无法编码");
    append_uvarint(out, static_cast<uint32_t>(payload.size()));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

static std::vector<uint8_t> frame_payload_redundant(const std::vector<uint8_t> & payload, int radix, int redundancy_level) {
    (void)radix;
    int block_size = redundancy_block_size(redundancy_level);
    if (block_size <= 0) return frame_payload_legacy(payload, radix);
    if (payload.size() > 0xffffffffu - 4u) throw std::runtime_error("top-k payload is too large for redundant frame");
    std::vector<uint8_t> protected_data = payload;
    append_u32_le(protected_data, crc32_bytes(payload.data(), payload.size()));

    std::vector<uint8_t> out;
    out.insert(out.end(), {'C', 'I', 'R', '1'});
    out.push_back(static_cast<uint8_t>(redundancy_level));
    out.push_back(static_cast<uint8_t>(block_size));
    append_uvarint(out, static_cast<uint32_t>(payload.size()));
    out.insert(out.end(), protected_data.begin(), protected_data.end());
    append_redundancy_parity(out, protected_data, block_size);
    return out;
}

static bool try_unframe_redundant_payload(const std::vector<uint8_t> & frame, std::vector<uint8_t> & payload) {
    payload.clear();
    if (frame.size() < 7 || frame[0] != 'C' || frame[1] != 'I' || frame[2] != 'R' || frame[3] != '1') {
        return false;
    }
    size_t pos = 4;
    int level = frame[pos++];
    int block_size = frame[pos++];
    if (block_size != redundancy_block_size(level)) return false;
    uint32_t payload_len = 0;
    if (!read_uvarint(frame, pos, payload_len)) return false;
    size_t data_len = static_cast<size_t>(payload_len) + 4u;
    size_t block_count = data_len ? (data_len + static_cast<size_t>(block_size) - 1u) / static_cast<size_t>(block_size) : 1u;
    size_t parity_len = block_count * 2u;
    if (pos > frame.size() || data_len > frame.size() - pos || parity_len > frame.size() - pos - data_len) {
        return false;
    }
    std::vector<uint8_t> protected_data(frame.begin() + static_cast<std::ptrdiff_t>(pos),
                                        frame.begin() + static_cast<std::ptrdiff_t>(pos + data_len));
    size_t parity_pos = pos + data_len;
    for (size_t block = 0; block < block_count; ++block) {
        size_t offset = block * static_cast<size_t>(block_size);
        size_t len = std::min(static_cast<size_t>(block_size), protected_data.size() - offset);
        uint8_t p0 = frame[parity_pos + block * 2u];
        uint8_t p1 = frame[parity_pos + block * 2u + 1u];
        if (!repair_redundancy_block(protected_data, offset, len, p0, p1)) {
            throw std::runtime_error("top-k redundant frame parity check failed");
        }
    }
    size_t crc_read_pos = static_cast<size_t>(payload_len);
    uint32_t expected_crc = 0;
    if (!read_u32_le(protected_data, crc_read_pos, expected_crc)) return false;
    uint32_t actual_crc = crc32_bytes(protected_data.data(), payload_len);
    if (actual_crc != expected_crc) {
        throw std::runtime_error("top-k redundant frame CRC check failed");
    }
    payload.assign(protected_data.begin(), protected_data.begin() + static_cast<std::ptrdiff_t>(payload_len));
    return true;
}
static std::vector<uint8_t> unframe_payload_legacy(const std::vector<uint8_t> & frame, int radix) {
    (void)radix;
    if (frame.empty()) throw std::runtime_error("top-k 紧凑载荷帧为空，无法读取长度");
    size_t pos = 0;
    uint32_t payload_len = 0;
    if (!read_uvarint(frame, pos, payload_len) || payload_len == 0) {
        throw std::runtime_error("top-k 紧凑载荷帧长度前缀无效，可能是 seed/tokenizer 不一致或复制内容不完整");
    }
    size_t needed = pos + size_t(payload_len);
    if (frame.size() < needed) {
        throw std::runtime_error("top-k 紧凑载荷帧被截断：需要 " + std::to_string(needed) +
                                 " 字节，实际恢复 " + std::to_string(frame.size()) +
                                 " 字节；请确认载体文本完整复制，且两端安装包、模型和 tokenizer 完全一致");
    }
    std::vector<uint8_t> payload(frame.begin() + static_cast<std::ptrdiff_t>(pos),
                                 frame.begin() + static_cast<std::ptrdiff_t>(needed));
    return payload;
}

static std::vector<uint8_t> unframe_payload(const std::vector<uint8_t> & frame, int radix) {
    std::vector<uint8_t> payload;
    if (try_unframe_redundant_payload(frame, payload)) return payload;
    return unframe_payload_legacy(frame, radix);
}
static std::vector<int> encode_payload_to_digits(const std::vector<uint8_t> & payload, int radix, int redundancy_level) {
    auto framed = redundancy_level == 0 ? frame_payload_legacy(payload, radix) : frame_payload_redundant(payload, radix, redundancy_level);
    return bytes_to_base_digits(framed, radix);
}

static bool try_decode_payload_digits(const std::vector<int> & digits, int radix, std::vector<uint8_t> & payload, std::string & err) {
    try {
        auto bytes = base_digits_to_bytes(digits, radix);
        payload = unframe_payload(bytes, radix);
        return true;
    } catch (const std::exception & e) {
        err = e.what();
        return false;
    }
}

static std::vector<uint8_t> decode_digits_to_payload(const std::vector<int> & digits, int radix) {
    if (digits.empty()) {
        throw std::runtime_error("未从载体文本中解出任何 top-k 载荷位；请确认复制的是完整载体文本，且两端模型和 tokenizer 一致");
    }
    std::vector<uint8_t> payload;
    std::string err;
    if (try_decode_payload_digits(digits, radix, payload, err)) return payload;
    if (err.empty()) err = "top-k 紧凑载荷帧无法解码";
    err += "（top-k进制=" + std::to_string(radix) +
           "，恢复位数=" + std::to_string(digits.size()) + "）";
    throw std::runtime_error(err);
}

static std::string trim_text(std::string s) {
    auto is_ws = [](unsigned char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    while (!s.empty() && is_ws(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && is_ws(static_cast<unsigned char>(s.back()))) s.pop_back();
    return s;
}

static std::string strip_thinking_blocks(std::string s) {
    for (;;) {
        size_t start = s.find("<think>");
        if (start == std::string::npos) break;
        size_t end = s.find("</think>", start);
        if (end == std::string::npos) {
            s.erase(start);
            break;
        }
        s.erase(start, end + 8 - start);
    }
    for (;;) {
        size_t p = s.find("</think>");
        if (p == std::string::npos) break;
        s.erase(p, 8);
    }
    return s;
}

static bool contains_any_phrase(const std::string & text, const std::vector<std::string> & phrases) {
    for (const auto & phrase : phrases) {
        if (!phrase.empty() && text.find(phrase) != std::string::npos) return true;
    }
    return false;
}

static bool contains_runtime_reject_phrase(const std::string & text, const std::string & prompt_dir) {
    if (prompt_dir.empty()) return false;
    return contains_any_phrase(text, read_line_list_file(fs::path(prompt_dir) / "reject_phrases.txt"));
}

static bool has_enough_article_before(const std::string & text, size_t pos, size_t min_cjk = 260) {
    if (pos == std::string::npos || pos == 0) return false;
    return cjk_count(text.substr(0, pos)) >= min_cjk;
}

static void truncate_at_tail_phrase(std::string & text, const std::vector<std::string> & phrases, size_t min_cjk = 260) {
    size_t cut = std::string::npos;
    for (const auto & phrase : phrases) {
        size_t pos = text.find(phrase);
        if (pos != std::string::npos && has_enough_article_before(text, pos, min_cjk)) cut = std::min(cut, pos);
    }
    if (cut != std::string::npos) {
        text.resize(cut);
        text = trim_text(text);
    }
}

static bool is_chinese_section_marker(uint32_t cp) {
    return cp == 0x4e00 || cp == 0x4e8c || cp == 0x4e09 || cp == 0x56db ||
           cp == 0x4e94 || cp == 0x516d || cp == 0x4e03 || cp == 0x516b ||
           cp == 0x4e5d || cp == 0x5341;
}

static bool starts_with_outline_ordinal(const std::string & line) {
    const char * ordinal[] = {
        "\xe9\xa6\x96\xe5\x85\x88",
        "\xe5\x85\xb6\xe6\xac\xa1",
        "\xe6\x9c\x80\xe5\x90\x8e",
    };
    for (const char * marker : ordinal) {
        const size_t ml = std::strlen(marker);
        if (line.rfind(marker, 0) == 0 && line.size() > ml) {
            size_t k = ml;
            uint32_t cp = 0;
            if (!next_utf8(line, k, cp) ||
                cp == 0x3001 || cp == 0xff0c || cp == 0xff1a ||
                cp == ':' || std::isspace(static_cast<unsigned char>(line[ml]))) {
                return true;
            }
        }
    }
    return false;
}

static bool contains_outline_markers_precise(const std::string & text) {
    auto has_phrase = [&](const char * phrase) {
        return phrase && phrase[0] && text.find(phrase) != std::string::npos;
    };
    if (has_phrase("\xe6\x8f\x90\xe7\xba\xb2") ||
        has_phrase("\xe6\xa0\x87\xe9\xa2\x98\xef\xbc\x9a") ||
        has_phrase("\xe6\xa0\x87\xe9\xa2\x98:") ||
        has_phrase("\xe5\xb0\x8f\xe6\xa0\x87\xe9\xa2\x98\xef\xbc\x9a") ||
        has_phrase("\xe5\xb0\x8f\xe6\xa0\x87\xe9\xa2\x98:") ||
        has_phrase("\xe4\xb8\x8b\xe9\x9d\xa2\xe6\x98\xaf\xe6\xad\xa3\xe6\x96\x87") ||
        has_phrase("\xe6\xad\xa3\xe6\x96\x87\xe5\xa6\x82\xe4\xb8\x8b")) {
        return true;
    }
    size_t pos = 0;
    while (pos < text.size()) {
        size_t line_end = text.find('\n', pos);
        std::string line = trim_text(line_end == std::string::npos ? text.substr(pos) : text.substr(pos, line_end - pos));
        if (!line.empty()) {
            size_t n = 0;
            while (n < line.size() && std::isdigit(static_cast<unsigned char>(line[n]))) ++n;
            if (n > 0 && n < line.size() &&
                (line[n] == '.' || line[n] == ':' || line.compare(n, 3, "\xe3\x80\x81") == 0 || line.compare(n, 3, "\xef\xbc\x9a") == 0)) {
                return true;
            }
            size_t i = 0;
            uint32_t cp = 0;
            if (next_utf8(line, i, cp) && is_chinese_section_marker(cp)) {
                uint32_t next_cp = 0;
                size_t j = i;
                bool has_next = next_utf8(line, j, next_cp);
                if (!has_next || std::isspace(static_cast<unsigned char>(line[i])) ||
                    next_cp == 0x3001 || next_cp == 0xff1a || next_cp == ':') {
                    return true;
                }
            }
            if (starts_with_outline_ordinal(line)) return true;
        }
        if (line_end == std::string::npos) break;
        pos = line_end + 1;
    }
    return false;
}

static bool looks_like_meta_or_compliance_text(const std::string & text) {
    return contains_any_phrase(text, {
        "合规检查", "合规性", "安全检查", "安全过滤", "安全审查",
        "正常辅助工作", "超出了正常辅助", "拒绝进一步",
        "不符合正式出版", "核心能力范围", "服务安全性",
        "风险缺失", "法律法规", "准确性",
        "请确认阅读", "请确认", "请您", "请提供", "继续处理",
        "是否完成", "新的要求", "用户需求", "写作需求", "格式需求",
        "准备好接受", "下方评论区", "根据你提供", "你提供的", "你的要求",
        "提纲内容", "注意结尾", "注：", "注:", "此处根据"
    });
}

static bool contains_outline_markers(const std::string & text) {
    if (contains_any_phrase(text, {
            "提纲", "标题：", "标题:", "小标题：", "小标题:",
            "首先", "其次", "最后", "本段将", "本文将", "下面是正文", "正文如下"
        })) {
        return true;
    }
    size_t pos = 0;
    while (pos < text.size()) {
        size_t line_end = text.find('\n', pos);
        std::string line = trim_text(line_end == std::string::npos ? text.substr(pos) : text.substr(pos, line_end - pos));
        if (!line.empty()) {
            size_t n = 0;
            while (n < line.size() && std::isdigit(static_cast<unsigned char>(line[n]))) ++n;
            if (n > 0 && n < line.size() &&
                (line[n] == '.' || line[n] == ':' || line.compare(n, 3, "、") == 0 || line.compare(n, 3, "：") == 0)) {
                return true;
            }
            size_t i = 0;
            uint32_t cp = 0;
            if (next_utf8(line, i, cp) && is_chinese_section_marker(cp)) {
                uint32_t next_cp = 0;
                size_t j = i;
                bool has_next = next_utf8(line, j, next_cp);
                if (!has_next || std::isspace(static_cast<unsigned char>(line[i])) ||
                    next_cp == 0x3001 || next_cp == 0xff1a || next_cp == ':') {
                    return true;
                }
            }
        }
        if (line_end == std::string::npos) break;
        pos = line_end + 1;
    }
    return false;
}

static bool looks_like_numbered_section_body(const std::string & text) {
    size_t pos = 0;
    while (pos < text.size()) {
        size_t line_end = text.find('\n', pos);
        std::string line = trim_text(line_end == std::string::npos ? text.substr(pos) : text.substr(pos, line_end - pos));
        if (!line.empty()) {
            size_t i = 0;
            uint32_t cp = 0;
            if (next_utf8(line, i, cp) && is_chinese_section_marker(cp)) {
                uint32_t next_cp = 0;
                size_t j = i;
                bool has_next = next_utf8(line, j, next_cp);
                if (!has_next || std::isspace(static_cast<unsigned char>(line[i])) ||
                    next_cp == 0x3001 || next_cp == 0xff1a || next_cp == ':') return true;
            }
        }
        if (line_end == std::string::npos) break;
        pos = line_end + 1;
    }
    return false;
}

static void collapse_repeated_tail_paragraphs(std::string & text) {
    std::vector<std::string> parts;
    size_t pos = 0;
    while (pos < text.size()) {
        size_t next = text.find("\n\n", pos);
        std::string part = trim_text(next == std::string::npos ? text.substr(pos) : text.substr(pos, next - pos));
        if (!part.empty()) parts.push_back(part);
        if (next == std::string::npos) break;
        pos = next + 2;
    }
    if (parts.size() < 3) return;
    bool changed = false;
    while (parts.size() >= 2) {
        const std::string & last = parts.back();
        const std::string & prev = parts[parts.size() - 2];
        if (cjk_count(last) < 24 || last != prev) break;
        parts.pop_back();
        changed = true;
    }
    if (!changed) return;
    text = trim_text(std::accumulate(std::next(parts.begin()), parts.end(), parts.front(),
        [](std::string a, const std::string & b) { return std::move(a) + "\n\n" + b; }));
}

static std::string clean_generated_article(std::string text) {
    text = strip_thinking_blocks(text);
    text = trim_text(text);
    truncate_at_tail_phrase(text, {
        "<|im_", "```", "以上是我", "以上就是", "以上内容", "以上正文", "以上文章",
        "根据提纲撰写", "完整正文所有内容", "字数约", "符合文章主题", "满足写作助手",
        "请您继续处理", "请继续处理", "请确认", "是否完成此请求", "是否有新的要求",
        "新的要求需要调整", "如果不需要继续", "不需要继续处理", "直接输入", "不写内容",
        "最终输出文档", "即可执行", "生成最终输出", "合规检查", "安全检查", "安全过滤",
        "安全审查", "正常辅助工作", "超出了正常辅助", "拒绝进一步", "不符合正式出版",
        "核心能力范围", "服务安全性", "根据你提供", "你提供的", "你的要求", "提纲内容",
        "注意结尾", "注：", "注:", "此处根据"
    });
    for (;;) {
        bool changed = false;
        text = trim_text(text);
        for (const auto & prefix : {"正文：", "正文:", "文章：", "文章:"}) {
            if (text.rfind(prefix, 0) == 0) {
                text.erase(0, std::strlen(prefix));
                changed = true;
                break;
            }
        }
        if (!changed) break;
    }
    collapse_repeated_tail_paragraphs(text);
    return trim_text(text);
}

static bool looks_like_instruction_reply(const std::string & text, const std::string & prompt_dir) {
    if (looks_like_meta_or_compliance_text(text)) return true;
    std::string head = text.substr(0, std::min<size_t>(text.size(), 1800));
    if (contains_runtime_reject_phrase(head, prompt_dir)) return true;
    if (contains_any_phrase(head, {
            "请提供具体", "请提供更多", "请提供完整", "提供具体的写作需求", "写作需求",
            "这是一个关于", "这是一篇关于", "建议文章吗", "完整的长篇文章",
            "我可以继续", "我会继续", "继续为你", "进一步处理", "开始处理",
            "如果你希望", "如果你需要", "是否要", "是否需要", "你希望我",
            "请确认", "请告诉我", "让我们从", "我们可以先",
            "抱歉", "对不起", "纠正之前", "纠正前文", "正确的自我介绍",
            "这是正确的", "以下是"
        })) {
        return true;
    }
    std::string tail = text.size() > 2200 ? text.substr(text.size() - 2200) : text;
    if (contains_runtime_reject_phrase(tail, prompt_dir)) return true;
    return contains_any_phrase(tail, {
        "以上是我", "以上就是", "完整正文所有内容", "字数约", "满足写作助手",
        "请您继续处理", "请继续处理", "请确认", "是否完成此请求", "是否有新的要求",
        "如果不需要继续", "直接输入", "不写内容", "最终输出文档", "即可执行"
    });
}

static bool disallowed_article_continuation(const std::string & generated_text,
                                            const std::string & piece,
                                            const std::vector<std::string> & reject_phrases) {
    if (contains_bracket(piece) || piece.find("<|") != std::string::npos) return true;
    if (disallowed_punctuation_transition(generated_text, piece)) return true;
    std::string probe = generated_text + piece;
    std::string tail = probe.size() > 4096 ? probe.substr(probe.size() - 4096) : probe;
    if (looks_like_meta_or_compliance_text(tail)) return true;
    if (contains_any_phrase(tail, reject_phrases)) return true;
    return contains_any_phrase(tail, {
        "如果你", "如果您", "你有任何", "您有任何", "对你有", "对您有",
        "欢迎直接问", "欢迎随时", "祝你", "祝您", "简要版本",
        "请放心提问", "提问和解答", "写作需求的满足",
        "if you", "if i", "i can", "i will", "i would", "this response",
        "for instance", "as an example", "the output could", "your instructions",
        "requirements", "happy to be of service", "this is an example"
    });
}
struct ScoredToken {
    int token = 0;
    float score = 0.0f;
    std::string text;
};

static float apply_repeat_penalty(float score, float penalty) {
    if (penalty <= 1.0f) return score;
    return score > 0 ? score / penalty : score * penalty;
}

static int trailing_token_run(const std::vector<int> & tokens, int token) {
    int run = 0;
    for (size_t i = tokens.size(); i > 0; --i) {
        if (tokens[i - 1] != token) break;
        ++run;
    }
    return run;
}

static float apply_contiguous_repeat_penalty(float score, const std::vector<int> & generated_tokens, int token) {
    int run = trailing_token_run(generated_tokens, token);
    if (run <= 0) return score;
    float penalty = std::min(2.25f, 1.18f + 0.22f * static_cast<float>(run));
    return apply_repeat_penalty(score, penalty);
}

static int chars_since_sentence_break(const std::string & text) {
    int count = 0;
    size_t i = text.size();
    while (i > 0) {
        size_t start = i - 1;
        while (start > 0 && (uint8_t(text[start]) & 0xc0) == 0x80) --start;
        size_t tmp = start; uint32_t cp = 0;
        if (!next_utf8(text, tmp, cp)) break;
        if (cp == 0x3002 || cp == 0xff01 || cp == 0xff1f) break;
        if (is_cjk(cp)) ++count;
        i = start;
    }
    return count;
}

static int chars_since_punctuation(const std::string & text) {
    int count = 0;
    size_t i = text.size();
    while (i > 0) {
        size_t start = i - 1;
        while (start > 0 && (uint8_t(text[start]) & 0xc0) == 0x80) --start;
        size_t tmp = start; uint32_t cp = 0;
        if (!next_utf8(text, tmp, cp)) break;
        if (is_chinese_punct(cp)) break;
        if (is_cjk(cp)) ++count;
        i = start;
    }
    return count;
}

static float punctuation_ramp(int chars) {
    if (chars < 20) return 0.0f;
    if (chars < 40) return float(chars - 19) / 21.0f;
    return std::min(5.0f, 1.0f + float(chars - 40) / 12.0f);
}

static void build_stability_tail(const llama_vocab * vocab, const std::vector<int> & generated_tokens,
                                 std::vector<int> & tail_tokens, std::string & tail_text) {
    tail_tokens.clear();
    tail_text.clear();
    const size_t n = generated_tokens.size();
    const size_t start = n > 64 ? n - 64 : 0;
    tail_tokens.reserve(n - start);
    for (size_t i = start; i < n; ++i) {
        int id = generated_tokens[i];
        tail_tokens.push_back(id);
        tail_text += token_piece(vocab, id);
    }
}

static bool stable_append_tail(const llama_vocab * vocab, const std::string & tail_text,
                               const std::vector<int> & tail_tokens, int token, const std::string & piece) {
    auto ids = tokenize(vocab, tail_text + piece, false, false);
    if (ids.size() != tail_tokens.size() + 1) return false;
    for (size_t i = 0; i < tail_tokens.size(); ++i) if (ids[i] != tail_tokens[i]) return false;
    return ids.back() == token;
}

static int topk_digit_for_token(const std::string & seed, size_t payload_pos, int token, int radix) {
        if (!is_power_of_two_radix(radix)) throw std::runtime_error("top-k 载荷进制必须是 2、4、8 或 16");
    Sha256 h;
    h.update("ChineseInputAgent top-k token digit v1");
    const uint8_t zero = 0;
    h.update(&zero, 1);
    h.update(seed);
    h.update(&zero, 1);
    std::string pos = std::to_string(payload_pos);
    h.update(pos);
    h.update(&zero, 1);
    std::string tok = std::to_string(token);
    h.update(tok);
    auto digest = h.final();
    return int(digest[0] & uint8_t(radix - 1));
}
class LlamaPayloadWorker {
public:
    std::string model_path;
    std::string adapter_path;
    int radix = DEFAULT_RADIX;
    int n_gpu_layers = 99;
    int n_ctx = 4096;
    int n_threads = std::max(2u, std::thread::hardware_concurrency());
    int free_tail_tokens = 64;
    int min_tail_tokens = 0;
    int max_tail_tokens = 64;
    float temperature = 0.7f;
    float top_p = 0.8f;
    int top_k = 20;
    int min_k = 64;
    int redundancy_level = 0;
    PromptLengthConfig length_config;
    int encode_attempts = 5;
    int retry_seed_stride = 9973;
    int progress_interval_ms = 1000;
    int batch_min_tokens = 512;
    int context_keep_tokens = 256;
    int rolling_context_tokens = 768;
    int context_shift_margin = 128;
    int self_check_initial_digits = 32;
    int self_check_interval_digits = 32;
    int self_check_tail_chars = 4096;
    bool outline_enabled = true;
    int outline_tokens = 96;
    int outline_min_chars = 24;
    int outline_context_extra_tokens = 64;
    std::string prompt_dir;
    std::string tokenizer_id = "model";
    std::string tokenizer_dir;
    std::vector<std::string> decode_tokenizers;
    std::map<std::string, std::string> tokenizer_paths;
    int decode_threads = 4;
    std::string backend_preference = "auto";
    std::string backend_used = "cpu";

    llama_model * model = nullptr;
    llama_adapter_lora * adapter = nullptr;
    const llama_vocab * vocab = nullptr;
    std::map<std::string, TokenTable> table_cache;
    ggml_backend_dev_t selected_devices[2] = { nullptr, nullptr };

    struct LoadedTokenizer {
        std::string id;
        llama_model * model = nullptr;
        const llama_vocab * vocab = nullptr;
        bool primary = false;
    };
    std::vector<LoadedTokenizer> loaded_tokenizers;
    std::mutex tokenizer_lock;

    ~LlamaPayloadWorker() {
        if (adapter) llama_adapter_lora_free(adapter);
        for (auto & tokenizer : loaded_tokenizers) {
            if (!tokenizer.primary && tokenizer.model) llama_model_free(tokenizer.model);
        }
        if (model) llama_model_free(model);
    }

    std::string device_backend_name(ggml_backend_dev_t dev) const {
        if (!dev) return "cpu";
        std::string label;
        ggml_backend_reg_t reg = ggml_backend_dev_backend_reg(dev);
        const char * reg_name = reg ? ggml_backend_reg_name(reg) : nullptr;
        const char * dev_name = ggml_backend_dev_name(dev);
        const char * desc = ggml_backend_dev_description(dev);
        if (reg_name) label += reg_name;
        if (dev_name) { if (!label.empty()) label += ":"; label += dev_name; }
        if (desc) { if (!label.empty()) label += ":"; label += desc; }
        return label.empty() ? "gpu" : label;
    }

    void add_matching_devices(std::vector<ggml_backend_dev_t> & out, const std::string & backend) const {
        const size_t count = ggml_backend_dev_count();
        for (size_t i = 0; i < count; ++i) {
            ggml_backend_dev_t dev = ggml_backend_dev_get(i);
            if (!dev) continue;
            if (std::find(out.begin(), out.end(), dev) != out.end()) continue;
            std::string label = device_backend_name(dev);
            if (contains_ci(label, backend)) out.push_back(dev);
        }
    }

    void add_gpu_devices(std::vector<ggml_backend_dev_t> & out) const {
        const size_t count = ggml_backend_dev_count();
        for (size_t i = 0; i < count; ++i) {
            ggml_backend_dev_t dev = ggml_backend_dev_get(i);
            if (!dev) continue;
            if (std::find(out.begin(), out.end(), dev) != out.end()) continue;
            auto type = ggml_backend_dev_type(dev);
            if (type == GGML_BACKEND_DEVICE_TYPE_GPU || type == GGML_BACKEND_DEVICE_TYPE_IGPU) out.push_back(dev);
        }
    }

    int64_t device_priority_score(ggml_backend_dev_t dev) const {
        if (!dev) return 0;
        std::string label = device_backend_name(dev);
        std::string lower = ascii_lower(label);
        int64_t score = 0;

        // Backend order: CUDA first, then Vulkan, then any other accelerator. Within
        // Vulkan, strongly prefer a discrete GPU so AMD/NVIDIA dGPUs do not lose to
        // Intel/AMD integrated adapters that may report large shared system memory.
        if (contains_ci(label, "cuda")) score += 1000000;
        else if (contains_ci(label, "vulkan")) score += 700000;
        else score += 400000;

        auto type = ggml_backend_dev_type(dev);
        if (type == GGML_BACKEND_DEVICE_TYPE_GPU) score += 250000;
        else if (type == GGML_BACKEND_DEVICE_TYPE_IGPU) score -= 250000;

        if (contains_ci(label, "nvidia")) score += 70000;
        if (contains_ci(label, "geforce") || contains_ci(label, "rtx") || contains_ci(label, "gtx")) score += 50000;
        if (contains_ci(label, "amd") || contains_ci(label, "radeon")) score += 30000;
        if (contains_ci(label, "radeon rx") || contains_ci(label, "radeon pro") ||
            lower.find(" rx ") != std::string::npos || lower.find("(rx ") != std::string::npos) {
            score += 60000;
        }
        if (contains_ci(label, "intel") || contains_ci(label, "uhd") || contains_ci(label, "iris") ||
            contains_ci(label, "integrated") || contains_ci(label, "igpu")) {
            score -= 160000;
        }
        if (contains_ci(label, "radeon(tm) graphics") || contains_ci(label, "radeon graphics") ||
            contains_ci(label, "vega")) {
            score -= 80000;
        }

        size_t free_mem = 0, total_mem = 0;
        ggml_backend_dev_memory(dev, &free_mem, &total_mem);
        const int64_t total_mib = static_cast<int64_t>(total_mem / (1024ull * 1024ull));
        const int64_t free_mib = static_cast<int64_t>(free_mem / (1024ull * 1024ull));
        if (type == GGML_BACKEND_DEVICE_TYPE_GPU) {
            score += std::min<int64_t>(total_mib, 65536);
            score += std::min<int64_t>(free_mib / 2, 32768);
        } else if (type == GGML_BACKEND_DEVICE_TYPE_IGPU) {
            score += std::min<int64_t>(total_mib / 32, 2048);
            score += std::min<int64_t>(free_mib / 64, 1024);
        }

        return score;
    }

    void sort_devices_by_priority(std::vector<ggml_backend_dev_t> & devices) const {
        std::stable_sort(devices.begin(), devices.end(), [&](ggml_backend_dev_t a, ggml_backend_dev_t b) {
            return device_priority_score(a) > device_priority_score(b);
        });
    }

    std::vector<ggml_backend_dev_t> preferred_devices() const {
        std::vector<ggml_backend_dev_t> devices;
        std::string pref = ascii_lower(backend_preference);
        if (pref == "cpu") return devices;
        if (pref == "cuda") {
            add_matching_devices(devices, "cuda");
            sort_devices_by_priority(devices);
            return devices;
        }
        if (pref == "vulkan") {
            add_matching_devices(devices, "vulkan");
            sort_devices_by_priority(devices);
            return devices;
        }
        add_matching_devices(devices, "cuda");
        add_matching_devices(devices, "vulkan");
        add_gpu_devices(devices);
        sort_devices_by_priority(devices);
        return devices;
    }

    llama_model * load_model_file(const std::string & path, std::string & used_backend) {
        std::vector<ggml_backend_dev_t> candidates = preferred_devices();
        candidates.push_back(nullptr);
        std::string first_error;
        for (ggml_backend_dev_t dev : candidates) {
            llama_model_params mp = llama_model_default_params();
            if (dev) {
                selected_devices[0] = dev;
                selected_devices[1] = nullptr;
                mp.devices = selected_devices;
                mp.n_gpu_layers = n_gpu_layers;
            } else {
                selected_devices[0] = nullptr;
                selected_devices[1] = nullptr;
                mp.devices = nullptr;
                mp.n_gpu_layers = 0;
            }
            llama_model * loaded = llama_model_load_from_file(path.c_str(), mp);
            if (loaded) {
                used_backend = dev ? device_backend_name(dev) : "cpu";
                return loaded;
            }
            if (first_error.empty()) first_error = dev ? device_backend_name(dev) : "cpu";
        }
        throw std::runtime_error("无法加载 GGUF 模型：" + path);
    }

    void load() {
        ggml_backend_load_all();
        model = load_model_file(model_path, backend_used);
        if (!model) throw std::runtime_error("无法加载 GGUF 模型：" + model_path);
        vocab = llama_model_get_vocab(model);
        if (!vocab) throw std::runtime_error("已加载模型不包含 tokenizer 词表");
        if (!adapter_path.empty()) {
            std::error_code ec;
            if (!fs::exists(adapter_path, ec) || ec) throw std::runtime_error("LoRA adapter 文件不存在：" + adapter_path);
            adapter = llama_adapter_lora_init(model, adapter_path.c_str());
            if (!adapter) throw std::runtime_error("无法加载 LoRA adapter：" + adapter_path);
        }
        LoadedTokenizer primary;
        primary.id = tokenizer_id.empty() ? "model" : tokenizer_id;
        primary.model = model;
        primary.vocab = vocab;
        primary.primary = true;
        loaded_tokenizers.push_back(primary);
    }

    llama_model * load_vocab_only_model(const std::string & path) const {
        llama_model_params mp = llama_model_default_params();
        mp.vocab_only = true;
        mp.n_gpu_layers = 0;
        return llama_model_load_from_file(path.c_str(), mp);
    }

    std::string tokenizer_file_for_id(const std::string & id) const {
        auto mapped = tokenizer_paths.find(id);
        if (mapped != tokenizer_paths.end()) return mapped->second;
        fs::path base = tokenizer_dir.empty() ? fs::path("tokenizers") : fs::path(tokenizer_dir);
        fs::path candidate = base / (id + ".gguf");
        return candidate.string();
    }

    const llama_vocab * vocab_for_tokenizer(const std::string & id) {
        std::lock_guard<std::mutex> guard(tokenizer_lock);
        std::string wanted = id.empty() ? (tokenizer_id.empty() ? "model" : tokenizer_id) : id;
        for (const auto & tokenizer : loaded_tokenizers) {
            if (tokenizer.id == wanted) return tokenizer.vocab;
        }
        std::string path = tokenizer_file_for_id(wanted);
        std::error_code ec;
        if (!fs::exists(fs::path(path), ec) || ec) {
            throw std::runtime_error("tokenizer asset not found: " + wanted);
        }
        llama_model * tokenizer_model = load_vocab_only_model(path);
        if (!tokenizer_model) throw std::runtime_error("failed to load tokenizer asset: " + wanted);
        const llama_vocab * tokenizer_vocab = llama_model_get_vocab(tokenizer_model);
        if (!tokenizer_vocab) {
            llama_model_free(tokenizer_model);
            throw std::runtime_error("tokenizer asset has no vocab: " + wanted);
        }
        LoadedTokenizer loaded;
        loaded.id = wanted;
        loaded.model = tokenizer_model;
        loaded.vocab = tokenizer_vocab;
        loaded.primary = false;
        loaded_tokenizers.push_back(loaded);
        return loaded.vocab;
    }

    std::vector<std::string> ordered_decode_tokenizers(const std::string & preferred) const {
        std::vector<std::string> ordered;
        append_unique_string(ordered, preferred);
        append_unique_string(ordered, tokenizer_id.empty() ? "model" : tokenizer_id);
        for (const auto & id : decode_tokenizers) append_unique_string(ordered, id);
        for (const auto & entry : tokenizer_paths) append_unique_string(ordered, entry.first);
        return ordered;
    }

    TokenTable & table_for_seed(const std::string & seed) {
        auto it = table_cache.find(seed);
        if (it != table_cache.end()) return it->second;
        auto inserted = table_cache.emplace(seed, build_token_table(vocab, seed, radix));
        return inserted.first->second;
    }

    llama_sampler * make_sampler(uint32_t seed) const {
        auto params = llama_sampler_chain_default_params();
        params.no_perf = true;
        llama_sampler * smpl = llama_sampler_chain_init(params);
        if (!smpl) throw std::runtime_error("无法初始化 llama.cpp 采样器");
        auto add_sampler = [&](llama_sampler * child, const char * name) {
            if (!child) {
                llama_sampler_free(smpl);
                throw std::runtime_error(std::string("无法初始化 llama.cpp 采样器组件：") + name);
            }
            llama_sampler_chain_add(smpl, child);
        };
        add_sampler(llama_sampler_init_top_k(top_k), "top-k");
        add_sampler(llama_sampler_init_top_p(top_p, 1), "top-p");
        add_sampler(llama_sampler_init_temp(temperature), "temperature");
        add_sampler(llama_sampler_init_dist(seed), "distribution");
        return smpl;
    }

    int sample_free_text_token(llama_sampler * smpl, const float * logits) const {
        const int n_vocab = llama_vocab_n_tokens(vocab);
        std::vector<llama_token_data> data;
        data.reserve(static_cast<size_t>(n_vocab));
        for (int token = 0; token < n_vocab; ++token) {
            if (llama_vocab_is_control(vocab, token) && !llama_vocab_is_eog(vocab, token)) continue;
            data.push_back({token, logits[token], 0.0f});
        }
        if (data.empty()) throw std::runtime_error("outline sampler has no candidate tokens");
        llama_token_data_array cur{data.data(), data.size(), -1, false};
        llama_sampler_apply(smpl, &cur);
        if (cur.selected < 0 || static_cast<size_t>(cur.selected) >= data.size()) {
            throw std::runtime_error("outline sampler did not select a valid token");
        }
        int token = data[static_cast<size_t>(cur.selected)].id;
        llama_sampler_accept(smpl, token);
        return token;
    }

    std::string generate_outline_once(const std::string & prompt, uint32_t sample_seed) {
        if (!outline_enabled || outline_tokens <= 0) return {};
        auto prompt_tokens = tokenize(vocab, prompt, false, true);
        if (prompt_tokens.empty()) return {};
        const int max_new = std::max(1, outline_tokens);
        llama_context_params cp = llama_context_default_params();
        cp.n_ctx = static_cast<uint32_t>(std::max(n_ctx, static_cast<int>(prompt_tokens.size()) + max_new +
                                                  std::max(0, outline_context_extra_tokens)));
        cp.n_batch = static_cast<uint32_t>(std::max<int>(batch_min_tokens, static_cast<int>(prompt_tokens.size())));
        cp.n_ubatch = static_cast<uint32_t>(batch_min_tokens);
        cp.n_threads = n_threads;
        cp.n_threads_batch = n_threads;
        cp.no_perf = true;
        llama_context * ctx = llama_init_from_model(model, cp);
        if (!ctx) return {};
        llama_sampler * smpl = make_sampler(sample_seed);
        std::string outline;
        std::vector<int> generated_tokens;
        try {
            llama_batch batch = llama_batch_get_one(prompt_tokens.data(), static_cast<int32_t>(prompt_tokens.size()));
            if (llama_decode(ctx, batch) != 0) throw std::runtime_error("outline prompt decode failed");
            for (int i = 0; i < max_new; ++i) {
                const float * logits = llama_get_logits_ith(ctx, -1);
                if (!logits) throw std::runtime_error("outline logits unavailable");
                int token = sample_free_text_token(smpl, logits);
                if (llama_vocab_is_eog(vocab, token)) break;
                std::string piece = token_piece(vocab, token);
                if (piece.find("<|") != std::string::npos || piece.find("<think") != std::string::npos ||
                    piece.find("</think") != std::string::npos) break;
                generated_tokens.push_back(token);
                outline += piece;
                if (cjk_count(outline) >= static_cast<size_t>(std::max(0, outline_min_chars)) &&
                    contains_sentence_break(piece)) {
                    break;
                }
                batch = llama_batch_get_one(&generated_tokens.back(), 1);
                if (llama_decode(ctx, batch) != 0) break;
            }
        } catch (...) {
            llama_sampler_free(smpl);
            llama_free(ctx);
            return {};
        }
        llama_sampler_free(smpl);
        llama_free(ctx);
        outline = trim_text(strip_thinking_blocks(outline));
        if (looks_like_meta_or_compliance_text(outline)) return {};
        return outline;
    }

    std::vector<int> candidate_subset(const std::vector<int> & allowed, const std::vector<int> & generated_tokens,
                                      const std::string & generated_text, size_t limit) const {
        if (allowed.size() <= limit) return allowed;
        uint64_t h = 1469598103934665603ull;
        auto mix = [&](uint64_t v) {
            h ^= v;
            h *= 1099511628211ull;
        };
        mix(static_cast<uint64_t>(allowed.size()));
        mix(static_cast<uint64_t>(generated_tokens.size()));
        const size_t token_tail = std::min<size_t>(16, generated_tokens.size());
        for (size_t i = generated_tokens.size() - token_tail; i < generated_tokens.size(); ++i) {
            mix(static_cast<uint64_t>(static_cast<uint32_t>(generated_tokens[i])));
        }
        const size_t text_tail = std::min<size_t>(96, generated_text.size());
        for (size_t i = generated_text.size() - text_tail; i < generated_text.size(); ++i) {
            mix(static_cast<unsigned char>(generated_text[i]));
        }
        std::vector<int> out;
        out.reserve(limit + 96);
        std::unordered_set<int> seen;
        seen.reserve(limit + 96);
        size_t pos = static_cast<size_t>(h % allowed.size());
        size_t stride = static_cast<size_t>(((h >> 33) | 1ull) % allowed.size());
        if (stride == 0) stride = 1;
        const size_t max_walk = std::min(allowed.size(), limit * 8);
        for (size_t walked = 0; walked < max_walk && out.size() < limit; ++walked) {
            int id = allowed[pos];
            if (seen.insert(id).second) out.push_back(id);
            pos += stride;
            pos %= allowed.size();
        }
        for (size_t i = allowed.size() - std::min<size_t>(96, allowed.size()); i < allowed.size() && out.size() < limit + 96; ++i) {
            int id = allowed[i];
            if (seen.insert(id).second) out.push_back(id);
        }
        return out.empty() ? std::vector<int>(allowed.begin(), allowed.begin() + static_cast<std::ptrdiff_t>(std::min(limit, allowed.size()))) : out;
    }

    int sample_allowed_fast(llama_sampler * smpl, const TokenTable & table, const std::vector<int> & allowed, const float * logits,
                            const std::vector<int> & generated_tokens = {}, const std::string & generated_text = {}) const {
        std::vector<int> candidates = candidate_subset(allowed, generated_tokens, generated_text, 1536);
        std::vector<llama_token_data> data;
        data.reserve(candidates.size());
        for (int id : candidates) {
            auto tx = table.token_text.find(id);
            const std::string & piece = tx == table.token_text.end() ? std::string() : tx->second;
            if (!piece.empty() && contains_bracket(piece)) continue;
            if (!piece.empty() && disallowed_punctuation_transition(generated_text, piece)) continue;
            float score = apply_contiguous_repeat_penalty(logits[id], generated_tokens, id);
            data.push_back({id, score, 0.0f});
        }
        if (data.empty()) throw std::runtime_error("采样器没有可用的候选 token");
        llama_token_data_array cur{data.data(), data.size(), -1, false};
        llama_sampler_apply(smpl, &cur);
        if (cur.selected < 0 || static_cast<size_t>(cur.selected) >= data.size()) throw std::runtime_error("采样器未选出有效 token");
        int token = data[static_cast<size_t>(cur.selected)].id;
        llama_sampler_accept(smpl, token);
        return token;
    }

    bool should_insert_free_punctuation(const std::string & generated_text, size_t step) const {
        if (cjk_count(generated_text) < 14) return false;
        int since_punc = chars_since_punctuation(generated_text);
        if (since_punc < 20) return false;
        if (since_punc >= 44) return true;
        if (since_punc >= 34) return (step % 2) == 0;
        if (since_punc >= 26) return (step % 4) == 0;
        return false;
    }

    int sample_free_punctuation(llama_sampler * smpl, const TokenTable & table, const float * logits,
                                const std::vector<int> & generated_tokens, const std::string & generated_text) const {
        if (table.punctuation_tokens.empty()) return -1;
        const int since_break = chars_since_sentence_break(generated_text);
        const int since_punc = chars_since_punctuation(generated_text);
        std::vector<int> tail_tokens;
        std::string tail_text;
        build_stability_tail(vocab, generated_tokens, tail_tokens, tail_text);
        std::vector<ScoredToken> scored;
        scored.reserve(table.punctuation_tokens.size());
        for (int id : table.punctuation_tokens) {
            auto tx = table.token_text.find(id);
            std::string piece = tx == table.token_text.end() ? token_piece(vocab, id) : tx->second;
            if (disallowed_punctuation_transition(generated_text, piece)) continue;
            bool stable = false;
            try { stable = stable_append_tail(vocab, tail_text, tail_tokens, id, piece); } catch (const std::exception &) { stable = false; }
            if (!stable) continue;
            float score = logits[id];
            if (!contains_sentence_break(piece)) score += since_punc >= 26 ? 1.1f : 0.2f;
            if (contains_sentence_break(piece)) score += since_break >= 34 ? 2.2f : -0.4f;
            if (piece == "，") score += 0.8f;
            if (piece == "。") score += since_break >= 32 ? 1.4f : 0.2f;
            if (piece == "！" || piece == "？") score -= 0.7f;
            if (piece.size() > 6) score -= 1.0f;
            scored.push_back({id, score, piece});
        }
        if (scored.empty()) return -1;
        std::sort(scored.begin(), scored.end(), [](const ScoredToken & a, const ScoredToken & b) { return a.score > b.score; });
        std::vector<llama_token_data> data;
        data.reserve(24);
        for (size_t i = 0; i < scored.size() && data.size() < 24; ++i) {
            data.push_back({scored[i].token, scored[i].score, 0.0f});
        }
        llama_token_data_array cur{data.data(), data.size(), -1, false};
        llama_sampler_apply(smpl, &cur);
        int token = data[(cur.selected >= 0 && static_cast<size_t>(cur.selected) < data.size()) ? static_cast<size_t>(cur.selected) : 0].id;
        llama_sampler_accept(smpl, token);
        return token;
    }

    std::vector<ScoredToken> apply_top_p_min_k(const std::vector<ScoredToken> & scored,
                                               size_t min_limit,
                                               size_t max_limit) const {
        if (scored.empty()) return {};
        max_limit = std::min(max_limit, scored.size());
        min_limit = std::min(min_limit, max_limit);
        if (top_p >= 1.0f) return std::vector<ScoredToken>(scored.begin(), scored.begin() + max_limit);

        const float max_score = scored.front().score;
        double total_weight = 0.0;
        std::vector<double> weights;
        weights.reserve(max_limit);
        for (size_t idx = 0; idx < max_limit; ++idx) {
            double weight = std::exp(static_cast<double>(scored[idx].score - max_score));
            if (!std::isfinite(weight) || weight < 0.0) weight = 0.0;
            weights.push_back(weight);
            total_weight += weight;
        }
        if (total_weight <= 0.0) {
            size_t keep = std::max<size_t>(1, min_limit);
            return std::vector<ScoredToken>(scored.begin(), scored.begin() + keep);
        }

        double cumulative = 0.0;
        size_t keep = 0;
        while (keep < max_limit) {
            cumulative += weights[keep];
            ++keep;
            if (keep >= min_limit && cumulative / total_weight >= static_cast<double>(top_p)) break;
        }
        keep = std::max<size_t>(1, std::min(keep, max_limit));
        return std::vector<ScoredToken>(scored.begin(), scored.begin() + keep);
    }

    std::vector<ScoredToken> make_topk_code_candidates(const TokenTable & table, const float * logits,
                                                       const std::vector<int> & generated_tokens,
                                                       const std::string & generated_text,
                                                       size_t max_limit,
                                                       size_t min_limit) const {
        std::unordered_map<int, int> recent_counts;
        int start = std::max<int>(0, static_cast<int>(generated_tokens.size()) - 192);
        for (int i = start; i < static_cast<int>(generated_tokens.size()); ++i) {
            recent_counts[generated_tokens[static_cast<size_t>(i)]]++;
        }
        const int since_break = chars_since_sentence_break(generated_text);
        const int since_punc = chars_since_punctuation(generated_text);
        const float punc_ramp = punctuation_ramp(since_punc);
        std::vector<int> tail_tokens;
        std::string tail_text;
        build_stability_tail(vocab, generated_tokens, tail_tokens, tail_text);
        std::vector<ScoredToken> scored;
        scored.reserve(table.free_text_tokens.size());
        for (int id : table.free_text_tokens) {
            auto tx = table.token_text.find(id);
            std::string piece = tx == table.token_text.end() ? token_piece(vocab, id) : tx->second;
            if (piece.empty() || contains_bracket(piece)) continue;
            float score = logits[id];
            auto seen = recent_counts.find(id);
            if (seen != recent_counts.end()) {
                score = apply_repeat_penalty(score, std::min(1.85f, 1.12f + 0.08f * float(seen->second)));
            }
            score = apply_contiguous_repeat_penalty(score, generated_tokens, id);
            if (punc_ramp > 0.0f && contains_punctuation(piece)) {
                score += 0.55f * punc_ramp * (contains_sentence_break(piece) ? 1.9f : 1.0f);
            }
            int overdue = std::max(0, since_break - 56);
            if (overdue > 0 && !contains_sentence_break(piece)) {
                score = apply_repeat_penalty(score, std::min(4.25f, 1.0f + float(overdue) * 0.025f));
            }
            scored.push_back({id, score, piece});
        }
        std::sort(scored.begin(), scored.end(), [](const ScoredToken & a, const ScoredToken & b) { return a.score > b.score; });
        std::vector<ScoredToken> stable_scored;
        stable_scored.reserve(max_limit);
        size_t tested = 0;
        const size_t test_limit = std::min(scored.size(), std::max<size_t>(max_limit * 16, 256));
        for (const auto & s : scored) {
            if (tested++ >= test_limit && stable_scored.size() >= std::min<size_t>(max_limit, 8)) break;
            bool stable = false;
            try { stable = stable_append_tail(vocab, tail_text, tail_tokens, s.token, s.text); } catch (const std::exception &) { stable = false; }
            if (!stable) continue;
            stable_scored.push_back(s);
            if (stable_scored.size() >= max_limit) break;
        }
        if (stable_scored.empty()) {
            for (const auto & s : scored) {
                if (stable_scored.size() >= max_limit) break;
                stable_scored.push_back(s);
            }
        }
        return apply_top_p_min_k(stable_scored, min_limit, max_limit);
    }

    int select_topk_payload_token(const std::string & seed, size_t payload_pos, int digit,
                                  const TokenTable & table, const float * logits,
                                  const std::vector<int> & generated_tokens,
                                  const std::string & generated_text,
                                  const std::vector<std::string> & reject_phrases) const {
        if (digit < 0 || digit >= radix) throw std::runtime_error("top-k 载荷位超出当前进制范围");
        const size_t min_limits[] = {
            static_cast<size_t>(std::max(min_k, radix * 16)),
            static_cast<size_t>(std::max(min_k * 2, radix * 32)),
            static_cast<size_t>(std::max(min_k * 4, radix * 64)),
        };
        const size_t max_limits[] = {
            static_cast<size_t>(std::max(top_k, static_cast<int>(min_limits[0]))),
            static_cast<size_t>(std::max(top_k * 2, static_cast<int>(min_limits[1]))),
            static_cast<size_t>(std::max(top_k * 4, static_cast<int>(min_limits[2]))),
        };
        for (size_t attempt = 0; attempt < sizeof(max_limits) / sizeof(max_limits[0]); ++attempt) {
            auto candidates = make_topk_code_candidates(table, logits, generated_tokens, generated_text,
                                                        max_limits[attempt], min_limits[attempt]);
            for (const auto & c : candidates) {
                if (topk_digit_for_token(seed, payload_pos, c.token, radix) != digit) continue;
                if (disallowed_article_continuation(generated_text, c.text, reject_phrases)) continue;
                return c.token;
            }
        }
        throw std::runtime_error("top-k 编码器在当前模型候选集中找不到匹配载荷位的 token");
    }

    std::string generate_topk_once(const std::string & seed, const std::vector<int> & digits,
                                   const std::string & prompt,
                                   uint32_t sample_seed,
                                   int tail_tokens_override = -1,
                                   const std::function<void(const std::string &, size_t, size_t, double)> & progress_cb = {}) {
        TokenTable & table = table_for_seed(seed);
        auto prompt_tokens = tokenize(vocab, prompt, false, true);
        if (prompt_tokens.empty()) throw std::runtime_error("top-k 生成提示词无法被 tokenizer 编码");
        const int requested_tail = tail_tokens_override >= 0 ? tail_tokens_override : free_tail_tokens;
        const int tail_budget = std::max(0, std::min(requested_tail, max_tail_tokens));
        const int min_tail = std::min(std::max(0, min_tail_tokens), tail_budget);
        const int max_new = static_cast<int>(digits.size()) + tail_budget;
        llama_context_params cp = llama_context_default_params();
        cp.n_ctx = static_cast<uint32_t>(std::max(n_ctx, static_cast<int>(prompt_tokens.size()) + max_new + 64));
        cp.n_batch = static_cast<uint32_t>(std::max<int>(batch_min_tokens, static_cast<int>(prompt_tokens.size())));
        cp.n_ubatch = static_cast<uint32_t>(batch_min_tokens);
        cp.n_threads = n_threads;
        cp.n_threads_batch = n_threads;
        cp.no_perf = true;
        llama_context * ctx = llama_init_from_model(model, cp);
        if (!ctx) throw std::runtime_error("无法创建 top-k 生成上下文");
        llama_memory_t mem = llama_get_memory(ctx);
        const bool can_shift_context = mem && llama_memory_can_shift(mem);
        const llama_pos keep_prompt_tokens = static_cast<llama_pos>(
            std::min<size_t>(prompt_tokens.size(), static_cast<size_t>(std::max(0, context_keep_tokens))));
        const llama_pos rolling_tokens = static_cast<llama_pos>(std::max(0, rolling_context_tokens));
        llama_sampler * smpl = make_sampler(sample_seed);
        const std::vector<std::string> reject_phrases =
            prompt_dir.empty() ? std::vector<std::string>() :
            read_line_list_file(fs::path(prompt_dir) / "reject_phrases.txt");
        std::string generated_text;
        std::vector<int> generated_tokens;
        auto progress_start = std::chrono::steady_clock::now();
        auto last_progress = std::chrono::steady_clock::now() - std::chrono::milliseconds(1000);
        auto maybe_progress = [&](bool force, size_t done) {
            if (!progress_cb) return;
            auto now = std::chrono::steady_clock::now();
            if (!force && now - last_progress < std::chrono::milliseconds(progress_interval_ms)) return;
            last_progress = now;
            double elapsed = std::chrono::duration<double>(now - progress_start).count();
            double tps = elapsed > 0.05 ? static_cast<double>(generated_tokens.size()) / elapsed : 0.0;
            progress_cb(generated_text, std::min(done, digits.size()), std::max<size_t>(1, digits.size()), tps);
        };
        auto maybe_shift_context = [&]() {
            if (!can_shift_context || keep_prompt_tokens <= 0) return;
            llama_pos pos_max = llama_memory_seq_pos_max(mem, 0);
            if (pos_max < 0) return;
            const llama_pos used = pos_max + 1;
            const llama_pos target = keep_prompt_tokens + rolling_tokens;
            if (used <= target + static_cast<llama_pos>(std::max(0, context_shift_margin))) return;
            const llama_pos discard = used - target;
            if (discard <= 0) return;
            if (llama_memory_seq_rm(mem, 0, keep_prompt_tokens, keep_prompt_tokens + discard)) {
                llama_memory_seq_add(mem, 0, keep_prompt_tokens + discard, -1, -discard);
            }
        };
        try {
            maybe_progress(true, 0);
            llama_batch batch = llama_batch_get_one(prompt_tokens.data(), static_cast<int32_t>(prompt_tokens.size()));
            if (llama_decode(ctx, batch) != 0) throw std::runtime_error("top-k 生成提示词前向计算失败");
            for (size_t i = 0; i < digits.size(); ++i) {
                const float * logits = llama_get_logits_ith(ctx, -1);
                if (!logits) throw std::runtime_error("top-k 生成时无法读取模型 logits");
                int token = select_topk_payload_token(seed, i, digits[i], table, logits, generated_tokens, generated_text,
                                                      reject_phrases);
                llama_sampler_accept(smpl, token);
                std::string piece = token_piece(vocab, token);
                generated_tokens.push_back(token);
                generated_text += piece;
                const bool should_self_check =
                    (self_check_initial_digits > 0 && i < static_cast<size_t>(self_check_initial_digits)) ||
                    (self_check_interval_digits > 0 && (i % static_cast<size_t>(self_check_interval_digits)) ==
                        static_cast<size_t>(self_check_interval_digits - 1)) ||
                    i + 1 == digits.size();
                if (should_self_check &&
                    (looks_like_meta_or_compliance_text(generated_text.size() > static_cast<size_t>(self_check_tail_chars) ? generated_text.substr(generated_text.size() - static_cast<size_t>(self_check_tail_chars)) : generated_text) ||
                     looks_like_instruction_reply(generated_text.size() > static_cast<size_t>(self_check_tail_chars) ? generated_text.substr(generated_text.size() - static_cast<size_t>(self_check_tail_chars)) : generated_text, prompt_dir))) {
                    throw std::runtime_error("模型生成了元说明或合规检查文本，已拒绝该候选");
                }
                if (contains_bracket(piece)) throw std::runtime_error("模型生成了括号类 token，已拒绝该候选");
                maybe_progress(false, i + 1);
                maybe_shift_context();
                batch = llama_batch_get_one(&generated_tokens.back(), 1);
                if (llama_decode(ctx, batch) != 0) throw std::runtime_error("top-k 载荷 token 前向计算失败");
            }
            for (int tail = 0; tail < tail_budget; ++tail) {
                const float * logits = llama_get_logits_ith(ctx, -1);
                if (!logits) throw std::runtime_error("top-k 收尾生成时无法读取模型 logits");
                int token = should_insert_free_punctuation(generated_text, static_cast<size_t>(tail))
                    ? sample_free_punctuation(smpl, table, logits, generated_tokens, generated_text)
                    : sample_allowed_fast(smpl, table, table.free_text_tokens, logits, generated_tokens, generated_text);
                if (token < 0) token = sample_allowed_fast(smpl, table, table.free_text_tokens, logits, generated_tokens, generated_text);
                std::string piece = token_piece(vocab, token);
                if (contains_bracket(piece)) break;
                generated_tokens.push_back(token);
                generated_text += piece;
                maybe_progress(false, digits.size());
                if (tail >= min_tail && contains_sentence_break(piece)) break;
                maybe_shift_context();
                batch = llama_batch_get_one(&generated_tokens.back(), 1);
                if (llama_decode(ctx, batch) != 0) break;
            }
        } catch (...) {
            llama_sampler_free(smpl);
            llama_free(ctx);
            throw;
        }
        llama_sampler_free(smpl);
        llama_free(ctx);
        if (progress_cb) {
            auto now = std::chrono::steady_clock::now();
            double elapsed = std::chrono::duration<double>(now - progress_start).count();
            double tps = elapsed > 0.05 ? static_cast<double>(generated_tokens.size()) / elapsed : 0.0;
            progress_cb(generated_text, digits.size(), std::max<size_t>(1, digits.size()), tps);
        }
        return generated_text;
    }

    std::vector<int> text_to_topk_digits(const std::string & seed, const std::string & text, int radix) {
        auto text_tokens = tokenize(vocab, text, false, false);
        if (text_tokens.empty()) throw std::runtime_error("载体文本无法被 tokenizer 切分出有效 token");
        std::vector<int> digits;
        digits.reserve(text_tokens.size());
        for (int token : text_tokens) {
            digits.push_back(topk_digit_for_token(seed, digits.size(), token, radix));
        }
        return digits;
    }

    std::string encode_payload(const std::string & seed, const std::vector<uint8_t> & payload, const std::string & topic,
                               const std::string & prompt_template_name,
                               int tail_tokens_override = -1,
                               const std::string & custom_prompt_template = std::string(),
                               float temperature_override = -1.0f,
                               float top_p_override = -1.0f,
                               int redundancy_override = -1,
                               std::string * outline_used = nullptr,
                               const std::function<void(const std::string &, size_t, size_t, double)> & progress_cb = {}) {
        struct SamplingOverride {
            LlamaPayloadWorker & worker;
            float old_temperature;
            float old_top_p;
            SamplingOverride(LlamaPayloadWorker & w, float temp_value, float top_p_value)
                : worker(w), old_temperature(w.temperature), old_top_p(w.top_p) {
                if (temp_value > 0.0f) worker.temperature = temp_value;
                if (top_p_value > 0.0f && top_p_value <= 1.0f) worker.top_p = top_p_value;
            }
            ~SamplingOverride() {
                worker.temperature = old_temperature;
                worker.top_p = old_top_p;
            }
        } sampling_override(*this, temperature_override, top_p_override);
        TokenTable & table = table_for_seed(seed);
        if (!is_power_of_two_radix(table.radix)) throw std::runtime_error("top-k 载荷进制必须是 2、4、8 或 16");
        int effective_redundancy = redundancy_override >= 0 ? redundancy_override : redundancy_level;
        if (effective_redundancy < 0 || effective_redundancy > 3) effective_redundancy = 0;
        auto digits = encode_payload_to_digits(payload, table.radix, effective_redundancy);
        const int requested_tail = tail_tokens_override >= 0 ? tail_tokens_override : free_tail_tokens;
        const int tail_budget = std::max(0, std::min(requested_tail, max_tail_tokens));
        PromptLengthBounds bounds = prompt_length_bounds(digits.size(), tail_budget, length_config);
        uint32_t base_seed = 0;
        auto digest = topk_generation_seed_digest(seed, payload);
        for (int i = 0; i < 4; ++i) base_seed = (base_seed << 8) | digest[static_cast<size_t>(i)];
        std::string outline_text;
        if (outline_enabled && outline_tokens > 0) {
            std::string outline_prompt = build_outline_prompt(topic, prompt_template_name, bounds, prompt_dir);
            outline_text = generate_outline_once(outline_prompt, base_seed ^ 0x9e3779b9u);
        }
        if (outline_used) *outline_used = outline_text;
        const std::string prompt = build_topk_prompt(topic, digits.size(), tail_budget, length_config,
                                                     prompt_dir, prompt_template_name, custom_prompt_template, outline_text);
        std::string last_error;
        for (int attempt = 1; attempt <= encode_attempts; ++attempt) {
            std::string text;
            try {
                text = generate_topk_once(seed, digits, prompt,
                                          base_seed + static_cast<uint32_t>(attempt * retry_seed_stride),
                                          tail_tokens_override, progress_cb);
                auto recovered_digits = text_to_topk_digits(seed, text, table.radix);
                auto recovered = decode_digits_to_payload(recovered_digits, table.radix);
                if (looks_like_instruction_reply(text, prompt_dir)) {
                    last_error = "自检拒绝：模型输出像是在请求继续指令";
                    continue;
                }
                if (contains_bracket(text)) {
                    last_error = "自检拒绝：载体文本包含括号类 token";
                    continue;
                }
                if (recovered == payload) return text;

                last_error = "自检拒绝：载体文本恢复出的二进制载荷与原始载荷不一致";
            } catch (const std::exception & e) {
                last_error = e.what();
            }
        }
        throw std::runtime_error("top-k 载体文本生成失败，无法通过本地可解码性自检：" + last_error);
    }

    std::vector<int> text_to_topk_digits_for_vocab(const llama_vocab * decode_vocab,
                                                   const std::string & seed,
                                                   const std::string & text) const {
        auto text_tokens = tokenize(decode_vocab, text, false, false);
        if (text_tokens.empty()) throw std::runtime_error("载体文本无法被 tokenizer 切分出有效 token");
        std::vector<int> digits;
        digits.reserve(text_tokens.size());
        for (int token : text_tokens) {
            digits.push_back(topk_digit_for_token(seed, digits.size(), token, radix));
        }
        return digits;
    }

    std::vector<uint8_t> decode_payload_for_vocab(const llama_vocab * decode_vocab,
                                                  const std::string & seed,
                                                  const std::string & text) const {
        auto digits = text_to_topk_digits_for_vocab(decode_vocab, seed, text);
        return decode_digits_to_payload(digits, radix);
    }

    std::vector<uint8_t> decode_payload(const std::string & seed, const std::string & text) {
        return decode_payload_for_vocab(vocab, seed, text);
    }

    std::vector<DecodeCandidate> decode_payload_multi(const std::string & seed,
                                                      const std::string & text,
                                                      const std::string & preferred_tokenizer) {
        std::vector<std::string> tokenizers = ordered_decode_tokenizers(preferred_tokenizer);
        if (tokenizers.empty()) append_unique_string(tokenizers, "model");
        std::vector<DecodeCandidate> candidates;
        std::mutex candidates_lock;
        std::vector<std::future<void>> jobs;
        size_t next = 0;
        int limit = std::max(1, decode_threads);
        auto launch_one = [&](const std::string & id) {
            return std::async(std::launch::async, [&, id]() {
                try {
                    const llama_vocab * decode_vocab = vocab_for_tokenizer(id);
                    DecodeCandidate candidate;
                    candidate.tokenizer_id = id;
                    candidate.payload = decode_payload_for_vocab(decode_vocab, seed, text);
                    std::lock_guard<std::mutex> guard(candidates_lock);
                    bool duplicate = false;
                    for (const auto & existing : candidates) {
                        if (existing.payload == candidate.payload) {
                            duplicate = true;
                            break;
                        }
                    }
                    if (!duplicate) candidates.push_back(std::move(candidate));
                } catch (const std::exception &) {
                    /* Wrong tokenizer candidates are expected; crypto authentication decides the winner. */
                }
            });
        };
        while (next < tokenizers.size() || !jobs.empty()) {
            while (next < tokenizers.size() && jobs.size() < static_cast<size_t>(limit)) {
                jobs.push_back(launch_one(tokenizers[next++]));
            }
            if (!jobs.empty()) {
                jobs.front().get();
                jobs.erase(jobs.begin());
            }
        }
        if (candidates.empty()) {
            throw std::runtime_error("no configured tokenizer decoded a framed top-k payload");
        }
        return candidates;
    }
};

static fs::path current_path_noexcept() {
    std::error_code ec;
    fs::path cwd = fs::current_path(ec);
    return ec ? fs::path(".") : cwd;
}

static bool path_exists_noexcept(const fs::path & path) {
    std::error_code ec;
    bool ok = fs::exists(path, ec);
    return ok && !ec;
}

static bool dir_exists_noexcept(const fs::path & path) {
    std::error_code ec;
    bool ok = fs::is_directory(path, ec);
    return ok && !ec;
}

static fs::path exe_dir_path(int argc, char ** argv) {
    if (argc <= 0 || !argv || !argv[0] || !argv[0][0]) return current_path_noexcept();
    std::error_code ec;
    fs::path abs = fs::absolute(fs::path(argv[0]), ec);
    return ec ? current_path_noexcept() : abs.parent_path();
}

static std::string default_model_path(int argc, char ** argv) {
    std::vector<fs::path> candidates;
    fs::path cwd = current_path_noexcept();
    fs::path exe_dir = exe_dir_path(argc, argv);
    const char * names[] = {
        "base_model.gguf",
        "Qwen3-4B-Instruct-2507-Q4_K_M.gguf",
        "qwen3-4b-instruct-2507-q4_k_m.gguf",
        "Qwen3.5-2B-Q4_K_M.gguf",
        "qwen3.5-2b-q4_k_m.gguf",
    };
    auto add_dir = [&](const fs::path & dir) {
        for (const char * name : names) candidates.push_back(dir / name);
    };
    add_dir(cwd / "models");
    add_dir(cwd);
    add_dir(cwd / ".." / "models");
    add_dir(cwd / "..");
    add_dir(cwd / ".." / ".." / "models");
    add_dir(cwd / ".." / "..");
    add_dir(exe_dir / "models");
    add_dir(exe_dir);
    add_dir(exe_dir / ".." / "models");
    add_dir(exe_dir / "..");
    add_dir(exe_dir / ".." / ".." / "models");
    add_dir(exe_dir / ".." / "..");
    for (const auto & p : candidates) {
        if (path_exists_noexcept(p)) {
            std::error_code ec;
            fs::path abs = fs::absolute(p, ec);
            return (ec ? p : abs).string();
        }
    }
    throw std::runtime_error("未找到默认 GGUF 模型文件 base_model.gguf。请把模型放在 models 目录，或使用 --model 指定。");
}

static std::string default_adapter_path(char ** argv) {
    const char * env_path = std::getenv("CIA_PAYLOAD_ADAPTER");
    if (env_path && env_path[0]) {
        std::string p = env_path;
        if (ascii_lower(p) == "none" || ascii_lower(p) == "off" || ascii_lower(p) == "disabled") return "";
        if (path_exists_noexcept(fs::path(p))) {
            std::error_code ec;
            fs::path abs = fs::absolute(fs::path(p), ec);
            return (ec ? fs::path(p) : abs).string();
        }
        return p;
    }
    (void) argv;
    return "";
}

static std::string default_prompt_dir(int argc, char ** argv) {
    const char * env_path = std::getenv("CIA_PROMPT_DIR");
    if (env_path && env_path[0]) return env_path;

    fs::path cwd = current_path_noexcept();
    fs::path exe_dir = exe_dir_path(argc, argv);
    std::vector<fs::path> candidates = {
        cwd / "prompts",
        exe_dir / "prompts",
        cwd / "tools" / "payload_watermark" / "prompts",
        exe_dir / ".." / ".." / "tools" / "payload_watermark" / "prompts",
    };
    for (const auto & candidate : candidates) {
        if (dir_exists_noexcept(candidate)) {
            std::error_code ec;
            fs::path abs = fs::absolute(candidate, ec);
            return (ec ? candidate : abs).string();
        }
    }
    return (cwd / "prompts").string();
}

static std::string default_tokenizer_dir(int argc, char ** argv) {
    const char * env_path = std::getenv("CIA_TOKENIZER_DIR");
    if (env_path && env_path[0]) return env_path;

    fs::path cwd = current_path_noexcept();
    fs::path exe_dir = exe_dir_path(argc, argv);
    std::vector<fs::path> candidates = {
        cwd / "tokenizers",
        exe_dir / "tokenizers",
        cwd / "tools" / "payload_watermark" / "tokenizers",
        exe_dir / ".." / ".." / "tools" / "payload_watermark" / "tokenizers",
    };
    for (const auto & candidate : candidates) {
        if (dir_exists_noexcept(candidate)) {
            std::error_code ec;
            fs::path abs = fs::absolute(candidate, ec);
            return (ec ? candidate : abs).string();
        }
    }
    return (cwd / "tokenizers").string();
}

static std::string resolve_directory_path(const std::string & configured_dir, int argc, char ** argv) {
    if (configured_dir.empty()) return configured_dir;
    fs::path configured_path(configured_dir);
    if (dir_exists_noexcept(configured_path)) {
        std::error_code ec;
        fs::path abs = fs::absolute(configured_path, ec);
        return (ec ? configured_path : abs).string();
    }
    fs::path cwd = current_path_noexcept();
    fs::path exe_dir = exe_dir_path(argc, argv);
    std::vector<fs::path> candidates = {
        cwd / configured_path,
        exe_dir / configured_path,
        cwd / "tools" / "payload_watermark" / configured_path,
        exe_dir / ".." / ".." / "tools" / "payload_watermark" / configured_path,
    };
    for (const auto & candidate : candidates) {
        if (dir_exists_noexcept(candidate)) {
            std::error_code ec;
            fs::path abs = fs::absolute(candidate, ec);
            return (ec ? candidate : abs).string();
        }
    }
    return configured_dir;
}

static void apply_tokenizer_manifest(LlamaPayloadWorker & worker) {
    if (worker.tokenizer_dir.empty()) return;
    std::string text;
    fs::path manifest = fs::path(worker.tokenizer_dir) / "manifest.txt";
    if (!read_utf8_template_file(manifest, text)) return;
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t end = text.find('\n', pos);
        std::string line = trim_ascii(end == std::string::npos ? text.substr(pos) : text.substr(pos, end - pos));
        if (!line.empty() && line[0] != '#' && line[0] != ';') {
            size_t eq = line.find('=');
            if (eq != std::string::npos) {
                std::string id = trim_ascii(line.substr(0, eq));
                std::string path = trim_ascii(line.substr(eq + 1));
                if (!id.empty() && !path.empty() && worker.tokenizer_paths.find(id) == worker.tokenizer_paths.end()) {
                    fs::path configured(path);
                    worker.tokenizer_paths[id] = configured.is_absolute() ? configured.string() : (fs::path(worker.tokenizer_dir) / configured).string();
                }
            }
        }
        if (end == std::string::npos) break;
        pos = end + 1;
    }
}

static std::string default_worker_config_path(int argc, char ** argv) {
    const char * env_path = std::getenv("CIA_WORKER_CONFIG");
    if (env_path && env_path[0]) return env_path;

    fs::path cwd = current_path_noexcept();
    fs::path exe_dir = exe_dir_path(argc, argv);
    std::vector<fs::path> candidates = {
        cwd / "worker_config.txt",
        exe_dir / "worker_config.txt",
        cwd / "tools" / "payload_watermark" / "worker_config.txt",
        exe_dir / ".." / ".." / "tools" / "payload_watermark" / "worker_config.txt",
    };
    for (const auto & candidate : candidates) {
        if (path_exists_noexcept(candidate)) {
            std::error_code ec;
            fs::path abs = fs::absolute(candidate, ec);
            return (ec ? candidate : abs).string();
        }
    }
    return "";
}

static std::string resolve_model_path(const std::string & configured_model, int argc, char ** argv) {
    if (configured_model.empty()) return default_model_path(argc, argv);
    fs::path configured_path(configured_model);
    if (path_exists_noexcept(configured_path)) {
        std::error_code ec;
        fs::path abs = fs::absolute(configured_path, ec);
        return (ec ? configured_path : abs).string();
    }

    fs::path cwd = current_path_noexcept();
    fs::path exe_dir = exe_dir_path(argc, argv);
    std::vector<fs::path> candidates = {
        cwd / "models" / configured_path,
        cwd / configured_path,
        cwd / ".." / "models" / configured_path,
        cwd / ".." / configured_path,
        cwd / ".." / ".." / "models" / configured_path,
        cwd / ".." / ".." / configured_path,
        exe_dir / "models" / configured_path,
        exe_dir / configured_path,
        exe_dir / ".." / "models" / configured_path,
        exe_dir / ".." / configured_path,
        exe_dir / ".." / ".." / "models" / configured_path,
        exe_dir / ".." / ".." / configured_path,
    };
    for (const auto & candidate : candidates) {
        if (path_exists_noexcept(candidate)) {
            std::error_code ec;
            fs::path abs = fs::absolute(candidate, ec);
            return (ec ? candidate : abs).string();
        }
    }
    return configured_model;
}

static void apply_worker_config_key(LlamaPayloadWorker & worker, const std::string & key, const std::string & value) {
    if (key == "model") worker.model_path = value;
    else if (key == "adapter") worker.adapter_path = value;
    else if (key == "radix") worker.radix = std::stoi(value);
    else if (key == "gpu_layers") worker.n_gpu_layers = std::stoi(value);
    else if (key == "ctx") worker.n_ctx = std::stoi(value);
    else if (key == "threads") worker.n_threads = std::stoi(value);
    else if (key == "free_tail_tokens") worker.free_tail_tokens = std::stoi(value);
    else if (key == "min_tail_tokens") worker.min_tail_tokens = std::stoi(value);
    else if (key == "max_tail_tokens") worker.max_tail_tokens = std::stoi(value);
    else if (key == "temperature") worker.temperature = std::stof(value);
    else if (key == "top_p") worker.top_p = std::stof(value);
    else if (key == "top_k") worker.top_k = std::stoi(value);
    else if (key == "min_k") worker.min_k = std::stoi(value);
    else if (key == "redundancy_level") worker.redundancy_level = std::stoi(value);
    else if (key == "length_min_chars") worker.length_config.min_chars_floor = std::stoi(value);
    else if (key == "length_payload_multiplier") worker.length_config.payload_digit_multiplier = std::stof(value);
    else if (key == "length_upper_tail_extra_chars") worker.length_config.upper_tail_extra_chars = std::stoi(value);
    else if (key == "length_upper_lower_multiplier") worker.length_config.upper_lower_multiplier = std::stof(value);
    else if (key == "length_upper_extra_chars") worker.length_config.upper_extra_chars = std::stoi(value);
    else if (key == "encode_attempts") worker.encode_attempts = std::stoi(value);
    else if (key == "retry_seed_stride") worker.retry_seed_stride = std::stoi(value);
    else if (key == "progress_interval_ms") worker.progress_interval_ms = std::stoi(value);
    else if (key == "batch_min_tokens") worker.batch_min_tokens = std::stoi(value);
    else if (key == "context_keep_tokens") worker.context_keep_tokens = std::stoi(value);
    else if (key == "rolling_context_tokens") worker.rolling_context_tokens = std::stoi(value);
    else if (key == "context_shift_margin") worker.context_shift_margin = std::stoi(value);
    else if (key == "self_check_initial_digits") worker.self_check_initial_digits = std::stoi(value);
    else if (key == "self_check_interval_digits") worker.self_check_interval_digits = std::stoi(value);
    else if (key == "self_check_tail_chars") worker.self_check_tail_chars = std::stoi(value);
    else if (key == "outline_enabled") worker.outline_enabled = std::stoi(value) != 0;
    else if (key == "outline_tokens") worker.outline_tokens = std::stoi(value);
    else if (key == "outline_min_chars") worker.outline_min_chars = std::stoi(value);
    else if (key == "outline_context_extra_tokens") worker.outline_context_extra_tokens = std::stoi(value);
    else if (key == "backend") worker.backend_preference = value;
    else if (key == "prompt_dir") worker.prompt_dir = value;
    else if (key == "tokenizer_id") worker.tokenizer_id = value;
    else if (key == "tokenizer_dir") worker.tokenizer_dir = value;
    else if (key == "decode_tokenizers") worker.decode_tokenizers = split_csv_list(value);
    else if (key == "decode_threads") worker.decode_threads = std::stoi(value);
    else if (key.rfind("tokenizer.", 0) == 0 && key.size() > 10) worker.tokenizer_paths[key.substr(10)] = value;
}

static void apply_worker_config_file(LlamaPayloadWorker & worker, const std::string & config_path) {
    if (config_path.empty()) return;
    std::string text;
    if (!read_utf8_template_file(fs::path(config_path), text)) return;
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t end = text.find('\n', pos);
        std::string line = trim_ascii(end == std::string::npos ? text.substr(pos) : text.substr(pos, end - pos));
        if (!line.empty() && line[0] != '#' && line[0] != ';') {
            size_t eq = line.find('=');
            if (eq != std::string::npos) {
                std::string key = trim_ascii(line.substr(0, eq));
                std::string value = trim_ascii(line.substr(eq + 1));
                if (!key.empty() && !value.empty()) apply_worker_config_key(worker, key, value);
            }
        }
        if (end == std::string::npos) break;
        pos = end + 1;
    }
}

static void emit_json(const std::string & line) {
    std::cout << line << "\n";
    std::cout.flush();
}

static std::string ok_response(int id, const std::string & body) {
    return "{\"id\":" + std::to_string(id) + ",\"ok\":true" + body + "}";
}

static std::string err_response(int id, const std::string & error) {
    return "{\"id\":" + std::to_string(id) + ",\"ok\":false,\"error\":\"" + json_escape(error) + "\"}";
}

int main(int argc, char ** argv) {
    std::setlocale(LC_ALL, "C.UTF-8");
    LlamaPayloadWorker worker;
    try {
        worker.adapter_path = default_adapter_path(argv);
        worker.prompt_dir = default_prompt_dir(argc, argv);
        worker.tokenizer_dir = default_tokenizer_dir(argc, argv);
        std::string config_path = default_worker_config_path(argc, argv);
        for (int i = 1; i < argc; ++i) {
            std::string a = argv[i];
            if (a == "--config" && i + 1 < argc) config_path = argv[++i];
        }
        apply_worker_config_file(worker, config_path);
        for (int i = 1; i < argc; ++i) {
            std::string a = argv[i];
            auto need = [&](const char * name) -> const char * {
                if (i + 1 >= argc) throw std::runtime_error(std::string("缺少命令行参数值：") + name);
                return argv[++i];
            };
            if (a == "--model") worker.model_path = need("--model");
            else if (a == "--adapter") worker.adapter_path = need("--adapter");
            else if (a == "--radix") worker.radix = std::stoi(need("--radix"));
            else if (a == "--gpu-layers") worker.n_gpu_layers = std::stoi(need("--gpu-layers"));
            else if (a == "--ctx") worker.n_ctx = std::stoi(need("--ctx"));
            else if (a == "--threads") worker.n_threads = std::stoi(need("--threads"));
            else if (a == "--free-tail-tokens") worker.free_tail_tokens = std::stoi(need("--free-tail-tokens"));
            else if (a == "--max-tail-tokens") worker.max_tail_tokens = std::stoi(need("--max-tail-tokens"));
            else if (a == "--temperature") worker.temperature = std::stof(need("--temperature"));
            else if (a == "--top-p") worker.top_p = std::stof(need("--top-p"));
            else if (a == "--top-k") worker.top_k = std::stoi(need("--top-k"));
            else if (a == "--min-k") worker.min_k = std::stoi(need("--min-k"));
            else if (a == "--redundancy-level") worker.redundancy_level = std::stoi(need("--redundancy-level"));
            else if (a == "--outline-enabled") worker.outline_enabled = std::stoi(need("--outline-enabled")) != 0;
            else if (a == "--outline-tokens") worker.outline_tokens = std::stoi(need("--outline-tokens"));
            else if (a == "--prompt-dir") worker.prompt_dir = need("--prompt-dir");
            else if (a == "--tokenizer-id") worker.tokenizer_id = need("--tokenizer-id");
            else if (a == "--tokenizer-dir") worker.tokenizer_dir = need("--tokenizer-dir");
            else if (a == "--decode-tokenizers") worker.decode_tokenizers = split_csv_list(need("--decode-tokenizers"));
            else if (a == "--config") (void) need("--config");
            else if (a == "--backend") worker.backend_preference = need("--backend");
            else throw std::runtime_error("未知命令行参数：" + a);
        }
        worker.model_path = resolve_model_path(worker.model_path, argc, argv);
        worker.tokenizer_dir = resolve_directory_path(worker.tokenizer_dir, argc, argv);
        apply_tokenizer_manifest(worker);
        if (!is_power_of_two_radix(worker.radix)) throw std::runtime_error("top-k 载荷进制必须是 2、4、8 或 16");
        if (worker.n_ctx < 512 || worker.n_threads <= 0 || worker.top_k <= 0 || worker.min_k <= 0) throw std::runtime_error("worker 运行参数不合法");
        if (worker.temperature <= 0.0f || worker.top_p <= 0.0f || worker.top_p > 1.0f) throw std::runtime_error("worker 采样参数不合法");
        if (worker.redundancy_level < 0 || worker.redundancy_level > 3) throw std::runtime_error("worker redundancy level is invalid");
        if (worker.free_tail_tokens < 0 || worker.min_tail_tokens < 0 || worker.max_tail_tokens < 0 ||
            worker.min_tail_tokens > worker.max_tail_tokens) throw std::runtime_error("worker 收尾参数不合法");
        if (worker.length_config.min_chars_floor < 0 ||
            worker.length_config.payload_digit_multiplier <= 0.0f ||
            worker.length_config.upper_tail_extra_chars < 0 ||
            worker.length_config.upper_lower_multiplier <= 0.0f ||
            worker.length_config.upper_extra_chars < 0) throw std::runtime_error("worker 字数提示参数不合法");
        if (worker.encode_attempts <= 0 || worker.encode_attempts > 50 || worker.retry_seed_stride <= 0) throw std::runtime_error("worker 重试参数不合法");
        if (worker.progress_interval_ms < 50 || worker.batch_min_tokens <= 0 ||
            worker.context_keep_tokens < 0 || worker.rolling_context_tokens < 0 ||
            worker.context_shift_margin < 0) throw std::runtime_error("worker 上下文参数不合法");
        if (worker.self_check_initial_digits < 0 || worker.self_check_interval_digits < 0 ||
            worker.self_check_tail_chars <= 0) throw std::runtime_error("worker 自检参数不合法");
        if (worker.outline_tokens < 0 || worker.outline_tokens > 1024 ||
            worker.outline_min_chars < 0 || worker.outline_context_extra_tokens < 0) throw std::runtime_error("worker 提纲参数不合法");
        if (worker.decode_threads <= 0 || worker.decode_threads > 32) throw std::runtime_error("worker tokenizer decode thread count is invalid");
        worker.load();
        emit_json("{\"type\":\"ready\",\"ok\":true,\"backend\":\"llama.cpp\",\"backend_detail\":\"" + json_escape(worker.backend_used) + "\",\"model\":\"" + json_escape(worker.model_path) + "\",\"adapter\":\"" + json_escape(worker.adapter_path) + "\",\"adapter_loaded\":" + std::string(worker.adapter ? "true" : "false") + ",\"radix\":" + std::to_string(worker.radix) + ",\"top_p\":" + std::to_string(worker.top_p) + ",\"min_k\":" + std::to_string(worker.min_k) + ",\"prompt_dir\":\"" + json_escape(worker.prompt_dir) + "\",\"tokenizer_id\":\"" + json_escape(worker.tokenizer_id) + "\"}");
    } catch (const std::exception & e) {
        emit_json("{\"type\":\"ready\",\"ok\":false,\"error\":\"" + json_escape(e.what()) + "\"}");
        return 1;
    }

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        int id = 0;
        if (!json_get_int_strict(line, "id", id)) {
            emit_json(err_response(0, "worker 请求缺少有效 id 字段"));
            continue;
        }
        try {
            std::string cmd;
            if (!json_get_string(line, "cmd", cmd) || cmd.empty()) throw std::runtime_error("worker 请求缺少 cmd 字段");
            if (cmd == "shutdown") {
                emit_json(ok_response(id, ",\"bye\":true"));
                break;
            } else if (cmd == "encode") {
                std::string payload_path, out_path;
                if (!json_get_string(line, "payload", payload_path) || !json_get_string(line, "out", out_path)) throw std::runtime_error("top-k 编码请求缺少 payload 或 out 字段");
                std::string topic = "日常生活";
                std::string topic_path;
                if (json_get_string(line, "topic_file", topic_path)) topic = read_text(topic_path);
                else json_get_string(line, "topic", topic);
                std::string prompt_template_name = "default";
                json_get_string(line, "prompt_template", prompt_template_name);
                std::string custom_prompt_template;
                std::string prompt_file_path;
                if (json_get_string(line, "prompt_file", prompt_file_path) && !prompt_file_path.empty()) {
                    custom_prompt_template = read_text(prompt_file_path);
                }
                std::string seed;
                if (!json_get_string(line, "seed", seed) || seed.empty()) throw std::runtime_error("top-k 编码请求缺少 seed 字段");
                int tail_tokens = -1;
                if (json_has_key(line, "tail_tokens") && !json_get_int_strict(line, "tail_tokens", tail_tokens)) throw std::runtime_error("top-k 编码请求 tail_tokens 字段无效");
                double request_temperature = -1.0;
                double request_top_p = -1.0;
                if (json_has_key(line, "temperature") && !json_get_double_strict(line, "temperature", request_temperature)) throw std::runtime_error("top-k encode request temperature is invalid");
                if (json_has_key(line, "top_p") && !json_get_double_strict(line, "top_p", request_top_p)) throw std::runtime_error("top-k encode request top_p is invalid");
                int request_redundancy = -1;
                if (json_has_key(line, "redundancy_level") && !json_get_int_strict(line, "redundancy_level", request_redundancy)) throw std::runtime_error("top-k encode request redundancy_level is invalid");
                std::string outline_out_path;
                bool write_outline = json_get_string(line, "outline_out", outline_out_path);
                auto payload = read_binary(payload_path);
                std::string outline_used;
                auto progress_cb = [&](const std::string & partial, size_t done, size_t total, double tps) {
                    std::ostringstream speed;
                    speed.setf(std::ios::fixed);
                    speed << std::setprecision(2) << tps;
                    emit_json("{\"id\":" + std::to_string(id) +
                              ",\"type\":\"progress\",\"ok\":true,\"done\":" + std::to_string(done) +
                              ",\"total\":" + std::to_string(total) +
                              ",\"tps\":" + speed.str() +
                              ",\"text\":\"" + json_escape(partial) + "\"}");
                };
                std::string text = worker.encode_payload(seed, payload, topic, prompt_template_name, tail_tokens,
                                                         custom_prompt_template,
                                                         static_cast<float>(request_temperature),
                                                         static_cast<float>(request_top_p),
                                                         request_redundancy,
                                                         write_outline ? &outline_used : nullptr, progress_cb);
                write_text_file(out_path, text);
                if (write_outline) write_text_file(outline_out_path, outline_used);
                emit_json(ok_response(id, ",\"backend\":\"llama.cpp\",\"backend_detail\":\"" + json_escape(worker.backend_used) + "\",\"radix\":" + std::to_string(worker.radix) + ",\"bytes\":" + std::to_string(payload.size()) + ",\"chars\":" + std::to_string(cjk_count(text)) + ",\"tokenizer_id\":\"" + json_escape(worker.tokenizer_id) + "\"" + (write_outline ? ",\"outline_chars\":" + std::to_string(cjk_count(outline_used)) : "")));
            } else if (cmd == "decode") {
                std::string text_path, out_path;
                if (!json_get_string(line, "text", text_path) || !json_get_string(line, "out", out_path)) throw std::runtime_error("top-k 解码请求缺少 text 或 out 字段");
                std::string seed;
                if (!json_get_string(line, "seed", seed) || seed.empty()) throw std::runtime_error("top-k 解码请求缺少 seed 字段");
                std::string text = read_text(text_path);
                auto payload = worker.decode_payload(seed, text);
                write_binary(out_path, payload);
                emit_json(ok_response(id, ",\"backend\":\"llama.cpp\",\"backend_detail\":\"" + json_escape(worker.backend_used) + "\",\"radix\":" + std::to_string(worker.radix) + ",\"bytes\":" + std::to_string(payload.size()) + ",\"tokenizer_id\":\"" + json_escape(worker.tokenizer_id) + "\""));
            } else if (cmd == "decode_multi") {
                std::string text_path, out_path;
                if (!json_get_string(line, "text", text_path) || !json_get_string(line, "out", out_path)) throw std::runtime_error("top-k multi-decode request is missing text or out");
                std::string seed;
                if (!json_get_string(line, "seed", seed) || seed.empty()) throw std::runtime_error("top-k multi-decode request is missing seed");
                std::string preferred_tokenizer;
                json_get_string(line, "preferred_tokenizer", preferred_tokenizer);
                std::string text = read_text(text_path);
                auto candidates = worker.decode_payload_multi(seed, text, preferred_tokenizer);
                write_decode_candidates_file(out_path, candidates);
                emit_json(ok_response(id, ",\"backend\":\"llama.cpp\",\"backend_detail\":\"" + json_escape(worker.backend_used) + "\",\"radix\":" + std::to_string(worker.radix) + ",\"candidates\":" + std::to_string(candidates.size())));
            } else {
                throw std::runtime_error("未知 worker 命令：" + cmd);
            }
        } catch (const std::exception & e) {
            std::cerr << "request failed: " << e.what() << std::endl;
            emit_json(err_response(id, e.what()));
        }
    }
    return 0;
}
