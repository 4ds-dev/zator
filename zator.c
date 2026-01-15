#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h> // Добавлено для strerror
#include <math.h>  // Для fmin
#define MAX_LINES 8192
#define MAX_LINE 4096
#define MAX_VARS 1024
#define MAX_PATH_LEN MAX_PATH
/* ---------------- Types ---------------- */
typedef enum { VAR_INT = 0, VAR_STRING = 1, VAR_IMAGE = 2 } VarType;
typedef struct {
    char *b64;           // base64 image data (allocated)
    int w, h;
    char path[MAX_PATH_LEN]; // relative path after save
    int saved;           // 0/1
} Image;
typedef struct {
    char name[128];
    VarType type;
    int iv;
    char sv[32768];
    Image img;
} Var;
/* ---------------- Globals ---------------- */
char *lines[MAX_LINES];
int line_count = 0;
Var vars[MAX_VARS];
int var_count = 0;
char context_str[8192] = "";
char base_dir[MAX_PATH_LEN] = "";
char api_server[256] = "http://localhost:5001"; // Default KoboldCpp server
/// Simple demo array (strings)
char *demo_array[128];
int demo_array_len = 0;
/* ---------------- Utilities ---------------- */
static char *safe_strdup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char *r = (char*)malloc(n + 1);
    if (!r) return NULL;
    memcpy(r, s, n + 1);
    return r;
}
char *trim(char *s) {
    if (!s) return s;
    while (*s && isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s) - 1;
    while (e >= s && isspace((unsigned char)*e)) { *e = 0; e--; }
    return s;
}
int starts_with(const char *s, const char *p) {
    return s && p && strncmp(s, p, strlen(p)) == 0;
}
Var* get_var(const char *name) {
    if (!name) return NULL;
    for (int i = 0; i < var_count; ++i) {
        if (strcmp(vars[i].name, name) == 0) return &vars[i];
    }
    return NULL;
}
int find_var_index(const char *name) {
    if (!name) return -1;
    for (int i = 0; i < var_count; ++i) {
        if (strcmp(vars[i].name, name) == 0) return i;
    }
    return -1;
}
Var* create_var_if_missing(const char *name) {
    Var *v = get_var(name);
    if (v) return v;
    if (var_count >= MAX_VARS) return NULL;
    v = &vars[var_count++];
    memset(v, 0, sizeof(Var));
    strncpy(v->name, name, sizeof(v->name) - 1);
    v->type = VAR_STRING;
    v->iv = 0;
    v->sv[0] = 0;
    v->img.b64 = NULL;
    v->img.w = v->img.h = 0;
    v->img.saved = 0;
    v->img.path[0] = 0;
    return v;
}
/* ---------------- Escaping / Unescaping ---------------- */
/* JSON-escape (for building JSON safely) */
void json_escape(const char *src, char *dst, int dstlen) {
    if (!src || !dst) return;
    char *d = dst;
    int left = dstlen - 1;
    while (*src && left > 0) {
        unsigned char c = (unsigned char)*src;
        if (c == '"') {
            if (left < 2) break;
            *d++ = '\\'; *d++ = '"'; left -= 2;
        } else if (c == '\\') {
            if (left < 2) break;
            *d++ = '\\'; *d++ = '\\'; left -= 2;
        } else if (c == '\n') {
            if (left < 2) break;
            *d++ = '\\'; *d++ = 'n'; left -= 2;
        } else if (c == '\r') {
            if (left < 2) break;
            *d++ = '\\'; *d++ = 'r'; left -= 2;
        } else if (c == '\t') {
            if (left < 2) break;
            *d++ = '\\'; *d++ = 't'; left -= 2;
        } else if (c < 32 || c > 126) {
            // Skip non-printable ASCII characters
            src++;
        } else {
            *d++ = c; left--;
        }
        src++;
    }
    *d = 0;
}
/* Unescape sequences into dst (size aware) */
void unescape_inplace(const char *src, char *dst, size_t dstlen) {
    if (!src || !dst || dstlen == 0) {
        if (dst && dstlen) dst[0] = 0;
        return;
    }
    char *d = dst;
    size_t left = dstlen - 1;
    while (*src && left > 0) {
        if (*src == '\\') {
            src++;
            if (*src == 'n') { *d++ = '\n'; src++; left--; }
            else if (*src == 't') { *d++ = '\t'; src++; left--; }
            else if (*src == 'r') { *d++ = '\r'; src++; left--; }
            else if (*src == '"') { *d++ = '"'; src++; left--; }
            else if (*src == '\\') { *d++ = '\\'; src++; left--; }
            else { *d++ = *src++; left--; }
        } else {
            *d++ = *src++; left--;
        }
    }
    *d = 0;
}
/* ---------------- f-string implementation ----------------
Поддержка подстановки {name} при рендеринге строки.
Для записи литеральной '{' и '}' в шаблон используйте '\{' и '\}'.
В C-строке это будет "\\{" и "\\}".
Кроме того, render_fstring_with_map принимает ключи/значения
для подстановки (например "context" -> context_str).
*/
const char *var_to_string(const Var *v, char *buf, size_t buflen) {
    if (!v) { buf[0] = 0; return buf; }
    if (v->type == VAR_STRING) {
        strncpy(buf, v->sv, buflen-1);
        buf[buflen-1] = 0;
        return buf;
    } else if (v->type == VAR_INT) {
        _snprintf(buf, (int)buflen, "%d", v->iv);
        buf[buflen-1] = 0;
        return buf;
    } else if (v->type == VAR_IMAGE) {
        if (v->img.saved && v->img.path[0]) {
            strncpy(buf, v->img.path, buflen-1); buf[buflen-1] = 0;
        } else {
            strncpy(buf, "<image>", buflen-1); buf[buflen-1] = 0;
        }
        return buf;
    }
    buf[0] = 0;
    return buf;
}
/* keys, values arrays: if a placeholder name found in keys -> use values[i].
otherwise attempt to find variable with that name in vars[].
*/
void render_fstring_with_map(const char *fmt, const char **keys, const char **values, int nkeys, char *out, size_t outlen) {
    if (!fmt || !out || outlen == 0) return;
    char *d = out;
    size_t left = outlen - 1;
    const char *p = fmt;
    while (*p && left > 0) {
        if (*p == '\\') {
            // escaped literal: \{ -> {, \} -> }, \\ -> \
            if (*(p+1) == '{') { if (left > 0) { *d++ = '{'; left--; } p += 2; continue; }
            if (*(p+1) == '}') { if (left > 0) { *d++ = '}'; left--; } p += 2; continue; }
            if (*(p+1) == '\\') { if (left > 0) { *d++ = '\\'; left--; } p += 2; continue; }
            // unknown escape -> copy literally
            if (left > 0) { *d++ = *p++; left--; }
        } else if (*p == '{') {
            // placeholder: {name}
            const char *q = p + 1;
            const char *start = q;
            while (*q && *q != '}') q++;
            if (*q != '}') {
                // unmatched, copy '{' literally
                if (left > 0) { *d++ = *p; left--; p++; }
            } else {
                size_t keylen = (size_t)(q - start);
                char key[512]; if (keylen >= sizeof(key)) keylen = sizeof(key)-1;
                memcpy(key, start, keylen); key[keylen] = 0;
                // trim spaces
                char *kstart = key;
                while (*kstart && isspace((unsigned char)*kstart)) kstart++;
                char *kend = key + strlen(key) - 1;
                while (kend > kstart && isspace((unsigned char)*kend)) { *kend = 0; kend--; }
                const char *replacement = NULL;
                // search in provided map first
                for (int i = 0; i < nkeys; ++i) {
                    if (keys[i] && strcmp(keys[i], kstart) == 0) { replacement = values[i]; break; }
                }
                char tmpbuf[65536];
                if (!replacement) {
                    // fallback to variable lookup
                    Var *v = get_var(kstart);
                    if (v) replacement = var_to_string(v, tmpbuf, sizeof(tmpbuf));
                }
                if (!replacement) replacement = "";
                // append replacement
                size_t rlen = strlen(replacement);
                size_t tocopy = (rlen < left) ? rlen : left;
                if (tocopy > 0) {
                    memcpy(d, replacement, tocopy);
                    d += tocopy;
                    left -= tocopy;
                }
                p = q + 1;
            }
        } else {
            *d++ = *p++;
            left--;
        }
    }
    *d = 0;
}
/* ---------------- Files & Directories ---------------- */
void make_dirs_for_path(const char *fullpath) {
    if (!fullpath) return;
    char tmp[MAX_PATH_LEN];
    strncpy(tmp, fullpath, sizeof(tmp)-1);
    tmp[sizeof(tmp)-1] = 0;
    // convert '/' to '\'
    for (char *p = tmp; *p; ++p) if (*p == '/') *p = '\\';
    char *p = tmp;
    // skip drive "C:\"
    if (strlen(tmp) > 2 && tmp[1] == ':') p = tmp + 2;
    for (; *p; ++p) {
        if (*p == '\\') {
            char save = *p;
            *p = 0;
            CreateDirectoryA(tmp, NULL);
            *p = save;
        }
    }
}
/* Normalize relative path (remove leading slashes, convert / to \) */
void normalize_relpath(char *dst, size_t dstlen, const char *rel) {
    if (!dst || !rel) return;
    size_t j = 0;
    size_t i = 0;
    // skip initial ./ or .\ or leading slashes
    if ((rel[0] == '.' && (rel[1] == '\\' || rel[1] == '/')) ) i = 2;
    while (rel[i] && j + 1 < dstlen) {
        char c = rel[i++];
        if (c == '/') c = '\\';
        // skip leading backslash
        if (j == 0 && (c == '\\')) continue;
        dst[j++] = c;
    }
    dst[j] = 0;
}
/* ---------------- Exec command ---------------- */
void exec_cmd_capture(const char *cmd, char *outbuf, int outbufsz) {
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hRead = NULL, hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        if (outbuf && outbufsz) outbuf[0] = 0;
        return;
    }
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    ZeroMemory(&pi, sizeof(pi));
    char cmdline[8192];
    snprintf(cmdline, sizeof(cmdline), "cmd.exe /C %s", cmd);
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        if (outbuf && outbufsz) outbuf[0] = 0;
        CloseHandle(hWrite);
        CloseHandle(hRead);
        return;
    }
    CloseHandle(hWrite);
    DWORD read = 0;
    int total = 0;
    while (1) {
        BOOL ok = ReadFile(hRead, outbuf + total, outbufsz - total - 1, &read, NULL);
        if (!ok || read == 0) break;
        total += (int)read;
        if (total >= outbufsz - 1) break;
    }
    outbuf[total] = 0;
    CloseHandle(hRead);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}
/* ---------------- File write helpers ---------------- */
void write_utf8_file(const char *name, const char *data) {
    FILE *f = fopen(name, "wb");
    if (!f) { fprintf(stderr, "Failed to write %s\n", name); return; }
    fwrite(data, 1, strlen(data), f);
    fclose(f);
}
/* ---------------- Generation functions (используют f-строки) ---------------- */
void gen_text_var(Var *out, const char *prompt, int max_length) {
    if (!out || !prompt) {
        if (out) {
            out->type = VAR_STRING;
            out->sv[0] = 0;
        }
        return;
    }
    // Use full context as specified in the KoboldCpp API
    char full_context[16384];
    snprintf(full_context, sizeof(full_context), "%s\n%s", context_str, prompt);
    // Escape for JSON
    char esc_prompt[16384];
    json_escape(full_context, esc_prompt, sizeof(esc_prompt));
    // Build JSON request according to KoboldCpp API spec
    char json_req[24576];
    snprintf(json_req, sizeof(json_req),
        "{"
        "\"prompt\": \"%s\","
        "\"max_length\": %d,"
        "\"max_context_length\": 2048,"
        "\"temperature\": 0.7,"
        "\"top_p\": 0.9,"
        "\"top_k\": 100,"
        "\"rep_pen\": 1.1,"
        "\"use_default_badwordsids\": false"
        "}",
        esc_prompt, max_length);
    write_utf8_file("req.json", json_req);
    char resp[262144];
    snprintf(resp, sizeof(resp), "curl -s -X POST %s/api/v1/generate -H \"Content-Type: application/json\" --data-binary @req.json", api_server);
    exec_cmd_capture(resp, resp, sizeof(resp));
    // Extract results text
    extern char *extract_results_text(const char *json); // forward
    char *txt = extract_results_text(resp);
    if (!txt) {
        out->type = VAR_STRING;
        strncpy(out->sv, "[Error generating text]", sizeof(out->sv)-1);
        out->sv[sizeof(out->sv)-1] = 0;
        return;
    }
    out->type = VAR_STRING;
    strncpy(out->sv, txt, sizeof(out->sv)-1);
    out->sv[sizeof(out->sv)-1] = 0;
    free(txt);
}
void gen_img_var(Var *out, const char *prompt, int width, int height) {
    if (!out || !prompt) {
        if (out) {
            out->type = VAR_IMAGE;
            out->img.b64 = NULL;
            out->img.w = width;
            out->img.h = height;
            out->img.saved = 0;
            out->img.path[0] = 0;
        }
        return;
    }
    // Escape prompt for JSON
    char escaped_prompt[8192];
    json_escape(prompt, escaped_prompt, sizeof(escaped_prompt));
    // Build JSON request according to SD API spec
    char json_req[16384];
    snprintf(json_req, sizeof(json_req),
        "{"
        "\"prompt\": \"%s\","
        "\"negative_prompt\": \"ugly, deformed, noisy, blurry, distorted\","
        "\"width\": %d,"
        "\"height\": %d,"
        "\"sampler_name\": \"Euler a\","
        "\"steps\": 20,"
        "\"cfg_scale\": 7.0,"
        "\"seed\": -1"
        "}",
        escaped_prompt, width, height);
    write_utf8_file("img.json", json_req);
    char resp[1048576];
    snprintf(resp, sizeof(resp), "curl -s -X POST %s/sdapi/v1/txt2img -H \"Content-Type: application/json\" --data-binary @img.json", api_server);
    exec_cmd_capture(resp, resp, sizeof(resp));
    extern char *extract_first_image_b64(const char *json); // forward
    char *b64 = extract_first_image_b64(resp);
    out->type = VAR_IMAGE;
    if (out->img.b64) { free(out->img.b64); out->img.b64 = NULL; }
    out->img.b64 = b64; // may be NULL
    out->img.w = width;
    out->img.h = height;
    out->img.saved = 0;
    out->img.path[0] = 0;
    if (!b64) {
        fprintf(stderr, "Image generation failed. Response: %s\n", resp);
    }
}
/* ---------------- Save functions ---------------- */
// --- Вспомогательная функция для декодирования Base64 ---
static int base64_decode(const char* input, unsigned char** output, size_t* output_len) {
    if (!input || !output || !output_len) {
        fprintf(stderr, "base64_decode: Input pointers are NULL.\n");
        return 0;
    }
    size_t len = strlen(input);
    if (len == 0) {
        fprintf(stderr, "base64_decode: Input string is empty.\n");
        return 0;
    }
    // Удаляем пробелы и переносы строк из строки Base64
    char *clean_input = (char*)malloc(len + 1);
    if (!clean_input) {
        fprintf(stderr, "base64_decode: Memory allocation failed for cleaning input.\n");
        return 0;
    }
    
    size_t clean_len = 0;
    for (size_t i = 0; i < len; i++) {
        if (!isspace((unsigned char)input[i])) {
            clean_input[clean_len++] = input[i];
        }
    }
    clean_input[clean_len] = 0;
    
    // Проверяем, что длина кратна 4, добавляя padding при необходимости
    size_t padding_needed = (4 - (clean_len % 4)) % 4;
    char *padded_input = (char*)malloc(clean_len + padding_needed + 1);
    if (!padded_input) {
        free(clean_input);
        fprintf(stderr, "base64_decode: Memory allocation failed for padded input.\n");
        return 0;
    }
    
    strncpy(padded_input, clean_input, clean_len);
    for (size_t i = 0; i < padding_needed; i++) {
        padded_input[clean_len + i] = '=';
    }
    padded_input[clean_len + padding_needed] = 0;
    
    free(clean_input);
    clean_len += padding_needed;
    
    // Check for invalid characters
    static const char* valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    for (size_t i = 0; i < clean_len; i++) {
        if (!strchr(valid_chars, padded_input[i])) {
            fprintf(stderr, "base64_decode: Invalid character '%c' (ASCII %d) at position %zu.\n", padded_input[i], padded_input[i], i);
            free(padded_input);
            return 0;
        }
    }
    
    size_t expected_len = clean_len * 3 / 4;
    if (clean_len > 0 && padded_input[clean_len - 1] == '=') expected_len--;
    if (clean_len > 1 && padded_input[clean_len - 2] == '=') expected_len--;
    
    *output = (unsigned char*)malloc(expected_len + 1); // +1 for null terminator
    if (!*output) {
        free(padded_input);
        fprintf(stderr, "base64_decode: Memory allocation failed for output buffer.\n");
        return 0;
    }
    
    static const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t in_idx = 0, out_idx = 0;
    int buffer = 0, bits = 0;
    
    while (in_idx < clean_len) {
        char c = padded_input[in_idx++];
        if (c == '=') break; // Конец данных
        
        const char *pos = strchr(table, c);
        if (!pos) {
            fprintf(stderr, "base64_decode: Character '%c' not found in table at position %zu.\n", c, in_idx - 1);
            free(padded_input);
            free(*output);
            *output = NULL;
            return 0;
        }
        
        int val = (int)(pos - table);
        buffer = (buffer << 6) | val;
        bits += 6;
        
        if (bits >= 8) {
            bits -= 8;
            (*output)[out_idx++] = (buffer >> bits) & 0xFF;
        }
    }
    
    (*output)[out_idx] = 0; // Null terminator for safety
    *output_len = out_idx;
    
    free(padded_input);
    return 1; // Успех
}

// --- Исправленная функция извлечения Base64 изображения из JSON ---
char *extract_first_image_b64(const char *json) {
    if (!json) return NULL;
    
    // Находим начало массива изображений
    char *images = strstr((char*)json, "\"images\":");
    if (!images) {
        fprintf(stderr, "Could not find \"images\" field in JSON response.\n");
        return NULL;
    }
    
    char *start_bracket = strchr(images, '[');
    if (!start_bracket) {
        fprintf(stderr, "Could not find opening bracket for images array.\n");
        return NULL;
    }
    
    char *first_quote = strchr(start_bracket, '"');
    if (!first_quote) {
        fprintf(stderr, "Could not find opening quote for base64 string.\n");
        return NULL;
    }
    
    first_quote++; // Пропускаем начальную кавычку
    
    // Находим конец строки Base64 (следующую незэкранированную кавычку)
    const char *end_quote = first_quote;
    while (*end_quote) {
        if (*end_quote == '"' && (end_quote == first_quote || *(end_quote - 1) != '\\')) 
            break;
        end_quote++;
    }
    
    if (*end_quote != '"') {
        fprintf(stderr, "Could not find closing quote for base64 string.\n");
        return NULL;
    }
    
    // Вычисляем длину и копируем данные
    size_t length = end_quote - first_quote;
    if (length == 0) {
        fprintf(stderr, "Empty base64 string found.\n");
        return NULL;
    }
    
    char *raw_b64 = (char*)malloc(length + 1);
    if (!raw_b64) {
        fprintf(stderr, "Memory allocation failed for raw base64 string.\n");
        return NULL;
    }
    
    strncpy(raw_b64, first_quote, length);
    raw_b64[length] = 0;
    
    // Создаем буфер для очищенной строки
    size_t clean_size = length + 1; // +1 for null terminator
    char *clean = (char*)malloc(clean_size);
    if (!clean) {
        free(raw_b64);
        fprintf(stderr, "Memory allocation failed for cleaned base64 string.\n");
        return NULL;
    }
    
    // Удаляем все escape-последовательности JSON и пробелы
    size_t j = 0;
    for (size_t i = 0; i < length; i++) {
        // Пропускаем обратные слэши и обрабатываем escape-последовательности
        if (raw_b64[i] == '\\') {
            i++; // Пропускаем сам слэш
            if (i < length) {
                // Обрабатываем только специальные escape-последовательности JSON
                if (raw_b64[i] == '"' || raw_b64[i] == '\\' || raw_b64[i] == '/') {
                    if (j + 1 >= clean_size) {
                        clean_size *= 2;
                        char *tmp = (char*)realloc(clean, clean_size);
                        if (!tmp) {
                            free(clean);
                            free(raw_b64);
                            fprintf(stderr, "Memory reallocation failed during base64 cleaning.\n");
                            return NULL;
                        }
                        clean = tmp;
                    }
                    clean[j++] = raw_b64[i];
                }
                // Игнорируем другие escape-последовательности (\n, \r, \t и т.д.)
            }
        } else if (!isspace((unsigned char)raw_b64[i])) {
            // Пропускаем все пробельные символы
            if (j + 1 >= clean_size) {
                clean_size *= 2;
                char *tmp = (char*)realloc(clean, clean_size);
                if (!tmp) {
                    free(clean);
                    free(raw_b64);
                    fprintf(stderr, "Memory reallocation failed during base64 cleaning.\n");
                    return NULL;
                }
                clean = tmp;
            }
            clean[j++] = raw_b64[i];
        }
    }
    clean[j] = 0;
    
    free(raw_b64);
    
    // Добавляем padding, если необходимо
    size_t clean_len = strlen(clean);
    size_t padding_needed = (4 - (clean_len % 4)) % 4;
    
    if (padding_needed > 0) {
        char *padded = (char*)realloc(clean, clean_len + padding_needed + 1);
        if (!padded) {
            free(clean);
            fprintf(stderr, "Memory reallocation failed for base64 padding.\n");
            return NULL;
        }
        clean = padded;
        
        for (size_t i = 0; i < padding_needed; i++) {
            clean[clean_len + i] = '=';
        }
        clean[clean_len + padding_needed] = 0;
    }
    
    return clean;
}

// --- Обновлённая функция сохранения изображения с отладкой ---
void save_img_var(Var *v, const char *relpath) {
    if (!v || v->type != VAR_IMAGE) {
        fprintf(stderr, "save_img: Variable is not an image.\n");
        return;
    }
    if (!v->img.b64) {
        fprintf(stderr, "save_img: No base64 data to save for variable '%s'.\n", v->name);
        return;
    }
    
    char relnorm[MAX_PATH_LEN];
    normalize_relpath(relnorm, sizeof(relnorm), relpath);
    char abs[MAX_PATH_LEN];
    snprintf(abs, sizeof(abs), "%s\\%s", base_dir, relnorm);
    make_dirs_for_path(abs);
    
    // 1. Декодируем base64 данные напрямую в память
    unsigned char* decoded_data = NULL;
    size_t decoded_len = 0;
    if (!base64_decode(v->img.b64, &decoded_data, &decoded_len)) {
        fprintf(stderr, "save_img: Failed to decode base64 data for '%s'. Check previous error messages.\n", abs);
        return;
    }
    
    // Проверяем, что данные похожи на PNG или JPEG (простая проверка)
    if (decoded_len < 4) {
        fprintf(stderr, "save_img: Decoded data is too short to be a valid image.\n");
        free(decoded_data);
        return;
    }
    
    // 2. Сохраняем декодированные бинарные данные в файл
    FILE *f = fopen(abs, "wb"); // Открываем в бинарном режиме ("wb")
    if (!f) {
        fprintf(stderr, "save_img: Cannot open file for writing '%s'. Error: %s\n", abs, strerror(errno));
        free(decoded_data);
        return;
    }
    
    size_t written = fwrite(decoded_data, 1, decoded_len, f);
    if (written != decoded_len) {
        fprintf(stderr, "save_img: Failed to write complete image data to '%s'. Expected: %zu, Written: %zu. Error: %s\n",
            abs, decoded_len, written, ferror(f) ? strerror(errno) : "Unknown error");
        fclose(f);
        free(decoded_data);
        return;
    }
    
    fclose(f);
    free(decoded_data); // Освобождаем буфер декодированных данных
    
    // 3. Устанавливаем пути и статус
    strncpy(v->img.path, relnorm, sizeof(v->img.path)-1);
    v->img.path[sizeof(v->img.path)-1] = 0;
    v->img.saved = 1;
    
    printf("Successfully saved image to %s\n", abs);
}

void save_txt_var(Var *v, const char *relpath) {
    if (!v || v->type != VAR_STRING) return;
    char relnorm[MAX_PATH_LEN];
    normalize_relpath(relnorm, sizeof(relnorm), relpath);
    char abs[MAX_PATH_LEN];
    snprintf(abs, sizeof(abs), "%s\\%s", base_dir, relnorm);
    make_dirs_for_path(abs);
    FILE *f = fopen(abs, "wb");
    if (!f) { fprintf(stderr, "save_txt: cannot open %s\n", abs); return; }
    fwrite(v->sv, 1, strlen(v->sv), f);
    fclose(f);
}
/* ---------------- Print / Input ---------------- */
void do_print_arg(const char *arg) {
    if (!arg) return;
    // string literal
    size_t len = strlen(arg);
    if (len >= 2 && arg[0] == '"' && arg[len-1] == '"') {
        char tmp[32768];
        size_t innerlen = len - 2;
        if (innerlen > sizeof(tmp)-1) innerlen = sizeof(tmp)-1;
        strncpy(tmp, arg+1, innerlen);
        tmp[innerlen] = 0;
        char out[32768];
        unescape_inplace(tmp, out, sizeof(out));
        fputs(out, stdout);
        return;
    }
    // variable
    Var *v = get_var(arg);
    if (!v) return;
    if (v->type == VAR_STRING) fputs(v->sv, stdout);
    else if (v->type == VAR_INT) {
        char buf[64];
        snprintf(buf, sizeof(buf), "%d", v->iv);
        fputs(buf, stdout);
    } else if (v->type == VAR_IMAGE) {
        if (v->img.saved && v->img.path[0]) fputs(v->img.path, stdout);
        else fputs("<image>", stdout);
    }
}
/* input(varname) reads one line from stdin (no prompt). Trims CR/LF */
void do_input_var(const char *name) {
    if (!name) return;
    char nm[128];
    strncpy(nm, name, sizeof(nm)-1); nm[sizeof(nm)-1] = 0;
    char *p = nm;
    while (*p && isspace((unsigned char)*p)) p++;
    char *end = nm + strlen(nm) - 1;
    while (end > p && isspace((unsigned char)*end)) { *end = 0; end--; }
    if (*p == '"' && end > p && *end == '"') { *end = 0; p++; }
    Var *v = create_var_if_missing(p);
    if (!v) return;
    if (!fgets(v->sv, sizeof(v->sv), stdin)) {
        v->sv[0] = 0;
    } else {
        size_t L = strlen(v->sv);
        while (L > 0 && (v->sv[L-1] == '\n' || v->sv[L-1] == '\r')) { v->sv[L-1] = 0; L--; }
    }
    v->type = VAR_STRING;
}
/* ---------------- Arrays and utilities ---------------- */
void array_push_demo(const char *s) {
    if (demo_array_len >= (int)(sizeof(demo_array)/sizeof(demo_array[0]))) return;
    demo_array[demo_array_len++] = safe_strdup(s ? s : "");
}
void print_demo_array(void) {
    printf("[");
    for (int i = 0; i < demo_array_len; ++i) {
        printf("\"%s\"", demo_array[i] ? demo_array[i] : "");
        if (i + 1 < demo_array_len) printf(", ");
    }
    printf("]\n");
}
char *to_upper_str(const char *s) {
    if (!s) return NULL;
    char *r = safe_strdup(s);
    for (char *p = r; *p; ++p) *p = (char)toupper((unsigned char)*p);
    return r;
}
/* ---------------- Embedded C code insertion ---------------- */
const char *embedded_c_code =
    "/* Пример вставленного кода на C */\n"
    "#include <stdio.h>\n"
    "int add(int a, int b) { return a + b; }\n"
    "// Конец вставки\n";
void save_embedded_c_code(const char *relpath) {
    char relnorm[MAX_PATH_LEN];
    normalize_relpath(relnorm, sizeof(relnorm), relpath);
    char abs[MAX_PATH_LEN];
    snprintf(abs, sizeof(abs), "%s\\%s", base_dir, relnorm);
    make_dirs_for_path(abs);
    write_utf8_file(abs, embedded_c_code);
}
/* ---------------- JSON extract helpers ---------------- */
/* Extract JSON string value robustly: find "key" then colon then quoted string, handle escapes.
Returns heap-allocated unescaped C string (caller must free) or NULL.
*/
char *extract_json_string(const char *json, const char *key) {
    if (!json || !key) return NULL;
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    char *p = strstr(json, pattern);
    if (!p) return NULL;
    p += strlen(pattern);
    // find ':'
    while (*p && *p != ':') p++;
    if (!*p) return NULL;
    p++;
    // skip spaces
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p != '"') {
        // try find next quote
        while (*p && *p != '"') p++;
        if (!*p) return NULL;
    }
    p++; // now at start of content
    const char *q = p;
    size_t cap = 4096;
    size_t len = 0;
    char *acc = (char*)malloc(cap);
    if (!acc) return NULL;
    while (*q) {
        if (*q == '"' && *(q - 1) != '\\') break;
        if (len + 1 >= cap) {
            cap *= 2;
            char *tmp = (char*)realloc(acc, cap);
            if (!tmp) { free(acc); return NULL; }
            acc = tmp;
        }
        acc[len++] = *q++;
    }
    acc[len] = 0;
    // unescape into final
    char *final = (char*)malloc(len + 1 + 8);
    if (!final) { free(acc); return NULL; }
    unescape_inplace(acc, final, len + 1 + 8);
    free(acc);
    return final;
}
/* Extract results[0].text (handles {"results":[{"text":"..."}]}) */
char *extract_results_text(const char *json) {
    if (!json) return NULL;
    // First try to extract from results array
    char *results = strstr((char*)json, "\"results\":");
    if (results) {
        char *text = strstr(results, "\"text\":");
        if (text) {
            return extract_json_string(text, "text");
        }
    }
    // Fallback to top-level text field
    return extract_json_string(json, "text");
}

/* ---------------- Script parsing & execution ----------------
Добавлены:
- if <var> == <value> / if <var> > <num> ...  (только для простоты однословных значений)
- repeat N { ... } .. } блок с поддержкой "break"
- команды: emit_c("relpath") для записи embedded C-кода
- set_server("http://localhost:5001") to change API server
*/
void execute_line_command(const char *l);
void parse_and_run_script(const char *script_path) {
    FILE *f = fopen(script_path, "r");
    if (!f) { fprintf(stderr, "Cannot open script: %s\n", script_path); return; }
    char buf[MAX_LINE];
    while (fgets(buf, sizeof(buf), f)) {
        char *ln = trim(buf);
        if (strlen(ln) == 0) continue;
        lines[line_count++] = safe_strdup(ln);
        if (line_count >= MAX_LINES-1) break;
    }
    fclose(f);
    // main execution pointer
    int i = 0;
    while (i < line_count) {
        char *l = lines[i];
        if (!l || l[0] == '#') { i++; continue; }
        // context = "..."
        if (starts_with(l, "context")) {
            char val[MAX_LINE];
            if (sscanf(l, "context = \"%[^\"]\"", val) == 1) {
                // Render f-string for context
                const char *keys[] = { "context" };
                const char *vals[] = { context_str };
                char rendered_val[8192];
                render_fstring_with_map(val, keys, vals, 1, rendered_val, sizeof(rendered_val));
                strncpy(context_str, rendered_val, sizeof(context_str)-1);
                context_str[sizeof(context_str)-1] = 0;
            } else {
                context_str[0] = 0;
            }
            i++; continue;
        }
        // server = "http://localhost:5001"
        if (starts_with(l, "server")) {
            char val[MAX_LINE];
            if (sscanf(l, "server = \"%[^\"]\"", val) == 1) {
                // Render f-string for server
                const char *keys[] = { "context" };
                const char *vals[] = { context_str };
                char rendered_val[256];
                render_fstring_with_map(val, keys, vals, 1, rendered_val, sizeof(rendered_val));
                strncpy(api_server, rendered_val, sizeof(api_server)-1);
                api_server[sizeof(api_server)-1] = 0;
            }
            i++; continue;
        }
        // var name = ...
        if (starts_with(l, "var ")) {
            char name[128];
            if (sscanf(l, "var %127s", name) != 1) { i++; continue; }
            char *eq = strchr(name, '=');
            if (eq) *eq = 0;
            Var *v = create_var_if_missing(name);
            // generate_text
            if (strstr(l, "generate_text(")) {
                char pmt[128];
                int tokens = 0;
                if (sscanf(l, "var %*s = generate_text(%127[^,], context, %d)", pmt, &tokens) >= 1) {
                    char *pp = pmt; while (*pp && isspace((unsigned char)*pp)) pp++;
                    // if pmt is a variable name, use its content; if it's a quoted literal, extract
                    char prompt_text[32768] = "";
                    if (*pp == '"') {
                        // literal
                        char tmp[32768]; if (sscanf(pp, "\"%[^\"]\"", tmp) == 1) {
                            // Render f-string for prompt
                            const char *keys[] = { "context" };
                            const char *vals[] = { context_str };
                            render_fstring_with_map(tmp, keys, vals, 1, prompt_text, sizeof(prompt_text));
                        }
                    } else {
                        Var *vp = get_var(pp);
                        if (vp) strncpy(prompt_text, vp->sv, sizeof(prompt_text)-1);
                    }
                    gen_text_var(v, prompt_text, tokens);
                } else {
                    v->type = VAR_STRING; v->sv[0] = 0;
                }
                i++; continue;
            }
            // generate_img
            if (strstr(l, "generate_img(")) {
                char pmt[128];
                int w = 512, h = 512;
                if (sscanf(l, "var %*s = generate_img(%127[^,], context, %d, %d", pmt, &w, &h) >= 1) {
                    char *pp = pmt; while (*pp && isspace((unsigned char)*pp)) pp++;
                    char prompt_text[32768] = "";
                    if (*pp == '"') {
                        char tmp[32768]; if (sscanf(pp, "\"%[^\"]\"", tmp) == 1) {
                            // Render f-string for prompt
                            const char *keys[] = { "context" };
                            const char *vals[] = { context_str };
                            render_fstring_with_map(tmp, keys, vals, 1, prompt_text, sizeof(prompt_text));
                        }
                    } else {
                        Var *vp = get_var(pp);
                        if (vp) strncpy(prompt_text, vp->sv, sizeof(prompt_text)-1);
                    }
                    gen_img_var(v, prompt_text, w, h);
                } else {
                    v->type = VAR_IMAGE; v->img.b64 = NULL; v->img.w = w; v->img.h = h; v->img.saved = 0;
                }
                i++; continue;
            }
            // literal string?
            char lit[32768];
            if (sscanf(l, "var %*s = \"%[^\"]\"", lit) == 1) {
                v->type = VAR_STRING;
                // Render f-string for literal
                const char *keys[] = { "context" };
                const char *vals[] = { context_str };
                render_fstring_with_map(lit, keys, vals, 1, v->sv, sizeof(v->sv));
                i++; continue;
            }
            // integer?
            int ival;
            if (sscanf(l, "var %*s = %d", &ival) == 1) {
                v->type = VAR_INT;
                v->iv = ival;
                i++; continue;
            }
            // else leave as empty string
            v->type = VAR_STRING;
            v->sv[0] = 0;
            i++; continue;
        }
        // input(name) - also support f-strings in the variable name
        if (starts_with(l, "input(")) {
            char name[256];
            if (sscanf(l, "input(%255[^)])", name) == 1) {
                // Render f-string for variable name
                const char *keys[] = { "context" };
                const char *vals[] = { context_str };
                char rendered_name[256];
                render_fstring_with_map(name, keys, vals, 1, rendered_name, sizeof(rendered_name));
                do_input_var(rendered_name);
            }
            i++; continue;
        }
        // save_img(var, "rel/path")
        if (starts_with(l, "save_img(")) {
            char varname[128], rel[512];
            if (sscanf(l, "save_img(%127[^,], \"%511[^\"]\")", varname, rel) == 2) {
                char *p = varname; while (*p && isspace((unsigned char)*p)) p++;
                Var *v = get_var(p);
                if (v) {
                    // Render f-string for rel path
                    const char *keys[] = { "context" };
                    const char *vals[] = { context_str };
                    char rendered_rel[512];
                    render_fstring_with_map(rel, keys, vals, 1, rendered_rel, sizeof(rendered_rel));
                    save_img_var(v, rendered_rel);
                }
            }
            i++; continue;
        }
        // save_txt(var, "rel/path")
        if (starts_with(l, "save_txt(")) {
            char varname[128], rel[512];
            if (sscanf(l, "save_txt(%127[^,], \"%511[^\"]\")", varname, rel) == 2) {
                char *p = varname; while (*p && isspace((unsigned char)*p)) p++;
                Var *v = get_var(p);
                if (v) {
                    // Render f-string for rel path
                    const char *keys[] = { "context" };
                    const char *vals[] = { context_str };
                    char rendered_rel[512];
                    render_fstring_with_map(rel, keys, vals, 1, rendered_rel, sizeof(rendered_rel));
                    save_txt_var(v, rendered_rel);
                }
            }
            i++; continue;
        }
        // emit_c("rel/path") -> saves embedded C code
        if (starts_with(l, "emit_c(")) {
            char rel[512];
            if (sscanf(l, "emit_c(\"%511[^\"]\")", rel) == 1) {
                // Render f-string for rel path
                const char *keys[] = { "context" };
                const char *vals[] = { context_str };
                char rendered_rel[512];
                render_fstring_with_map(rel, keys, vals, 1, rendered_rel, sizeof(rendered_rel));
                save_embedded_c_code(rendered_rel);
            }
            i++; continue;
        }
        // print(...)
        if (starts_with(l, "print(")) {
            char arg[4096];
            if (sscanf(l, "print(%4095[^)])", arg) == 1) {
                char *a = arg;
                while (*a && isspace((unsigned char)*a)) a++;
                char *end = a + strlen(a) - 1;
                while (end > a && isspace((unsigned char)*end)) { *end = 0; end--; }
                // support f-string inside print: render with map containing context
                const char *keys[] = { "context" };
                const char *vals[] = { context_str };
                char out[32768];
                // if arg is a quoted literal, render it as f-string (so {var} substitutions also work)
                if (a[0] == '"' && a[strlen(a)-1] == '"') {
                    char tmp[32768]; strncpy(tmp, a+1, sizeof(tmp)-1); tmp[sizeof(tmp)-1]=0;
                    // remove trailing quote
                    if (tmp[strlen(tmp)-1] == '"') tmp[strlen(tmp)-1] = 0;
                    render_fstring_with_map(tmp, keys, vals, 1, out, sizeof(out));
                    // unescape sequences
                    char final_out[32768];
                    unescape_inplace(out, final_out, sizeof(final_out));
                    fputs(final_out, stdout);
                } else {
                    // variable or expression
                    do_print_arg(a);
                }
            }
            i++; continue;
        }
        // if condition: supports e.g. if varname == "value"  OR if varname > 10
        if (starts_with(l, "if ")) {
            // parse crude condition
            char varname[128], op[8], rhs[256];
            if (sscanf(l, "if %127s %7s %255[^\n]", varname, op, rhs) >= 2) {
                // trim rhs spaces and quotes
                char *r = rhs;
                while (*r && isspace((unsigned char)*r)) r++;
                char *rend = r + strlen(r) - 1;
                while (rend > r && isspace((unsigned char)*rend)) { *rend = 0; rend--; }
                // remove possible quotes
                if (*r == '"' && rend > r && *rend == '"') { r++; *rend = 0; }
                Var *v = get_var(varname);
                bool cond = false;
                if (v) {
                    if (v->type == VAR_INT) {
                        int rhsnum = atoi(r);
                        if (strcmp(op, "==") == 0) cond = (v->iv == rhsnum);
                        else if (strcmp(op, "!=") == 0) cond = (v->iv != rhsnum);
                        else if (strcmp(op, ">") == 0) cond = (v->iv > rhsnum);
                        else if (strcmp(op, "<") == 0) cond = (v->iv < rhsnum);
                        else if (strcmp(op, ">=") == 0) cond = (v->iv >= rhsnum);
                        else if (strcmp(op, "<=") == 0) cond = (v->iv <= rhsnum);
                    } else {
                        // string comparison
                        if (strcmp(op, "==") == 0) cond = (strcmp(v->sv, r) == 0);
                        else if (strcmp(op, "!=") == 0) cond = (strcmp(v->sv, r) != 0);
                        else {
                            // unsupported operator for strings
                            cond = false;
                        }
                    }
                } else {
                    cond = false;
                }
                // simple handling: if false -> skip next line
                if (!cond) {
                    i += 2; // skip next line
                    continue;
                } else {
                    i++; continue; // execute next line
                }
            } else {
                i++; continue;
            }
        }
        // repeat block: repeat N { ... }
        if (starts_with(l, "repeat ")) {
            int times = 0;
            if (sscanf(l, "repeat %d", &times) >= 1 && times > 0) {
                // find block start: current line may be "repeat N {" or "repeat N"
                int j = i + 1;
                // if current line ends with "{" then j = i + 1; else find next line that is "{"
                if (strchr(l, '{') == NULL) {
                    // skip any blank lines to find '{'
                    while (j < line_count && strcmp(lines[j], "{") != 0) j++;
                    if (j >= line_count) { i++; continue; }
                    j++; // block starts after '{'
                } else {
                    // block starts next line
                    // the '{' may be at end of this line - start at i+1
                }
                int block_start = j;
                int block_end = block_start;
                // find matching "}" line
                int depth = 1;
                for (int k = block_start; k < line_count; ++k) {
                    if (strcmp(lines[k], "{") == 0) depth++;
                    else if (strcmp(lines[k], "}") == 0) { depth--; if (depth == 0) { block_end = k; break; } }
                }
                if (block_end <= block_start) { i++; continue; }
                bool broken = false;
                for (int t = 0; t < times && !broken; ++t) {
                    for (int k = block_start; k < block_end; ++k) {
                        if (!lines[k]) continue;
                        // if line is "break" -> break from repeat
                        if (strcmp(lines[k], "break") == 0) { broken = true; break; }
                        // execute the line: we simply call a helper to process a single command line
                        execute_line_command(lines[k]);
                        // note: this simple approach doesn't support nested repeat properly,
                        // but demonstrates repeat/break behaviour
                    }
                }
                // move instruction pointer after block_end
                i = block_end + 1;
                continue;
            }
        }
        // single-word commands: e.g. break (ignored outside repeat), emit_array_push("x")
        if (starts_with(l, "array_push_demo(")) {
            char val[512];
            if (sscanf(l, "array_push_demo(\"%511[^\"]\")", val) == 1) {
                // Render f-string for val
                const char *keys[] = { "context" };
                const char *vals[] = { context_str };
                char rendered_val[512];
                render_fstring_with_map(val, keys, vals, 1, rendered_val, sizeof(rendered_val));
                array_push_demo(rendered_val);
            }
            i++; continue;
        }
        if (starts_with(l, "print_array()")) {
            print_demo_array(); i++; continue;
        }
        // generic execute for other commands
        execute_line_command(l);
        i++;
    }
}
/* Helper для выполнения "одной" строки (упрощённо): поддерживает print, var assignments, save_txt и т.д.
Это позволяет повторно использовать логику в repeat-блоках.
*/
void execute_line_command(const char *l) {
    if (!l) return;
    // reuse a subset of parse logic:
    if (starts_with(l, "print(")) {
        char arg[4096];
        if (sscanf(l, "print(%4095[^)])", arg) == 1) {
            char *a = arg;
            while (*a && isspace((unsigned char)*a)) a++;
            char *end = a + strlen(a) - 1;
            while (end > a && isspace((unsigned char)*end)) { *end = 0; end--; }
            // render as f-string
            const char *keys[] = { "context" };
            const char *vals[] = { context_str };
            char out[32768];
            if (a[0] == '"' && a[strlen(a)-1] == '"') {
                char tmp[32768]; strncpy(tmp, a+1, sizeof(tmp)-1); tmp[sizeof(tmp)-1]=0;
                if (tmp[strlen(tmp)-1] == '"') tmp[strlen(tmp)-1] = 0;
                render_fstring_with_map(tmp, keys, vals, 1, out, sizeof(out));
                char final_out[32768];
                unescape_inplace(out, final_out, sizeof(final_out));
                fputs(final_out, stdout);
            } else {
                do_print_arg(a);
            }
        }
        return;
    }
    if (starts_with(l, "save_txt(")) {
        char varname[128], rel[512];
        if (sscanf(l, "save_txt(%127[^,], \"%511[^\"]\")", varname, rel) == 2) {
            char *p = varname; while (*p && isspace((unsigned char)*p)) p++;
            Var *v = get_var(p);
            if (v) {
                // Render f-string for rel path
                const char *keys[] = { "context" };
                const char *vals[] = { context_str };
                char rendered_rel[512];
                render_fstring_with_map(rel, keys, vals, 1, rendered_rel, sizeof(rendered_rel));
                save_txt_var(v, rendered_rel);
            }
        }
        return;
    }
    if (starts_with(l, "break")) {
        // handled in repeat loop context (execute_line_command can signal break via global flag if needed)
        return;
    }
    // fallback: do nothing
}
/* ---------------- Entry point ---------------- */
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s script.zator\n", argv[0]);
        return 1;
    }
    char full[MAX_PATH_LEN];
    if (!GetFullPathNameA(argv[1], MAX_PATH_LEN, full, NULL)) {
        fprintf(stderr, "GetFullPathNameA failed\n");
        return 1;
    }
    char *p = strrchr(full, '\\');
    if (!p) p = strrchr(full, '/');
    if (p) { *p = 0; strncpy(base_dir, full, sizeof(base_dir)-1); base_dir[sizeof(base_dir)-1] = 0; }
    else {
        if (!GetCurrentDirectoryA(MAX_PATH_LEN, base_dir)) base_dir[0] = 0;
    }
    // small demo: push some demo array items
    array_push_demo("first");
    array_push_demo("second");
    // demo of to_upper_str
    char *u = to_upper_str("demo"); if (u) { array_push_demo(u); free(u); }
    parse_and_run_script(argv[1]);
    // at exit: save embedded code automatically to base_dir\embedded\snippet.c
    save_embedded_c_code("embedded\\snippet.c");
    // cleanup allocated base64 strings
    for (int i = 0; i < var_count; ++i) {
        if (vars[i].type == VAR_IMAGE && vars[i].img.b64) {
            free(vars[i].img.b64);
            vars[i].img.b64 = NULL;
        }
    }
    for (int i = 0; i < line_count; ++i) free(lines[i]);
    for (int i = 0; i < demo_array_len; ++i) free(demo_array[i]);
    return 0;
}