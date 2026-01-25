#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <shlwapi.h> // For PathRemoveFileSpecA
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h> // Include stdint.h for uint32_t
#include <stdbool.h>
#include <time.h>
#include <errno.h> // Добавлено для strerror
#include <math.h>  // Для fmin, abs
#include <limits.h> // Для INT_MAX

// Define _GNU_SOURCE or similar if strndup is needed and not available
// For MinGW, defining it explicitly often helps.
#define _GNU_SOURCE
#include <string.h> // Ensure string.h is included after macro definition


// --- НОВЫЕ ЗАГОЛОВКИ ДЛЯ PNG ---
#include <png.h>
#include <setjmp.h>
// --- КОНЕЦ НОВЫХ ЗАГОЛОВКОВ ---

#define MAX_LINES 8192
#define MAX_LINE 4096
#define MAX_VARS 1024
#define MAX_PATH_LEN MAX_PATH

/* ---------------- Types ---------------- */
// --- НОВАЯ СТРУКТУРА ДЛЯ ВНУТРЕННЕГО ИЗОБРАЖЕНИЯ ---
typedef struct {
    uint32_t *pixels; // Массив RGBA пикселей (0xAABBGGRR на Windows x86)
    int w, h;
} RGBAImage;
// --- КОНЕЦ НОВОЙ СТРУКТУРЫ ---

typedef enum { VAR_INT = 0, VAR_STRING = 1, VAR_IMAGE = 2 } VarType;
typedef struct {
    char *b64;           // base64 image data (allocated)
    int w, h;
    char path[MAX_PATH_LEN]; // relative path after save
    int saved;           // 0/1
    // --- ДОБАВЛЕНО: внутреннее представление ---
    RGBAImage *internal_img;
    // --- КОНЕЦ ДОБАВЛЕНИЯ ---
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
    v->img.internal_img = NULL; // Инициализация
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

// --- НОВАЯ ФУНКЦИЯ: ОСВОБОЖДЕНИЕ RGBAImage ---
void free_rgba_image(RGBAImage *img) {
    if (img && img->pixels) {
        free(img->pixels);
        img->pixels = NULL;
        img->w = 0;
        img->h = 0;
    }
}
// --- КОНЕЦ НОВОЙ ФУНКЦИИ ---

// --- НОВАЯ СТРУКТУРА ДЛЯ ХРАНЕНИЯ ДАННЫХ ЧТЕНИЯ PNG ИЗ ПАМЯТИ ---
struct mem_read_struct {
    unsigned char *data;
    size_t offset;
    size_t size;
};
// --- КОНЕЦ НОВОЙ СТРУКТУРЫ ---

// --- НОВАЯ ФУНКЦИЯ ЧТЕНИЯ ДЛЯ PNG ИЗ ПАМЯТИ ---
void png_mem_read_data(png_structp png_ptr, png_bytep data, png_size_t length) {
    struct mem_read_struct *src = (struct mem_read_struct *)png_get_io_ptr(png_ptr);
    if (src->offset + length > src->size) {
        png_error(png_ptr, "Read Error: Out of bounds");
        return;
    }
    memcpy(data, src->data + src->offset, length);
    src->offset += length;
}
// --- КОНЕЦ НОВОЙ ФУНКЦИИ ---

// --- НОВАЯ ФУНКЦИЯ: ДЕКОДИРОВАНИЕ PNG ИЗ ПАМЯТИ ---
int decode_png_from_memory(unsigned char *in_data, size_t in_len, RGBAImage *out_img) {
    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) {
        fprintf(stderr, "PNG: Could not init png read struct\n");
        return 0;
    }

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        fprintf(stderr, "PNG: Could not init png info struct\n");
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        return 0;
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        fprintf(stderr, "PNG: Error during read\n");
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return 0;
    }

    // Установка источника данных
    struct mem_read_struct mem_src;
    mem_src.data = in_data;
    mem_src.offset = 0;
    mem_src.size = in_len;

    png_set_read_fn(png_ptr, &mem_src, png_mem_read_data);

    png_read_info(png_ptr, info_ptr);

    png_uint_32 width, height;
    int bit_depth, color_type, interlace_type;
    png_get_IHDR(png_ptr, info_ptr, &width, &height, &bit_depth, &color_type, &interlace_type, NULL, NULL);

    // Установка параметров для получения RGBA
    if (color_type == PNG_COLOR_TYPE_PALETTE) {
        png_set_palette_to_rgb(png_ptr);
    }
    if (color_type == PNG_COLOR_TYPE_GRAY && bit_depth < 8) {
        png_set_expand_gray_1_2_4_to_8(png_ptr);
    }
    if (png_get_valid(png_ptr, info_ptr, PNG_INFO_tRNS)) {
        png_set_tRNS_to_alpha(png_ptr);
    }
    if (bit_depth == 16) {
        png_set_strip_16(png_ptr);
    }
    png_set_filler(png_ptr, 0xff, PNG_FILLER_AFTER); // Ensure alpha channel exists

    png_read_update_info(png_ptr, info_ptr);

    // Выделение памяти и чтение строк
    size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
    out_img->pixels = (uint32_t*)malloc(width * height * sizeof(uint32_t));
    if (!out_img->pixels) {
        fprintf(stderr, "PNG: Could not allocate pixel memory\n");
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return 0;
    }
    out_img->w = width;
    out_img->h = height;

    png_bytep *row_pointers = (png_bytep*)malloc(height * sizeof(png_bytep));
    if (!row_pointers) {
         fprintf(stderr, "PNG: Could not allocate row pointers memory\n");
         free(out_img->pixels);
         out_img->pixels = NULL;
         png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
         return 0;
    }
    for (int y = 0; y < height; y++) {
        row_pointers[y] = (png_bytep)(out_img->pixels + y * width);
    }
    png_read_image(png_ptr, row_pointers);
    free(row_pointers);

    png_read_end(png_ptr, info_ptr);
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    return 1;
}
// --- КОНЕЦ НОВОЙ ФУНКЦИИ ---

// --- НОВАЯ СТРУКТУРА ДЛЯ ХРАНЕНИЯ ДАННЫХ ЗАПИСИ PNG В ПАМЯТЬ ---
struct mem_write_struct {
    unsigned char *data;
    size_t size;
    size_t alloc_size;
};
// --- КОНЕЦ НОВОЙ СТРУКТУРЫ ---

// --- НОВАЯ ФУНКЦИЯ ЗАПИСИ ДЛЯ PNG В ПАМЯТЬ ---
void png_mem_write_data(png_structp png_ptr, png_bytep data, png_size_t length) {
    struct mem_write_struct *dst = (struct mem_write_struct *)png_get_io_ptr(png_ptr);
    if (dst->size + length > dst->alloc_size) {
        size_t new_size = (dst->alloc_size == 0) ? 8192 : dst->alloc_size * 2;
        while (new_size < dst->size + length) new_size *= 2;
        unsigned char *tmp = realloc(dst->data, new_size);
        if (!tmp) {
            png_error(png_ptr, "Write Error: Realloc failed");
            return;
        }
        dst->data = tmp;
        dst->alloc_size = new_size;
    }
    memcpy(dst->data + dst->size, data, length);
    dst->size += length;
}

void png_mem_flush_data(png_structp png_ptr) {
    // No-op for memory buffer
}
// --- КОНЕЦ НОВОЙ ФУНКЦИИ ---

// --- НОВАЯ ФУНКЦИЯ: КОДИРОВАНИЕ PNG В ПАМЯТЬ ---
int encode_png_to_memory(RGBAImage *in_img, unsigned char **out_data, size_t *out_len) {
    if (!in_img || !in_img->pixels || in_img->w <= 0 || in_img->h <= 0) {
        fprintf(stderr, "Encode PNG: Invalid input image\n");
        return 0;
    }

    png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) {
        fprintf(stderr, "PNG: Could not init png write struct\n");
        return 0;
    }

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        fprintf(stderr, "PNG: Could not init png info struct\n");
        png_destroy_write_struct(&png_ptr, NULL);
        return 0;
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        fprintf(stderr, "PNG: Error during write\n");
        png_destroy_write_struct(&png_ptr, &info_ptr);
        if (*out_data) { free(*out_data); *out_data = NULL; }
        return 0;
    }

    // Используем пользовательскую функцию записи в память
    struct mem_write_struct mem_dst = {NULL, 0, 0};

    png_set_write_fn(png_ptr, &mem_dst, png_mem_write_data, png_mem_flush_data);

    png_set_IHDR(png_ptr, info_ptr, in_img->w, in_img->h, 8, PNG_COLOR_TYPE_RGBA, PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);

    png_write_info(png_ptr, info_ptr);

    // Write rows
    png_bytep *row_pointers = (png_bytep*)malloc(in_img->h * sizeof(png_bytep));
    if (!row_pointers) {
         fprintf(stderr, "PNG: Could not allocate row pointers memory for encoding\n");
         png_destroy_write_struct(&png_ptr, &info_ptr);
         return 0;
    }
    for (int y = 0; y < in_img->h; y++) {
        row_pointers[y] = (png_bytep)(in_img->pixels + y * in_img->w);
    }
    png_write_image(png_ptr, row_pointers);
    free(row_pointers);

    png_write_end(png_ptr, info_ptr);

    *out_data = mem_dst.data;
    *out_len = mem_dst.size;

    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 1;
}
// --- КОНЕЦ НОВОЙ ФУНКЦИИ ---


// --- НОВАЯ ФУНКЦИЯ: ОБРЕЗКА ПО ХРОМАКЕЮ С ДОПУСКОМ ---
RGBAImage* chroma_key_crop_image(RGBAImage *src_img, int x, int y, float tolerance_percent) {
    if (!src_img || !src_img->pixels || x < 0 || x >= src_img->w || y < 0 || y >= src_img->h) {
        fprintf(stderr, "Chroma Key Crop: Invalid input or coordinates\n");
        return NULL;
    }
    if (tolerance_percent < 0.0f || tolerance_percent > 100.0f) {
        fprintf(stderr, "Chroma Key Crop: Tolerance must be between 0.0 and 100.0\n");
        return NULL;
    }

    uint32_t chroma_color = src_img->pixels[y * src_img->w + x];
    uint32_t R_mask = 0x000000FF;
    uint32_t G_mask = 0x0000FF00;
    uint32_t B_mask = 0x00FF0000;
    uint32_t A_mask = 0xFF000000; // Альфа-канал

    uint8_t cr = (chroma_color & R_mask);
    uint8_t cg = (chroma_color & G_mask) >> 8;
    uint8_t cb = (chroma_color & B_mask) >> 16;

    // Вычисляем максимальную допустимую разницу для каждой компоненты
    uint8_t max_diff = (uint8_t)((tolerance_percent / 100.0) * 255.0);

    // Проход 1: Найти границы и отметить пиксели хромакея как прозрачные
    int min_x = src_img->w, max_x = -1;
    int min_y = src_img->h, max_y = -1;

    for (int py = 0; py < src_img->h; py++) {
        for (int px = 0; px < src_img->w; px++) {
            int idx = py * src_img->w + px;
            uint32_t pixel = src_img->pixels[idx];
            uint8_t pr = (pixel & R_mask);
            uint8_t pg = (pixel & G_mask) >> 8;
            uint8_t pb = (pixel & B_mask) >> 16;
            // uint8_t pa = (pixel & A_mask) >> 24; // Получаем текущий альфа-канал (не используется напрямую)

            // Проверяем, находится ли пиксель в пределах допуска от цвета хромакея
            if (abs(pr - cr) <= max_diff && abs(pg - cg) <= max_diff && abs(pb - cb) <= max_diff) {
                // Это пиксель хромакея - делаем его прозрачным (альфа = 0)
                src_img->pixels[idx] &= 0x00FFFFFF; // Оставляем только RGB, устанавливаем альфа = 0
            } else {
                // Это не пиксель хромакея - он видимый
                if (px < min_x) min_x = px;
                if (px > max_x) max_x = px;
                if (py < min_y) min_y = py;
                if (py > max_y) max_y = py;
            }
        }
    }

    if (min_x > max_x || min_y > max_y) {
        // Изображение состоит только из цвета хромакея или пустое
        fprintf(stderr, "Chroma Key Crop: No non-chroma pixels found. Creating 1x1 transparent image.\n");
        RGBAImage *cropped = (RGBAImage*)malloc(sizeof(RGBAImage));
        if (!cropped) return NULL;
        cropped->w = 1; cropped->h = 1;
        cropped->pixels = (uint32_t*)malloc(sizeof(uint32_t));
        if (!cropped->pixels) { free(cropped); return NULL; }
        cropped->pixels[0] = 0x00000000; // Полностью прозрачный пиксель
        return cropped;
    }

    int new_w = max_x - min_x + 1;
    int new_h = max_y - min_y + 1;

    RGBAImage *cropped = (RGBAImage*)malloc(sizeof(RGBAImage));
    if (!cropped) return NULL;
    cropped->w = new_w;
    cropped->h = new_h;
    cropped->pixels = (uint32_t*)malloc(new_w * new_h * sizeof(uint32_t));
    if (!cropped->pixels) { free(cropped); return NULL; }

    // Проход 2: Скопировать область из исходного изображения
    for (int cy = 0; cy < new_h; cy++) {
        for (int cx = 0; cx < new_w; cx++) {
            int sy = min_y + cy;
            int sx = min_x + cx;
            int src_idx = sy * src_img->w + sx;
            cropped->pixels[cy * new_w + cx] = src_img->pixels[src_idx];
        }
    }

    return cropped;
}
// --- КОНЕЦ НОВОЙ ФУНКЦИИ ---


// --- НОВАЯ ФУНКЦИЯ: МАСШТАБИРОВАНИЕ ИЗОБРАЖЕНИЯ ---
RGBAImage* scale_image(RGBAImage *src_img, int new_width, int new_height) {
    if (!src_img || !src_img->pixels || new_width <= 0 || new_height <= 0) {
        fprintf(stderr, "Scale Image: Invalid input or target dimensions\n");
        return NULL;
    }

    RGBAImage *scaled = (RGBAImage*)malloc(sizeof(RGBAImage));
    if (!scaled) return NULL;
    scaled->w = new_width;
    scaled->h = new_height;
    scaled->pixels = (uint32_t*)malloc(new_width * new_height * sizeof(uint32_t));
    if (!scaled->pixels) { free(scaled); return NULL; }

    double x_ratio = (double)src_img->w / new_width;
    double y_ratio = (double)src_img->h / new_height;

    for (int dy = 0; dy < new_height; dy++) {
        for (int dx = 0; dx < new_width; dx++) {
            int sx = (int)(dx * x_ratio);
            int sy = (int)(dy * y_ratio);
            // Clamp to avoid out-of-bounds access if rounding causes issues
            if (sx >= src_img->w) sx = src_img->w - 1;
            if (sy >= src_img->h) sy = src_img->h - 1;
            scaled->pixels[dy * new_width + dx] = src_img->pixels[sy * src_img->w + sx];
        }
    }

    return scaled;
}
// --- КОНЕЦ НОВОЙ ФУНКЦИИ ---


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
            out->img.internal_img = NULL; // Инициализация
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
    out->img.internal_img = NULL; // Инициализация
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
    // Приоритет у internal_img, если он существует
    RGBAImage *img_to_save = v->img.internal_img;
    if (!img_to_save) {
        if (!v->img.b64) {
            fprintf(stderr, "save_img: No base64 data and no internal image to save for variable '%s'.\n", v->name);
            return;
        }
        // Если есть только base64, декодируем его в временный RGBAImage
        unsigned char* decoded_data = NULL;
        size_t decoded_len = 0;
        if (!base64_decode(v->img.b64, &decoded_data, &decoded_len)) {
            fprintf(stderr, "save_img: Failed to decode base64 data for '%s'. Check previous error messages.\n", v->name);
            return;
        }

        RGBAImage temp_img = {0};
        if (!decode_png_from_memory(decoded_data, decoded_len, &temp_img)) {
            fprintf(stderr, "save_img: Failed to decode PNG from base64 data for '%s'.\n", v->name);
            free(decoded_data);
            return;
        }
        free(decoded_data); // Буфер больше не нужен

        // Теперь кодируем временный RGBAImage обратно в PNG
        unsigned char* encoded_data = NULL;
        size_t encoded_len = 0;
        if (!encode_png_to_memory(&temp_img, &encoded_data, &encoded_len)) {
             fprintf(stderr, "save_img: Failed to encode PNG data for saving '%s'.\n", v->name);
             free_rgba_image(&temp_img);
             return;
        }
        free_rgba_image(&temp_img); // Освобождаем временный буфер пикселей

        // Сохраняем закодированные PNG данные в файл
        char relnorm[MAX_PATH_LEN];
        normalize_relpath(relnorm, sizeof(relnorm), relpath);
        char abs[MAX_PATH_LEN];
        snprintf(abs, sizeof(abs), "%s\\%s", base_dir, relnorm);
        make_dirs_for_path(abs);

        FILE *f = fopen(abs, "wb");
        if (!f) {
            fprintf(stderr, "save_img: Cannot open file for writing '%s'. Error: %s\n", abs, strerror(errno));
            free(encoded_data);
            return;
        }
        size_t written = fwrite(encoded_data, 1, encoded_len, f);
        free(encoded_data);
        if (written != encoded_len) {
            fprintf(stderr, "save_img: Failed to write complete image data to '%s'. Expected: %zu, Written: %zu. Error: %s\n",
                abs, encoded_len, written, ferror(f) ? strerror(errno) : "Unknown error");
            fclose(f);
            return;
        }
        fclose(f);

        // Устанавливаем пути и статус
        strncpy(v->img.path, relnorm, sizeof(v->img.path)-1);
        v->img.path[sizeof(v->img.path)-1] = 0;
        v->img.saved = 1;
        printf("Successfully saved image to %s\n", abs);
        return; // Выходим после сохранения из base64
    }

    // Если internal_img существует, кодируем его и сохраняем
    unsigned char* encoded_data = NULL;
    size_t encoded_len = 0;
    if (!encode_png_to_memory(img_to_save, &encoded_data, &encoded_len)) {
         fprintf(stderr, "save_img: Failed to encode internal PNG data for saving '%s'.\n", v->name);
         return;
    }

    char relnorm[MAX_PATH_LEN];
    normalize_relpath(relnorm, sizeof(relnorm), relpath);
    char abs[MAX_PATH_LEN];
    snprintf(abs, sizeof(abs), "%s\\%s", base_dir, relnorm);
    make_dirs_for_path(abs);

    FILE *f = fopen(abs, "wb");
    if (!f) {
        fprintf(stderr, "save_img: Cannot open file for writing '%s'. Error: %s\n", abs, strerror(errno));
        free(encoded_data);
        return;
    }
    size_t written = fwrite(encoded_data, 1, encoded_len, f);
    free(encoded_data);
    if (written != encoded_len) {
        fprintf(stderr, "save_img: Failed to write complete image data to '%s'. Expected: %zu, Written: %zu. Error: %s\n",
            abs, encoded_len, written, ferror(f) ? strerror(errno) : "Unknown error");
        fclose(f);
        return;
    }
    fclose(f);

    // Устанавливаем пути и статус
    strncpy(v->img.path, relnorm, sizeof(v->img.path)-1);
    v->img.path[sizeof(v->img.path)-1] = 0;
    v->img.saved = 1;
    printf("Successfully saved processed image to %s\n", abs);
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

// --- НОВАЯ ФУНКЦИЯ: ПРОЦЕССИНГ CHROMA_KEY_CROP С ДОПУСКОМ ---
void process_chroma_key_crop(const char *line) {
    char varname[128], src_varname[128];
    int x, y;
    float tolerance = 0.0f; // По умолчанию 0%
    // Пытаемся распарсить вызов с тремя или четырьмя аргументами
    int args_parsed = sscanf(line, "var %127s = chroma_key_crop(%127[^,], %d, %d, %f)", varname, src_varname, &x, &y, &tolerance);
    if (args_parsed < 4) {
         // Попробуем парсинг с тремя аргументами (без допуска)
         args_parsed = sscanf(line, "var %127s = chroma_key_crop(%127[^,], %d, %d)", varname, src_varname, &x, &y);
         if (args_parsed != 4) {
              fprintf(stderr, "chroma_key_crop: Invalid syntax. Expected: var name = chroma_key_crop(src_var, x, y) or var name = chroma_key_crop(src_var, x, y, tolerance_percent)\n");
              return;
         }
         // tolerance уже инициализирован 0.0f
    }

    Var *src_var = get_var(src_varname);
    if (!src_var || src_var->type != VAR_IMAGE) {
        fprintf(stderr, "chroma_key_crop: Source variable '%s' is not an image.\n", src_varname);
        return;
    }

    Var *dst_var = create_var_if_missing(varname);
    if (!dst_var) {
        fprintf(stderr, "chroma_key_crop: Could not create destination variable '%s'.\n", varname);
        return;
    }

    // Убедимся, что внутреннее изображение загружено
    if (!src_var->img.internal_img && src_var->img.b64) {
        unsigned char* decoded_data = NULL;
        size_t decoded_len = 0;
        if (!base64_decode(src_var->img.b64, &decoded_data, &decoded_len)) {
            fprintf(stderr, "chroma_key_crop: Failed to decode base64 data for source '%s'.\n", src_varname);
            return;
        }
        RGBAImage *temp_img = (RGBAImage*)malloc(sizeof(RGBAImage));
        if (!temp_img) {
             fprintf(stderr, "chroma_key_crop: Memory allocation failed for temporary image.\n");
             free(decoded_data);
             return;
        }
        memset(temp_img, 0, sizeof(RGBAImage)); // Инициализируем поля
        if (!decode_png_from_memory(decoded_data, decoded_len, temp_img)) {
            fprintf(stderr, "chroma_key_crop: Failed to decode PNG from base64 data for source '%s'.\n", src_varname);
            free(decoded_data);
            free(temp_img);
            return;
        }
        free(decoded_data);
        src_var->img.internal_img = temp_img;
    }

    if (!src_var->img.internal_img) {
        fprintf(stderr, "chroma_key_crop: Source variable '%s' has no internal image data.\n", src_varname);
        return;
    }

    // Создаём копию изображения перед обработкой, чтобы не изменять оригинал
    RGBAImage *src_copy = (RGBAImage*)malloc(sizeof(RGBAImage));
    if (!src_copy) {
         fprintf(stderr, "chroma_key_crop: Memory allocation failed for source image copy.\n");
         return;
    }
    src_copy->w = src_var->img.internal_img->w;
    src_copy->h = src_var->img.internal_img->h;
    src_copy->pixels = (uint32_t*)malloc(src_copy->w * src_copy->h * sizeof(uint32_t));
    if (!src_copy->pixels) {
         fprintf(stderr, "chroma_key_crop: Memory allocation failed for source image pixel copy.\n");
         free(src_copy);
         return;
    }
    memcpy(src_copy->pixels, src_var->img.internal_img->pixels, src_copy->w * src_copy->h * sizeof(uint32_t));

    RGBAImage *cropped_img = chroma_key_crop_image(src_copy, x, y, tolerance);
    // Освобождаем копию сразу после обработки
    free_rgba_image(src_copy);
    free(src_copy);

    if (!cropped_img) {
        fprintf(stderr, "chroma_key_crop: Failed to crop image from variable '%s'.\n", src_varname);
        return;
    }

    // Очищаем старое внутреннее изображение в dst_var, если есть
    if (dst_var->img.internal_img) {
        free_rgba_image(dst_var->img.internal_img);
        free(dst_var->img.internal_img);
        dst_var->img.internal_img = NULL;
    }
    // Очищаем старые base64 данные, если они есть
    if (dst_var->img.b64) {
        free(dst_var->img.b64);
        dst_var->img.b64 = NULL;
    }

    dst_var->type = VAR_IMAGE;
    dst_var->img.internal_img = cropped_img;
    dst_var->img.w = cropped_img->w;
    dst_var->img.h = cropped_img->h;
    dst_var->img.b64 = NULL; // b64 теперь неактуален, используется internal_img
    dst_var->img.saved = 0;
    dst_var->img.path[0] = 0;

    printf("Successfully created cropped image variable '%s' (%dx%d) with tolerance %.2f%%\n", varname, cropped_img->w, cropped_img->h, tolerance);
}
// --- КОНЕЦ НОВОЙ ФУНКЦИИ ---

// --- НОВАЯ ФУНКЦИЯ: ПРОЦЕССИНГ SCALE_TO ---
void process_scale_to(const char *line) {
    char varname[128], src_varname[128];
    int width, height;
    if (sscanf(line, "var %127s = scale_to(%127[^,], %d, %d)", varname, src_varname, &width, &height) == 4) {
        Var *src_var = get_var(src_varname);
        if (!src_var || src_var->type != VAR_IMAGE) {
            fprintf(stderr, "scale_to: Source variable '%s' is not an image.\n", src_varname);
            return;
        }

        Var *dst_var = create_var_if_missing(varname);
        if (!dst_var) {
            fprintf(stderr, "scale_to: Could not create destination variable '%s'.\n", varname);
            return;
        }

        // Убедимся, что внутреннее изображение загружено
        if (!src_var->img.internal_img && src_var->img.b64) {
            unsigned char* decoded_data = NULL;
            size_t decoded_len = 0;
            if (!base64_decode(src_var->img.b64, &decoded_data, &decoded_len)) {
                fprintf(stderr, "scale_to: Failed to decode base64 data for source '%s'.\n", src_varname);
                return;
            }
            RGBAImage *temp_img = (RGBAImage*)malloc(sizeof(RGBAImage));
            if (!temp_img) {
                 fprintf(stderr, "scale_to: Memory allocation failed for temporary image.\n");
                 free(decoded_data);
                 return;
            }
            memset(temp_img, 0, sizeof(RGBAImage)); // Инициализируем поля
            if (!decode_png_from_memory(decoded_data, decoded_len, temp_img)) {
                fprintf(stderr, "scale_to: Failed to decode PNG from base64 data for source '%s'.\n", src_varname);
                free(decoded_data);
                free(temp_img);
                return;
            }
            free(decoded_data);
            src_var->img.internal_img = temp_img;
        }

        if (!src_var->img.internal_img) {
            fprintf(stderr, "scale_to: Source variable '%s' has no internal image data.\n", src_varname);
            return;
        }

        RGBAImage *scaled_img = scale_image(src_var->img.internal_img, width, height);
        if (!scaled_img) {
            fprintf(stderr, "scale_to: Failed to scale image from variable '%s'.\n", src_varname);
            return;
        }

        // Очищаем старое внутреннее изображение в dst_var, если есть
        if (dst_var->img.internal_img) {
            free_rgba_image(dst_var->img.internal_img);
            free(dst_var->img.internal_img);
            dst_var->img.internal_img = NULL;
        }
        // Очищаем старые base64 данные, если они есть
        if (dst_var->img.b64) {
            free(dst_var->img.b64);
            dst_var->img.b64 = NULL;
        }

        dst_var->type = VAR_IMAGE;
        dst_var->img.internal_img = scaled_img;
        dst_var->img.w = scaled_img->w;
        dst_var->img.h = scaled_img->h;
        dst_var->img.b64 = NULL; // b64 теперь неактуален, используется internal_img
        dst_var->img.saved = 0;
        dst_var->img.path[0] = 0;

        printf("Successfully created scaled image variable '%s' (%dx%d)\n", varname, scaled_img->w, scaled_img->h);
    }
}
// --- КОНЕЦ НОВОЙ ФУНКЦИИ ---


/* ---------------- Script parsing & execution ----------------
Добавлены:
- if <var> == <value> / if <var> > <num> ...  (только для простоты однословных значений)
- repeat N { ... } .. } блок с поддержкой "break"
- команды: emit_c("relpath") для записи embedded C-кода
- set_server("http://localhost:5001") to change API server
- chroma_key_crop(var, x, y, tolerance) и scale_to(var, width, height)
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
                    v->type = VAR_IMAGE; v->img.b64 = NULL; v->img.w = w; v->img.h = h; v->img.saved = 0; v->img.internal_img = NULL;
                }
                i++; continue;
            }

            // --- ДОБАВЛЕНО: Обработка chroma_key_crop ---
            if (strstr(l, "chroma_key_crop(")) {
                process_chroma_key_crop(l);
                i++; continue;
            }
            // --- КОНЕЦ ДОБАВЛЕНИЯ ---

            // --- ДОБАВЛЕНО: Обработка scale_to ---
            if (strstr(l, "scale_to(")) {
                process_scale_to(l);
                i++; continue;
            }
            // --- КОНЕЦ ДОБАВЛЕНИЯ ---

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
            // Fixed sscanf format string: removed newline character and corrected syntax
            if (sscanf(l, "if %127s %7s %255s", varname, op, rhs) >= 2) {
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
    // Use shlwapi function to remove filename part
    PathRemoveFileSpecA(full);
    strncpy(base_dir, full, sizeof(base_dir)-1);
    base_dir[sizeof(base_dir)-1] = 0;

    // small demo: push some demo array items
    array_push_demo("first");
    array_push_demo("second");

    // demo of to_upper_str
    char *u = to_upper_str("demo"); if (u) { array_push_demo(u); free(u); }

    parse_and_run_script(argv[1]);

    // at exit: save embedded code automatically to base_dir\embedded\snippet.c
    save_embedded_c_code("embedded\\snippet.c");

    // cleanup allocated base64 strings and internal images
    for (int i = 0; i < var_count; ++i) {
        if (vars[i].type == VAR_IMAGE) {
            if (vars[i].img.b64) {
                free(vars[i].img.b64);
                vars[i].img.b64 = NULL;
            }
            if (vars[i].img.internal_img) {
                free_rgba_image(vars[i].img.internal_img);
                free(vars[i].img.internal_img);
                vars[i].img.internal_img = NULL;
            }
        }
    }
    for (int i = 0; i < line_count; ++i) free(lines[i]);
    for (int i = 0; i < demo_array_len; ++i) free(demo_array[i]);
    return 0;
}