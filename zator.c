#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include <math.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>
#define _GNU_SOURCE
#include <string.h>
#include <png.h>
#include <setjmp.h>

/* ---------------- Constants ---------------- */
#define MAX_LINES 8192
#define MAX_LINE 4096
#define MAX_VARS 1024
#define MAX_PATH_LEN 4096
#define MAX_FUNC_PARAMS 10
#define MAX_FUNC_LINES 512

/* ---------------- Types ---------------- */
typedef struct {
    uint32_t *pixels;
    int w, h;
} RGBAImage;

typedef enum { VAR_INT = 0, VAR_STRING = 1, VAR_IMAGE = 2 } VarType;

typedef struct {
    char *b64;
    int w, h;
    char path[MAX_PATH_LEN];
    int saved;
    RGBAImage *internal_img;
} Image;

typedef struct {
    char name[128];
    VarType type;
    int iv;
    char sv[32768];
    Image img;
} Var;

typedef struct {
    char name[128];
    char *lines[MAX_FUNC_LINES];
    int num_lines;
    int active;
    char params[MAX_FUNC_PARAMS][128];
    int param_count;
} FuncDef;

/* ---------------- Globals ---------------- */
char *lines[MAX_LINES];
int line_count = 0;
Var vars[MAX_VARS];
int var_count = 0;
char context_str[8192] = "";
char base_dir[MAX_PATH_LEN] = "";
char api_server[256] = "http://localhost:5001";
FuncDef funcs[MAX_VARS];
int func_count = 0;

/* ---------------- Forward Declarations ---------------- */
void execute_line_command(const char *l);
void parse_and_run_script_recursive(const char *script_path, const char *base_dir_for_this_script);
void process_func_call(const char *line, int call_index);
void process_func_def(const char *line, int start_index);

/* ---------------- Utilities ---------------- */
static char *safe_strdup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char *r = (char *)malloc(n + 1);
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

int is_import_line(const char *line) {
    char trimmed_line[MAX_LINE];
    strncpy(trimmed_line, line, sizeof(trimmed_line) - 1);
    trimmed_line[sizeof(trimmed_line) - 1] = '\0';
    char *trimmed = trim(trimmed_line);
    return starts_with(trimmed, "#import");
}

Var* get_var(const char *name) {
    if (!name) return NULL;
    for (int i = 0; i < var_count; ++i) {
        if (strcmp(vars[i].name, name) == 0) return &vars[i];
    }
    return NULL;
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
    v->img.internal_img = NULL;
    return v;
}

FuncDef* get_func(const char *name) {
    if (!name) return NULL;
    for (int i = 0; i < func_count; ++i) {
        if (strcmp(funcs[i].name, name) == 0) return &funcs[i];
    }
    return NULL;
}

/* ---------------- Escaping / Unescaping ---------------- */
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
            src++;
        } else {
            *d++ = c; left--;
        }
        src++;
    }
    *d = 0;
}

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

/* ---------------- f-string implementation ---------------- */
const char *var_to_string(const Var *v, char *buf, size_t buflen) {
    if (!v) { buf[0] = 0; return buf; }
    if (v->type == VAR_STRING) {
        strncpy(buf, v->sv, buflen-1);
        buf[buflen-1] = 0;
        return buf;
    } else if (v->type == VAR_INT) {
        snprintf(buf, (int)buflen, "%d", v->iv);
        buf[buflen-1] = 0;
        return buf;
    } else if (v->type == VAR_IMAGE) {
        if (v->img.saved && v->img.path[0]) {
            strncpy(buf, v->img.path, buflen-1); buf[buflen-1] = 0;
        } else {
            strncpy(buf, "", buflen-1); buf[buflen-1] = 0;
        }
        return buf;
    }
    buf[0] = 0;
    return buf;
}

void render_fstring_with_map(const char *fmt, const char **keys, const char **values, int nkeys, char *out, size_t outlen) {
    if (!fmt || !out || outlen == 0) return;
    char *d = out;
    size_t left = outlen - 1;
    const char *p = fmt;
    while (*p && left > 0) {
        if (*p == '\\') {
            if (*(p+1) == '{') { if (left > 0) { *d++ = '{'; left--; } p += 2; continue; }
            if (*(p+1) == '}') { if (left > 0) { *d++ = '}'; left--; } p += 2; continue; }
            if (*(p+1) == '\\') { if (left > 0) { *d++ = '\\'; left--; } p += 2; continue; }
            if (left > 0) { *d++ = *p++; left--; }
        } else if (*p == '{') {
            const char *q = p + 1;
            const char *start = q;
            while (*q && *q != '}') q++;
            if (*q != '}') {
                if (left > 0) { *d++ = *p; left--; p++; }
            } else {
                size_t keylen = (size_t)(q - start);
                char key[512]; if (keylen >= sizeof(key)) keylen = sizeof(key)-1;
                memcpy(key, start, keylen); key[keylen] = 0;
                char *kstart = key;
                while (*kstart && isspace((unsigned char)*kstart)) kstart++;
                char *kend = key + strlen(key) - 1;
                while (kend > kstart && isspace((unsigned char)*kend)) { *kend = 0; kend--; }
                const char *replacement = NULL;
                for (int i = 0; i < nkeys; ++i) {
                    if (keys[i] && strcmp(keys[i], kstart) == 0) { replacement = values[i]; break; }
                }
                char tmpbuf[65536];
                if (!replacement) {
                    Var *v = get_var(kstart);
                    if (v) replacement = var_to_string(v, tmpbuf, sizeof(tmpbuf));
                }
                if (!replacement) replacement = "";
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
    for (char *p = tmp; *p; ++p) if (*p == '\\') *p = '/';
    char *p = tmp;
    if (tmp[0] == '/') p++;
    char *next_slash = p;
    while ((next_slash = strchr(next_slash, '/')) != NULL) {
        *next_slash = 0;
        if (access(tmp, F_OK) != 0) {
            #ifdef _WIN32
                if (mkdir(tmp) != 0 && errno != EEXIST) {
            #else
                if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
            #endif
            fprintf(stderr, "Failed to create directory %s: %s\n", tmp, strerror(errno));
            }
        }
        *next_slash = '/';
        next_slash++;
    }
    if (access(tmp, F_OK) != 0) {
        #ifdef _WIN32
            if (mkdir(tmp) != 0 && errno != EEXIST) {
        #else
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        #endif
        fprintf(stderr, "Failed to create directory %s: %s\n", tmp, strerror(errno));
        }
    }
}

void normalize_relpath(char *dst, size_t dstlen, const char *rel) {
    if (!dst || !rel) return;
    size_t j = 0;
    size_t i = 0;
    if ((rel[0] == '.' && (rel[1] == '/' || rel[1] == '\\')) ) i = 2;
    while (rel[i] && j + 1 < dstlen) {
        char c = rel[i++];
        if (c == '\\') c = '/';
        if (j == 0 && (c == '/')) continue;
        dst[j++] = c;
    }
    dst[j] = 0;
}

/* ---------------- Exec command ---------------- */
void exec_cmd_capture(const char *cmd, char *outbuf, int outbufsz) {
    if (!cmd || !outbuf || outbufsz <= 0) return;
    outbuf[0] = 0;
    FILE *pipe = popen(cmd, "r");
    if (!pipe) {
        fprintf(stderr, "popen failed: %s\n", strerror(errno));
        return;
    }
    int total = 0;
    char *ptr = outbuf;
    int remaining = outbufsz - 1;
    int chunk_size = 1024;
    char chunk[chunk_size];
    while (remaining > 0 && fgets(chunk, (remaining < chunk_size ? remaining : chunk_size), pipe)) {
        int len = strlen(chunk);
        if (len > remaining) len = remaining;
        memcpy(ptr, chunk, len);
        ptr += len;
        total += len;
        remaining -= len;
    }
    if (remaining <= 0) {
        fprintf(stderr, "Output buffer too small for command result.\n");
    }
    *ptr = 0;
    int status = pclose(pipe);
    if (status == -1) {
        fprintf(stderr, "pclose failed: %s\n", strerror(errno));
    }
}

/* ---------------- File write helpers ---------------- */
void write_utf8_file(const char *name, const char *data) {
    FILE *f = fopen(name, "wb");
    if (!f) { fprintf(stderr, "Failed to write %s\n", name); return; }
    fwrite(data, 1, strlen(data), f);
    fclose(f);
}

void free_rgba_image(RGBAImage *img) {
    if (img && img->pixels) {
        free(img->pixels);
        img->pixels = NULL;
        img->w = 0;
        img->h = 0;
    }
}

/* ---------------- PNG Functions ---------------- */
struct mem_read_struct {
    unsigned char *data;
    size_t offset;
    size_t size;
};

void png_mem_read_data(png_structp png_ptr, png_bytep data, png_size_t length) {
    struct mem_read_struct *src = (struct mem_read_struct *)png_get_io_ptr(png_ptr);
    if (src->offset + length > src->size) {
        png_error(png_ptr, "Read Error: Out of bounds");
        return;
    }
    memcpy(data, src->data + src->offset, length);
    src->offset += length;
}

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
    struct mem_read_struct mem_src;
    mem_src.data = in_data;
    mem_src.offset = 0;
    mem_src.size = in_len;
    png_set_read_fn(png_ptr, &mem_src, png_mem_read_data);
    png_read_info(png_ptr, info_ptr);
    png_uint_32 width, height;
    int bit_depth, color_type, interlace_type;
    png_get_IHDR(png_ptr, info_ptr, &width, &height, &bit_depth, &color_type, &interlace_type, NULL, NULL);
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
    png_set_filler(png_ptr, 0xff, PNG_FILLER_AFTER);
    png_read_update_info(png_ptr, info_ptr);
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

struct mem_write_struct {
    unsigned char *data;
    size_t size;
    size_t alloc_size;
};

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
    struct mem_write_struct mem_dst = {NULL, 0, 0};
    png_set_write_fn(png_ptr, &mem_dst, png_mem_write_data, png_mem_flush_data);
    png_set_IHDR(png_ptr, info_ptr, in_img->w, in_img->h, 8, PNG_COLOR_TYPE_RGBA, PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
    png_write_info(png_ptr, info_ptr);
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
    uint8_t cr = (chroma_color & R_mask);
    uint8_t cg = (chroma_color & G_mask) >> 8;
    uint8_t cb = (chroma_color & B_mask) >> 16;
    uint8_t max_diff = (uint8_t)((tolerance_percent / 100.0) * 255.0);
    int min_x = src_img->w, max_x = -1;
    int min_y = src_img->h, max_y = -1;
    for (int py = 0; py < src_img->h; py++) {
        for (int px = 0; px < src_img->w; px++) {
            int idx = py * src_img->w + px;
            uint32_t pixel = src_img->pixels[idx];
            uint8_t pr = (pixel & R_mask);
            uint8_t pg = (pixel & G_mask) >> 8;
            uint8_t pb = (pixel & B_mask) >> 16;
            if (abs(pr - cr) <= max_diff && abs(pg - cg) <= max_diff && abs(pb - cb) <= max_diff) {
                src_img->pixels[idx] &= 0x00FFFFFF;
            } else {
                if (px < min_x) min_x = px;
                if (px > max_x) max_x = px;
                if (py < min_y) min_y = py;
                if (py > max_y) max_y = py;
            }
        }
    }
    if (min_x > max_x || min_y > max_y) {
        fprintf(stderr, "Chroma Key Crop: No non-chroma pixels found. Creating 1x1 transparent image.\n");
        RGBAImage *cropped = (RGBAImage*)malloc(sizeof(RGBAImage));
        if (!cropped) return NULL;
        cropped->w = 1; cropped->h = 1;
        cropped->pixels = (uint32_t*)malloc(sizeof(uint32_t));
        if (!cropped->pixels) { free(cropped); return NULL; }
        cropped->pixels[0] = 0x00000000;
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
            if (sx >= src_img->w) sx = src_img->w - 1;
            if (sy >= src_img->h) sy = src_img->h - 1;
            scaled->pixels[dy * new_width + dx] = src_img->pixels[sy * src_img->w + sx];
        }
    }
    return scaled;
}

/* ---------------- Generation functions ---------------- */
void gen_text_var(Var *out, const char *prompt, int max_length) {
    if (!out || !prompt) {
        if (out) {
            out->type = VAR_STRING;
            out->sv[0] = 0;
        }
        return;
    }
    char full_context[16384];
    snprintf(full_context, sizeof(full_context), "%s\n%s", context_str, prompt);
    char esc_prompt[16384];
    json_escape(full_context, esc_prompt, sizeof(esc_prompt));
    char json_req[24576];
    snprintf(json_req, sizeof(json_req),
        "{ "
        "\"prompt\": \"%s\", "
        "\"max_length\": %d, "
        "\"max_context_length\": 2048, "
        "\"temperature\": 0.7, "
        "\"top_p\": 0.9, "
        "\"top_k\": 100, "
        "\"rep_pen\": 1.1, "
        "\"use_default_badwordsids\": false "
        "}",
        esc_prompt, max_length);
    write_utf8_file("req.json", json_req);
    char resp[262144];
    snprintf(resp, sizeof(resp), "curl -s -X POST %s/api/v1/generate -H \"Content-Type: application/json\" --data-binary @req.json", api_server);
    exec_cmd_capture(resp, resp, sizeof(resp));
    extern char *extract_results_text(const char *json);
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
            out->img.internal_img = NULL;
        }
        return;
    }
    char escaped_prompt[8192];
    json_escape(prompt, escaped_prompt, sizeof(escaped_prompt));
    char json_req[16384];
    snprintf(json_req, sizeof(json_req),
        "{ "
        "\"prompt\": \"%s\", "
        "\"negative_prompt\": \"ugly, deformed, noisy, blurry, distorted\", "
        "\"width\": %d, "
        "\"height\": %d, "
        "\"sampler_name\": \"Euler a\", "
        "\"steps\": 20, "
        "\"cfg_scale\": 7.0, "
        "\"seed\": -1 "
        "}",
        escaped_prompt, width, height);
    write_utf8_file("img.json", json_req);
    char resp[1048576];
    snprintf(resp, sizeof(resp), "curl -s -X POST %s/sdapi/v1/txt2img -H \"Content-Type: application/json\" --data-binary @img.json", api_server);
    exec_cmd_capture(resp, resp, sizeof(resp));
    extern char *extract_first_image_b64(const char *json);
    char *b64 = extract_first_image_b64(resp);
    out->type = VAR_IMAGE;
    if (out->img.b64) { free(out->img.b64); out->img.b64 = NULL; }
    out->img.b64 = b64;
    out->img.w = width;
    out->img.h = height;
    out->img.saved = 0;
    out->img.path[0] = 0;
    out->img.internal_img = NULL;
    if (!b64) {
        fprintf(stderr, "Image generation failed. Response: %s\n", resp);
    }
}

/* ---------------- Base64 Decode ---------------- */
static int base64_decode(const char *input, unsigned char** output, size_t* output_len) {
    if (!input || !output || !output_len) {
        fprintf(stderr, "base64_decode: Input pointers are NULL.\n");
        return 0;
    }
    size_t len = strlen(input);
    if (len == 0) {
        fprintf(stderr, "base64_decode: Input string is empty.\n");
        return 0;
    }
    char *clean_input = (char *)malloc(len + 1);
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
    *output = (unsigned char*)malloc(expected_len + 1);
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
        if (c == '=') break;
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
    (*output)[out_idx] = 0;
    *output_len = out_idx;
    free(padded_input);
    return 1;
}

char *extract_first_image_b64(const char *json) {
    if (!json) return NULL;
    char *images = strstr((char *)json, "\"images\":");
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
    first_quote++;
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
    size_t clean_size = length + 1;
    char *clean = (char*)malloc(clean_size);
    if (!clean) {
        free(raw_b64);
        fprintf(stderr, "Memory allocation failed for cleaned base64 string.\n");
        return NULL;
    }
    size_t j = 0;
    for (size_t i = 0; i < length; i++) {
        if (raw_b64[i] == '\\') {
            i++;
            if (i < length) {
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
            }
        } else if (!isspace((unsigned char)raw_b64[i])) {
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

void save_img_var(Var *v, const char *relpath) {
    if (!v || v->type != VAR_IMAGE) {
        fprintf(stderr, "save_img: Variable is not an image.\n");
        return;
    }
    RGBAImage *img_to_save = v->img.internal_img;
    if (!img_to_save) {
        if (!v->img.b64) {
            fprintf(stderr, "save_img: No base64 data and no internal image to save for variable '%s'.\n", v->name);
            return;
        }
        unsigned char *decoded_data = NULL;
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
        free(decoded_data);
        unsigned char* encoded_data = NULL;
        size_t encoded_len = 0;
        if (!encode_png_to_memory(&temp_img, &encoded_data, &encoded_len)) {
             fprintf(stderr, "save_img: Failed to encode PNG data for saving '%s'.\n", v->name);
             free_rgba_image(&temp_img);
             return;
        }
        free_rgba_image(&temp_img);
        char relnorm[MAX_PATH_LEN];
        normalize_relpath(relnorm, sizeof(relnorm), relpath);
        char abs[MAX_PATH_LEN];
        snprintf(abs, sizeof(abs), "%s/%s", base_dir, relnorm);
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
        strncpy(v->img.path, relnorm, sizeof(v->img.path)-1);
        v->img.path[sizeof(v->img.path)-1] = 0;
        v->img.saved = 1;
        printf("Successfully saved image to %s\n", abs);
        return;
    }
    unsigned char* encoded_data = NULL;
    size_t encoded_len = 0;
    if (!encode_png_to_memory(img_to_save, &encoded_data, &encoded_len)) {
         fprintf(stderr, "save_img: Failed to encode internal PNG data for saving '%s'.\n", v->name);
         return;
    }
    char relnorm[MAX_PATH_LEN];
    normalize_relpath(relnorm, sizeof(relnorm), relpath);
    char abs[MAX_PATH_LEN];
    snprintf(abs, sizeof(abs), "%s/%s", base_dir, relnorm);
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
    snprintf(abs, sizeof(abs), "%s/%s", base_dir, relnorm);
    make_dirs_for_path(abs);
    FILE *f = fopen(abs, "wb");
    if (!f) { fprintf(stderr, "save_txt: cannot open %s\n", abs); return; }
    fwrite(v->sv, 1, strlen(v->sv), f);
    fclose(f);
}

/* ---------------- Print / Input ---------------- */
void do_print_arg(const char *arg) {
    if (!arg) return;
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
    Var *v = get_var(arg);
    if (!v) return;
    if (v->type == VAR_STRING) fputs(v->sv, stdout);
    else if (v->type == VAR_INT) {
        char buf[64];
        snprintf(buf, sizeof(buf), "%d", v->iv);
        fputs(buf, stdout);
    } else if (v->type == VAR_IMAGE) {
        if (v->img.saved && v->img.path[0]) fputs(v->img.path, stdout);
        else fputs("", stdout);
    }
}

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

/* ---------------- Embedded C code ---------------- */
const char *embedded_c_code =
"/* Пример встроенного кода на C */\n"
"#include <stdio.h>\n"
"int add(int a, int b) { return a + b; }\n"
"// Другие функции\n";

void save_embedded_c_code(const char *relpath) {
    char relnorm[MAX_PATH_LEN];
    normalize_relpath(relnorm, sizeof(relnorm), relpath);
    char abs[MAX_PATH_LEN];
    snprintf(abs, sizeof(abs), "%s/%s", base_dir, relnorm);
    make_dirs_for_path(abs);
    write_utf8_file(abs, embedded_c_code);
}

/* ---------------- JSON extract helpers ---------------- */
char *extract_json_string(const char *json, const char *key) {
    if (!json || !key) return NULL;
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    char *p = strstr(json, pattern);
    if (!p) return NULL;
    p += strlen(pattern);
    while (*p && *p != ':') p++;
    if (!*p) return NULL;
    p++;
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p != '"') {
        while (*p && *p != '"') p++;
        if (!*p) return NULL;
    }
    p++;
    const char *q = p;
    size_t cap = 4096;
    size_t len = 0;
    char *acc = (char *)malloc(cap);
    if (!acc) return NULL;
    while (*q) {
        if (*q == '"' && *(q - 1) != '\\') break;
        if (len + 1 >= cap) {
            cap *= 2;
            char *tmp = (char *)realloc(acc, cap);
            if (!tmp) { free(acc); return NULL; }
            acc = tmp;
        }
        acc[len++] = *q++;
    }
    acc[len] = 0;
    char *final = (char *)malloc(len + 1 + 8);
    if (!final) { free(acc); return NULL; }
    unescape_inplace(acc, final, len + 1 + 8);
    free(acc);
    return final;
}

char *extract_results_text(const char *json) {
    if (!json) return NULL;
    char *results = strstr((char *)json, "\"results\":");
    if (results) {
        char *text = strstr(results, "\"text\":");
        if (text) {
            return extract_json_string(text, "text");
        }
    }
    return extract_json_string(json, "text");
}

/* ---------------- REQUEST ---------------- */
void gen_request_var(Var *out, const char *url, const char *method, const char *body) {
    if (!out || !url || !method) {
        if (out) {
            out->type = VAR_STRING;
            out->sv[0] = 0;
        }
        return;
    }
    char curl_cmd[32768];
    if (strcmp(method, "POST") == 0) {
        if (body && strlen(body) > 0) {
            snprintf(curl_cmd, sizeof(curl_cmd),
                 "curl -s -X POST -H \"Content-Type: application/json\" -d '%s' \"%s\"",
                body, url);
        } else {
            snprintf(curl_cmd, sizeof(curl_cmd),
                 "curl -s -X POST \"%s\"",
                url);
        }
    } else if (strcmp(method, "PUT") == 0) {
        if (body && strlen(body) > 0) {
            snprintf(curl_cmd, sizeof(curl_cmd),
                 "curl -s -X PUT -H \"Content-Type: application/json\" -d '%s' \"%s\"",
                body, url);
        } else {
            snprintf(curl_cmd, sizeof(curl_cmd),
                 "curl -s -X PUT \"%s\"",
                url);
        }
    } else if (strcmp(method, "DELETE") == 0) {
        snprintf(curl_cmd, sizeof(curl_cmd),
             "curl -s -X DELETE \"%s\"",
            url);
    } else {
        snprintf(curl_cmd, sizeof(curl_cmd),
             "curl -s -X GET \"%s\"",
            url);
    }
    char resp[65536];
    exec_cmd_capture(curl_cmd, resp, sizeof(resp));
    out->type = VAR_STRING;
    strncpy(out->sv, resp, sizeof(out->sv)-1);
    out->sv[sizeof(out->sv)-1] = 0;
}

/* ---------------- EXEC_CMD ---------------- */
void process_exec_cmd(const char *line) {
    char varname[128], cmd[32768];
    
    // Format 1: var name = exec_cmd("command")
    if (sscanf(line, "var %127s = exec_cmd(%32767[^)])", varname, cmd) == 2) {
        char *p = cmd;
        while (*p && isspace((unsigned char)*p)) p++;
        char *end = p + strlen(p) - 1;
        while (end > p && isspace((unsigned char)*end)) { *end = 0; end--; }
        if (*p == '"' && end > p && *end == '"') {
            p++;
            *end = 0;
        }
        
        const char *keys[] = { "context" };
        const char *vals[] = { context_str };
        char rendered_cmd[32768];
        render_fstring_with_map(p, keys, vals, 1, rendered_cmd, sizeof(rendered_cmd));
        
        Var *v = create_var_if_missing(varname);
        if (!v) {
            fprintf(stderr, "exec_cmd: Could not create variable '%s'.\n", varname);
            return;
        }
        
        char output[65536];
        exec_cmd_capture(rendered_cmd, output, sizeof(output));
        
        v->type = VAR_STRING;
        strncpy(v->sv, output, sizeof(v->sv)-1);
        v->sv[sizeof(v->sv)-1] = 0;
        
        printf("exec_cmd: Executed '%s', output length: %zu\n", rendered_cmd, strlen(output));
    }
    // Format 2: exec_cmd("command", output_var)
    else if (sscanf(line, "exec_cmd(%32767[^,], %127[^)])", cmd, varname) == 2) {
        char *p = cmd;
        while (*p && isspace((unsigned char)*p)) p++;
        char *end = p + strlen(p) - 1;
        while (end > p && isspace((unsigned char)*end)) { *end = 0; end--; }
        if (*p == '"' && end > p && *end == '"') {
            p++;
            *end = 0;
        }
        
        char *vn = varname;
        while (*vn && isspace((unsigned char)*vn)) vn++;
        end = vn + strlen(vn) - 1;
        while (end > vn && isspace((unsigned char)*end)) { *end = 0; end--; }
        
        const char *keys[] = { "context" };
        const char *vals[] = { context_str };
        char rendered_cmd[32768];
        render_fstring_with_map(p, keys, vals, 1, rendered_cmd, sizeof(rendered_cmd));
        
        Var *v = create_var_if_missing(vn);
        if (!v) {
            fprintf(stderr, "exec_cmd: Could not create variable '%s'.\n", vn);
            return;
        }
        
        char output[65536];
        exec_cmd_capture(rendered_cmd, output, sizeof(output));
        
        v->type = VAR_STRING;
        strncpy(v->sv, output, sizeof(v->sv)-1);
        v->sv[sizeof(v->sv)-1] = 0;
        
        printf("exec_cmd: Executed '%s', output length: %zu\n", rendered_cmd, strlen(output));
    }
}

/* ---------------- Chroma Key Crop ---------------- */
void process_chroma_key_crop(const char *line) {
    char varname[128], src_varname[128];
    int x, y;
    float tolerance = 0.0f;
    int args_parsed = sscanf(line, "var %127s = chroma_key_crop(%127[^,], %d, %d, %f)", varname, src_varname, &x, &y, &tolerance);
    if (args_parsed < 4) {
        args_parsed = sscanf(line, "var %127s = chroma_key_crop(%127[^,], %d, %d)", varname, src_varname, &x, &y);
        if (args_parsed != 4) {
            fprintf(stderr, "chroma_key_crop: Invalid syntax.\n");
            return;
        }
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
    if (!src_var->img.internal_img && src_var->img.b64) {
        unsigned char* decoded_data = NULL;
        size_t decoded_len = 0;
        if (!base64_decode(src_var->img.b64, &decoded_data, &decoded_len)) {
            fprintf(stderr, "chroma_key_crop: Failed to decode base64 data for source '%s'.\n", src_varname);
            return;
        }
        RGBAImage *temp_img = (RGBAImage*)malloc(sizeof(RGBAImage));
        if (!temp_img) {
             fprintf(stderr, "chroma_key_crop: Memory allocation failed.\n");
             free(decoded_data);
             return;
        }
        memset(temp_img, 0, sizeof(RGBAImage));
        if (!decode_png_from_memory(decoded_data, decoded_len, temp_img)) {
            fprintf(stderr, "chroma_key_crop: Failed to decode PNG.\n");
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
    RGBAImage *src_copy = (RGBAImage*)malloc(sizeof(RGBAImage));
    if (!src_copy)  {
         fprintf(stderr, "chroma_key_crop: Memory allocation failed.\n");
         return;
    }
    src_copy->w = src_var->img.internal_img->w;
    src_copy->h = src_var->img.internal_img->h;
    src_copy->pixels = (uint32_t*)malloc(src_copy->w * src_copy->h * sizeof(uint32_t));
    if (!src_copy->pixels) {
         fprintf(stderr, "chroma_key_crop: Memory allocation failed.\n");
         free(src_copy);
         return;
    }
    memcpy(src_copy->pixels, src_var->img.internal_img->pixels, src_copy->w * src_copy->h * sizeof(uint32_t));
    RGBAImage *cropped_img = chroma_key_crop_image(src_copy, x, y, tolerance);
    free_rgba_image(src_copy);
    free(src_copy);
    if (!cropped_img) {
        fprintf(stderr, "chroma_key_crop: Failed to crop image.\n");
        return;
    }
    if (dst_var->img.internal_img) {
        free_rgba_image(dst_var->img.internal_img);
        free(dst_var->img.internal_img);
        dst_var->img.internal_img = NULL;
    }
    if (dst_var->img.b64) {
        free(dst_var->img.b64);
        dst_var->img.b64 = NULL;
    }
    dst_var->type = VAR_IMAGE;
    dst_var->img.internal_img = cropped_img;
    dst_var->img.w = cropped_img->w;
    dst_var->img.h = cropped_img->h;
    dst_var->img.b64 = NULL;
    dst_var->img.saved = 0;
    dst_var->img.path[0] = 0;
    printf("Successfully created cropped image variable '%s' (%dx%d)\n", varname, cropped_img->w, cropped_img->h);
}

/* ---------------- Scale To ---------------- */
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
        if (!src_var->img.internal_img && src_var->img.b64) {
            unsigned char* decoded_data = NULL;
            size_t decoded_len = 0;
            if (!base64_decode(src_var->img.b64, &decoded_data, &decoded_len)) {
                fprintf(stderr, "scale_to: Failed to decode base64 data.\n");
                return;
            }
            RGBAImage *temp_img = (RGBAImage*)malloc(sizeof(RGBAImage));
            if (!temp_img) {
                 fprintf(stderr, "scale_to: Memory allocation failed.\n");
                 free(decoded_data);
                 return;
            }
            memset(temp_img, 0, sizeof(RGBAImage));
            if (!decode_png_from_memory(decoded_data, decoded_len, temp_img)) {
                fprintf(stderr, "scale_to: Failed to decode PNG.\n");
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
            fprintf(stderr, "scale_to: Failed to scale image.\n");
            return;
        }
        if (dst_var->img.internal_img) {
            free_rgba_image(dst_var->img.internal_img);
            free(dst_var->img.internal_img);
            dst_var->img.internal_img = NULL;
        }
        if (dst_var->img.b64) {
            free(dst_var->img.b64);
            dst_var->img.b64 = NULL;
        }
        dst_var->type = VAR_IMAGE;
        dst_var->img.internal_img = scaled_img;
        dst_var->img.w = scaled_img->w;
        dst_var->img.h = scaled_img->h;
        dst_var->img.b64 = NULL;
        dst_var->img.saved = 0;
        dst_var->img.path[0] = 0;
        printf("Successfully created scaled image variable '%s' (%dx%d)\n", varname, scaled_img->w, scaled_img->h);
    }
}

/* ---------------- Function Definition with Parameters ---------------- */
void process_func_def(const char *line, int start_index) {
    char func_name[128], params_str[512];
    int has_params = 0;
    
    if (sscanf(line, "def %127[^ (](%511[^)])", func_name, params_str) == 2) {
        has_params = 1;
    } else if (sscanf(line, "def %127s", func_name) == 1) {
        has_params = 0;
        params_str[0] = 0;
    } else {
        fprintf(stderr, "def: Invalid syntax at line %d: %s\n", start_index + 1, line);
        return;
    }
    
    int j = start_index + 1;
    while (j < line_count && strcmp(lines[j], "{") != 0) j++;
    if (j >= line_count) {
        fprintf(stderr, "def: Missing '{' for function '%s'\n", func_name);
        return;
    }
    j++;
    
    int block_start = j;
    int block_end = block_start;
    int depth = 1;
    for (int k = block_start; k < line_count; ++k) {
        if (strcmp(lines[k], "{") == 0) depth++;
        else if (strcmp(lines[k], "}") == 0) {
            depth--;
            if (depth == 0) {
                block_end = k;
                break;
            }
        }
    }
    
    if (block_end <= block_start) {
        fprintf(stderr, "def: Empty or invalid function block for '%s'\n", func_name);
        return;
    }
    
    if (func_count >= MAX_VARS) {
        fprintf(stderr, "def: Too many functions defined.\n");
        return;
    }
    
    FuncDef *func = &funcs[func_count++];
    strncpy(func->name, func_name, sizeof(func->name) - 1);
    func->name[sizeof(func->name) - 1] = 0;
    func->num_lines = 0;
    func->active = 0;
    func->param_count = 0;
    
    if (has_params && strlen(params_str) > 0) {
        char *token = strtok(params_str, ",");
        while (token && func->param_count < MAX_FUNC_PARAMS) {
            char *p = token;
            while (*p && isspace((unsigned char)*p)) p++;
            char *end = p + strlen(p) - 1;
            while (end > p && isspace((unsigned char)*end)) { *end = 0; end--; }
            if (strlen(p) > 0) {
                strncpy(func->params[func->param_count], p, sizeof(func->params[0]) - 1);
                func->params[func->param_count][sizeof(func->params[0]) - 1] = 0;
                func->param_count++;
            }
            token = strtok(NULL, ",");
        }
    }
    
    for (int k = block_start; k < block_end; ++k) {
        if (func->num_lines < MAX_FUNC_LINES - 1) {
            func->lines[func->num_lines++] = safe_strdup(lines[k]);
        }
    }
    
    printf("def: Registered function '%s' with %d parameters\n", func_name, func->param_count);
}

/* ---------------- Function Call with Parameters ---------------- */
void process_func_call(const char *line, int call_index) {
    char func_name[128], args_str[4096];
    int has_args = 0;
    
    if (sscanf(line, "call %127[^ (](%4095[^)])", func_name, args_str) == 2) {
        has_args = 1;
    } else if (sscanf(line, "call %127s", func_name) == 1) {
        has_args = 0;
        args_str[0] = 0;
    } else {
        fprintf(stderr, "call: Invalid syntax at line %d: %s\n", call_index + 1, line);
        return;
    }
    
    FuncDef *func = get_func(func_name);
    if (!func) {
        fprintf(stderr, "call: Function '%s' not found.\n", func_name);
        return;
    }
    
    if (func->active) {
        fprintf(stderr, "call: Recursive call to function '%s' detected.\n", func_name);
        return;
    }
    
    char *arg_values[MAX_FUNC_PARAMS] = {NULL};
    int arg_count = 0;
    
    if (has_args && strlen(args_str) > 0) {
        char args_copy[4096];
        strncpy(args_copy, args_str, sizeof(args_copy) - 1);
        
        char *token = strtok(args_copy, ",");
        while (token && arg_count < MAX_FUNC_PARAMS) {
            char *p = token;
            while (*p && isspace((unsigned char)*p)) p++;
            char *end = p + strlen(p) - 1;
            while (end > p && isspace((unsigned char)*end)) { *end = 0; end--; }
            
            if (*p == '"' && end > p && *end == '"') {
                p++;
                *end = 0;
                end--;
            }
            
            if (strlen(p) > 0) {
                arg_values[arg_count] = safe_strdup(p);
                arg_count++;
            }
            token = strtok(NULL, ",");
        }
    }
    
    if (arg_count != func->param_count) {
        fprintf(stderr, "call: Function '%s' expects %d parameters, got %d.\n", 
                func_name, func->param_count, arg_count);
        for (int i = 0; i < arg_count; i++) {
            if (arg_values[i]) free(arg_values[i]);
        }
        return;
    }
    
    char old_param_values[MAX_FUNC_PARAMS][32768];
    Var *param_vars[MAX_FUNC_PARAMS];
    
    for (int i = 0; i < func->param_count; i++) {
        param_vars[i] = get_var(func->params[i]);
        if (param_vars[i]) {
            strncpy(old_param_values[i], param_vars[i]->sv, sizeof(old_param_values[i]) - 1);
        }
    }
    
    for (int i = 0; i < func->param_count; i++) {
        Var *v = create_var_if_missing(func->params[i]);
        if (v) {
            v->type = VAR_STRING;
            
            const char *keys[] = { "context" };
            const char *vals[] = { context_str };
            char rendered_arg[32768];
            render_fstring_with_map(arg_values[i], keys, vals, 1, rendered_arg, sizeof(rendered_arg));
            
            strncpy(v->sv, rendered_arg, sizeof(v->sv) - 1);
            v->sv[sizeof(v->sv) - 1] = 0;
        }
    }
    
    func->active = 1;
    for (int j = 0; j < func->num_lines; j++) {
        execute_line_command(func->lines[j]);
    }
    func->active = 0;
    
    for (int i = 0; i < func->param_count; i++) {
        if (param_vars[i]) {
            strncpy(param_vars[i]->sv, old_param_values[i], sizeof(param_vars[i]->sv) - 1);
        }
        if (arg_values[i]) free(arg_values[i]);
    }
    
    printf("call: Executed function '%s' with %d arguments\n", func_name, arg_count);
}

/* ---------------- Script parsing & execution ---------------- */
void execute_line_command(const char *l);

void parse_and_run_script_recursive(const char *script_path, const char *base_dir_for_this_script) {
    FILE *f = fopen(script_path, "r");
    if (!f) { fprintf(stderr, "Cannot open script: %s\n", script_path); return; }
    
    char original_base_dir[MAX_PATH_LEN];
    strncpy(original_base_dir, base_dir, sizeof(original_base_dir) - 1);
    original_base_dir[sizeof(original_base_dir) - 1] = '\0';
    
    char temp_path[MAX_PATH_LEN];
    strncpy(temp_path, script_path, sizeof(temp_path) - 1);
    temp_path[sizeof(temp_path) - 1] = '\0';
    char *script_dir = dirname(temp_path);
    strncpy(base_dir, script_dir, sizeof(base_dir) - 1);
    base_dir[sizeof(base_dir) - 1] = '\0';
    
    char buf[MAX_LINE];
    int initial_line_count = line_count;
    while (fgets(buf, sizeof(buf), f)) {
        char *ln = trim(buf);
        if (strlen(ln) == 0) continue;
        if (line_count >= MAX_LINES-1) break;
        lines[line_count++] = safe_strdup(ln);
    }
    fclose(f);
    
    for (int i = initial_line_count; i < line_count; i++) {
        if (is_import_line(lines[i])) {
            char imported_file[MAX_PATH_LEN];
            if (sscanf(lines[i], "#import \"%[^\"]\"", imported_file) == 1) {
                char full_import_path[MAX_PATH_LEN];
                snprintf(full_import_path, sizeof(full_import_path), "%s/%s", base_dir, imported_file);
                printf("Importing: %s\n", full_import_path);
                parse_and_run_script_recursive(full_import_path, base_dir);
            } else {
                fprintf(stderr, "Invalid import format in script: %s, line: %s\n", script_path, lines[i]);
            }
            free(lines[i]);
            lines[i] = NULL;
        }
    }
    
    int write_idx = initial_line_count;
    for (int read_idx = initial_line_count; read_idx < line_count; read_idx++) {
        if (lines[read_idx] != NULL) {
            if (write_idx != read_idx) {
                lines[write_idx] = lines[read_idx];
            }
            write_idx++;
        }
    }
    line_count = write_idx;
    
    // PASS 1: Register all functions first (without executing)
    int i = initial_line_count;
    while (i < line_count) {
        char *l = lines[i];
        if (!l || l[0] == '#') { i++; continue; }
        
        if (starts_with(l, "def ")) {
            process_func_def(l, i);
            
            int j = i + 1;
            while (j < line_count && strcmp(lines[j], "{") != 0) j++;
            if (j < line_count) {
                j++;
                int depth = 1;
                for (int k = j; k < line_count; ++k) {
                    if (strcmp(lines[k], "{") == 0) depth++;
                    else if (strcmp(lines[k], "}") == 0) {
                        depth--;
                        if (depth == 0) {
                            i = k + 1;
                            break;
                        }
                    }
                }
            }
            continue;
        }
        i++;
    }
    
    // PASS 2: Execute code in order
    i = initial_line_count;
    while (i < line_count) {
        char *l = lines[i];
        if (!l || l[0] == '#') { i++; continue; }
        
        // Skip function definitions (already processed)
        if (starts_with(l, "def ")) {
            int j = i + 1;
            while (j < line_count && strcmp(lines[j], "{") != 0) j++;
            if (j < line_count) {
                j++;
                int depth = 1;
                for (int k = j; k < line_count; ++k) {
                    if (strcmp(lines[k], "{") == 0) depth++;
                    else if (strcmp(lines[k], "}") == 0) {
                        depth--;
                        if (depth == 0) {
                            i = k + 1;
                            break;
                        }
                    }
                }
            }
            continue;
        }
        
        // context
        if (starts_with(l, "context ")) {
            char val[MAX_LINE];
            if (sscanf(l, "context = \"%[^\"]\"", val) == 1) {
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
        
        // server
        if (starts_with(l, "server ")) {
            char val[MAX_LINE];
            if (sscanf(l, "server = \"%[^\"]\"", val) == 1) {
                const char *keys[] = { "context" };
                const char *vals[] = { context_str };
                char rendered_val[256];
                render_fstring_with_map(val, keys, vals, 1, rendered_val, sizeof(rendered_val));
                strncpy(api_server, rendered_val, sizeof(api_server)-1);
                api_server[sizeof(api_server)-1] = 0;
            }
            i++; continue;
        }
        
        // var
        if (starts_with(l, "var ")) {
            char name[128];
            if (sscanf(l, "var %127s", name) != 1) { i++; continue; }
            char *eq = strchr(name, '=');
            if (eq) *eq = 0;
            Var *v = create_var_if_missing(name);
            
            if (strstr(l, "generate_text(")) {
                char pmt[128];
                int tokens = 0;
                if (sscanf(l, "var %*s = generate_text(%127[^,], context, %d)", pmt, &tokens) >= 1) {
                    char *pp = pmt; while (*pp && isspace((unsigned char)*pp)) pp++;
                    char prompt_text[32768] = "";
                    if (*pp == '"') {
                        char tmp[32768]; if (sscanf(pp, "\"%[^\"]\"", tmp) == 1) {
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
            
            if (strstr(l, "generate_img(")) {
                char pmt[128];
                int w = 512, h = 512;
                if (sscanf(l, "var %*s = generate_img(%127[^,], context, %d, %d", pmt, &w, &h) >= 1) {
                    char *pp = pmt; while (*pp && isspace((unsigned char)*pp)) pp++;
                    char prompt_text[32768] = "";
                    if (*pp == '"') {
                        char tmp[32768]; if (sscanf(pp, "\"%[^\"]\"", tmp) == 1) {
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
            
            if (strstr(l, "request(")) {
                char url[128], method[16], result_var_name[128], body[32768];
                int arg_count = sscanf(l, "var %127s = request(\"%127[^\"]\", \"%15[^\"]\", \"%32767[^\"]\")", result_var_name, url, method, body);
                if (arg_count == 4) {
                    Var *result_var = create_var_if_missing(result_var_name);
                    if (result_var) {
                        gen_request_var(result_var, url, method, body);
                    } else {
                        fprintf(stderr, "request: Could not create result variable '%s'.\n", result_var_name);
                    }
                } else if ((arg_count = sscanf(l, "var %127s = request(\"%127[^\"]\", \"%15[^\"]\")", result_var_name, url, method)) == 3) {
                    Var *result_var = create_var_if_missing(result_var_name);
                    if (result_var) {
                        gen_request_var(result_var, url, method, NULL);
                    } else {
                        fprintf(stderr, "request: Could not create result variable '%s'.\n", result_var_name);
                    }
                } else {
                    fprintf(stderr, "request: Invalid syntax.\n");
                }
                i++; continue;
            }
            
            if (strstr(l, "exec_cmd(")) {
                process_exec_cmd(l);
                i++; continue;
            }
            
            if (strstr(l, "chroma_key_crop(")) {
                process_chroma_key_crop(l);
                i++; continue;
            }
            
            if (strstr(l, "scale_to(")) {
                process_scale_to(l);
                i++; continue;
            }
            
            char lit[32768];
            if (sscanf(l, "var %*s = \"%[^\"]\"", lit) == 1) {
                v->type = VAR_STRING;
                const char *keys[] = { "context" };
                const char *vals[] = { context_str };
                render_fstring_with_map(lit, keys, vals, 1, v->sv, sizeof(v->sv));
                i++; continue;
            }
            
            int ival;
            if (sscanf(l, "var %*s = %d", &ival) == 1) {
                v->type = VAR_INT;
                v->iv = ival;
                i++; continue;
            }
            
            v->type = VAR_STRING;
            v->sv[0] = 0;
            i++; continue;
        }
        
        // input
        if (starts_with(l, "input(")) {
            char name[256];
            if (sscanf(l, "input(%255[^)])", name) == 1) {
                const char *keys[] = { "context" };
                const char *vals[] = { context_str };
                char rendered_name[256];
                render_fstring_with_map(name, keys, vals, 1, rendered_name, sizeof(rendered_name));
                do_input_var(rendered_name);
            }
            i++; continue;
        }
        
        // save_img
        if (starts_with(l, "save_img(")) {
            char varname[128], rel[512];
            if (sscanf(l, "save_img(%127[^,], \"%511[^\"]\")", varname, rel) == 2) {
                char *p = varname; while (*p && isspace((unsigned char)*p)) p++;
                Var *v = get_var(p);
                if (v) {
                    const char *keys[] = { "context" };
                    const char *vals[] = { context_str };
                    char rendered_rel[512];
                    render_fstring_with_map(rel, keys, vals, 1, rendered_rel, sizeof(rendered_rel));
                    save_img_var(v, rendered_rel);
                }
            }
            i++; continue;
        }
        
        // save_txt
        if (starts_with(l, "save_txt(")) {
            char varname[128], rel[512];
            if (sscanf(l, "save_txt(%127[^,], \"%511[^\"]\")", varname, rel) == 2) {
                char *p = varname; while (*p && isspace((unsigned char)*p)) p++;
                Var *v = get_var(p);
                if (v) {
                    const char *keys[] = { "context" };
                    const char *vals[] = { context_str };
                    char rendered_rel[512];
                    render_fstring_with_map(rel, keys, vals, 1, rendered_rel, sizeof(rendered_rel));
                    save_txt_var(v, rendered_rel);
                }
            }
            i++; continue;
        }
        
        // emit_c
        if (starts_with(l, "emit_c(")) {
            char rel[512];
            if (sscanf(l, "emit_c(\"%511[^\"]\")", rel) == 1) {
                const char *keys[] = { "context" };
                const char *vals[] = { context_str };
                char rendered_rel[512];
                render_fstring_with_map(rel, keys, vals, 1, rendered_rel, sizeof(rendered_rel));
                save_embedded_c_code(rendered_rel);
            }
            i++; continue;
        }
        
        // call (with parameters)
        if (starts_with(l, "call ")) {
            process_func_call(l, i);
            i++; continue;
        }
        
        // print
        if (starts_with(l, "print(")) {
            char arg[4096];
            if (sscanf(l, "print(%4095[^)])", arg) == 1) {
                char *a = arg;
                while (*a && isspace((unsigned char)*a)) a++;
                char *end = a + strlen(a) - 1;
                while (end > a && isspace((unsigned char)*end)) { *end = 0; end--; }
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
            i++; continue;
        }
        
        // if
        if (starts_with(l, "if ")) {
            char *and_pos = strstr(l, " and ");
            if (and_pos) {
                char cond1_part[256], cond2_part[256];
                if (sscanf(l, "if %255s and %255s", cond1_part, cond2_part) >= 2) {
                    char *orig_cond1 = strstr(l, cond1_part);
                    char *orig_cond2 = strstr(l, cond2_part);
                    char varname1[128], op1[8], rhs1[256];
                    if (sscanf(orig_cond1, "%127s %7s %255s", varname1, op1, rhs1) < 2) {
                        i++; continue;
                    }
                    char *r1 = rhs1; while (*r1 && isspace((unsigned char)*r1)) r1++;
                    char *rend1 = r1 + strlen(r1) - 1; while (rend1 > r1 && isspace((unsigned char)*rend1)) { *rend1 = 0; rend1--; }
                    if (*r1 == '"' && rend1 > r1 && *rend1 == '"') { r1++; *rend1 = 0; }
                    Var *v1 = get_var(varname1);
                    bool cond1_res = false;
                    if (v1) {
                        if (v1->type == VAR_INT) {
                            int rhsnum1 = atoi(r1);
                            if (strcmp(op1, "==") == 0) cond1_res = (v1->iv == rhsnum1);
                            else if (strcmp(op1, "!=") == 0) cond1_res = (v1->iv != rhsnum1);
                            else if (strcmp(op1, ">") == 0) cond1_res = (v1->iv > rhsnum1);
                            else if (strcmp(op1, "<") == 0) cond1_res = (v1->iv < rhsnum1);
                            else if (strcmp(op1, ">=") == 0) cond1_res = (v1->iv >= rhsnum1);
                            else if (strcmp(op1, "<=") == 0) cond1_res = (v1->iv <= rhsnum1);
                        } else {
                            if (strcmp(op1, "==") == 0) cond1_res = (strcmp(v1->sv, r1) == 0);
                            else if (strcmp(op1, "!=") == 0) cond1_res = (strcmp(v1->sv, r1) != 0);
                            else { cond1_res = false; }
                        }
                    }
                    char varname2[128], op2[8], rhs2[256];
                    if (sscanf(orig_cond2, "%127s %7s %255s", varname2, op2, rhs2) < 2) {
                         i++; continue;
                    }
                    char *r2 = rhs2; while (*r2 && isspace((unsigned char)*r2)) r2++;
                    char *rend2 = r2 + strlen(r2) - 1; while (rend2 > r2 && isspace((unsigned char)*rend2)) { *rend2 = 0; rend2--; }
                    if (*r2 == '"' && rend2 > r2 && *rend2 == '"') { r2++; *rend2 = 0; }
                    Var *v2 = get_var(varname2);
                    bool cond2_res = false;
                    if (v2) {
                        if (v2->type == VAR_INT) {
                            int rhsnum2 = atoi(r2);
                            if (strcmp(op2, "==") == 0) cond2_res = (v2->iv == rhsnum2);
                            else if (strcmp(op2, "!=") == 0) cond2_res = (v2->iv != rhsnum2);
                            else if (strcmp(op2, ">") == 0) cond2_res = (v2->iv > rhsnum2);
                            else if (strcmp(op2, "<") == 0) cond2_res = (v2->iv < rhsnum2);
                            else if (strcmp(op2, ">=") == 0) cond2_res = (v2->iv >= rhsnum2);
                            else if (strcmp(op2, "<=") == 0) cond2_res = (v2->iv <= rhsnum2);
                        } else {
                            if (strcmp(op2, "==") == 0) cond2_res = (strcmp(v2->sv, r2) == 0);
                            else if (strcmp(op2, "!=") == 0) cond2_res = (strcmp(v2->sv, r2) != 0);
                            else { cond2_res = false; }
                        }
                    }
                    bool overall_cond = cond1_res && cond2_res;
                    if (!overall_cond) {
                        i += 2;
                        continue;
                    } else {
                        i++; continue;
                    }
                } else {
                    i++; continue;
                }
            } else {
                char varname[128], op[8], rhs[256];
                if (sscanf(l, "if %127s %7s %255s", varname, op, rhs) >= 2) {
                    char *r = rhs;
                    while (*r && isspace((unsigned char)*r)) r++;
                    char *rend = r + strlen(r) - 1;
                    while (rend > r && isspace((unsigned char)*rend)) { *rend = 0; rend--; }
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
                            if (strcmp(op, "==") == 0) cond = (strcmp(v->sv, r) == 0);
                            else if (strcmp(op, "!=") == 0) cond = (strcmp(v->sv, r) != 0);
                            else {
                                cond = false;
                            }
                        }
                    } else {
                        cond = false;
                    }
                    if (!cond) {
                        i += 2;
                        continue;
                    } else {
                        i++; continue;
                    }
                } else {
                    i++; continue;
                }
            }
        }
        
        // repeat
        if (starts_with(l, "repeat ")) {
            int times = 0;
            if (sscanf(l, "repeat %d", &times) >= 1 && times > 0) {
                int j = i + 1;
                if (strchr(l, '{') == NULL) {
                    while (j < line_count && strcmp(lines[j], "{") != 0) j++;
                    if (j >= line_count) { i++; continue; }
                    j++;
                }
                int block_start = j;
                int block_end = block_start;
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
                        if (strcmp(lines[k], "break") == 0) { broken = true; break; }
                        execute_line_command(lines[k]);
                    }
                }
                i = block_end + 1;
                continue;
            }
        }
        
        execute_line_command(l);
        i++;
    }
    
    strncpy(base_dir, original_base_dir, sizeof(base_dir) - 1);
    base_dir[sizeof(base_dir) - 1] = '\0';
}

void execute_line_command(const char *l) { 
    if (!l) return;
    if (starts_with(l, "print(")) {
        char arg[4096];
        if (sscanf(l, "print(%4095[^)])", arg) == 1) {
            char *a = arg;
            while (*a && isspace((unsigned char)*a)) a++;
            char *end = a + strlen(a) - 1;
            while (end > a && isspace((unsigned char)*end)) { *end = 0; end--; }
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
        return;
    }
}

/* ---------------- Entry point ---------------- */
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s script.zator\n", argv[0]);
        return 1;
    }
    char temp_path[MAX_PATH_LEN];
    strncpy(temp_path, argv[1], sizeof(temp_path) - 1);
    temp_path[sizeof(temp_path) - 1] = '\0';
    char *script_dir = dirname(temp_path);
    strncpy(base_dir, script_dir, sizeof(base_dir) - 1);
    base_dir[sizeof(base_dir) - 1] = '\0';
    parse_and_run_script_recursive(argv[1], base_dir);
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
    for (int i = 0; i < func_count; i++) {
        for (int j = 0; j < funcs[i].num_lines; j++) {
            if (funcs[i].lines[j]) {
                free(funcs[i].lines[j]);
                funcs[i].lines[j] = NULL;
            }
        }
    }
    for (int i = 0; i < line_count; ++i) {
        if (lines[i]) {
            free(lines[i]);
            lines[i] = NULL;
        }
    }
    return 0;
}