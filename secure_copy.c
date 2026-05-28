#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include "rc4.h"       

#define SALT_SIZE 16
#define MAX_THREADS 5
#define MAX_PATH_LEN 4096
#define CHUNK_SIZE 65536

typedef struct {
    uint32_t content_size;
    uint32_t name_len;
    unsigned char salt[SALT_SIZE];
    char *name;
    unsigned char *content;
} file_record;

typedef struct {
    uint32_t count;
    file_record *records;
} disk_image;

typedef struct {
    char **src_paths;
    char **img_names;
    int count;
    int capacity;
} file_list;

typedef struct {
    char src[MAX_PATH_LEN];
    char name[MAX_PATH_LEN];
    unsigned char salt[SALT_SIZE];
    uint32_t file_size;
    int status;
    off_t file_offset;
    unsigned char *encrypted;
} work_item;

typedef struct {
    work_item *items;
    int total;
    int next;
    pthread_mutex_t mutex;
    const char *key;
    int key_len;
    int image_fd;
} work_queue;

static int write_u32(FILE *f, uint32_t v) {
    unsigned char buf[4];
    buf[0] = v & 0xFF;
    buf[1] = (v >> 8) & 0xFF;
    buf[2] = (v >> 16) & 0xFF;
    buf[3] = (v >> 24) & 0xFF;
    return fwrite(buf, 1, 4, f) == 4 ? 0 : -1;
}

static int read_u32(FILE *f, uint32_t *v) {
    unsigned char buf[4];
    if (fread(buf, 1, 4, f) != 4) return -1;
    *v = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
         ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    return 0;
}

static void generate_salt(unsigned char *salt) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t r = fread(salt, 1, SALT_SIZE, f);
        fclose(f);
        if (r == SALT_SIZE) return;
    }
    for (int i = 0; i < SALT_SIZE; i++)
        salt[i] = (unsigned char)(rand() % 256);
}

static void file_list_init(file_list *list) {
    list->src_paths = NULL;
    list->img_names = NULL;
    list->count = 0;
    list->capacity = 0;
}

static int file_list_add(file_list *list, const char *src, const char *name) {
    if (list->count >= list->capacity) {
        int new_cap = list->capacity ? list->capacity * 2 : 64;
        char **new_src = realloc(list->src_paths, (size_t)new_cap * sizeof(char *));
        if (!new_src) return -1;
        char **new_names = realloc(list->img_names, (size_t)new_cap * sizeof(char *));
        if (!new_names) {
            free(new_src);
            return -1;
        }
        list->src_paths = new_src;
        list->img_names = new_names;
        list->capacity = new_cap;
    }
    list->src_paths[list->count] = strdup(src);
    list->img_names[list->count] = strdup(name);
    if (!list->src_paths[list->count] || !list->img_names[list->count]) {
        free(list->src_paths[list->count]);
        free(list->img_names[list->count]);
        return -1;
    }
    list->count++;
    return 0;
}

static void file_list_free(file_list *list) {
    for (int i = 0; i < list->count; i++) {
        free(list->src_paths[i]);
        free(list->img_names[i]);
    }
    free(list->src_paths);
    free(list->img_names);
    list->src_paths = NULL;
    list->img_names = NULL;
    list->count = 0;
    list->capacity = 0;
}

static int image_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static void free_image(disk_image *img) {
    for (uint32_t i = 0; i < img->count; i++) {
        free(img->records[i].name);
        free(img->records[i].content);
    }
    free(img->records);
    img->records = NULL;
    img->count = 0;
}

static int read_image(const char *path, disk_image *img) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    img->count = 0;
    img->records = NULL;

    while (1) {
        uint32_t content_size, name_len;
        if (read_u32(f, &content_size) != 0) break;
        if (read_u32(f, &name_len) != 0) break;

        file_record rec;
        rec.content_size = content_size;
        rec.name_len = name_len;

        if (fread(rec.salt, 1, SALT_SIZE, f) != SALT_SIZE) break;

        rec.name = malloc(name_len + 1);
        if (!rec.name) break;
        if (fread(rec.name, 1, name_len, f) != name_len) {
            free(rec.name);
            break;
        }
        rec.name[name_len] = '\0';

        if (content_size > 0) {
            rec.content = malloc(content_size);
            if (!rec.content) {
                free(rec.name);
                break;
            }
            if (fread(rec.content, 1, content_size, f) != content_size) {
                free(rec.name);
                free(rec.content);
                break;
            }
        } else {
            rec.content = NULL;
        }

        img->count++;
        file_record *new_records = realloc(img->records, img->count * sizeof(file_record));
        if (!new_records) {
            free(rec.name);
            free(rec.content);
            break;
        }
        img->records = new_records;
        img->records[img->count - 1] = rec;
    }

    fclose(f);
    return 0;
}

static int write_image(const char *path, disk_image *img) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    int err = 0;
    for (uint32_t i = 0; i < img->count && !err; i++) {
        file_record *r = &img->records[i];
        if (write_u32(f, r->content_size) != 0) err = 1;
        else if (write_u32(f, r->name_len) != 0) err = 1;
        else if (fwrite(r->salt, 1, SALT_SIZE, f) != SALT_SIZE) err = 1;
        else if (r->name_len > 0 && fwrite(r->name, 1, r->name_len, f) != r->name_len) err = 1;
        else if (r->content_size > 0 && fwrite(r->content, 1, r->content_size, f) != r->content_size) err = 1;
    }

    fclose(f);
    return err ? -1 : 0;
}

static int encrypt_file(const char *src_path, const char *key, int key_len,
                        unsigned char *salt, unsigned char **out, uint32_t *out_size) {
    FILE *f = fopen(src_path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    if (size < 0) { fclose(f); return -1; }
    fseek(f, 0, SEEK_SET);

    unsigned char *data = NULL;
    if (size > 0) {
        data = malloc((size_t)size);
        if (!data) { fclose(f); return -1; }
        if (fread(data, 1, (size_t)size, f) != (size_t)size) {
            free(data);
            fclose(f);
            return -1;
        }
    }
    fclose(f);

    unsigned char *rc4_key = (unsigned char *)mmap(NULL, (size_t)(key_len + SALT_SIZE),
                                                    PROT_READ | PROT_WRITE,
                                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (rc4_key == MAP_FAILED) { free(data); return -1; }
    mlock(rc4_key, (size_t)(key_len + SALT_SIZE));
    memcpy(rc4_key, key, (size_t)key_len);
    memcpy(rc4_key + key_len, salt, SALT_SIZE);

    *out = NULL;
    if (size > 0) {
        *out = malloc((size_t)size);
        if (!*out) { free(data); mprotect(rc4_key, (size_t)(key_len + SALT_SIZE), PROT_READ | PROT_WRITE); memset(rc4_key, 0, (size_t)(key_len + SALT_SIZE)); munlock(rc4_key, (size_t)(key_len + SALT_SIZE)); munmap(rc4_key, (size_t)(key_len + SALT_SIZE)); return -1; }
        rc4_crypt(rc4_key, key_len + SALT_SIZE, data, *out, (int)size);
    }
    *out_size = (uint32_t)size;

    free(data);
    mprotect(rc4_key, (size_t)(key_len + SALT_SIZE), PROT_READ | PROT_WRITE);
    memset(rc4_key, 0, (size_t)(key_len + SALT_SIZE));
    munlock(rc4_key, (size_t)(key_len + SALT_SIZE));
    munmap(rc4_key, (size_t)(key_len + SALT_SIZE));
    return 0;
}

static void collect_files(const char *path, const char *base, file_list *list, int depth) {
    if (depth > 4) return;

    DIR *dir = opendir(path);
    if (!dir) return;

    size_t base_len = strlen(base);

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char child[MAX_PATH_LEN];
        snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);

        struct stat st;
        if (stat(child, &st) != 0) continue;

        if (S_ISREG(st.st_mode)) {
            char img_name[MAX_PATH_LEN];
            snprintf(img_name, sizeof(img_name), "/%s", child + base_len + 1);
            file_list_add(list, child, img_name);
        } else if (S_ISDIR(st.st_mode)) {
            collect_files(child, base, list, depth + 1);
        }
    }

    closedir(dir);
}

static int write_record_at(int fd, off_t offset,
                            const char *name, uint32_t name_len,
                            const unsigned char *salt,
                            const unsigned char *content, uint32_t content_size) {
    unsigned char header[24];
    header[0] = (unsigned char)(content_size & 0xFF);
    header[1] = (unsigned char)((content_size >> 8) & 0xFF);
    header[2] = (unsigned char)((content_size >> 16) & 0xFF);
    header[3] = (unsigned char)((content_size >> 24) & 0xFF);
    header[4] = (unsigned char)(name_len & 0xFF);
    header[5] = (unsigned char)((name_len >> 8) & 0xFF);
    header[6] = (unsigned char)((name_len >> 16) & 0xFF);
    header[7] = (unsigned char)((name_len >> 24) & 0xFF);
    memcpy(header + 8, salt, 16);

    off_t off = offset;
    if (pwrite(fd, header, 24, off) != 24) return -1;
    off += 24;
    if (name_len > 0 && pwrite(fd, name, name_len, off) != (ssize_t)name_len) return -1;
    off += name_len;
    if (content_size > 0 && pwrite(fd, content, content_size, off) != (ssize_t)content_size) return -1;
    return 0;
}

static void *worker_thread(void *arg) {
    work_queue *q = (work_queue *)arg;

    while (1) {
        pthread_mutex_lock(&q->mutex);
        int idx = q->next++;
        pthread_mutex_unlock(&q->mutex);

        if (idx >= q->total) break;

        work_item *item = &q->items[idx];

        FILE *f = fopen(item->src, "rb");
        if (!f) { item->status = -1; continue; }


        unsigned char *rc4_key = (unsigned char *)mmap(NULL, (size_t)(q->key_len + SALT_SIZE),
                                                       PROT_READ | PROT_WRITE,
                                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (rc4_key == MAP_FAILED) { fclose(f); item->status = -1; continue; }
        mlock(rc4_key, (size_t)(q->key_len + SALT_SIZE));
        memcpy(rc4_key, q->key, (size_t)q->key_len);
        memcpy(rc4_key + q->key_len, item->salt, SALT_SIZE);

        rc4_ctx *ctx;
        if (rc4_init(&ctx, rc4_key, q->key_len + SALT_SIZE) != 0) {
            memset(rc4_key, 0, (size_t)(q->key_len + SALT_SIZE));
            munlock(rc4_key, (size_t)(q->key_len + SALT_SIZE));
            munmap(rc4_key, (size_t)(q->key_len + SALT_SIZE));
            fclose(f);
            item->status = -1;
            continue;
        }
        mprotect(rc4_key, (size_t)(q->key_len + SALT_SIZE), PROT_NONE);

        uint32_t name_len = (uint32_t)strlen(item->name);
        unsigned char header[24];
        header[0] = (unsigned char)(item->file_size & 0xFF);
        header[1] = (unsigned char)((item->file_size >> 8) & 0xFF);
        header[2] = (unsigned char)((item->file_size >> 16) & 0xFF);
        header[3] = (unsigned char)((item->file_size >> 24) & 0xFF);
        
        header[4] = (unsigned char)(name_len & 0xFF);
        header[5] = (unsigned char)((name_len >> 8) & 0xFF);
        header[6] = (unsigned char)((name_len >> 16) & 0xFF);
        header[7] = (unsigned char)((name_len >> 24) & 0xFF);
        memcpy(header + 8, item->salt, 16);

        off_t off = item->file_offset;
        int ok = 1;
        if (pwrite(q->image_fd, header, 24, off) != 24) ok = 0;
        off += 24;
        if (name_len > 0 && pwrite(q->image_fd, item->name, name_len, off) != (ssize_t)name_len) ok = 0;
        off += name_len;

        if (!ok) {
            rc4_destroy(ctx);
            mprotect(rc4_key, (size_t)(q->key_len + SALT_SIZE), PROT_READ | PROT_WRITE);
            memset(rc4_key, 0, (size_t)(q->key_len + SALT_SIZE));
            munlock(rc4_key, (size_t)(q->key_len + SALT_SIZE));
            munmap(rc4_key, (size_t)(q->key_len + SALT_SIZE));
            fclose(f);
            item->status = -1;
            continue;
        }

        unsigned char *chunk = (unsigned char *)mmap(NULL, CHUNK_SIZE,
                                                      PROT_READ | PROT_WRITE,
                                                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (chunk == MAP_FAILED) {
            rc4_destroy(ctx);
            mprotect(rc4_key, (size_t)(q->key_len + SALT_SIZE), PROT_READ | PROT_WRITE);
            memset(rc4_key, 0, (size_t)(q->key_len + SALT_SIZE));
            munlock(rc4_key, (size_t)(q->key_len + SALT_SIZE));
            munmap(rc4_key, (size_t)(q->key_len + SALT_SIZE));
            fclose(f);
            item->status = -1;
            continue;
        }

        size_t remaining = item->file_size;
        off_t data_off = off;
        int err = 0;

        while (remaining > 0) {
            size_t to_read = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
            if (fread(chunk, 1, to_read, f) != to_read) { err = 1; break; }
            rc4_encrypt(ctx, chunk, chunk, (int)to_read);
            if (pwrite(q->image_fd, chunk, to_read, data_off) != (ssize_t)to_read) { err = 1; break; }
            data_off += to_read;
            remaining -= to_read;
        }

        munmap(chunk, CHUNK_SIZE);
        rc4_destroy(ctx);
        mprotect(rc4_key, (size_t)(q->key_len + SALT_SIZE), PROT_READ | PROT_WRITE);
        memset(rc4_key, 0, (size_t)(q->key_len + SALT_SIZE));
        munlock(rc4_key, (size_t)(q->key_len + SALT_SIZE));
        munmap(rc4_key, (size_t)(q->key_len + SALT_SIZE));
        fclose(f);

        item->status = (err == 0) ? 1 : -1;
    }

    return NULL;
}

static int find_record(disk_image *img, const char *name) {
    for (uint32_t i = 0; i < img->count; i++) {
        if (strcmp(img->records[i].name, name) == 0)
            return (int)i;
    }
    return -1;
}

static int do_add(const char *image_path, const char *key, int key_len,
                  char **args, int arg_count) {

    file_list list;
    file_list_init(&list);

    for (int i = 0; i < arg_count; i++) {
        struct stat st;
        if (stat(args[i], &st) != 0) {
            fprintf(stderr, "Warning: cannot access '%s'\n", args[i]);
            continue;
        }

        if (S_ISREG(st.st_mode)) {
            const char *base = strrchr(args[i], '/');
            base = base ? base + 1 : args[i];

            char img_name[MAX_PATH_LEN];
            snprintf(img_name, sizeof(img_name), "/%s", base);

            file_list_add(&list, args[i], img_name);
        } else if (S_ISDIR(st.st_mode)) {
            char base[MAX_PATH_LEN];
            strncpy(base, args[i], sizeof(base) - 1);
            base[sizeof(base) - 1] = '\0';
            size_t len = strlen(base);
            if (len > 0 && base[len - 1] == '/')
                base[len - 1] = '\0';

            collect_files(base, base, &list, 0);
        }
    }

    if (list.count == 0) {
        fprintf(stderr, "Error: no files to add\n");
        file_list_free(&list);
        return -1;
    }

    disk_image img;
    img.count = 0;
    img.records = NULL;

    off_t existing_data_end = 0;

    if (image_exists(image_path)) {
        if (read_image(image_path, &img) != 0) {
            fprintf(stderr, "Error: failed to read image\n");
            file_list_free(&list);
            return -1;
        }
        for (uint32_t i = 0; i < img.count; i++) {
            existing_data_end += 4 + 4 + 16 + img.records[i].name_len + img.records[i].content_size;
        }
    }

    work_item *items = calloc((size_t)list.count, sizeof(work_item));
    if (!items) {
        fprintf(stderr, "Error: memory allocation failed\n");
        file_list_free(&list);
        free_image(&img);
        return -1;
    }
    int need_full_rebuild = 0;
    for (int i = 0; i < list.count; i++) {
        struct stat st;
        if (stat(list.src_paths[i], &st) != 0) continue;
        uint32_t new_size = (uint32_t)st.st_size;
        int existing_idx = find_record(&img, list.img_names[i]);
        if (existing_idx >= 0 && img.records[existing_idx].content_size != new_size) {
            need_full_rebuild = 1;
            break;
        }
    }

    if (need_full_rebuild) {
        for (int i = 0; i < list.count; i++) {
            struct stat st;
            if (stat(list.src_paths[i], &st) != 0) continue;
            items[i].file_size = (uint32_t)st.st_size;
            generate_salt(items[i].salt);
            strncpy(items[i].src, list.src_paths[i], MAX_PATH_LEN - 1);
            items[i].src[MAX_PATH_LEN - 1] = '\0';
            strncpy(items[i].name, list.img_names[i], MAX_PATH_LEN - 1);
            items[i].name[MAX_PATH_LEN - 1] = '\0';

            if (encrypt_file(items[i].src, key, key_len,
                             items[i].salt, &items[i].encrypted, &items[i].file_size) == 0) {
                items[i].status = 1;
            } else {
                items[i].status = -1;
            }
        }

        for (int i = 0; i < list.count; i++) {
            if (items[i].status != 1) { free(items[i].encrypted); continue; }
            int existing_idx = find_record(&img, items[i].name);
            if (existing_idx >= 0) {
                free(img.records[existing_idx].name);
                free(img.records[existing_idx].content);
                img.records[existing_idx].content_size = items[i].file_size;
                img.records[existing_idx].name_len = (uint32_t)strlen(items[i].name);
                memcpy(img.records[existing_idx].salt, items[i].salt, SALT_SIZE);
                img.records[existing_idx].name = strdup(items[i].name);
                img.records[existing_idx].content = items[i].encrypted;
            } else {
                uint32_t idx = img.count;
                img.count++;
                file_record *new_records = realloc(img.records, img.count * sizeof(file_record));
                if (!new_records) { free(items[i].encrypted); continue; }
                img.records = new_records;
                img.records[idx].content_size = items[i].file_size;
                img.records[idx].name_len = (uint32_t)strlen(items[i].name);
                memcpy(img.records[idx].salt, items[i].salt, SALT_SIZE);
                img.records[idx].name = strdup(items[i].name);
                img.records[idx].content = items[i].encrypted;
            }
        }

        int result = write_image(image_path, &img);
        free(items);
        file_list_free(&list);
        free_image(&img);
        return result;
    }

    off_t append_offset = existing_data_end;

    for (int i = 0; i < list.count; i++) {
        strncpy(items[i].src, list.src_paths[i], MAX_PATH_LEN - 1);
        items[i].src[MAX_PATH_LEN - 1] = '\0';
        strncpy(items[i].name, list.img_names[i], MAX_PATH_LEN - 1);
        items[i].name[MAX_PATH_LEN - 1] = '\0';
        generate_salt(items[i].salt);
        items[i].status = 0;
        items[i].encrypted = NULL;

        struct stat st;
        if (stat(items[i].src, &st) != 0) {
            fprintf(stderr, "Warning: cannot stat '%s', skipping\n", items[i].src);
            items[i].status = -1;
            continue;
        }
        items[i].file_size = (uint32_t)st.st_size;

        int existing_idx = find_record(&img, items[i].name);
        if (existing_idx >= 0) {
            off_t old_offset = 0;
            for (int j = 0; j < existing_idx; j++) {
                old_offset += 4 + 4 + 16 + img.records[j].name_len + img.records[j].content_size;
            }

            if (img.records[existing_idx].content_size == items[i].file_size) {
                items[i].file_offset = old_offset;     // in-place перезапись
            } else {
                items[i].file_offset = append_offset;  // дописываем в конец
                append_offset += 4 + 4 + 16 + (uint32_t)strlen(items[i].name) + items[i].file_size;
            }
            free(img.records[existing_idx].name);
            free(img.records[existing_idx].content);
            img.records[existing_idx].name = NULL;
            img.records[existing_idx].content = NULL;
        } else {
            items[i].file_offset = append_offset;
            append_offset += 4 + 4 + 16 + (uint32_t)strlen(items[i].name) + items[i].file_size;
        }
    }

    int fd = open(image_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fprintf(stderr, "Error: cannot create image file\n");
        free(items);
        file_list_free(&list);
        free_image(&img);
        return -1;
    }
    if (ftruncate(fd, append_offset) != 0) {
        fprintf(stderr, "Error: cannot allocate image file\n");
        close(fd);
        free(items);
        file_list_free(&list);
        free_image(&img);
        return -1;
    }

    off_t write_off = 0;
    for (uint32_t i = 0; i < img.count; i++) {
        if (img.records[i].name == NULL) {
            write_off += 4 + 4 + 16 + img.records[i].name_len + img.records[i].content_size;
            continue;
        }
        write_record_at(fd, write_off,
                        img.records[i].name, img.records[i].name_len,
                        img.records[i].salt,
                        img.records[i].content, img.records[i].content_size);
        write_off += 4 + 4 + 16 + img.records[i].name_len + img.records[i].content_size;
    }
    free_image(&img);

    work_queue q;
    q.items = items;
    q.total = list.count;
    q.next = 0;
    q.key = key;
    q.key_len = key_len;
    q.image_fd = fd;
    pthread_mutex_init(&q.mutex, NULL);

    int num_threads = list.count < MAX_THREADS ? list.count : MAX_THREADS;
    pthread_t *threads = malloc((size_t)num_threads * sizeof(pthread_t));
    if (!threads) {
        fprintf(stderr, "Error: memory allocation failed\n");
        close(fd);
        free(items);
        file_list_free(&list);
        pthread_mutex_destroy(&q.mutex);
        return -1;
    }

    for (int i = 0; i < num_threads; i++)
        pthread_create(&threads[i], NULL, worker_thread, &q);

    for (int i = 0; i < num_threads; i++)
        pthread_join(threads[i], NULL);

    close(fd);
    free(threads);
    pthread_mutex_destroy(&q.mutex);
    free(items);
    file_list_free(&list);

    return 0;
}

static int do_list(const char *image_path) {
    disk_image img;
    if (read_image(image_path, &img) != 0) {
        fprintf(stderr, "Error: failed to read image\n");
        return -1;
    }

    int *idx = malloc(img.count * sizeof(int));
    if (!idx && img.count > 0) {
        fprintf(stderr, "Error: memory allocation failed\n");
        free_image(&img);
        return -1;
    }
    for (uint32_t i = 0; i < img.count; i++)
        idx[i] = (int)i;

    for (uint32_t i = 0; i < img.count - 1; i++) {
        for (uint32_t j = 0; j < img.count - i - 1; j++) {
            if (strcmp(img.records[idx[j]].name, img.records[idx[j + 1]].name) > 0) {
                int tmp = idx[j];
                idx[j] = idx[j + 1];
                idx[j + 1] = tmp;
            }
        }
    }

    for (uint32_t i = 0; i < img.count; i++) {
        printf("%s\t%u\n", img.records[idx[i]].name, img.records[idx[i]].content_size);
    }

    free(idx);
    free_image(&img);
    return 0;
}

static int do_get(const char *image_path, const char *key, int key_len,
                  const char *out_path, const char *file_name) {
    disk_image img;
    if (read_image(image_path, &img) != 0) {
        fprintf(stderr, "Error: failed to read image\n");
        return -1;
    }

    int found = -1;
    for (uint32_t i = 0; i < img.count; i++) {
        if (strcmp(img.records[i].name, file_name) == 0) {
            found = (int)i;
            break;
        }
    }

    if (found < 0) {
        fprintf(stderr, "Error: file '%s' not found\n", file_name);
        free_image(&img);
        return -1;
    }

    unsigned char *rc4_key = (unsigned char *)mmap(NULL, (size_t)(key_len + SALT_SIZE),
                                                    PROT_READ | PROT_WRITE,
                                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (rc4_key == MAP_FAILED) {
        fprintf(stderr, "Error: memory allocation failed\n");
        free_image(&img);
        return -1;
    }
    mlock(rc4_key, (size_t)(key_len + SALT_SIZE));
    memcpy(rc4_key, key, (size_t)key_len);
    memcpy(rc4_key + key_len, img.records[found].salt, SALT_SIZE);

    unsigned char *decrypted = NULL;
    if (img.records[found].content_size > 0) {
        decrypted = malloc(img.records[found].content_size);
        if (!decrypted) {
            fprintf(stderr, "Error: memory allocation failed\n");
            memset(rc4_key, 0, (size_t)(key_len + SALT_SIZE));
            munlock(rc4_key, (size_t)(key_len + SALT_SIZE));
            munmap(rc4_key, (size_t)(key_len + SALT_SIZE));
            free_image(&img);
            return -1;
        }
        rc4_crypt(rc4_key, key_len + SALT_SIZE,
                  img.records[found].content, decrypted,
                  (int)img.records[found].content_size);
        mprotect(rc4_key, (size_t)(key_len + SALT_SIZE), PROT_NONE);
    }

    FILE *f = fopen(out_path, "wb");
    if (!f) {
        fprintf(stderr, "Error: cannot create output file\n");
        free(decrypted);
        mprotect(rc4_key, (size_t)(key_len + SALT_SIZE), PROT_READ | PROT_WRITE);
        memset(rc4_key, 0, (size_t)(key_len + SALT_SIZE));
        munlock(rc4_key, (size_t)(key_len + SALT_SIZE));
        munmap(rc4_key, (size_t)(key_len + SALT_SIZE));
        free_image(&img);
        return -1;
    }

    if (img.records[found].content_size > 0)
        fwrite(decrypted, 1, img.records[found].content_size, f);
    fclose(f);

    free(decrypted);
    mprotect(rc4_key, (size_t)(key_len + SALT_SIZE), PROT_READ | PROT_WRITE);
    memset(rc4_key, 0, (size_t)(key_len + SALT_SIZE));
    munlock(rc4_key, (size_t)(key_len + SALT_SIZE));
    munmap(rc4_key, (size_t)(key_len + SALT_SIZE));
    free_image(&img);
    return 0;
}

int main(int argc, char *argv[]) {
    const char *mode = NULL;
    const char *key = NULL;
    const char *image = NULL;
    const char *out = NULL;
    char **paths = NULL;
    int path_count = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-add") == 0) {
            mode = "add";
        } else if (strcmp(argv[i], "-list") == 0) {
            mode = "list";
        } else if (strcmp(argv[i], "-get") == 0) {
            mode = "get";
        } else if (strcmp(argv[i], "-key") == 0 && i + 1 < argc) {
            key = argv[++i];
        } else if (strcmp(argv[i], "-image") == 0 && i + 1 < argc) {
            image = argv[++i];
        } else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            out = argv[++i];
        } else {
            char **new_paths = realloc(paths, (size_t)(path_count + 1) * sizeof(char *));
            if (!new_paths) {
                fprintf(stderr, "Error: memory allocation failed\n");
                free(paths);
                return 1;
            }
            paths = new_paths;
            paths[path_count++] = argv[i];
        }
    }

    if (!mode || !image) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s -add -key \"key\" -image disk.img file1 dir1/ ...\n", argv[0]);
        fprintf(stderr, "  %s -list -image disk.img\n", argv[0]);
        fprintf(stderr, "  %s -get -key \"key\" -image disk.img -out file file_name\n", argv[0]);
        free(paths);
        return 1;
    }

    srand((unsigned int)time(NULL));

    char *locked_key = NULL;
    int key_len = 0;
    if (key) {
        key_len = (int)strlen(key);
        locked_key = malloc((size_t)key_len + 1);
        if (locked_key) {
            memcpy(locked_key, key, (size_t)key_len + 1);
            mlock(locked_key, (size_t)key_len + 1);
        }
    }

    int result = 0;
    if (strcmp(mode, "add") == 0) {
        if (!key || path_count == 0) {
            fprintf(stderr, "Error: -add requires -key and at least one file/directory\n");
            result = 1;
        } else {
            result = do_add(image, locked_key, key_len, paths, path_count);
        }
    } else if (strcmp(mode, "list") == 0) {
        result = do_list(image);
    } else if (strcmp(mode, "get") == 0) {
        if (!key || !out || path_count == 0) {
            fprintf(stderr, "Error: -get requires -key, -out, and file name\n");
            result = 1;
        } else {
            result = do_get(image, locked_key, key_len, out, paths[0]);
        }
    }

    if (locked_key) {
        memset(locked_key, 0, (size_t)key_len + 1);
        munlock(locked_key, (size_t)key_len + 1);
        free(locked_key);
    }

    free(paths);
    return result != 0 ? 1 : 0;
}
