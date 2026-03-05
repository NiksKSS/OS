#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <signal.h>

static const char* files_to_remove[] = {
    "decrypted.bin",
    "decrypted.txt",
    "encrypted.bin",
    "encrypted.txt",
    "output.txt",
    NULL
};

static FILE* g_input = NULL;
static FILE* g_output = NULL;
static void* g_buffer = NULL;
static void* g_result = NULL;
static void* g_handle = NULL;

void cleanup_handler(int sig) {
    for (int i = 0; files_to_remove[i] != NULL; i++) {
        remove(files_to_remove[i]);
    }

    if (g_output) fclose(g_output);
    if (g_input) fclose(g_input);
    if (g_result) free(g_result);
    if (g_buffer) free(g_buffer);
    if (g_handle) dlclose(g_handle);

    exit(1);
}

typedef void (*set_key_func)(char);
typedef void (*caesar_func)(void*, void*, int);

int main(int argc, char* argv[]) {

    signal(SIGINT, cleanup_handler);

    if (argc != 5) {
        printf("Usage: %s <lib_path> <key> <input_file> <output_file>\n", argv[0]);
        return 1;
    }
    //приемка аргументов
    char* lib_path = argv[1];
    char key = argv[2][0];
    char* input_path = argv[3];
    char* output_path = argv[4];

    void* handle = dlopen(lib_path, RTLD_LAZY);
    g_handle = handle;
    if (!handle) {
        printf("Cannot load library\n");
        return 1;
    }

    set_key_func set_key = (set_key_func)dlsym(handle, "set_key");
    caesar_func caesar = (caesar_func)dlsym(handle, "caesar"); // извлечение адресов фнкций

    if (!set_key || !caesar) {
        printf("Cannot load functions\n");
        return 1;
    }

    FILE* input = fopen(input_path, "rb");
    FILE* output = fopen(output_path, "wb");
    g_input = input;
    g_output = output;

    fseek(input, 0, SEEK_END); // определение размера входного файла
    int size = ftell(input);
    rewind(input);

    unsigned char* buffer = malloc(size);
    unsigned char* result = malloc(size);
    g_buffer = buffer;
    g_result = result;

    fread(buffer, 1, size, input);

    //вызываем функции из библиотеки!!
    set_key(key);
    caesar(buffer, result, size);

    fwrite(result, 1, size, output); // запись результатов в файлы

    fclose(input);
    fclose(output);
    free(buffer);
    free(result);
    dlclose(handle); // очистка памяти закрытие файлов и тп

    return 0;
}
