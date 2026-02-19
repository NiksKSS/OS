#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h> //для динамической загрузки библиотеки

typedef void (*set_key_func)(char); //создание типов фнукций для вызова их через указатели
typedef void (*caesar_func)(void*, void*, int);

int main(int argc, char* argv[]) {

    if (argc != 5) { // проверка на правильное количество аргументов
        printf("Usage: %s <lib_path> <key> <input_file> <output_file>\n", argv[0]);
        return 1;
    }
    //приемка аргументов
    char* lib_path = argv[1];
    char key = argv[2][0];
    char* input_path = argv[3];
    char* output_path = argv[4];

    void* handle = dlopen(lib_path, RTLD_LAZY); //загрузка библиотеки именно во время выполнения
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

    fseek(input, 0, SEEK_END); // определение размера входного файла
    int size = ftell(input);
    rewind(input);

    unsigned char* buffer = malloc(size); //выделение памяти для входного буфера и выходного результата
    unsigned char* result = malloc(size);

    fread(buffer, 1, size, input); //чтение данных из входного файла в буфер


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
