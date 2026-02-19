#include "caesar.h"
//реализация библиотеки шифрования Цезаря (т.е ее содержимое)
static unsigned char global_key = 0; //ключ шифрования хранимымй внутри билиотеки, не видимый снаружи

void set_key(char key) {
    global_key = (unsigned char)key; //ключ сохраняем в глобальной переменной
}

void caesar(void* src, void* dst, int len) { //получает два массивы и их длину, src - исходные данные, dst - куда записать результат
    unsigned char* s = (unsigned char*)src; //приведение к байтовому типу
    unsigned char* d = (unsigned char*)dst;

    for (int i = 0; i < len; i++) {
        d[i] = s[i] ^ global_key; //применение xor
    }
}
