#ifndef CAESAR_H //заголовок библиотеки, чтобы не было повторного включения
#define CAESAR_H 

void set_key(char key); //запоминание ключа для шифрования
void caesar(void* src, void* dst, int len);//функция запоминающая ключ

#endif
