#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include "caesar.h"

#define NUM_THREADS 3
#define TIMEOUT_SEC 5
#define MAX_FILENAME 512
#define MAX_FILES 100

// структура для хранения списка файлов которые надо обработать
// next_index показывает какой файл следующий на очереди
// mutex нужен чтобы два потока случайно не взяли один и тот же файл
typedef struct {
    char** files;
    int count;
    int next_index;
    pthread_mutex_t mutex;
} file_queue;

// всё что мы передаём каждому потоку когда он стартует
// все три потока получают указатель на одну и ту же структуру
typedef struct {
    file_queue* queue;
    char* output_dir;
    char key;
    int* processed_count;
    pthread_mutex_t* log_mutex;   // отдельный замок для лога
    pthread_mutex_t* count_mutex; // отдельный замок для счётчика
} thread_data;

// пока 1 - потоки работают, как только станет 0 - все останавливаются
static volatile int keep_running = 1;

// пользователь нажимает Ctrl+C
void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0;
}

// заполняем структуру очереди и создаём для неё мьютекс
void queue_init(file_queue* q, char** files, int count) {
    q->files = files;
    q->count = count;
    q->next_index = 0;
    pthread_mutex_init(&q->mutex, NULL);
}

// поток вызывает эту функцию чтобы получить следующий файл
// используем trylock 
// если не можем взять замок больше 5 секунд - возвращаем -1 (таймаут)
int queue_pop(file_queue* q, char** filename, int timeout_sec) {
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start); 

    while (keep_running) {
        int lock_result = pthread_mutex_trylock(&q->mutex);
        
        if (lock_result == 0) { // замок взяли успешно
            if (q->next_index >= q->count) { // файлы закончились
                pthread_mutex_unlock(&q->mutex);
                return 0;
            }

            // берём файл и сразу двигаем указатель вперёд
            *filename = q->files[q->next_index];
            q->next_index++;
            
            pthread_mutex_unlock(&q->mutex);
            return 1;
        }
        
        // замок занят другим потоком, смотрим сколько времени уже ждём
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - start.tv_sec) + (now.tv_nsec - start.tv_nsec) / 1e9;
        
        if (elapsed >= timeout_sec) {
            return -1; // ждали 5 секунд
        }
        
        usleep(10000);
    }
    
    return 0;
}

// просто уничтожаем мьютекс очереди когда всё закончилось
void queue_destroy(file_queue* q) {
    pthread_mutex_destroy(&q->mutex);
}

// записываем в log.txt строку: время, номер потока, имя файла
// берём замок перед записью 
void write_log(const char* filename, pthread_t thread_id, pthread_mutex_t* mutex) {
    pthread_mutex_lock(mutex);
    
    FILE* log_file = fopen("log.txt", "a"); 
    if (!log_file) {
        pthread_mutex_unlock(mutex);
        return;
    }

    // форматируем текущее время в читаемый вид 
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(log_file, "%s | Thread-%lu | %s\n", time_str, (unsigned long)thread_id, filename);
    fflush(log_file); 
    fclose(log_file);
    
    pthread_mutex_unlock(mutex);
}

// читаем файл целиком в память, шифруем через caesar, записываем с расширением .enc
int process_file(const char* input_path, const char* output_dir, char key) {
    char encrypted_path[MAX_FILENAME + MAX_FILENAME];
    
    const char* basename = strrchr(input_path, '/');
    basename = basename ? basename + 1 : input_path;
    
    snprintf(encrypted_path, sizeof(encrypted_path), "%s/%s.enc", output_dir, basename);
    
    FILE* input = fopen(input_path, "rb");
    if (!input) {
        return -1;
    }


    fseek(input, 0, SEEK_END); //читаем размер файла
    long file_size = ftell(input);
    fseek(input, 0, SEEK_SET);

    unsigned char* buffer = malloc(file_size); // выделяем память для всего файла
    if (!buffer) {
        fclose(input);
        return -1;
    }

    fread(buffer, 1, file_size, input); // читаем весь файл за один раз
    fclose(input);

    unsigned char* encrypted = malloc(file_size);
    if (!encrypted) {
        free(buffer);
        return -1;
    }


    set_key(key); // запоминаем ключ для шифрования
    caesar(buffer, encrypted, file_size); // вызываем функцию шифрования!!!
    
    FILE* output = fopen(encrypted_path, "wb"); 
    if (!output) {
        free(buffer);
        free(encrypted);
        return -1;
    }

    fwrite(encrypted, 1, file_size, output);// записываем весь зашифрованный файл
    fclose(output);

    // чистим буферы
    free(buffer);
    free(encrypted);

    return 0;
}


// бесконечно берём файл из очереди, шифруем, пишем в лог
void* worker_thread(void* arg) {
    thread_data* data = (thread_data*)arg;
    
    while (keep_running) {
        char* filename = NULL;
        
        int result = queue_pop(data->queue, &filename, TIMEOUT_SEC);
        
        if (result == -1) {
            continue;
        }
        
        if (result == 0) {
            break; // файлов больше нет, поток завершает работу
        }

        if (process_file(filename, data->output_dir, data->key) == 0) {
            write_log(filename, pthread_self(), data->log_mutex);
        }
        
        // увеличиваем счётчик мьютексом
        pthread_mutex_lock(data->count_mutex);
        (*data->processed_count)++;
        pthread_mutex_unlock(data->count_mutex);
    }
    
    return NULL;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        return 1;
    }

    int last_arg = argc - 1;
    char* output_dir = argv[last_arg - 1];
    char key = argv[last_arg][0]; // берём первый символ строки как ключ

    int num_files = last_arg - 2;
    if (num_files <= 0) {
        return 1;
    }

    char** files = malloc(num_files * sizeof(char*));
    for (int i = 0; i < num_files; i++) {
        files[i] = argv[i + 1];
    }

    // создаём папку для результатов
    if (mkdir(output_dir, 0777) == -1) {
        if (errno != EEXIST) {
            free(files);
            return 1;
        }
    }

    signal(SIGINT, handle_sigint); // регистрируем обработчик Ctrl+C

    file_queue queue;
    queue_init(&queue, files, num_files);

    int processed_count = 0;
    pthread_mutex_t log_mutex;
    pthread_mutex_t count_mutex;
    pthread_mutex_init(&log_mutex, NULL);
    pthread_mutex_init(&count_mutex, NULL);

    // заполняем структуру с данными для потоков
    thread_data data;
    data.queue = &queue;
    data.output_dir = output_dir;
    data.key = key;
    data.processed_count = &processed_count;
    data.log_mutex = &log_mutex;
    data.count_mutex = &count_mutex;

    pthread_t threads[NUM_THREADS];

    // запускаем все три потока
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, worker_thread, &data);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    // чистим
    queue_destroy(&queue);
    pthread_mutex_destroy(&log_mutex);
    pthread_mutex_destroy(&count_mutex);
    free(files);

    return 0;
}