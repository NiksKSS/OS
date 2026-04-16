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

#ifndef WORKERS_COUNT
#define WORKERS_COUNT 4
#endif

#define MAX_FILENAME 512
#define MAX_FILES 100
#define TIMEOUT_SEC 5

typedef enum {
    MODE_SEQUENTIAL,
    MODE_PARALLEL,
    MODE_AUTO
} work_mode;

typedef struct {
    double total_time;
    double avg_time;
    int processed_count;
    double* file_times;
} statistics;

typedef struct {
    char** files;
    int count;
    int next_index;
    int finished;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} file_queue;

typedef struct {
    file_queue* queue;
    char* output_dir;
    char key;
    int* processed_count;
    pthread_mutex_t* log_mutex;
    pthread_mutex_t* count_mutex;
    statistics* stats;
    pthread_mutex_t* stats_mutex;
} thread_data;

static volatile int keep_running = 1;

void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0;
}

void queue_init(file_queue* q, char** files, int count) {
    q->files = files;
    q->count = count;
    q->next_index = 0;
    q->finished = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond, NULL);
}

int queue_pop(file_queue* q, char** filename) {
    pthread_mutex_lock(&q->mutex);
    
    while (q->next_index >= q->count && !q->finished && keep_running) {
        pthread_cond_wait(&q->cond, &q->mutex);
    }
    
    if (q->finished || !keep_running) {
        pthread_mutex_unlock(&q->mutex);
        return 0;
    }

    *filename = q->files[q->next_index];
    q->next_index++;
    
    if (q->next_index >= q->count) {
        q->finished = 1;
    }
    
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->mutex);
    
    return 1;
}

void queue_destroy(file_queue* q) {
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond);
}

void write_log(const char* filename, pthread_t thread_id, pthread_mutex_t* mutex) {
    pthread_mutex_lock(mutex);
    
    FILE* log_file = fopen("log.txt", "a"); 
    if (!log_file) {
        pthread_mutex_unlock(mutex);
        return;
    }

    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(log_file, "%s | Thread-%lu | %s\n", time_str, (unsigned long)thread_id, filename);
    fflush(log_file); 
    fclose(log_file);
    
    pthread_mutex_unlock(mutex);
}

int process_file(const char* input_path, const char* output_dir, char key) {
    char encrypted_path[MAX_FILENAME + MAX_FILENAME];
    
    const char* basename = strrchr(input_path, '/');
    basename = basename ? basename + 1 : input_path;
    
    snprintf(encrypted_path, sizeof(encrypted_path), "%s/%s.enc", output_dir, basename);
    
    FILE* input = fopen(input_path, "rb");
    if (!input) {
        return -1;
    }

    fseek(input, 0, SEEK_END);
    long file_size = ftell(input);
    fseek(input, 0, SEEK_SET);

    unsigned char* buffer = malloc(file_size);
    if (!buffer) {
        fclose(input);
        return -1;
    }

    fread(buffer, 1, file_size, input);
    fclose(input);

    unsigned char* encrypted = malloc(file_size);
    if (!encrypted) {
        free(buffer);
        return -1;
    }

    set_key(key);
    caesar(buffer, encrypted, file_size);
    
    FILE* output = fopen(encrypted_path, "wb"); 
    if (!output) {
        free(buffer);
        free(encrypted);
        return -1;
    }

    fwrite(encrypted, 1, file_size, output);
    fclose(output);

    free(buffer);
    free(encrypted);

    return 0;
}

void* worker_thread(void* arg) {
    thread_data* data = (thread_data*)arg;
    pthread_t self = pthread_self();
    
    while (keep_running) {
        char* filename = NULL;
        struct timespec start, end;
        
        int result = queue_pop(data->queue, &filename);
        
        if (result == 0) {
            break;
        }

        clock_gettime(CLOCK_MONOTONIC, &start);
        
        int process_result = process_file(filename, data->output_dir, data->key);
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        pthread_mutex_lock(data->count_mutex);
        int idx = *data->processed_count;
        (*data->processed_count)++;
        pthread_mutex_unlock(data->count_mutex);
        
        if (process_result == 0) {
            write_log(filename, self, data->log_mutex);
        }
        
        pthread_mutex_lock(data->stats_mutex);
        double file_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        if (data->stats->file_times && idx < MAX_FILES) {
            data->stats->file_times[idx] = file_time;
        }
        pthread_mutex_unlock(data->stats_mutex);
    }
    
    return NULL;
}

void init_statistics(statistics* stats, int file_count) {
    stats->total_time = 0.0;
    stats->avg_time = 0.0;
    stats->processed_count = 0;
    stats->file_times = malloc(file_count * sizeof(double));
    if (stats->file_times) {
        for (int i = 0; i < file_count; i++) {
            stats->file_times[i] = 0.0;
        }
    }
}

void free_statistics(statistics* stats) {
    if (stats->file_times) {
        free(stats->file_times);
        stats->file_times = NULL;
    }
}

void compute_statistics(statistics* stats, double total_time) {
    stats->total_time = total_time;
    if (stats->processed_count > 0) {
        stats->avg_time = total_time / stats->processed_count;
    }
}

void print_statistics(const char* mode_name, statistics* stats) {
    printf("\n========== STATISTICS FOR %s MODE ==========\n", mode_name);
    printf("Total execution time: %.3f ms\n", stats->total_time * 1000);
    printf("Average time per file: %.3f ms\n", stats->avg_time * 1000);
    printf("Files processed: %d\n", stats->processed_count);
    printf("=============================================\n");
}

void print_comparison(statistics* seq_stats, statistics* par_stats) {
    printf("\n========== COMPARISON TABLE ==========\n");
    printf("%-20s | %-15s | %-15s\n", "Metric", "Sequential", "Parallel");
    printf("%-20s-+-%-15s-+-%-15s\n", "--------------------", "---------------", "---------------");
    printf("%-20s | %-15.3f ms | %-15.3f ms\n", "Total time", seq_stats->total_time * 1000, par_stats->total_time * 1000);
    printf("%-20s | %-15.3f ms | %-15.3f ms\n", "Avg time/file", seq_stats->avg_time * 1000, par_stats->avg_time * 1000);
    printf("%-20s | %-15d | %-15d\n", "Files processed", seq_stats->processed_count, par_stats->processed_count);
    
    double speedup = 0.0;
    if (par_stats->total_time > 0) {
        speedup = seq_stats->total_time / par_stats->total_time;
    }
    printf("%-20s | %-15.2fx\n", "Speedup", speedup);
    printf("========================================\n");
}

void reset_output_dir(const char* output_dir) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "rm -rf %s && mkdir -p %s", output_dir, output_dir);
    system(cmd);
}

int run_sequential(char** files, int file_count, const char* output_dir, char key, statistics* stats) {
    reset_output_dir(output_dir);
    
    struct timespec total_start, total_end;
    clock_gettime(CLOCK_MONOTONIC, &total_start);
    
    for (int i = 0; i < file_count && keep_running; i++) {
        struct timespec file_start, file_end;
        clock_gettime(CLOCK_MONOTONIC, &file_start);
        
        int result = process_file(files[i], output_dir, key);
        
        clock_gettime(CLOCK_MONOTONIC, &file_end);
        
        if (result == 0) {
            stats->processed_count++;
            double file_time = (file_end.tv_sec - file_start.tv_sec) + (file_end.tv_nsec - file_start.tv_nsec) / 1e9;
            if (stats->file_times && i < file_count) {
                stats->file_times[i] = file_time;
            }
        }
    }
    
    clock_gettime(CLOCK_MONOTONIC, &total_end);
    double total_time = (total_end.tv_sec - total_start.tv_sec) + (total_end.tv_nsec - total_start.tv_nsec) / 1e9;
    compute_statistics(stats, total_time);
    
    return 0;
}

int run_parallel(char** files, int file_count, const char* output_dir, char key, statistics* stats) {
    reset_output_dir(output_dir);
    
    file_queue queue;
    queue_init(&queue, files, file_count);

    int processed_count = 0;
    pthread_mutex_t log_mutex;
    pthread_mutex_t count_mutex;
    pthread_mutex_t stats_mutex;
    pthread_mutex_init(&log_mutex, NULL);
    pthread_mutex_init(&count_mutex, NULL);
    pthread_mutex_init(&stats_mutex, NULL);

    thread_data data;
    data.queue = &queue;
    data.output_dir = (char*)output_dir;
    data.key = key;
    data.processed_count = &processed_count;
    data.log_mutex = &log_mutex;
    data.count_mutex = &count_mutex;
    data.stats = stats;
    data.stats_mutex = &stats_mutex;

    pthread_t threads[WORKERS_COUNT];

    struct timespec total_start, total_end;
    clock_gettime(CLOCK_MONOTONIC, &total_start);
    
    for (int i = 0; i < WORKERS_COUNT; i++) {
        pthread_create(&threads[i], NULL, worker_thread, &data);
    }

    for (int i = 0; i < WORKERS_COUNT; i++) {
        pthread_join(threads[i], NULL);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &total_end);
    double total_time = (total_end.tv_sec - total_start.tv_sec) + (total_end.tv_nsec - total_start.tv_nsec) / 1e9;
    stats->processed_count = processed_count;
    compute_statistics(stats, total_time);

    queue_destroy(&queue);
    pthread_mutex_destroy(&log_mutex);
    pthread_mutex_destroy(&count_mutex);
    pthread_mutex_destroy(&stats_mutex);
    
    return 0;
}

work_mode parse_mode_arg(const char* arg) {
    if (strcmp(arg, "--mode=sequential") == 0) {
        return MODE_SEQUENTIAL;
    } else if (strcmp(arg, "--mode=parallel") == 0) {
        return MODE_PARALLEL;
    } else if (strcmp(arg, "--mode=auto") == 0) {
        return MODE_AUTO;
    }
    return MODE_AUTO;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s --mode=sequential|parallel|auto <input_files...> <output_dir> <key>\n", argv[0]);
        return 1;
    }

    work_mode mode = parse_mode_arg(argv[1]);
    
    int first_file_arg = 2;
    int last_arg = argc - 1;
    char* output_dir = argv[last_arg - 1];
    char key = argv[last_arg][0];

    int num_files = last_arg - first_file_arg - 1;
    if (num_files <= 0) {
        fprintf(stderr, "Error: No input files specified\n");
        return 1;
    }

    char** files = malloc(num_files * sizeof(char*));
    for (int i = 0; i < num_files; i++) {
        files[i] = argv[first_file_arg + i];
    }

    if (mkdir(output_dir, 0777) == -1) {
        if (errno != EEXIST) {
            free(files);
            return 1;
        }
    }

    signal(SIGINT, handle_sigint);

    statistics seq_stats, par_stats;
    init_statistics(&seq_stats, num_files);
    init_statistics(&par_stats, num_files);

    if (mode == MODE_AUTO) {
        printf("Auto mode: %d files detected\n", num_files);
        
        if (num_files < 5) {
            printf("Using SEQUENTIAL mode (files < 5)\n\n");
            run_sequential(files, num_files, output_dir, key, &seq_stats);
            print_statistics("SEQUENTIAL", &seq_stats);
            
            printf("\nRunning PARALLEL mode for comparison...\n");
            run_parallel(files, num_files, output_dir, key, &par_stats);
            print_statistics("PARALLEL", &par_stats);
            
            print_comparison(&seq_stats, &par_stats);
        } else {
            printf("Using PARALLEL mode (files >= 5)\n\n");
            run_parallel(files, num_files, output_dir, key, &par_stats);
            print_statistics("PARALLEL", &par_stats);
            
            printf("\nRunning SEQUENTIAL mode for comparison...\n");
            run_sequential(files, num_files, output_dir, key, &seq_stats);
            print_statistics("SEQUENTIAL", &seq_stats);
            
            print_comparison(&seq_stats, &par_stats);
        }
    } else if (mode == MODE_SEQUENTIAL) {
        printf("Running in SEQUENTIAL mode\n\n");
        run_sequential(files, num_files, output_dir, key, &seq_stats);
        print_statistics("SEQUENTIAL", &seq_stats);
    } else {
        printf("Running in PARALLEL mode (workers: %d)\n\n", WORKERS_COUNT);
        run_parallel(files, num_files, output_dir, key, &par_stats);
        print_statistics("PARALLEL", &par_stats);
    }

    free_statistics(&seq_stats);
    free_statistics(&par_stats);
    free(files);

    return 0;
}
