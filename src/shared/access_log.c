#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include "access_log.h"

#define TIMESTAMP_LEN 21  /* "2026-06-27T14:32:01Z\0" */

static void write_timestamp(FILE *f) {
    char buf[TIMESTAMP_LEN];
    time_t now = time(NULL);
    struct tm *tm = gmtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", tm);
    fprintf(f, "%s", buf);
}

struct access_log {
    FILE *file;
    int is_stderr;
};

access_log_t *access_log_create(const char *path) {
    access_log_t *log = calloc(1, sizeof(*log));
    if (log == NULL) {
        return NULL;
    }
    if (path == NULL) {
        log->file = stderr;
        log->is_stderr = 1;
    } else {
        log->file = fopen(path, "a");
        if (log->file == NULL) {
            free(log);
            return NULL;
        }
        log->is_stderr = 0;
    }
    return log;
}

void access_log_destroy(access_log_t *log) {
    if (log == NULL) {
        return;
    }
    if (!log->is_stderr) {
        fclose(log->file);
    }
    free(log);
}

void access_log_open(access_log_t *log, const char *user, const char *dest, uint16_t port) {
    write_timestamp(log->file);
    fprintf(log->file, "\t%s\t%s:%u\t-\t-\tOPEN\n", user ? user : "-", dest, port);
    fflush(log->file);
}

void access_log_close(access_log_t *log, const char *user, const char *dest, uint16_t port,
                      uint64_t bytes_c2o, uint64_t bytes_o2c) {
    write_timestamp(log->file);
    fprintf(log->file, "\t%s\t%s:%u\t%" PRIu64 "\t%" PRIu64 "\tCLOSE\n",
            user ? user : "-", dest, port, bytes_c2o, bytes_o2c);
    fflush(log->file);
}

void access_log_fail(access_log_t *log, const char *user, const char *dest, uint16_t port,
                     const char *reason) {
    write_timestamp(log->file);
    fprintf(log->file, "\t%s\t%s:%u\t-\t-\tFAIL: %s\n",
            user ? user : "-", dest ? dest : "-", port,
            reason ? reason : "unknown");
    fflush(log->file);
}
