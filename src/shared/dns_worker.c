#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include "dns_worker.h"

#define PORT_STR_LEN 6 /* "65535\0" */
#define HOST_MAX_LEN 256

typedef struct dns_job {
    char host[HOST_MAX_LEN];
    char port[PORT_STR_LEN];
    int fd;
    struct addrinfo **result_target;
    fd_selector selector;
    struct dns_job *next;
} dns_job_t;

struct dns_worker {
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    dns_job_t *queue_head;
    dns_job_t *queue_tail;
    bool running;
};

static void *
dns_thread(void *arg)
{
    dns_worker_t *w = arg;

    while (true) {
        pthread_mutex_lock(&w->mutex);
        while (w->queue_head == NULL && w->running) {
            pthread_cond_wait(&w->cond, &w->mutex);
        }
        if (!w->running && w->queue_head == NULL) {
            pthread_mutex_unlock(&w->mutex);
            break;
        }
        dns_job_t *job = w->queue_head;
        w->queue_head = job->next;
        if (w->queue_head == NULL) {
            w->queue_tail = NULL;
        }
        pthread_mutex_unlock(&w->mutex);

        struct addrinfo hints = {
            .ai_family   = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM,
        };
        struct addrinfo *result = NULL;
        getaddrinfo(job->host, job->port, &hints, &result);
        *job->result_target = result; /* NULL if resolution failed */

        selector_notify_block(job->selector, job->fd);
        free(job);
    }
    return NULL;
}

dns_worker_t *
dns_worker_create(void)
{
    dns_worker_t *w = calloc(1, sizeof(*w));
    if (w == NULL) {
        return NULL;
    }
    if (pthread_mutex_init(&w->mutex, NULL) != 0) {
        free(w);
        return NULL;
    }
    if (pthread_cond_init(&w->cond, NULL) != 0) {
        pthread_mutex_destroy(&w->mutex);
        free(w);
        return NULL;
    }
    w->running = true;
    if (pthread_create(&w->thread, NULL, dns_thread, w) != 0) {
        pthread_cond_destroy(&w->cond);
        pthread_mutex_destroy(&w->mutex);
        free(w);
        return NULL;
    }
    return w;
}

void
dns_worker_destroy(dns_worker_t *w)
{
    if (w == NULL) {
        return;
    }
    pthread_mutex_lock(&w->mutex);
    w->running = false;
    pthread_cond_signal(&w->cond);
    pthread_mutex_unlock(&w->mutex);
    pthread_join(w->thread, NULL);

    dns_job_t *j = w->queue_head;
    while (j != NULL) {
        dns_job_t *next = j->next;
        free(j);
        j = next;
    }
    pthread_cond_destroy(&w->cond);
    pthread_mutex_destroy(&w->mutex);
    free(w);
}

int
dns_worker_submit(dns_worker_t *w, int fd, const char *host, uint16_t port,
                  struct addrinfo **result_target, fd_selector selector)
{
    dns_job_t *job = malloc(sizeof(*job));
    if (job == NULL) {
        return -1;
    }
    strncpy(job->host, host, HOST_MAX_LEN - 1);
    job->host[HOST_MAX_LEN - 1] = '\0';
    snprintf(job->port, PORT_STR_LEN, "%u", port);
    job->fd = fd;
    job->result_target = result_target;
    job->selector = selector;
    job->next = NULL;

    pthread_mutex_lock(&w->mutex);
    if (w->queue_tail != NULL) {
        w->queue_tail->next = job;
    } else {
        w->queue_head = job;
    }
    w->queue_tail = job;
    pthread_cond_signal(&w->cond);
    pthread_mutex_unlock(&w->mutex);

    return 0;
}
