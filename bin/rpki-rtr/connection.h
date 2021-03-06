#ifndef _RTR_CONNECTION_H
#define _RTR_CONNECTION_H

// Declarations related to connection threads.
// Currently: main entry point and related arguments.

#include "util/bag.h"
#include "util/queue.h"

#include "cache_state.h"
#include "semaphores.h"


// memory is alocated by connection_control and free()d by connection
struct connection_main_args {
    int socket;
    const struct sockaddr *addr;
    socklen_t addr_len;
    const char *host;
    const char *serv;
    cxn_semaphore_t *semaphore;
    Queue *db_request_queue;
    db_semaphore_t *db_semaphore;
    struct global_cache_state *global_cache_state;
};
void *connection_main(
    void *args_voidp);

#endif
