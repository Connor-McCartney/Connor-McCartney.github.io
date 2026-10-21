



<br>


# Posix threads and semaphores


<br>

<https://medium.com/@akshatarhabib/understanding-semaphores-in-c-04835e97024f>

<br>


<https://man7.org/linux/man-pages/man7/sem_overview.7.html>


<br>

<br>


Normal posix threads code (no semaphores):

```c
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

void* thread_action(void* arg) {
    int thread_id = *(int*)arg;
    
    printf("Thread %d started\n", thread_id);
    sleep(1);
    printf("Thread %d finished\n", thread_id);

    return NULL;
}

int main() {
    pthread_t threads[10];
    int thread_ids[10];

    // create threads
    for (int i = 0; i < 10; i++) {
        thread_ids[i] = i + 1;
        pthread_create(&threads[i], NULL, thread_action, &thread_ids[i]);
    }

    // wait for all threads to finish executing
    for (int i = 0; i < 10; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("All threads finished.\n");
    return 0;
}



```


<br>


<br>



Now what if you only want say a maximum of 3 threads to execute at a time?


<br>

