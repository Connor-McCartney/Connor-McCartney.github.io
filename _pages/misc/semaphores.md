



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

You can use semaphores!

<br>

```c
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <semaphore.h>


sem_t my_semaphore;

void* thread_action(void* arg) {
    int thread_id = *(int*)arg;

    //printf("Thread %d waiting to start...\n", thread_id);

    // decrement semaphore (block if value is 0)
    sem_wait(&my_semaphore); 



    //printf("Thread %d started\n", thread_id);
    sleep(1);
    printf("Thread %d finished\n", thread_id);



    // increment semaphore when finished
    sem_post(&my_semaphore); 

    return NULL;
}

int main() {
    pthread_t threads[10];
    int thread_ids[10];


    /*
     * Initialize semaphore:
     * Argument 1: Pointer to the semaphore
     * Argument 2: 0 means shared between threads; non-zero means between processes
     * Argument 3: Initial value (3 threads allowed at a time)
     */
    sem_init(&my_semaphore, 0, 3);

    for (int i = 0; i < 10; i++) {
        thread_ids[i] = i + 1;
        pthread_create(&threads[i], NULL, thread_action, &thread_ids[i]);
    }

    // Wait for all threads to finish execution
    for (int i = 0; i < 10; i++) {
        pthread_join(threads[i], NULL);
    }


    sem_destroy(&my_semaphore); // cleanup

    printf("All threads finished.\n");
    return 0;
}
```
