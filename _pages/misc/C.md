---
permalink: /misc/C
title: C
---

<br>


# basic linked list 

```c
#include <stddef.h>
#include <stdio.h>

typedef struct Node {
    int value; 
    struct Node *next;
} node_t;


void push_end(node_t *head, node_t *next) {
    node_t *current = head;
    while (current->next != NULL) {
        current = current->next;
    }
    current->next = next;
}


int main() {
    node_t head;

    node_t one = {1, NULL};
    node_t two = {2, NULL};
    push_end(&head, &one);
    push_end(&head, &two);

    node_t *current = &head;
    while (current->next != NULL) {
        current = current->next;
        printf("%d\n", current->value);
    }
}
```

I'll leave the above for reference, but it kinda sucks because all your nodes have to already exist in the one function. 


So here's a better one using malloc to save stuff on the heap. 

<br>

<br>
