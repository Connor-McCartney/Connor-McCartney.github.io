---
permalink: /misc/C
title: C
---

<br>


# basic linked list 

```python
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

