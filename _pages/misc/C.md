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


So here's a better one using malloc to create nodes on the heap:

<br>

<br>

```c
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct Data {
    int x; 
} data_t;


typedef struct Node {
    data_t data;
    struct Node *next;
} node_t;


node_t *create_node(data_t data){
    node_t *new_node = malloc(sizeof(node_t));
    new_node->data = data;
    new_node->next = NULL;
    return new_node;
}

void destroy_list(node_t *head){
    node_t *current = head;
    node_t *next = current;
    while (current->next != NULL) {
        next = current->next;
        free(current);
        current = next;
    }
    free(current);

}

void push_end(node_t *head, data_t next) {
    node_t *current = head;
    while (current->next != NULL) {
        current = current->next;
    }
    node_t *new_node = create_node(next);
    current->next = new_node;
}


int main() {
    node_t *head = malloc(sizeof(node_t));
    head->next = NULL;

    for (int i=0; i<10; i++) {
        data_t d = {i};
        push_end(head, d);
    }

    node_t *current = head;
    while (current->next != NULL) {
        current = current->next;
        printf("%d\n", current->data.x);
    }

    destroy_list(head);
}
```


<br>

# Trees

Trees contain layers of branches, which contains nodes, which contain data.  

For example: 

```python
from random import randint

def random_leaf():
    return [randint(1, 9) for _ in range(3)]

tree = [[[random_leaf(), random_leaf()]]]

depth = 3
for _ in range(depth):
    new_branches = []
    for branch in tree[-1]:
        for leaf in branch:
            new_branch = []
            for item in leaf:
                new_branch.append(random_leaf())
            new_branches.append(new_branch)
    tree.append(new_branches)

for i in tree:
    print(i)
    print()
```


