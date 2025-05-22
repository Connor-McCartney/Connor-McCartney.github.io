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

def random_branch():
    return [randint(1, 9) for _ in range(3)]

tree = [[[random_branch(), random_branch()]]]

depth = 3
for _ in range(depth):
    new_layer = []
    for branches in tree[-1]:
        for branch in branches:
            new_branch = []
            for node in branch:
                new_branch.append(random_branch())
            new_layer.append(new_branch)
    tree.append(new_layer)

for layer in tree:
    print(layer)
    print()
```

<br>

To walk back up the tree, nodes can contain their parent's node in addition to their data. 


```python
from random import randint

class Node:
    def __init__(self, data, parent=None):
        self.data = data
        self.parent = parent

def random_branch(parent):
    return [Node(randint(1, 9), parent) for _ in range(3)]

tree = [[[random_branch(None), random_branch(None)]]]

depth = 3
for _ in range(depth):
    new_layer = []
    for branches in tree[-1]:
        for branch in branches:
            new_branch = []
            for node in branch:
                new_branch.append(random_branch(parent=node))
            new_layer.append(new_branch)
    tree.append(new_layer)

for layer in tree:
    print([[[node.data for node in branch] for branch in branches] for branches in layer])
    print()



def walk_up_tree(node):
    path = []
    current = node
    while current is not None:
        path.append(current)
        current = current.parent
    return path[::-1]


bottom_node = tree[-1][0][0][0] # arbitrary example
print(bottom_node.data)
path = walk_up_tree(bottom_node)
print([node.data for node in path])
```

<br>

```c
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

typedef struct Data {
    int x; 
} data_t;


typedef struct TreeNode {
    data_t data;
    struct TreeNode *parent;
} treenode_t;


typedef struct TreeListNode {
    treenode_t *treenode;
    struct TreeListNode *next;
} treelistnode_t;


treelistnode_t *create_treelist_node(treenode_t *treenode){
    treelistnode_t *new_node = malloc(sizeof(treelistnode_t));
    new_node->treenode = treenode;
    new_node->next = NULL;
    return new_node;
}


treenode_t *create_tree_node(data_t data, treenode_t *parent){
    treenode_t *new_node = malloc(sizeof(treenode_t));
    new_node->data = data;
    new_node->parent = parent;
    return new_node;
}

void push_end(treelistnode_t *head, treenode_t *next) {
    assert(head != NULL);
    treelistnode_t *current = head;
    while (current->next != NULL) {
        current = current->next;
    }
    treelistnode_t *new_node = create_treelist_node(next);
    current->next = new_node;
}

treenode_t *copy_treenode(treenode_t *original){
    assert(original!=NULL);
    treenode_t *copy = malloc(sizeof(treenode_t));
    copy->data = original->data;
    copy->parent = original->parent;
    return copy;
}

/*
treelistnode_t *copy_treelist(treelistnode_t *head){
    assert(head != NULL);

    treelistnode_t *copy = malloc(sizeof(treelistnode_t));
    copy->next = NULL;

    treelistnode_t *current = head;
    while (current->next != NULL) {
        current = current->next;
        treenode_t *treenode_copy = copy_treenode(current->treenode);
        push_end(copy, treenode_copy);
    }

    return copy;
}
*/

void destroy_treelist(treelistnode_t *head){
    assert(head != NULL);
    treelistnode_t *current = head;
    treelistnode_t *next = current;
    while (current->next != NULL) {
        next = current->next;
        free(current->treenode);
        free(current);
        current = next;
    }
    assert(current != NULL);
    assert(current->treenode != NULL);
    free(current->treenode);
    free(current);
}


void add_random_branch(treelistnode_t *tree, treenode_t *parent) {
    data_t d1 = {rand() % 10};
    data_t d2 = {rand() % 10};
    data_t d3 = {rand() % 10};
    treenode_t *r1 = create_tree_node(d1, parent);
    treenode_t *r2 = create_tree_node(d2, parent);
    treenode_t *r3 = create_tree_node(d3, parent);
    push_end(tree, r1);
    push_end(tree, r2);
    push_end(tree, r3);
}


int main() {
    treelistnode_t *current; treelistnode_t *tree = malloc(sizeof(treelistnode_t));
    tree->next = NULL;


    data_t d1 = {rand() % 10};
    data_t d2 = {rand() % 10};
    treenode_t *r1 = create_tree_node(d1, NULL);
    treenode_t *r2 = create_tree_node(d2, NULL);
    push_end(tree, r1);
    push_end(tree, r2);

    int max_depth = 1;
    for (int d=0; d<max_depth; d++) {
        printf("depth %d\n", d);

        treelistnode_t *to_push = malloc(sizeof(treelistnode_t));
        to_push->next = NULL;
        current = tree;
        while (current->next != NULL) {
            add_random_branch(to_push, current->treenode);
            current = current->next;
        }
        current = to_push;
        while (current->next != NULL) {
            current = current->next;
            printf("%d\n", current->treenode->data.x);
            push_end(tree, copy_treenode(current->treenode));
        }
        destroy_treelist(to_push);
    }
    
    destroy_treelist(tree);
}
```


