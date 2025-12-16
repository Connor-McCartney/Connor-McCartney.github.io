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
    node_t *next;
    for (node_t *current = head;  current != NULL;  current = next) {
        next = current->next;
        free(current);
    }
}

node_t* push_end(node_t *head, data_t next) {
    node_t *new_node = create_node(next);
    node_t *current;

    if (head==NULL) {
        head = new_node;
    } else {
        for (current = head; current->next != NULL; current = current->next) {
            ;
        }
        current->next = new_node;
    }
    return head;
}


node_t *reverse_list(node_t *head ) {
    node_t *prev = NULL;
    node_t *next;
    for (node_t *curr = head;  curr != NULL;  curr = next) {
        next = curr->next;
        curr->next = prev;
        prev = curr;
    }
    return prev;
}

void print_list(node_t *head) {
    for (node_t *current = head; current != NULL; current = current->next) {
        printf("%d\n", current->data.x);
    }
}

int main() {
    node_t *my_list = NULL;

    for (int i=1; i<10; i++) {
        data_t d = {i};
        my_list = push_end(my_list, d);
    }

    print_list(my_list);
    printf("\n");
    my_list = reverse_list(my_list);
    print_list(my_list);

    destroy_list(my_list);
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

treenode_t *treenode_create(data_t data, treenode_t *parent){
    treenode_t *new_node = malloc(sizeof(treenode_t));
    new_node->data = data;
    new_node->parent = parent;
    return new_node;
}

treenode_t *treenode_copy(treenode_t *original){
    assert(original!=NULL);
    treenode_t *copy = malloc(sizeof(treenode_t));
    copy->data = original->data;
    copy->parent = original->parent;
    return copy;
}

treelistnode_t* treelist_push_end(treelistnode_t *head, treenode_t *next) {
    treelistnode_t *new_node = create_treelist_node(next);
    treelistnode_t *current;

    if (head==NULL) {
        head = new_node;
    } else {
        for (current = head; current->next != NULL; current = current->next) {
            ;
        }
        current->next = new_node;
    }
    return head;
}

treelistnode_t *add_random_branch(treelistnode_t *tree, treenode_t *parent) {
    data_t d1 = {rand() % 10};
    data_t d2 = {rand() % 10};
    data_t d3 = {rand() % 10};
    treenode_t *r1 = treenode_create(d1, parent);
    treenode_t *r2 = treenode_create(d2, parent);
    treenode_t *r3 = treenode_create(d3, parent);
    tree = treelist_push_end(tree, r1);
    tree = treelist_push_end(tree, r2);
    tree = treelist_push_end(tree, r3);
    return tree;
}

void treelist_free(treelistnode_t *head){
    treelistnode_t *next;
    for (treelistnode_t *current = head;  current != NULL;  current = next) {
        next = current->next;
        free(current->treenode);
        free(current);
    }
}

treelistnode_t *treelist_reverse(treelistnode_t *head) {
    treelistnode_t *prev = NULL;
    treelistnode_t *next;
    for (treelistnode_t *curr = head;  curr != NULL;  curr = next) {
        next = curr->next;
        curr->next = prev;
        prev = curr;
    }
    return prev;
}


int treelist_length(treelistnode_t *head) {
    treelistnode_t *current;
    int length = 0;
    for (current = head; current != NULL; current = current->next) {
        length += 1;
    }
    return length;
}

treelistnode_t *walk_up_tree(treenode_t *node) {
    treelistnode_t *path = NULL;
    for (treenode_t* current = node; current != NULL; current = current->parent) {
        path = treelist_push_end(path, treenode_copy(current));
    }
    path = treelist_reverse(path);
    return path;
}

treelistnode_t *treelist_copy(treelistnode_t *head){
    treelistnode_t *ret = NULL; 
    for (treelistnode_t* current = head; current != NULL; current = current->next) {
        ret = treelist_push_end(ret, treenode_copy(current->treenode));
    }
    return ret;
}

treelistnode_t *tree_get_max(treelistnode_t *head) {
    // max depth prioritised first, max data prioritised second
    // assumes the tree nodes are ordered by depth already
    // returns a path from the root

    int x;
    int best_x = 0;
    int depth;
    int best_depth = 0;
    treelistnode_t *ret = NULL; 
    treelistnode_t *current; 
    treelistnode_t *path; 

    for (current = head; current != NULL; current = current->next) {
        x = current->treenode->data.x;
        path = walk_up_tree(current->treenode); 
        depth = treelist_length(path);

        if (depth > best_depth) {
            best_x = x; // prioritise depth more than x
        }
        if (depth >= best_depth) {
            if (x > best_x) {
                treelist_free(ret);
                ret = treelist_copy(path);
                best_x = x;
            }
            best_depth = depth;
        }
        treelist_free(path);
    }

    assert(ret != NULL);
    return ret;
}

int main() {
    treelistnode_t *current; 
    treelistnode_t *next;
    treelistnode_t *tree = NULL; 
    treelistnode_t *to_push; 

    data_t d1 = {111};
    data_t d2 = {222};
    treenode_t *r1 = treenode_create(d1, NULL);
    treenode_t *r2 = treenode_create(d2, NULL);
    tree = treelist_push_end(tree, r1);
    tree = treelist_push_end(tree, r2);

    int max_depth = 2;
    for (int d=0; d<max_depth; d++) {
        printf("depth %d\n", d);
        to_push = NULL;
        for (current = tree;  current != NULL;  current = next) {
            next = current->next;
            to_push = add_random_branch(to_push, current->treenode);
        }
        for (current = to_push; current != NULL; current = current->next) {
            printf("%d\n", current->treenode->data.x);
            tree = treelist_push_end(tree, treenode_copy(current->treenode));
        }
        treelist_free(to_push);
    }

    treelistnode_t *max = tree_get_max(tree);
    printf("max path: ");
    for (current = max; current != NULL; current = current->next) {
        printf("%d ", current->treenode->data.x);
    }
    treelist_free(max);
    

    treelist_free(tree);
    return 0;
}
```



<br>

# TCP Client

Let's write some code to replicate this functionality:

```
$ printf "HEAD / HTTP/1.0\n\n" | nc www.google.com 80

HTTP/1.0 200 OK
Content-Type: text/html; charset=ISO-8859-1
Content-Security-Policy-Report-Only: object-src 'none';base-uri 'self';script-src 'nonce-XTpTnaBEuxqhU5t0SKJYTQ' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp
P3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."
Date: ...
Server: gws
X-XSS-Protection: 0
X-Frame-Options: SAMEORIGIN
Expires: ...
Cache-Control: private
Set-Cookie: ...
Set-Cookie: ...
```

<br>

```c
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#define IP "142.251.221.78" // www.google.com
#define PORT 80 // http

int main() {
    int s;
    char* data;
    char buf[512];

    struct sockaddr_in sock;
    sock.sin_addr.s_addr = inet_addr(IP);
    sock.sin_port = htons(PORT);
    sock.sin_family = AF_INET;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s<0) {
        printf("socket() error\n");
        return -1;
    }

    if (connect(s, (struct sockaddr *) &sock, sizeof(struct sockaddr_in)) != 0) {
        printf("connect() error\n");
        close(s);
        return -1;
    }

    data = "HEAD / HTTP/1.0\n\n";
    write(s, data, strlen(data));
    read(s, buf, 511);
    printf("%s", buf);

    close(s);
    return 0;
}
```

<br>


<br>


# HTTP server

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>

#define BUFFER_SIZE 16000

struct Server {
    int domain;
    int port;
    int service;
    int protocol;
    int backlog;
    u_long interface;

    int socket;
    struct sockaddr_in address;

    void (*launch)(struct Server *server);
};

struct Server server_Constructor(int domain, int port, int service, int protocol, int backlog, u_long interface, void (*launch)(struct Server *server)) {
    struct Server server;

    server.domain = domain;
    server.service = service;
    server.port = port;
    server.protocol = protocol;
    server.backlog = backlog;

    server.address.sin_family = domain;
    server.address.sin_port = htons(port);
    server.address.sin_addr.s_addr = htonl(interface);

    server.socket = socket(domain, service, protocol);
    if (server.socket < 0) {
        perror("Failed to initialize/connect to socket...\n");
        exit(EXIT_FAILURE);
    }

    if (bind(server.socket, (struct sockaddr*)&server.address, sizeof(server.address)) < 0) {
        perror("Failed to bind socket...\n");
        exit(EXIT_FAILURE);
    }

    if (listen(server.socket, server.backlog) < 0) {
        perror("Failed to start listening...\n");
        exit(EXIT_FAILURE);
    }

    server.launch = launch;
    return server;
}

void launch(struct Server *server) {
    char buffer[BUFFER_SIZE];
    while (1) {
        printf("Waiting for connection\n");
        int addrlen = sizeof(server->address);
        int new_socket = accept(server->socket, (struct sockaddr*)&server->address, (socklen_t*)&addrlen);
        ssize_t bytesRead = read(new_socket, buffer, BUFFER_SIZE - 1);
        if (bytesRead >= 0) {
            buffer[bytesRead] = '\0';  
            puts(buffer);
        } else {
            perror("Error reading buffer...\n");
        }
        char *response = "HTTP/1.1 200 OK\r\n"
                         "Content-Type: text/html; charset=UTF-8\r\n\r\n"
                         "<!DOCTYPE html>\r\n"
                         "<html>\r\n"
                         "<head>\r\n"
                         "<title>Testing Basic HTTP-SERVER</title>\r\n"
                         "</head>\r\n"
                         "<body>\r\n"
                         "Hello world\r\n"
                         "</body>\r\n"
                         "</html>\r\n";
        write(new_socket, response, strlen(response));
        close(new_socket);
    }
}

int main() {
    struct Server server = server_Constructor(AF_INET, 8000, SOCK_STREAM, 0, 10, INADDR_ANY, launch);
    launch(&server);
}
```

<br>




<br>


# static keyword 


Roughly it's like the opposite of extern, it restricts things to within some scope. 

More specifically there's 3 main cases. 



<br>

# 1: static functions

The function can only be used within that file (although optimising compilers may inline it)

```c
static void foo() {

}
```


<br>

# 2: static global variables


Global variables that can't be accessed from other .c files. 

```c
static int foo = 5;
```

<br>


# 3: static function variables


The variable continues to exist even after the function returns. 

So it's only ever initialised once. 

A common use case is counters. Eg:

```c
#include <stdio.h>

void counter() {
    static int count = 0;
    count++;
    printf("%d\n", count);
}

int main() {
    for (int i=0; i<10; i++) {
        counter();
    }
}
```



<br>

---


# inline asm

There's 4 different types (afaik):

```c
int main() {
    asm (
        ""
    );

    asm volatile (
        ""
    );

    asm inline (
        ""
    );

    asm goto (
        ""
        :
        :
        :
        :
        label
    );

    label:
        return 0;
}
```


<br>

gcc will do AT&T syntax by default, you can change it but you should change it back at the end


eg

```c
    asm (
        ".intel_syntax noprefix\n\t"
        "mov rax, 1\n\t"
        ".att_syntax prefix\n\t"
    );
```


asm volatile indicates to the compiler not to optimise/change/delete it at all

asm inline, "for inlining purposes the size of the asm statement is taken as the smallest size possible" 

<br>


The colons should be used to separate into 4 parts (5 for the goto, there is an extra one for the label)

```c
asm ( "assembly code"
    : output_operands
    : input_operands
    : clobbered_registers
);
```


<https://gcc.gnu.org/onlinedocs/gcc-13.3.0/gcc/Extended-Asm.html>


<br>


# no main


```c
int _start() {
    asm (
        ".intel_syntax noprefix\n\t"

        "mov rax, 60\n\t"
        "mov rdi, 0\n\t"
        "syscall\n\t"

        ".att_syntax prefix\n\t"
        :
        :
        : "rax", "rdi"
    );

    return 0;
}
```

```
gcc x.c -nostdlib -static; ./a.out
```

<br>




<br>



# dll's / so's


To generate a shared library you first to compile your C code with the -fPIC (position independent code) flag. 

`gcc -c -fPIC hello.c -o hello.o` generates object file

`gcc hello.o -shared -o libhello.so` takes object file and makes .so

`gcc -shared -o libhello.so -fPIC hello.c` does it in one step




<br>

```
[~/t]
$ cat my_lib.c
int add(int a, int b) {
    return a+b;
}

[~/t]
$ gcc -shared -fPIC my_lib.c -o my_lib.so
```




So now lets see different ways we can use the .so


<br>

<br>

---

Option 1: Link at compile time


```c
#include <stdio.h>

int add(int, int);

int main() {
    printf("%d\n", add(2, 3));
}
```

```
[~/t]
$ l
main.c  my_lib.c  my_lib.so

[~/t]
$

[~/t]
$ gcc main.c -L. -lmy_lib -o main
/usr/bin/ld: cannot find -lmy_lib: No such file or directory
collect2: error: ld returned 1 exit status

[~/t]
$ # have to rename, it expects it to start with 'lib'

[~/t]
$ mv my_lib.so libmy_lib.so

[~/t]
$ gcc main.c -L. -lmy_lib -o main

[~/t]
$ ./main
./main: error while loading shared libraries: libmy_lib.so: cannot open shared object file: No such file or directory

[~/t]
$ LD_LIBRARY_PATH=. ./main
5

[~/t]
$ rm main

[~/t]
$ gcc main.c -L. -lmy_lib -Wl,-rpath='$ORIGIN' -o main    # this way recommended, embed the runtime path

[~/t]
$ ./main
5

```


<br>

<br>

<br>

---

<br>

<br>

<br>

Option 2: dlopen/dlsym

<br>

It's nice for plugins, optional dependencies, only loading it if it exists/choosing whether to, hot-reloading, sandboxing. 

<https://man7.org/linux/man-pages/man3/dlopen.3.html>

<https://man7.org/linux/man-pages/man3/dlsym.3.html>

<br>

RTLD_LAZY: resolve symbols on first call

RTLD_NOW: resolve everything immediately (fail fast)


<br>

```c
#include <stdio.h>
#include <dlfcn.h>


int main() {
    void* lib = dlopen("/home/connor/t/libmy_lib.so", RTLD_NOW);
    if (!lib) {
        fprintf(stderr, "%s\n", dlerror());
        return 1;
    }

    printf("lib = %p\n", lib);

    int (*add)(int a, int b) = dlsym(lib, "add");
    printf("add = %p\n", lib);

    printf("%d\n", add(2, 3));
    dlclose(lib);
}
```


<br>


