

It could be cool to make something like [The Matrix's opening scene](https://www.youtube.com/watch?v=Vb6bA4J1Gbg&t=30s)

<https://collider.com/the-matrix-green-codes-explained/>

<https://scifi.stackexchange.com/questions/137575/is-there-a-list-of-the-symbols-shown-in-the-matrixthe-symbols-rain-how-many>

```c
#include <termios.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

void enable_raw_mode() {
    struct termios raw;
    tcgetattr(STDIN_FILENO, &raw);
    raw.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

void print_green(char* text) {
    printf("\033[1;32m%s\033[0m\n", text);
}

int main() {
    enable_raw_mode();
    system("clear");
    system("printf \"\033[?25l\""); // hide cursor

    print_green("漢字\n");


    while (1) {

    }
}
```

<br>

