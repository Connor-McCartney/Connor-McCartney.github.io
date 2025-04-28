

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

Curses/ncurses seems to be nice for TUIs

```python
from curses import wrapper, curs_set, COLOR_GREEN, init_pair, COLOR_BLACK, color_pair
from time import sleep
from random import randint, choice

charset = "ﾊﾐﾋｰｳｼﾅﾓﾆｻﾜﾂｵﾘｱﾎﾃﾏｹﾒｴｶｷﾑﾕﾗｾﾈｽﾀﾇﾍ012345789Z:.=*+-¦|_"

def create_streams(width, height):
    streams = []
    for x in range(0, width):
        stream = {
            'x': x,
            'chars': [' ']*height,
            'state': 1,
            'length': randint(2, height),
        }
        streams.append(stream)
    return streams

def move_stream(stream, height):
    if stream['state'] == 1:
        next = ' '
    else:
        next = choice(charset)

    if stream['length'] == 0:
        stream['state'] ^= 1
        stream['length'] = randint(3, height//2)

    stream['length'] -= 1
    stream['chars'] = stream['chars'][1:] + [next]

def draw_streams(stdscr, streams, height):
    init_pair(1, COLOR_GREEN, COLOR_BLACK)
    GREEN = color_pair(1)
    stdscr.erase()
    for stream in streams:
        for i, c in enumerate(stream['chars']):
            stdscr.addch(height - 1 - i, stream['x'], c, GREEN)
        move_stream(stream, height)
    stdscr.refresh()

def main(stdscr):
    height, width = stdscr.getmaxyx()
    curs_set(0)
    streams = create_streams(width-1, height)
    while True:
        draw_streams(stdscr, streams, height)
        sleep(0.05)

wrapper(main)
```

<br>

