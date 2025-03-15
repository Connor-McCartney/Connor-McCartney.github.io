---
permalink: /misc/xguic
title: Simple X11 GUI Window in C
---

<br>


<https://www.youtube.com/watch?v=d2E7ryHCK08>

Doc: <https://www.x.org/releases/X11R7.7/doc/libX11/libX11/libX11.html>

<br>

```c
#include <X11/Xlib.h>

int main() {
    XEvent event;
    Display* display = XOpenDisplay(NULL);
    Window w = XCreateSimpleWindow(display, DefaultRootWindow(display), 50, 50, 250, 250, 1, BlackPixel(display, 0), WhitePixel(display, 0));
    XMapWindow(display, w);
    while (1) {
        XNextEvent(display, &event);
    }
}
```

```
gcc x.c -lX11
```
