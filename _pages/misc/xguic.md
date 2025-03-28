---
permalink: /misc/xguic
title: Simple X11 GUI Window in C
---

<br>


<https://www.youtube.com/watch?v=d2E7ryHCK08>

Doc: <https://www.x.org/releases/X11R7.7/doc/libX11/libX11/libX11.html>

<br>

# simple window

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



<br>

# translucent background

edit `attr.background_pixel`

```c
#include <X11/Xlib.h>
#include <X11/Xutil.h>

int main() {
    XEvent event;
    Display* display = XOpenDisplay(NULL);

    XVisualInfo vinfo;
    XMatchVisualInfo(display, DefaultScreen(display), 32, TrueColor, &vinfo);

    XSetWindowAttributes attr;
    attr.colormap = XCreateColormap(display, DefaultRootWindow(display), vinfo.visual, AllocNone);
    attr.background_pixel = 0x00000000;

    Window w = XCreateWindow(display, DefaultRootWindow(display), 0, 0, 300, 200, 0, vinfo.depth, InputOutput, vinfo.visual, CWColormap | CWBorderPixel | CWBackPixel, &attr);
    XMapWindow(display, w);

    while (1) {
        XNextEvent(display, &event);
    }
}
```

<br>

# Class hint properties

<https://tronche.com/gui/x/xlib/ICC/client-to-window-manager/wm-class.html#XClassHint>

```c
#include <X11/Xlib.h>
#include <X11/Xutil.h>

int main() {
    XEvent event;
    Display* display = XOpenDisplay(NULL);
    Window w = XCreateSimpleWindow(display, DefaultRootWindow(display), 50, 50, 250, 250, 1, BlackPixel(display, 0), WhitePixel(display, 0));
    XMapWindow(display, w);


    // set CLASS property
    XClassHint* class_hint = XAllocClassHint();
    class_hint->res_class = "myapp";
    class_hint->res_name= "myapp";
    XSetClassHint(display, w, class_hint);

    while (1) {
        XNextEvent(display, &event);
    }
}
```

```
$ xprop | grep CLASS
WM_CLASS(STRING) = "myapp", "myapp"
```

<br>

# text

<https://stackoverflow.com/questions/44476594/x11-why-i-cant-draw-any-text>

<br>


# Create a window unaffected by dwm tiling

```c
#include <X11/X.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>

int main() {
    Display* display = XOpenDisplay(NULL);
    int screen = DefaultScreen(display);
    Window root = RootWindow(display, screen);

    XSetWindowAttributes wa = {
	.override_redirect = True,
    };

    Window w = XCreateWindow(display, root, 50, 50, 500, 500, 0, DefaultDepth(display, screen),
            InputOutput, DefaultVisual(display, screen),
            CWOverrideRedirect | CWBackPixel, &wa);
    XMapRaised(display, w);

    XClassHint ch = {"dwm", "dwm"};
    XSetClassHint(display, w, &ch);

    XEvent event;
    while (1) {
        XNextEvent(display, &event);
    }
}
```


<br>

# Images

```python
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>

// Window size
int height = 256, width = 256;
XVisualInfo vinfo;

XImage *CreateTrueColorImage(Display *display, Visual *visual)
{

    int i, j;
    char *image32=(char *)malloc(width*height*4);
    char *p=image32;
    for(i=0; i<width; i++)
    {
        for(j=0; j<height;j++)
        {
            *p++ = 0x00; // B
            *p++ = 0x00; // G
            *p++ = 0xff; // R
            *p++ = 0xff; // alpha
        }
    }
    return XCreateImage(display, vinfo.visual, vinfo.depth,
        ZPixmap, 0, image32, width, height, 32, 0);
}

int main(int argc, char **argv)
{
    XImage *ximage;
    Display *display = XOpenDisplay(NULL);
    Visual *visual = DefaultVisual(display, 0);


    XMatchVisualInfo(display, DefaultScreen(display), 32, TrueColor, &vinfo);

    XSetWindowAttributes attr;
    attr.colormap = XCreateColormap(display, DefaultRootWindow(display), 
            vinfo.visual, AllocNone);
    attr.border_pixel = 0;
    attr.background_pixel = 0x00000000; 

    Window window = XCreateWindow(display, DefaultRootWindow(display), 0, 0,
            width, height, 0, vinfo.depth, InputOutput, vinfo.visual,
            CWColormap | CWBorderPixel | CWBackPixel, &attr);

    ximage = CreateTrueColorImage(display, vinfo.visual);
    XSelectInput(display, window, ButtonPressMask|ExposureMask);
    XMapWindow(display, window);
    GC gc = XCreateGC(display, window, 0, 0);


    XEvent event;
    while (1) {
        XNextEvent(display, &event);
        XPutImage(display, window, gc, ximage, 0, 0, 0, 0, width, height);
    }
}
```

<br>
