---
permalink: /misc/xguic
title: GUI stuff
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

```c
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


<br>

<br>

# Transparant and unaffected by dwm tiling

`-lX11 -lXrender`

```c
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xatom.h>
#include <X11/extensions/Xrender.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    Display* dpy = XOpenDisplay(NULL);
    if (!dpy) {
        fprintf(stderr, "Failed to open display\n");
        return 1;
    }

    int screen = DefaultScreen(dpy);
    Window root = RootWindow(dpy, screen);

    // Find a 32-bit TrueColor visual (ARGB)
    XVisualInfo vinfo;
    if (!XMatchVisualInfo(dpy, screen, 32, TrueColor, &vinfo)) {
        fprintf(stderr, "No 32-bit TrueColor visual available\n");
        return 1;
    }

    // Setup window attributes
    XSetWindowAttributes attrs;
    attrs.colormap = XCreateColormap(dpy, root, vinfo.visual, AllocNone);
    attrs.background_pixel = 0x00000000;
    attrs.border_pixel = 0;
    attrs.override_redirect = True;

    const int win_w = 300;
    const int win_h = 60;

    int screen_height = DisplayHeight(dpy, screen);
    int screen_width = DisplayWidth(dpy, screen);
    Window win = XCreateWindow(
        dpy, root,
        screen_width-win_w, screen_height-win_h, win_w, win_h,
        0, vinfo.depth, InputOutput, vinfo.visual,
        CWColormap | CWBackPixel | CWBorderPixel | CWOverrideRedirect,
        &attrs
    );

    XMapWindow(dpy, win);

    // Create XRender Picture for drawing
    XRenderPictFormat* fmt = XRenderFindVisualFormat(dpy, vinfo.visual);
    Picture pict = XRenderCreatePicture(dpy, win, fmt, 0, NULL);

    XRenderColor background = {0, 0, 0, 0}; // transparant
    //XRenderColor background = {0, 0xffff, 0, 0xffff};

    XRenderColor red = {0xffff, 0x0000, 0x0000, 0xffff};  // solid red

    int x = 0;
    int speed = 4;

    while (1) {
        // Clear window to transparent
        XRectangle clear_rect = {0, 0, win_w, win_h};
        XRenderFillRectangles(dpy, PictOpSrc, pict, &background, &clear_rect, 1);

        // Draw moving red rectangle
        XRectangle red_rect = {x, win_h / 2 - 20, 40, 40};
        XRenderFillRectangles(dpy, PictOpOver, pict, &red, &red_rect, 1);

        XFlush(dpy);

        // Update position
        x += speed;
        if (x < 0 || x > win_w - 40) speed = -speed;

        usleep(16000);  // ~60 FPS
    }

    // Cleanup (never actually reached)
    XRenderFreePicture(dpy, pict);
    XCloseDisplay(dpy);
    return 0;
}
```

<br>

With an image:

```c
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xatom.h>
#include <X11/extensions/Xrender.h>
#include <stdio.h>
#include <unistd.h>

// wget https://github.com/nothings/stb/blob/master/stb_image.h
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

int main() {
    Display* dpy = XOpenDisplay(NULL);
    if (!dpy) {
        fprintf(stderr, "Failed to open display\n");
        return 1;
    }

    int screen = DefaultScreen(dpy);
    Window root = RootWindow(dpy, screen);

    // Find a 32-bit TrueColor visual (ARGB)
    XVisualInfo vinfo;
    if (!XMatchVisualInfo(dpy, screen, 32, TrueColor, &vinfo)) {
        fprintf(stderr, "No 32-bit TrueColor visual available\n");
        return 1;
    }

    // Setup window attributes
    XSetWindowAttributes attrs;
    attrs.colormap = XCreateColormap(dpy, root, vinfo.visual, AllocNone);
    attrs.background_pixel = 0x00000000;
    attrs.border_pixel = 0;
    attrs.override_redirect = True;

    const int win_w = 800;
    const int win_h = 800;

    int screen_height = DisplayHeight(dpy, screen);
    int screen_width = DisplayWidth(dpy, screen);
    Window win = XCreateWindow(
        dpy, root,
        screen_width-win_w, screen_height-win_h, win_w, win_h,
        0, vinfo.depth, InputOutput, vinfo.visual,
        CWColormap | CWBackPixel | CWBorderPixel | CWOverrideRedirect,
        &attrs
    );

    XMapWindow(dpy, win);

    // Create XRender Picture for drawing
    XRenderPictFormat* fmt = XRenderFindVisualFormat(dpy, vinfo.visual);
    Picture pict = XRenderCreatePicture(dpy, win, fmt, 0, NULL);

    //XRenderColor background = {0, 0, 0, 0}; // transparant
    XRenderColor background = {0, 0xffff, 0, 0xffff};

    //XRenderColor red = {0xffff, 0x0000, 0x0000, 0xffff};  // solid red


    ///////////////////////////////
    // load image
    int img_w, img_h, img_channels;
    unsigned char* data = stbi_load("tst.png", &img_w, &img_h, &img_channels, 4);
    if (!data) {
        fprintf(stderr, "Failed to load image\n");
        return 1;
    }

    // Create Pixmap + XImage
    Pixmap img_pixmap = XCreatePixmap(dpy, win, img_w, img_h, vinfo.depth);
    XImage* ximage = XCreateImage(
        dpy, vinfo.visual, vinfo.depth, ZPixmap, 0,
        (char*)data, img_w, img_h, 32, 0
    );

    // Put image into pixmap
    GC gc = XCreateGC(dpy, img_pixmap, 0, NULL);
    XPutImage(dpy, img_pixmap, gc, ximage, 0, 0, 0, 0, img_w, img_h);

    // Create Picture from pixmap
    Picture img_picture = XRenderCreatePicture(dpy, img_pixmap, fmt, 0, NULL);
    ////////////////////////////////////


    while (1) {
        // Clear window to transparent
        XRectangle clear_rect = {0, 0, win_w, win_h};
        XRenderFillRectangles(dpy, PictOpSrc, pict, &background, &clear_rect, 1);

        // Draw image
        XRenderComposite(dpy, PictOpOver, img_picture, None, pict,
                         0, 0, 0, 0,     
                         0, 0, 300, 300); // dest x,y + size

        XFlush(dpy);

        usleep(16000);  // ~60 FPS
    }

    // Cleanup (never actually reached)
    XRenderFreePicture(dpy, pict);
    XCloseDisplay(dpy);
    return 0;
}
```

<br>

<br>

# Detect global X11 input

<https://stackoverflow.com/questions/22749444/listening-to-keyboard-events-without-consuming-them-in-x11-keyboard-hooking>

`-lX11 -lXtst`

```c
#include <stdio.h>
#include <X11/XKBlib.h>
#include <X11/extensions/record.h>

void key_pressed_cb(XPointer arg, XRecordInterceptData *d) {
    if (d->category != XRecordFromServer)
        return;
    
    int key = ((unsigned char*) d->data)[1];
    int type = ((unsigned char*) d->data)[0] & 0x7F;
    int repeat = d->data[2] & 1;

    if(!repeat) {
        switch (type) {
            case KeyPress:
                printf("key press %d\n", key);
                break;
            case KeyRelease:
                printf("key release %d\n", key);
                break;
            case ButtonPress:
                printf("button press %d\n", key);
                break;
            case ButtonRelease:
                printf("button release %d\n", key);
                break;
            default:
                break;
        }
    }
    XRecordFreeData (d);
}

void scan(int verbose) {
    XRecordRange* rr;
    XRecordClientSpec rcs;
    XRecordContext rc;
    Display *dpy = XOpenDisplay(NULL);
    rr = XRecordAllocRange();
    rr->device_events.first = KeyPress;
    rr->device_events.last = ButtonReleaseMask;
    rcs = XRecordAllClients;
    rc = XRecordCreateContext (dpy, 0, &rcs, 1, &rr, 1);
    XFree (rr);
    XRecordEnableContext(dpy, rc, key_pressed_cb, NULL);
}

int main() {
    scan(True);
    return 0;
}
```

<br>

<br>

Detect global input asynchronously (kinda hacky...)

```c
#include <stdio.h>
#include <unistd.h>
#include <X11/XKBlib.h>
#include <X11/extensions/record.h>
#include <sys/mman.h>

int *any_key_pressed;

void key_pressed_cb(XPointer arg, XRecordInterceptData *d) {
    if (d->category != XRecordFromServer)
        return;
    
    int key = ((unsigned char*) d->data)[1];
    int type = ((unsigned char*) d->data)[0] & 0x7F;
    int repeat = d->data[2] & 1;

    if(!repeat) {
        switch (type) {
            case KeyPress:
                *any_key_pressed = 1;
                //printf("key press %d\n", key);
                break;
            case KeyRelease:
                //printf("key release %d\n", key);
                break;
            case ButtonPress:
                //printf("button press %d\n", key);
                break;
            case ButtonRelease:
                //printf("button release %d\n", key);
                break;
            default:
                break;
        }
    }
    XRecordFreeData (d);
}

void scan() {
    XRecordRange* rr;
    XRecordClientSpec rcs;
    XRecordContext rc;
    Display *dpy = XOpenDisplay(NULL);
    rr = XRecordAllocRange();
    rr->device_events.first = KeyPress;
    rr->device_events.last = ButtonReleaseMask;
    rcs = XRecordAllClients;
    rc = XRecordCreateContext (dpy, 0, &rcs, 1, &rr, 1);
    XFree (rr);
    XRecordEnableContext(dpy, rc, key_pressed_cb, NULL);
}

int main() {
    any_key_pressed = mmap(NULL, sizeof(int), 
                      PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_ANONYMOUS,
                      -1, 0);
    if (fork()) {
        scan();
    } else {
        while (1) {
            if (*any_key_pressed == 1) {
                printf("pressed\n");
                *any_key_pressed = 0;
            }
        }
    }
    return 0;
}
```


<br>

<br>

Detect on both wayland/xorg: 

<br>

`evtest /dev/input/by-id/usb-*event-kbd`

<https://github.com/freedesktop-unofficial-mirror/evtest/blob/master/evtest.c> 

```c
#include <stdio.h>
#include <linux/input.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

void capture(char* filename)
{
    int fd = open(filename, O_RDONLY);
    struct input_event ev[64];
    int i, rd;
    while (1) {
        rd = read(fd, ev, sizeof(ev));
        for (i = 0; i < rd / sizeof(struct input_event); i++) {
            printf("a key was pressed!\n");
            fflush(stdout);
        }

    }
}

int main () {
    FILE *fp;
    fp = popen("/bin/echo /dev/input/by-path/*event-kbd", "r");
    char devices[1000];
    fgets(devices, sizeof(devices), fp);
    devices[strlen(devices)-1] = '\0'; // just remove newline
    pclose(fp);

    char *device, *str;
    str = strdup(devices);  
    while ((device = strsep(&str, " "))) {
        if (!fork()) {
            capture(device);
        }
    }
}
```

<br>

<br>

Wayland window: 

<br>

<https://www.youtube.com/watch?v=iIVIu7YRdY0>

<https://github.com/willth7/wayland-client-example> 

<br>

<br>

---

using GTK

GTK is a c library for GUI, more high level than direct X11 or wayland


<https://docs.gtk.org/gtk4/getting_started.html>

```c
#include <gtk/gtk.h>

static void on_activate (GtkApplication *app) {
  // Create a new window
  GtkWidget *window = gtk_application_window_new(app);
  gtk_window_present (GTK_WINDOW (window));
}

int main (int argc, char *argv[]) {
  // Create a new application
  GtkApplication *app = gtk_application_new("com.example.GtkApplication", G_APPLICATION_DEFAULT_FLAGS);
  g_signal_connect(app, "activate", G_CALLBACK (on_activate), NULL);
  return g_application_run(G_APPLICATION (app), argc, argv);
}
```

<br>

Compile with 

`gcc $( pkg-config --cflags gtk4 ) -o example-0 example-0.c $( pkg-config --libs gtk4 )`


But the clangd couldn't find the GTK library

<https://www.reddit.com/r/cprogramming/comments/16d39ht/how_can_i_setup_my_lsp_to_work_with_gtk4/>

<https://stackoverflow.com/questions/78044813/clangd-with-gtk-on-lunarvim-emitting-too-many-errors-compiling-and-executing-al>

TLDR you just need compile_commands.json in your project directory, which can be auto-created with `bear`

example Makefile:

```
CC = gcc
CFLAGS = $(shell pkg-config --cflags gtk4)
LDFLAGS = $(shell pkg-config --libs gtk4)

install:
	$(CC) main.c -o chess $(CFLAGS) $(LDFLAGS)

clean:
	-rm chess
```

Then run `bear -- make`, you only have to run that to create compile_commands.json, then you can go back to using regular make

<br>


---

I found this cool simple minesweeper clone <https://github.com/MelonFruit7/MinesweeperRemake/>

<br>

---


