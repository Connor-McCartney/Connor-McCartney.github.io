

# Empty X11 window



```c
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/XShm.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    int width = 800, height = 600;

    // window stuff
    Display* display = XOpenDisplay(NULL);
    int screen = DefaultScreen(display);
    Window root = RootWindow(display, screen);
    XSetWindowAttributes wa = {
        .override_redirect = True,
    };
    Window w = XCreateWindow(display, root, 100, 200, width, height, 0, DefaultDepth(display, screen), InputOutput, DefaultVisual(display, screen), CWOverrideRedirect | CWBackPixel, &wa);
    XMapRaised(display, w);
    GC gc = XCreateGC(display, w, 0, NULL);

    // SHM stuf
    XShmSegmentInfo shminfo;
    XImage* img = XShmCreateImage(display, DefaultVisual(display, screen), DefaultDepth(display, screen), ZPixmap, NULL, &shminfo, width, height);
    shminfo.shmid = shmget(IPC_PRIVATE, img->bytes_per_line * img->height, IPC_CREAT | 0777);
    shminfo.shmaddr = img->data = shmat(shminfo.shmid, 0, 0);
    shminfo.readOnly = False;
    XShmAttach(display, &shminfo);

    int frame = 0;
    while (1) {

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                unsigned long c = ((x + frame) ^ (y + frame)) & 0xFF;
                unsigned long pixel = (c << 16) | (c << 8) | c; // grayscale
                XPutPixel(img, x, y, pixel); // macro that writes pixels directly into img->data
            }
        }

        // Push the new image into the window
        XShmPutImage(display, w, gc, img,
                     0, 0, 0, 0,
                     width, height,
                     False);
        XSync(display, False);

        frame = (frame + 1) & 0xFF;  // wrap to 0–255
        usleep(16000); // ~60 FPS
    }
}
```

Or something like this for rgb


```c
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                //unsigned long c = ((x + frame) ^ (y + frame)) & 0xFF;
                //unsigned long pixel = (c << 16) | (c << 8) | c; // grayscale
                int r = 0;
                int g = 0;
                int b = rand() % 255;
                unsigned long pixel = (r << 16) | (g << 8) | (b);
                XPutPixel(img, x, y, pixel); // macro that writes pixels directly into img->data
            }
        }
```


In the fluid simulator I won't actually need to use the frame number. 


Another unrelated effect just for fun, vertical lines:

```c
    int r, g, b;
    while (1) {
        for (int x = 0; x < width; x++) {
            r = rand() % 255;
            g = 0;
            b = rand() % 255;
            for (int y = 0; y < height; y++) {
                unsigned long pixel = (r << 16) | (g << 8) | (b);
                XPutPixel(img, x, y, pixel); // macro that writes pixels directly into img->data
            }
        }

        XShmPutImage(display, w, gc, img, 0, 0, 0, 0, width, height, False);
        XSync(display, False);
    }
```



<br>

<br>


# draw a circle

`gcc x.c -lX11 -lXext -Wall -Wextra -pedantic && ./a.out`

```c
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/XShm.h> 
#include <sys/shm.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const int width = 600, height = 400;

void draw_circle_at_mouse(Display* display, Window w, XImage* img) {
    // get mouse coords
    int mouse_x, mouse_y;
    int root_x, root_y; 
    Window root_return, child_return;
    unsigned int mask_return;
    XQueryPointer(display, w, &root_return, &child_return, &root_x, &root_y, &mouse_x, &mouse_y, &mask_return);
    //printf("Mouse relative to window: %d %d\n", mouse_x, mouse_y);

    // draw circle
    int radius = 50;
    unsigned long pixel_color = (0 << 16) | (0 << 8) | (255);
    for (int x = mouse_x - radius; x < mouse_x + radius; x++) {
        for (int y = mouse_y - radius; y < mouse_y + radius; y++) {
            if (x >= 0 && x < width && y >= 0 && y < height) {
                int dx = x - mouse_x;
                int dy = y - mouse_y;
                if (dx*dx + dy*dy <= radius*radius) {
                    XPutPixel(img, x, y, pixel_color);
                }
            }

        }
    }

}
int main() {

    // window stuff
    Display* display = XOpenDisplay(NULL);
    int screen = DefaultScreen(display);
    Window w = XCreateSimpleWindow(display, DefaultRootWindow(display), 50, 50, width, height, 1, BlackPixel(display, 0), BlackPixel(display, 0));
    XMapWindow(display, w);
    GC gc = XCreateGC(display, w, 0, NULL);

    // SHM stuff
    XShmSegmentInfo shminfo;
    XImage* img = XShmCreateImage(display, DefaultVisual(display, screen), DefaultDepth(display, screen), ZPixmap, NULL, &shminfo, width, height);
    shminfo.shmid = shmget(IPC_PRIVATE, img->bytes_per_line * img->height, IPC_CREAT | 0777);
    shminfo.shmaddr = img->data = shmat(shminfo.shmid, 0, 0);
    shminfo.readOnly = False;
    XShmAttach(display, &shminfo);

    while (1) {
        memset(img->data, 255, img->bytes_per_line * img->height); // initialise white background every frame
        draw_circle_at_mouse(display, w, img);


        XShmPutImage(display, w, gc, img, 0, 0, 0, 0, width, height, False);
        XSync(display, False);
        usleep(16000); // ~60 FPS
    }
}

```



# Add a border:

```c
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/XShm.h> 
#include <sys/shm.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const int width = 600, height = 400, gap = 5;
static const unsigned long solid_colour = (0 << 16) | (0 << 8) | (255); // blue

void draw_circle_at_mouse(Display* display, Window w, XImage* img) {
    // get mouse coords
    int mouse_x, mouse_y;
    int root_x, root_y; 
    Window root_return, child_return;
    unsigned int mask_return;
    XQueryPointer(display, w, &root_return, &child_return, &root_x, &root_y, &mouse_x, &mouse_y, &mask_return);
    //printf("Mouse relative to window: %d %d\n", mouse_x, mouse_y);

    // draw circle
    int radius = 50;
    for (int x = mouse_x - radius; x < mouse_x + radius; x++) {
        for (int y = mouse_y - radius; y < mouse_y + radius; y++) {
            if (x >= 0 && x < width && y >= 0 && y < height) {
                int dx = x - mouse_x;
                int dy = y - mouse_y;
                if (dx*dx + dy*dy <= radius*radius) {
                    XPutPixel(img, x, y, solid_colour);
                }
            }

        }
    }
}

void draw_border(Display* display, Window w, XImage* img) {
    for (int x = gap; x < width-gap; x++) {
        XPutPixel(img, x, gap, solid_colour);
        XPutPixel(img, x, height-gap, solid_colour);
    }
    for (int y = gap; y < height-gap; y++) {
        XPutPixel(img, gap, y, solid_colour);
        XPutPixel(img, width-gap, y, solid_colour);
    }
}


int main() {

    // window stuff
    Display* display = XOpenDisplay(NULL);
    int screen = DefaultScreen(display);
    Window w = XCreateSimpleWindow(display, DefaultRootWindow(display), 50, 50, width, height, 1, BlackPixel(display, 0), BlackPixel(display, 0));
    XMapWindow(display, w);
    GC gc = XCreateGC(display, w, 0, NULL);

    // SHM stuff
    XShmSegmentInfo shminfo;
    XImage* img = XShmCreateImage(display, DefaultVisual(display, screen), DefaultDepth(display, screen), ZPixmap, NULL, &shminfo, width, height);
    shminfo.shmid = shmget(IPC_PRIVATE, img->bytes_per_line * img->height, IPC_CREAT | 0777);
    shminfo.shmaddr = img->data = shmat(shminfo.shmid, 0, 0);
    shminfo.readOnly = False;
    XShmAttach(display, &shminfo);

    while (1) {
        memset(img->data, 255, img->bytes_per_line * img->height); // initialise white background every frame
        draw_border(display, w, img);
        draw_circle_at_mouse(display, w, img);


        XShmPutImage(display, w, gc, img, 0, 0, 0, 0, width, height, False);
        XSync(display, False);
        usleep(16000); // ~60 FPS
    }
}
```




# eulerian (grid-based) fluid simulation

Let's assume incompressibility and zero viscocity to keep things simpler. 

We'll make big arrays with the horizontal and vertical (u and v) velocities for each pixel 

<img width="621" height="513" alt="image" src="https://github.com/user-attachments/assets/530903a8-a6ba-4604-9da2-7636bf24a058" />
