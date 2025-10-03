

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

void draw_border(XImage* img) {
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
        draw_border(img);
        draw_circle_at_mouse(display, w, img);


        XShmPutImage(display, w, gc, img, 0, 0, 0, 0, width, height, False);
        XSync(display, False);
        usleep(16000); // ~60 FPS
    }
}
```




# eulerian (grid-based) fluid simulation

Let's assume incompressibility and zero viscocity to keep things simpler. 

We'll make float arrays with the horizontal and vertical (u and v) velocities for each pixel 

<img width="621" height="513" alt="image" src="https://github.com/user-attachments/assets/530903a8-a6ba-4604-9da2-7636bf24a058" />

There's 3 main steps in the simulation, make the fluid incompressible, move the velocity field (advection), and then move the smoke/dye field (advection again) for a better visual. 


# incompressibility


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
static const int numX = width - 2*gap + 2;  // +2 for the borders on each side
static const int numY = height - 2*gap + 2;  // +2 for the borders on each side
//static const float dt = 1.0f / 60.0f;


void draw_circle_at_mouse(Display* display, Window w, int is_solid[numX][numY]) {
    // delete previous circle
    for (int x = 1; x < numX-1; x++) {
        for (int y = 1; y < numY-1; y++) {
            is_solid[x][y] = 1;
        }
    }

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
            if (x > 0 && x < numX && y > 0 && y < numY) {
                int dx = x - mouse_x;
                int dy = y - mouse_y;
                if (dx*dx + dy*dy <= radius*radius) {
                    is_solid[x][y] = 0;
                }
            }

        }
    }
}

void draw_border(int is_solid[numX][numY]) {
    for (int x = 0; x < numX; x++) {
        is_solid[x][0] = 0;
        is_solid[x][numY-1] = 0;
    }
    for (int y = 0; y < numY; y++) {
        is_solid[0][y] = 0;
        is_solid[numX-1][y] = 0;
    }
}

void draw_solids(XImage* img, int is_solid[numX][numY]) {
    for (int x = 0; x < numX; x++) {
        for (int y = 0; y < numY; y++) {
            if (is_solid[x][y] == 0) {
                XPutPixel(img, x+gap, y+gap, solid_colour);
            }
        }
    }
}

void solve_incompressibility(float u[numX][numY], float v[numX][numY], int is_solid[numX][numY]) {
    int numIters = 10; // can drastically affect performance
    for (int iter = 0; iter < numIters; iter++) {
        for (int i = 1; i < numX-1; i++) {
            for (int j = 1; j < numY-1; j++) {

                if (is_solid[i][j] == 0) { // if it's a solid, it's velocity should always remain 0
                    continue; 
                }

                int s = is_solid[i][j];
                int sx0 = is_solid[i-1][j];
                int sx1 = is_solid[i+1][j];
                int sy0 = is_solid[i][j-1];
                int sy1 = is_solid[i][j+1];
                s = sx0 + sx1 + sy0 + sy1;
                if (s == 0.0)
                    continue;

                float div = u[i+1][j] - u[i][j] + v[i][j+1] - v[i][j];
                float p = -div / s;
                u[i][j] -= sx0 * p;
                u[i+1][j] += sx1 * p;
                v[i][j] -= sy0 * p;
                v[i][j+1] += sy1 * p;
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

    // velocity arrays
    float u[numX][numY];
    float v[numX][numY];

    // 0 for solid cells, 1 for liquid cells
    int is_solid[numX][numY];

    // zero out the arrays
    for (int x = 0; x < numX; x++) {
        for (int y = 0; y < numY; y++) {
            u[x][y] = 0.0f;
            v[x][y] = 0.0f;
            is_solid[x][y] = 1;
        }
    }

    while (1) {
        memset(img->data, 255, img->bytes_per_line * img->height); // initialise white background every frame
        draw_border(is_solid);
        draw_circle_at_mouse(display, w, is_solid);
        draw_solids(img, is_solid);


        // simulation
        //solve_incompressibility(u, v, is_solid);


        XShmPutImage(display, w, gc, img, 0, 0, 0, 0, width, height, False);
        XSync(display, False);
        usleep(16000); // ~60 FPS
    }
}
```

