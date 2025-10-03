

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
