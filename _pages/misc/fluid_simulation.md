---
permalink: /misc/fluid
title: Fluid Simulation
---

# demo


```js
<!DOCTYPE html>
<html>
<body>
<canvas id="myCanvas" style="border:2px solid"></canvas>
<script>

var canvas = document.getElementById("myCanvas");
var c = canvas.getContext("2d");	
canvas.width = 600
canvas.height = 400

canvas.focus();

var simHeight = 1.0;	
var cScale = canvas.height / simHeight;
var simWidth = canvas.width / cScale;

var U_FIELD = 0;
var V_FIELD = 1;
var S_FIELD = 2;

var cnt = 0;

function cX(x) {
    return x * cScale;
}

function cY(y) {
    return canvas.height - y * cScale;
}

// ----------------- start of simulator ------------------------------

class Fluid {
    constructor(numX, numY, h) {
        this.numX = numX + 2; 
        this.numY = numY + 2;
        this.numCells = this.numX * this.numY;
        this.h = h;
        this.u = new Float32Array(this.numCells);
        this.v = new Float32Array(this.numCells);
        this.newU = new Float32Array(this.numCells);
        this.newV = new Float32Array(this.numCells);
        this.s = new Float32Array(this.numCells);
        this.m = new Float32Array(this.numCells);
        this.newM = new Float32Array(this.numCells);
        this.m.fill(1.0)
        var num = numX * numY;
    }

// this.numX → numX + 2; adds two for boundary/ghost cells.
// this.numY → numY + 2; adds two for boundary/ghost cells.
// this.numCells → total number of cells in the grid: this.numX * this.numY.
// this.h → cell size.
// this.u → horizontal velocity array for all cells (Float32Array of length numCells).
// this.v → vertical velocity array for all cells (Float32Array of length numCells).
// this.newU → temporary horizontal velocity array used during advection.
// this.newV → temporary vertical velocity array used during advection.
// this.s → scalar array indicating solid/empty cells (1 = fluid, 0 = obstacle).
// this.m → scalar field for smoke/dye concentration (initialized to 1.0 in all cells).
// this.newM → temporary scalar field used during advection.



    solveIncompressibility(numIters, dt) {

        var n = this.numY;

        for (var iter = 0; iter < numIters; iter++) {

            for (var i = 1; i < this.numX-1; i++) {
                for (var j = 1; j < this.numY-1; j++) {

                    if (this.s[i*n + j] == 0.0)
                        continue;

                    var s = this.s[i*n + j];
                    var sx0 = this.s[(i-1)*n + j];
                    var sx1 = this.s[(i+1)*n + j];
                    var sy0 = this.s[i*n + j-1];
                    var sy1 = this.s[i*n + j+1];
                    var s = sx0 + sx1 + sy0 + sy1;
                    if (s == 0.0)
                        continue;

                    var div = this.u[(i+1)*n + j] - this.u[i*n + j] + 
                        this.v[i*n + j+1] - this.v[i*n + j];

                    var p = -div / s;
                    this.u[i*n + j] -= sx0 * p;
                    this.u[(i+1)*n + j] += sx1 * p;
                    this.v[i*n + j] -= sy0 * p;
                    this.v[i*n + j+1] += sy1 * p;

                }
            }
        }
    }

extrapolate() {
    var n = this.numY;

    // Top and bottom walls
    for (var i = 0; i < this.numX; i++) {
        this.u[i*n + 0] = this.u[i*n + 1];                // copy tangential
        this.u[i*n + this.numY-1] = this.u[i*n + this.numY-2];
        this.v[i*n + 0] = 0.0;                            // zero normal
        this.v[i*n + this.numY-1] = 0.0;
    }

    // Left and right walls
    for (var j = 0; j < this.numY; j++) {
        this.v[0*n + j] = this.v[1*n + j];                // copy tangential
        this.v[(this.numX-1)*n + j] = this.v[(this.numX-2)*n + j];
        this.u[0*n + j] = 0.0;                            // zero normal
        this.u[(this.numX-1)*n + j] = 0.0;
    }
}

    sampleField(x, y, field) {
        var n = this.numY;
        var h = this.h;
        var h1 = 1.0 / h;
        var h2 = 0.5 * h;

        x = Math.max(Math.min(x, this.numX * h), h);
        y = Math.max(Math.min(y, this.numY * h), h);

        var dx = 0.0;
        var dy = 0.0;

        var f;

        switch (field) {
            case U_FIELD: f = this.u; dy = h2; break;
            case V_FIELD: f = this.v; dx = h2; break;
            case S_FIELD: f = this.m; dx = h2; dy = h2; break

        }

        var x0 = Math.min(Math.floor((x-dx)*h1), this.numX-1);
        var tx = ((x-dx) - x0*h) * h1;
        var x1 = Math.min(x0 + 1, this.numX-1);
        
        var y0 = Math.min(Math.floor((y-dy)*h1), this.numY-1);
        var ty = ((y-dy) - y0*h) * h1;
        var y1 = Math.min(y0 + 1, this.numY-1);

        var sx = 1.0 - tx;
        var sy = 1.0 - ty;

        var val = sx*sy * f[x0*n + y0] +
            tx*sy * f[x1*n + y0] +
            tx*ty * f[x1*n + y1] +
            sx*ty * f[x0*n + y1];
        
        return val;
    }

    avgU(i, j) {
        var n = this.numY;
        var u = (this.u[i*n + j-1] + this.u[i*n + j] +
            this.u[(i+1)*n + j-1] + this.u[(i+1)*n + j]) * 0.25;
        return u;
            
    }

    avgV(i, j) {
        var n = this.numY;
        var v = (this.v[(i-1)*n + j] + this.v[i*n + j] +
            this.v[(i-1)*n + j+1] + this.v[i*n + j+1]) * 0.25;
        return v;
    }

    advectVel(dt) {

        this.newU.set(this.u);
        this.newV.set(this.v);

        var n = this.numY;
        var h = this.h;
        var h2 = 0.5 * h;

        for (var i = 1; i < this.numX; i++) {
            for (var j = 1; j < this.numY; j++) {

                cnt++;

                // u component
                if (this.s[i*n + j] != 0.0 && this.s[(i-1)*n + j] != 0.0 && j < this.numY - 1) {
                    var x = i*h;
                    var y = j*h + h2;
                    var u = this.u[i*n + j];
                    var v = this.avgV(i, j);
                    x = x - dt*u;
                    y = y - dt*v;
                    u = this.sampleField(x,y, U_FIELD);
                    this.newU[i*n + j] = u;
                }
                // v component
                if (this.s[i*n + j] != 0.0 && this.s[i*n + j-1] != 0.0 && i < this.numX - 1) {
                    var x = i*h + h2;
                    var y = j*h;
                    var u = this.avgU(i, j);
                    var v = this.v[i*n + j];
                    x = x - dt*u;
                    y = y - dt*v;
                    v = this.sampleField(x,y, V_FIELD);
                    this.newV[i*n + j] = v;
                }
            }	 
        }

        this.u.set(this.newU);
        this.v.set(this.newV);
    }

    advectSmoke(dt) {

        this.newM.set(this.m);

        var n = this.numY;
        var h = this.h;
        var h2 = 0.5 * h;

        for (var i = 1; i < this.numX-1; i++) {
            for (var j = 1; j < this.numY-1; j++) {

                if (this.s[i*n + j] != 0.0) {
                    var u = (this.u[i*n + j] + this.u[(i+1)*n + j]) * 0.5;
                    var v = (this.v[i*n + j] + this.v[i*n + j+1]) * 0.5;
                    var x = i*h + h2 - dt*u;
                    var y = j*h + h2 - dt*v;

                    this.newM[i*n + j] = this.sampleField(x,y, S_FIELD);
                }
            }	 
        }
        this.m.set(this.newM);
    }

    // ----------------- end of simulator ------------------------------


    simulate(dt, numIters) {

        this.solveIncompressibility(numIters, dt);
        this.extrapolate(); // boundaries
        this.advectVel(dt);
        this.advectSmoke(dt);

    }
}

var scene = 
{
    dt : 1.0 / 120.0,
    numIters : 1000,
    frameNr : 0,
    obstacleX : 0.0,
    obstacleY : 0.0,
    obstacleRadius: 0.15,
    sceneNr: 2,
    showObstacle: false,
    fluid: null
};

function setupScene(sceneNr=0) 
{
    scene.sceneNr = sceneNr;
    scene.obstacleRadius = 0.15;
    scene.dt = 1.0 / 60.0;
    scene.numIters = 5;

    var res = 300;
    var domainHeight = 1.0;
    var domainWidth = (domainHeight/simHeight) * simWidth;
    var h = domainHeight / res;

    var numX = Math.floor(domainWidth / h);
    var numY = Math.floor(domainHeight / h);

    f = scene.fluid = new Fluid(numX, numY, h);

    //else if (sceneNr == 2) { // paint
    scene.gravity = 0.0;
    scene.obstacleRadius = 0.1;

    
}


// draw -------------------------------------------------------

function getSciColor(val, minVal, maxVal) {
    val = Math.min(Math.max(val, minVal), maxVal- 0.0001);
    var d = maxVal - minVal;
    val = d == 0.0 ? 0.5 : (val - minVal) / d;
    var m = 0.25;
    var num = Math.floor(val / m);
    var s = (val - num * m) / m;
    var r, g, b;

    switch (num) {
        case 0 : r = 0.0; g = s; b = 1.0; break;
        case 1 : r = 0.0; g = 1.0; b = 1.0-s; break;
        case 2 : r = s; g = 1.0; b = 0.0; break;
        case 3 : r = 1.0; g = 1.0 - s; b = 0.0; break;
    }

    return[255*r,255*g,255*b, 255]
}

function draw() 
{
    c.clearRect(0, 0, canvas.width, canvas.height);

    c.fillStyle = "#FF0000";
    f = scene.fluid;
    n = f.numY;

    var cellScale = 1.1;

    var h = f.h;


    id = c.getImageData(0,0, canvas.width, canvas.height)

    var color = [255, 255, 255, 255]

    for (var i = 0; i < f.numX; i++) {
        for (var j = 0; j < f.numY; j++) {

            //if (scene.showSmoke) {
            var s = f.m[i*n + j];
            color[0] = 255*s;
            color[1] = 255*s;
            color[2] = 255*s;
            //if (scene.sceneNr == 2)
            //color = getSciColor(s, 0.0, 1.0);
            //}

            var x = Math.floor(cX(i * h));
            var y = Math.floor(cY((j+1) * h));
            var cx = Math.floor(cScale * cellScale * h) + 1;
            var cy = Math.floor(cScale * cellScale * h) + 1;

            r = color[0];
            g = color[1];
            b = color[2];

            for (var yi = y; yi < y + cy; yi++) {
                var p = 4 * (yi * canvas.width + x)

                for (var xi = 0; xi < cx; xi++) {
                    id.data[p++] = r;
                    id.data[p++] = g;
                    id.data[p++] = b;
                    id.data[p++] = 255;
                }
            }
        }
    }

    c.putImageData(id, 0, 0);

    if (scene.showObstacle) {

        c.strokeW
        r = scene.obstacleRadius + f.h;
        c.fillStyle = "#DDDDDD";

        c.beginPath();	
        c.arc(
            cX(scene.obstacleX), cY(scene.obstacleY), cScale * r, 0.0, 2.0 * Math.PI); 
        c.closePath();
        c.fill();

        c.lineWidth = 3.0;
        c.strokeStyle = "#000000";
        c.beginPath();	
        c.arc(
            cX(scene.obstacleX), cY(scene.obstacleY), cScale * r, 0.0, 2.0 * Math.PI); 
        c.closePath();
        c.stroke();
        c.lineWidth = 1.0;
    }

}

function setObstacle(x, y, reset) {

    var f = scene.fluid;
    var n = f.numY;
    var r = scene.obstacleRadius;

    // Clamp obstacle inside the domain
    x = Math.max(x, r + f.h);
    x = Math.min(x, (f.numX - 1 - r) * f.h);
    y = Math.max(y, r + f.h);
    y = Math.min(y, (f.numY - 1 - r) * f.h);

    var vx = 0.0;
    var vy = 0.0;

    if (!reset) {
        vx = (x - scene.obstacleX) / scene.dt;
        vy = (y - scene.obstacleY) / scene.dt;
    }

    scene.obstacleX = x;
    scene.obstacleY = y;
    scene.showObstacle = true;

    var cd = Math.sqrt(2) * f.h;

    for (var i = 1; i < f.numX-1; i++) {
        for (var j = 1; j < f.numY-1; j++) {

            f.s[i*n + j] = 1.0; // fluid by default

            var dx = (i + 0.5) * f.h - x;
            var dy = (j + 0.5) * f.h - y;

            if (dx * dx + dy * dy < r * r) {

                f.s[i*n + j] = 0.0; // mark as obstacle

                if (scene.sceneNr == 2)
                    f.m[i*n + j] = 0.5 + 0.5 * Math.sin(0.1 * scene.frameNr);
                else
                    f.m[i*n + j] = 1.0;

                // Clamp array indices to avoid out-of-bounds
                let uIdx1 = Math.min(i+1, f.numX-1);
                let vIdx1 = Math.min(j+1, f.numY-1);

                f.u[i*n + j] = vx;
                f.u[uIdx1*n + j] = vx;
                f.v[i*n + j] = vy;
                f.v[i*n + vIdx1] = vy;
            }
        }
    }
}

// interaction -------------------------------------------------------

function drag(x, y) {
    let bounds = canvas.getBoundingClientRect();
    let mx = x - bounds.left - canvas.clientLeft;
    let my = y - bounds.top - canvas.clientTop;
    x = mx / cScale;
    y = (canvas.height - my) / cScale;
    setObstacle(x,y, false);
}

canvas.addEventListener('mousemove', event => {
    drag(event.x, event.y);
});

// main -------------------------------------------------------

function simulate() 
{
    scene.fluid.simulate(scene.dt, scene.numIters)
    scene.frameNr++;
}

function update() {
    simulate();
    draw();
    requestAnimationFrame(update);
}

setupScene(2);
update();

</script> 
</body>
</html>


```

<br>


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

```




# finished



```c
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/XShm.h> 
#include <sys/shm.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

static const int width = 600, height = 400, gap = 5;
static const unsigned long solid_colour = (0 << 16) | (0 << 8) | (255); // blue
static const int numX = width - 2*gap + 2;  // +2 for the borders on each side
static const int numY = height - 2*gap + 2;  // +2 for the borders on each side
static const float dt = 1.0f / 60.0f;

static const float h = 1.0f;

int obstacleX = 0;
int obstacleY = 0;
int frameNr = 0;

void setObstacle(int x, int y, int is_solid[numX][numY], float smoke[numX][numY], float u[numX][numY], float v[numX][numY]);


enum fields { // todo get rid of this
    U_FIELD,
    V_FIELD,
    SMOKE_FIELD,
};

void draw_circle_at_mouse(Display* display, Window w, int is_solid[numX][numY], float smoke[numX][numY], float u[numX][numY], float v[numX][numY]) {
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


    setObstacle(mouse_x, mouse_y, is_solid, smoke, u, v);

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
                if (s == 0)
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

void extrapolate(float u[numX][numY], float v[numX][numY]) {
    // enforce boundary conditions, otherwise the walls may 'leak'

    for (int i = 0; i < numX; i++) {
        u[i][0] = u[i][1];
        u[i][numY-1] = u[i][numY-2]; 
        v[i][0] = 0.0;
        v[i][numY-1] = 0.0;
    }
    for (int j = 0; j < numY; j++) {
        v[0][j] = v[1][j];
        v[(numX-1)][j] = v[(numX-2)][j];
        u[0][j] = 0.0; 
        u[numX-1][j] = 0.0;
    }
}

float max(float a, float b)
{
    return a > b ? a : b;
}

float min(float a, float b)
{
    return a < b ? a : b;
}

void copy_array(float a[numX][numY], float b[numX][numY]) {
    for (int x = 0; x < numX; x++) {
        for (int y = 0; y < numY; y++) {
            a[x][y] = b[x][y];
        }
    }
}

float sampleField(float x, float y, int field, float f[numX][numY]) {
    float h = 1.0f;
    float h1 = 1.0f;
    float h2 = 0.5f;

    x = max(min(x, numX * h), h);
    y = max(min(y, numY * h), h);

    float dx = 0.0;
    float dy = 0.0;

    //float f[numX][numY];

    switch (field) {
        case U_FIELD: 
            {
                //copy_array(f, u);
                dy = h2;
            }break;
        case V_FIELD: 
            {
                //copy_array(f, v);
                dx = h2; 
            }break;
        case SMOKE_FIELD: 
            {
                //copy_array(f, smoke);
                dx = h2; 
                dy = h2; 
            }break;
    }

    int x0 = min(floorf((x-dx)*h1), numX-1);
    float tx = ((x-dx) - x0*h) * h1;
    int x1 = min(x0 + 1, numX-1);

    int y0 = min(floorf((y-dy)*h1), numY-1);
    float ty = ((y-dy) - y0*h) * h1;
    int y1 = min(y0 + 1, numY-1);

    float sx = 1.0 - tx;
    float sy = 1.0 - ty;

    return sx*sy * f[x0][y0] +
        tx*sy * f[x1][y0] +
        tx*ty * f[x1][y1] +
        sx*ty * f[x0][y1];
}

float avgU(float u[numX][numY], int i, int j) {
    return (u[i][j-1] + u[i][j] +
        u[(i+1)][j-1] + u[(i+1)][j]) * 0.25;
}

float avgV(float v[numX][numY], int i, int j) {
    return (v[(i-1)][j] + v[i][j] +
        v[(i-1)][j+1] + v[i][j+1]) * 0.25;
}

void advectVel(float u[numX][numY], float v[numX][numY], int is_solid[numX][numY]) {
    float newU[numX][numY];
    float newV[numX][numY];

    copy_array(newU, u);
    copy_array(newV, v);

    float h = 1.0f;
    float h2 = 0.5f;

    for (int i = 1; i < numX; i++) {
        for (int j = 1; j < numY; j++) {

            // u component
            if (is_solid[i][j] != 0 && is_solid[(i-1)][j] != 0 && j < numY - 1) {
                float x = i*h;
                float y = j*h + h2;
                float uu = u[i][j];
                float vv = avgV(v, i, j);
                x = x - dt*uu;
                y = y - dt*vv;

                uu = sampleField(x, y, U_FIELD, u);
                newU[i][j] = uu;
            }

            // v component
            if (is_solid[i][j] != 0 && is_solid[i][j-1] != 0 && i < numX - 1) {
                float x = i*h + h2;
                float y = j*h;
                float uu = avgU(u, i, j);
                float vv = v[i][j];
                x = x - dt*uu;
                y = y - dt*vv;

                vv = sampleField(x, y, V_FIELD, v);
                newV[i][j] = vv;
            }
        }	 
    }


    copy_array(u, newU);
    copy_array(v, newV);
}

void advectSmoke(float u[numX][numY], float v[numX][numY], int is_solid[numX][numY], float smoke[numX][numY]) {
    float new_smoke[numX][numY];
    copy_array(new_smoke, smoke);

    float h = 1.0f;
    float h2 = 0.5f;

    for (int i = 1; i < numX-1; i++) {
        for (int j = 1; j < numY-1; j++) {

            if (is_solid[i][j] != 0.0) {
                float uu = (u[i][j] + u[(i+1)][j]) * 0.5;
                float vv = (v[i][j] + v[i][j+1]) * 0.5;
                float x = i*h + h2 - dt*uu;
                float y = j*h + h2 - dt*vv;

                new_smoke[i][j] = sampleField(x, y, SMOKE_FIELD, smoke);
            }
        }	 
    }
    copy_array(smoke, new_smoke);
}


void setObstacle(int x, int y, int is_solid[numX][numY], float smoke[numX][numY], float u[numX][numY], float v[numX][numY]) {

    int r = 50;

    // Clamp obstacle inside the domain
    x = max(x, r + h);
    x = min(x, (numX - 1 - r) * h);
    y = max(y, r + h);
    y = min(y, (numY - 1 - r) * h);

    float vx = 0.0;
    float vy = 0.0;

    vx = (x - obstacleX) / dt;
    vy = (y - obstacleY) / dt;

    obstacleX = x;
    obstacleY = y;

    for (int i = 1; i < numX-1; i++) {
        for (int j = 1; j < numY-1; j++) {

            is_solid[i][j] = 1; // fluid by default

            float dx = (i + 0.5) * h - x;
            float dy = (j + 0.5) * h - y;

            if (dx * dx + dy * dy < r * r) {

                is_solid[i][j] = 0; // mark as obstacle

                smoke[i][j] = 0.5 + 0.5 * sin(0.1 * frameNr);

                // Clamp array indices to avoid out-of-bounds
                int uIdx1 = min(i+1, numX-1);
                int vIdx1 = min(j+1, numY-1);

                u[i][j] = vx;
                u[uIdx1][j] = vx;
                v[i][j] = vy;
                v[i][vIdx1] = vy;
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

     // between 0.0 and 1.0 for each cell
    float smoke[numX][numY];


    // zero out the arrays
    for (int x = 0; x < numX; x++) {
        for (int y = 0; y < numY; y++) {
            u[x][y] = 0.0f;
            v[x][y] = 0.0f;
            is_solid[x][y] = 1;
            smoke[x][y] = 1.0;
        }
    }

    while (1) {
        frameNr++;

        memset(img->data, 255, img->bytes_per_line * img->height); // initialise white background every frame

        // draw smoke
        for (int i = 0; i < numX; i++) {
            for (int j = 0; j < numY; j++) {
                int px = i + gap;
                int py = j + gap;
                int val = (int)(smoke[i][j] * 255);
                unsigned long pixel = (val<<16) | (val<<8) | val;
                XPutPixel(img, px, py, pixel);
            }
        }

        draw_border(is_solid);
        draw_circle_at_mouse(display, w, is_solid, smoke, u, v);
        draw_solids(img, is_solid);


        // simulation
        solve_incompressibility(u, v, is_solid);
        extrapolate(u, v);
        advectVel(u, v, is_solid); 
        advectSmoke(u, v, is_solid, smoke);


        XShmPutImage(display, w, gc, img, 0, 0, 0, 0, width, height, False);
        XSync(display, False);
        usleep(16000); // ~60 FPS
    }
}
```


<img width="780" height="975" alt="image" src="https://github.com/user-attachments/assets/e1fe9b81-b033-4e95-9a53-468d1db8a5b8" />
