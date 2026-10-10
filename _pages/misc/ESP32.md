---
permalink: /misc/esp32
title: ESP32
---


<br>

<br>

I was given an ESP32 chip, a breadboard, some lights and other accessories by the very kind Mr Wise! Thank you!

<br>

As I'm writing this, I have no hardware/electrical experience so this is totally new to me. 

<br>

First I opened device manager on windows, it had a yellow icon next to it so I searched the device name for a driver online, downloaded that, unzipped it, and installed it. 

<br>

Then I downloaded Arduino IDE. 

<br>

Then I set Tools -> Board -> esp32 -> Esp32 Dev Module


<br>


wrote some code and uploaded (blinks on and off)


```c
const int ledPinA = 19;
const int ledPinB = 18; 

void setup() {
  pinMode(ledPinA, OUTPUT);
  pinMode(ledPinB, OUTPUT);
}

void loop() {
  digitalWrite(ledPinA, HIGH);   
  digitalWrite(ledPinB, HIGH);   
  delay(1000);
  digitalWrite(ledPinA, LOW);    
  digitalWrite(ledPinB, LOW); 
  delay(1000);                  
}
```


<br>


Wired it up, this is the result:

<img width="3472" height="4624" alt="PXL_20261002_102745515" src="https://github.com/user-attachments/assets/cd3cbb5b-5fd0-45e2-bfc3-64644b778bf0" />


<br>

<br>


<br>

<br>

<br>

---


<br>


<br>


Next project I got a display working!


<br>

First I installed Adafruit SSD 1306 and dependencies

<br>

<img width="963" height="449" alt="image" src="https://github.com/user-attachments/assets/940633fd-72b6-402b-a341-3553ba64e733" />



<br>

<br>

<br>

```cpp
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#define SCREEN_WIDTH 128 // OLED display width, in pixels
#define SCREEN_HEIGHT 64 // OLED display height, in pixels
#define OLED_RESET     -1 // Reset pin # (or -1 if sharing Arduino reset pin)
#define SCREEN_ADDRESS 0x3C // See datasheet for Address; 0x3C for 128x64, 0x3D for 128x32

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

void setup() {
  Serial.begin(115200); // baud rate

  // Initialize with I2C address 0x3C (for the 128x64)
  if(!display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS)) {
    Serial.println(F("SSD1306 allocation failed"));
    for(;;); // Don't proceed, loop forever
  }

  // Clear the buffer
  display.clearDisplay();

  // Draw white text
  display.setTextSize(1);      // Normal 1:1 pixel scale
  display.setTextColor(SSD1306_WHITE); // Draw white text
  display.setCursor(0, 0);     // Start at top-left corner
  display.println(F("Hello, world!"));

  display.display(); // Show initial text
}

void loop() {
}

```


<br>


<br>

GND to GND, VCC to 3V3, SCL to D22, SDA to D21

<br>

<br>

<br>


<img width="3472" height="4624" alt="helloworld" src="https://github.com/user-attachments/assets/517cb113-589d-4e3f-b44f-943634cdefe0" />




<br>

<br>

<br>

---

<br>


