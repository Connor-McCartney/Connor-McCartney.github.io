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

