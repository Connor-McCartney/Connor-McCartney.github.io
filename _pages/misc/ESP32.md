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

code for random black and white pixels noise like broken tv:

```cpp
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#define SCREEN_WIDTH 128 
#define SCREEN_HEIGHT 64 
#define OLED_RESET     -1 
#define SCREEN_ADDRESS 0x3C 

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

void setup() {
  if(!display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS)) {
    for(;;); 
  }
  
  display.clearDisplay();
}

void loop() {

    for (int y = 0; y < SCREEN_HEIGHT; y++) {
      for (int x = 0; x < SCREEN_WIDTH; x++) {
        if (rand() % 2 == 0) {
          display.drawPixel(x, y, SSD1306_WHITE);
        } else {
          display.drawPixel(x, y, SSD1306_BLACK);
        }
      }
    }


    display.display();
}

```



<br>

---

<br>



<br>

<br>

Now I'll try get it working with rust on linux. 


<br>

```
cargo install espflash
```


<br>

Put this in bashrc

```
. ~/export-esp.sh
export PATH=/home/connor/.cargo/bin:$PATH
```


<br>


```
[~/t] 
$ espflash board-info
[2026-10-11T03:51:22Z INFO ] Serial port: '/dev/ttyUSB0'
[2026-10-11T03:51:22Z INFO ] Connecting...
Error:   × Failed to open serial port /dev/
  │ ttyUSB0
  ├─▶ Error while connecting to device
  ╰─▶ Permission denied


[~/t] 
$ sudo usermod -aG uucp connor

[~/t] 
$ newgrp uucp

[~/t] 
$ espflash board-info
[2026-10-11T03:51:54Z INFO ] Serial port: '/dev/ttyUSB0'
[2026-10-11T03:51:54Z INFO ] Connecting...
[2026-10-11T03:52:00Z INFO ] Using flash stub
Chip type:         esp32 (revision v3.1)
Crystal frequency: 40 MHz
Flash size:        4MB
Features:          WiFi, BT, Dual Core, 240MHz, VRef calibration in efuse, Coding Scheme None
MAC address:       14:08:08:ab:62:b4
Security features: None
```


<br>

<br>

```
yay -Syu --noconfirm
cargo install cargo-generate
cargo generate esp-rs/esp-template
```

<br>

```rs
#![no_std]
#![no_main]

use esp_hal::{
    delay::Delay,
    gpio::{Level, Output, OutputConfig},
};
use esp_backtrace as _;

// Required for esp-hal v1.2+ binaries to be recognized by the bootloader
esp_bootloader_esp_idf::esp_app_desc!();

#[esp_hal::main]
fn main() -> ! {
    let peripherals = esp_hal::init({
        let config = esp_hal::Config::default();
        config
    });
    
    // Configure GPIO 19 and GPIO 18 as outputs
    let mut led_a = Output::new(peripherals.GPIO19, Level::Low, OutputConfig::default());
    let mut led_b = Output::new(peripherals.GPIO18, Level::Low, OutputConfig::default());

    let delay = Delay::new();

    loop {
        led_a.set_high();
        led_b.set_high();
        delay.delay_millis(1000);

        led_a.set_low();
        led_b.set_low();
        delay.delay_millis(1000);
    }
}


```


```rs
[package]
name = "test"
version = "0.1.0"
authors = ["Connor McCartney <connormccartney363@gmail.com>"]
edition = "2021"
license = "MIT OR Apache-2.0"

[dependencies]
esp-hal = { version = "1.2.2", features = ["esp32", "unstable"] }
esp-backtrace = { version = "0.14.2", features = ["esp32", "panic-handler", "println"] }
esp-println = { version = "0.12.0", features = ["esp32"] }
esp-bootloader-esp-idf = { version = "0.5.0", features = ["esp32"] }
log = { version = "0.4.22" }

[profile.dev]
# Rust debug is too slow.
# For debug builds always builds with some optimization
opt-level = "s"

[profile.release]
codegen-units = 1 # LLVM can perform better optimizations using a single thread
debug = 2
debug-assertions = false
incremental = false
lto = 'fat'
opt-level = 's'
overflow-checks = false
```


<br>

```
cargo install espup
espup install
cargo run
```

<br>


works!


<br>

<br>

<br>



---


<br>

<br>

<br>

random noise on the display:

```rs
#![no_std]
#![no_main]

use core::default::Default;
use embedded_graphics::{
    draw_target::DrawTarget,
    pixelcolor::BinaryColor,
};

use esp_hal::{
    delay::Delay,
    i2c::master::{Config as I2cConfig, I2c},
    time::Rate,
};
use esp_backtrace as _;
use ssd1306::{prelude::*, I2CDisplayInterface, Ssd1306};

esp_bootloader_esp_idf::esp_app_desc!();

struct SimpleRng {
    state: u32,
}

impl SimpleRng {
    fn new(seed: u32) -> Self {
        Self { state: seed }
    }

    fn next_bool(&mut self) -> bool {
        self.state = self.state.wrapping_mul(1103515245).wrapping_add(12345);
        (self.state / 65536) % 2 == 0
    }
}

#[esp_hal::main]
fn main() -> ! {
    let peripherals = esp_hal::init({
        let config = esp_hal::Config::default();
        config
    });

    // Initialize I2C at 400 kHz Fast Mode (GPIO 21 SDA, GPIO 22 SCL)
    let i2c = I2c::new(
        peripherals.I2C0,
        I2cConfig::default().with_frequency(Rate::from_khz(400)),
    )
    .unwrap()
    .with_sda(peripherals.GPIO21)
    .with_scl(peripherals.GPIO22);

    let interface = I2CDisplayInterface::new(i2c);
    let mut display = Ssd1306::new(interface, DisplaySize128x64, DisplayRotation::Rotate0)
        .into_buffered_graphics_mode();
    
    display.init().unwrap();
    display.clear(BinaryColor::Off).unwrap();
    display.flush().unwrap();

    let mut rng = SimpleRng::new(42);
    let delay = Delay::new();

    loop {
        for y in 0..64 {
            for x in 0..128 {
                let is_on = rng.next_bool();
                display.set_pixel(x, y, is_on);
            }
        }

        display.flush().unwrap();
        delay.delay_millis(10);
    }
}

```


<br>

```rs
[package]
name = "test"
version = "0.1.0"
authors = ["Connor McCartney <connormccartney363@gmail.com>"]
edition = "2021"
license = "MIT OR Apache-2.0"

[dependencies]
esp-hal = { version = "1.2.2", features = ["esp32", "unstable"] }
esp-backtrace = { version = "0.14.2", features = ["esp32", "panic-handler", "println"] }
esp-println = { version = "0.12.0", features = ["esp32"] }
esp-bootloader-esp-idf = { version = "0.5.0", features = ["esp32"] }
embedded-graphics = "0.8.1"
ssd1306 = "0.10.0"
log = { version = "0.4.22" }



[profile.dev]
# Rust debug is too slow.
# For debug builds always builds with some optimization
opt-level = "s"

[profile.release]
codegen-units = 1 # LLVM can perform better optimizations using a single thread
debug = 2
debug-assertions = false
incremental = false
lto = 'fat'
opt-level = 's'
overflow-checks = false
```

<br>

<br>

<br>

---

<br>

