
```python
from pynput.keyboard import Key, Controller
from pynput import keyboard

def on_press(key):
    try:
        k.press(bindings[key.char])
    except:
        pass

def on_release(key):
    try:
        k.release(bindings[key.char])
    except:
        pass

k = Controller()
bindings = {"h": Key.left, 
            "l": Key.right, 
            "j": Key.down, 
            "k": Key.up}

with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
```
