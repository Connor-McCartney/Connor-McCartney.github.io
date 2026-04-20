---
permalink: /misc/pythonthreads
title: Python Threads
---

<br>

<br>

```python
from threading import Thread
from time import sleep

def thread1():
    while True:
        print('1')
        sleep(1)

def thread2():
    while True:
        print('2')
        sleep(1)

def thread3():
    while True:
        print('3')
        sleep(1)

Thread(target=thread1).start()
Thread(target=thread2).start()
Thread(target=thread3).start()
```
