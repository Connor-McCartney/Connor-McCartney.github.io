---
permalink: /misc/golang
title: Learning Golang from scratch
---


<br>


# Hello World

```go
package main

import "fmt"

func main() {
	fmt.Println("Hello world")
}
```

# Running a program

```
[connor@fedora Desktop]$ go run program.go
Hello world
```

# Compiling and running

```
[connor@fedora Desktop]$ go build program.go
[connor@fedora Desktop]$ ./program 
Hello world
```
