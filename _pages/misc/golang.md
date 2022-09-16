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

<br>

# Running a program

```
[connor@fedora Desktop]$ go run program.go
Hello world
```

<br>

# Compiling and running

```
[connor@fedora Desktop]$ go build program.go
[connor@fedora Desktop]$ ./program 
Hello world
```

<br>

# Formats

<https://pkg.go.dev/fmt>

<br>

# Getting input 

There are no chars in golang<br>

The byte type in Golang is an alias for the unsigned integer 8 type ( uint8 ). <br>
The byte type is only used to semantically distinguish between an unsigned integer 8 and a byte. <br>
The range of a byte is 0 to 255 (same as uint8 ).

```go
package main

import "fmt"

func main() {
    var i int
    var f float64
    var s string
    
    fmt.Print("Enter an int: ") 
    fmt.Scanf("%d", &i)
    fmt.Printf("You entered %d\n\n", i)

    fmt.Print("Enter a float: ")
    fmt.Scanf("%f", &f)
    fmt.Printf("You entered %0.2f\n\n", f)
    
    fmt.Print("Enter a string: ")
    fmt.Scanf("%s", &s)
    fmt.Printf("You entered %s\n\n", s)
}
```

<br>

# For loops

```go
func main() {
    for i := 1; i <= 5; i++ {
        fmt.Println(i)
    }
}
```

```go
func main() {
    nums := []int{2, 3, 5, 7}
    for i, n := range nums {
        fmt.Println(i, n)
    }
}
```

<br>

# Creating dynamically-sized arrays

The make function allocates a zeroed array and returns a slice that refers to that array: <br>
```go
a := make([]int, 5)  // len(a)=5
```

To specify a capacity, pass a third argument to make:<br>
```go
b := make([]int, 0, 5) // len(b)=0, cap(b)=5
```

<br>

# Creating maps

```go
m := make(map[KeyType]ValueType)
```

<br>

# How to check if a map contains a key

This is the 'comma ok' idiom

```go
if val, ok := dict["foo"]; ok {
    //do something here
}
```

if statements in Go can include both a condition and an initialization statement. 

First: initializes two variables - val will receive either the value of "foo" from the <br>
map or a "zero value" (in this case the empty string) and ok will receive a bool that <br>
will be set to true if "foo" was actually present in the map

Second: evaluates ok, which will be true if "foo" was in the map

<br>
