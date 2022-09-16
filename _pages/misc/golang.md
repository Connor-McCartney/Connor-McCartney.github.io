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

# Accepting arrays as arguments

If you try this:

```go
func foo(lst []int) {

}

func main() {
    a := [...]int {1, 2, 3}    
    foo(a)
}
```

You will see 

```
./t.go:9:9: cannot use a (variable of type [3]int) as type []int in argument to foo
```

Go does not support generics. The solution is to slice arrays when passing them into a function

```go
func foo(lst []int) {
    
}

func main() {
    a := [...]int {1, 2, 3}    
    foo(a[:])
}
```
