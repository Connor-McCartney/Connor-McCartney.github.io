---
permalink: /misc/LinuxNetworkNamespaces
title: Linux Network Namespaces
---

<br>


<br>



There are many different types of [Linux namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html) - Cgroup, IPC, Mount, PID, User, UTS, Network.

Let's look at the Network one. 

It's kind of like having a container with its own isolated virtual network. 

Let's create 2. 


```
$ sudo ip netns add my_container_a

$ sudo ip netns add my_container_b

$ ip netns list
my_container_b
my_container_a
```
