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


<br>

Then you can kind of spawn a shell inside it. 

You'll notice networking is not set up, it can't even ping localhost. 

```
$ sudo ip netns exec my_container_a bash

# ping 127.0.0.1
ping: connect: Network is unreachable

# ip a
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
```



<br>

<br>


Now let's connect my_container_a to my_container_b. 


We use the veth interface, which is like a virtual ethernet cable. 

<br>

```
[ my_container_a ] my_veth_end_a <==== virtual cable ==== > my_veth_end_b [ my_container_b ]
```


<br>

We actually create the 2 ends of the cable at once. 

```
$ sudo ip link add my_veth_end_a type veth peer name my_veth_end_b
```

<br>

Next we 'plug in' each end of the cable:

```
$ sudo ip link set my_veth_end_a netns my_container_a
$ sudo ip link set my_veth_end_b netns my_container_b
```

<br>

And should now be able to see it from within the container:

```
# ip a
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
5: my_veth_end_a@if4: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 96:1a:bf:cf:64:ce brd ff:ff:ff:ff:ff:ff link-netns my_container_b
```


<br>


