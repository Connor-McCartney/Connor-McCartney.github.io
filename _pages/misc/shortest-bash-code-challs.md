---
permalink: /misc/shortest-bash-code-challs
title: Shortest Bash Code Challenges - Mystiko CTF 2022
---

<br>

There were 11 bash challenges with a one month Hack The Box VIP+ prize to the first person who completes all of them.

<br>

# 1. How many?

Use the smallest amount of code to echo the number of characters in the string 'a'.

`Mystiko{echo ${#a}}`

<br>


# 2. UpPeR or LOwErcaSe?

Use the smallest amount of code to echo the variable 'a' all lower case.

`Mystiko{echo ${a,}}`

<br>


# 3. Calculating a float?

Use the smallest amount of code to echo the answer of 2.50000 when dividing 5 by 2 on the command line.

`Mystiko{echo "scale=5;5/2"|bc}`

<br>


# 4. Alt+126

Use the smallest amount of code to list the directory contents of the user mystiko.

`Mystiko{ls ~mystiko}`

<br>


# 5. Where am I?

Use the smallest amount of code to return to your last directory.

`Mystiko{cd -}` 

<br>


# 6. AKA

Can some one help me make it easier to type the following command in just by typing in the letters www <br>
python3 -m http.server 8888 <br>

`Mystiko{alias www='python3 -m http.server 8888'}`

<br>


# 7. Read that file!!

You have a file. You need to read it. There are a few caveats:

It can only be read in a terminal.
You must only use a binary that contains two letters.
You cannot use an editor.
The flag is the md5 hash of the terminal answer after you have run it.

```bash
[connor@fedora Desktop]$ wget https://ctf-mystiko.com/files/7defa4c2f905792708a51497aa3c278f/not_the_flag.txt -O not_the_flag.txt
[connor@fedora Desktop]$ nl not_the_flag.txt | openssl md5
MD5(stdin)= de87beaf3d7a30134c0de342dcc43a76
```

`Mystiko{de87beaf3d7a30134c0de342dcc43a76}`

<br>


# 8. Enumeration: "Ubuntu what?"

Find a way to get the following (at a minimum) information for a box that you have just accessed. <br>

DISTRIB_ID=Ubuntu                         <br>
DISTRIB_DESCRIPTION="Ubuntu 21.10"        <br>
PRETTY_NAME="Ubuntu 21.10"                <br>
ID_LIKE=debian                            <br>

This information is found in /etc/lsb-release and /etc/os-release. <br>
I thought `nl /etc/*` was technically correct, but managed to guess the flag: `Mystiko{nl /etc/*release}`

<br>


# 9. My External IP

I need to find only my external IP address. How can I do that in the shortest BASH terminal command?

There are various websites that give you your IP, ifconfig.me and ifconfig.co seemed to have the shortest URLs. <br>
`Mystiko{curl ifconfig.co}` was not accepted, but `Mystiko{curl ifconfig.me}` was.

<br>


# 10. Hidden

You are setting up a CTF challenge for your friends but want to ensure that they cannot see your history. <br>
What is the shortest piece of code that you can use to hide your commands?

By default, commands with a space entered before them will not be saved in bash history. <br>
`Mystiko{ }`

<br>


# 11. Delete the file - quickly!!!

You have a file emailed to you by a spy you just met in a coffee shop. <br>
You must delete it as quickly as you can. You check the file first and <br>
notice that it has an 'i' attribute set. What is the shortest piece of <br>
code that you can use to delete the file called "a" while not running as root user?

`Mystiko{sudo chattr -i a;rm a}`


<br>

I ended up winning the prize!

![image](https://raw.githubusercontent.com/Connor-McCartney/Connor-McCartney.github.io/main/_pages/misc/images/bashchallenges.png)
