# Bleichenbacher in microcontroller libraries

## TLDR

Two libraries by different vendors are vulnerable to [Bleichenbacher's chosen ciphertext attack](http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf):

+ [STM32 cryptographic firmware library software expansion for STM32Cube (X-CUBE-CRYPTOLIB)](https://www.st.com/en/embedded-software/x-cube-cryptolib.html)

+ [Microchip Libraries for Applications (MLA)](https://www.microchip.com/mplab/microchip-libraries-for-applications)

The attack allows an adversary to decrypt messages previously encrypted with RSA, if there is a service which uses the vulnerable decryption routine and it doesn't specifically filter out cases of this attack. In practice this usually means that the developer returns different statuses based on the result of the decryption: either the decryption routine itself fails or logic after the decryption fails. Most modern cryptographic libraries either warn users that the vulnerable PKCS#1v1.5 padding scheme should not be used or have mititgations to stop attackers. These libraries however did not, when I came across them. One scenario of an attack is a MitM adversary capturing network packets containing ciphertexts and then using the oracle to decrypt them.

I have contacted the vendors, but:

+ Microchip just told me to use a different library. This was the single solution after almost 6 months of waiting: "I see that you have a PIC32 as target device. My suggestion is to use Harmony (latest version) instead of MLA". No CVE, no information on their site about the pitfalls of using the latest version of MLA
+ ST admitted there was a problem and promised an updated version of the X-CUBE-CRYPTOLIB in spring of 2019 (in December of 2018). They refused to submit a CVE because they had followed specification and in their opinion the fault was not with them. Later they decided against updating the vulnerable library (I was told that it would be replaced in the future), but at least added a warning to the official documentation.

So if you're using any of those two libraries for your encryption needs, you have to be extremely careful.

## Bleichenbacher's Padding Oracle

Modern variants of this attack surfaced in the recent years [The ROBOT Attack](https://robotattack.org/), but the original itself can still be found lurking in some old libraries.
### Basic RSA

The RSA primitive ($c=Enc(m)=m^e\space mod \space N; m=Dec(c)=c^d\space mod\space N$) has a few issues:
1. If $m_1=m_2$, then $c_1=c_2$, which is a problem, since it allows to Man-in-the-Middle to derive information. (For example, we can know that the same person is using the system at this time, since they sent the same encrypted password)
2. If $e\cdot bitlen(m)\lt bitlen(N)$, than $m^e$ doesn't wrap the modulus and can be easily decrypted by taking the $e$-th root of $C$

### PKCS#1 v1.5

To address these issues RSA (as in company) created a specification that became [PKCS\#1 v1.5](https://tools.ietf.org/html/rfc2313) (Public Key Cryptography Standards)
The specification introduces formatting for encrypted (or signed) blocks (effectively, a special padding).
Let's say the length of modulus $N$ in octets (bytes) is equal to $k$: $k=||N||$. The data we want to encrypt/sign is $D$. Then the encryption block is: 

``` EB = 00 || BT || PS || 00 || D ```

where $BT$ is $00$ or $01$ for private-key operations (signing) and $02$ is for public-key operations (encryption).
The encryption block is translated to integer using big-endian conversion (the first octet of EB is the most significant one)
$PS$ consists of $k-3-||D||$ octets. Its conents depend on $BT$:

1. $BT=00$, all octets in $PS$ have value $00$
2. $BT=01$, all octets in $PS$ have value FF
3. $BT=02$, all octets in $PS$ are pseudorandomly generated and not equal to $00$

It is recommended to use $BT=01$ for signatures and $BT=02$ for encryptions, since
1. With $BT=01$ $D$ can be unpadded regardless of its contents, with $BT=00$ the first byte of $D$, $D_0=00$ will also be unpadded, which creates a problem.
2. Both $BT=01$ and $BT=02$ create large integers for encryption, so all attacks depending on small $D$ don't work

You can also notice, that the first octet of $EB$ is $00$. It is chosen so that the integer resulting from $EB$ is always less than $N$.

### Bleichenbacher's Padding Oracle Attack

Frankly, Dr. Mathew Green summed it up best in [What is the Random Oracle Model and why should you care? (Part 4)](https://blog.cryptographyengineering.com/2011/11/02/what-is-random-oracle-model-and-why/) :
>Now, I said that almost nobody of a practical bent had a problem with PKCS. One notable exception was a bright cryptographer from Bell Labs named Daniel Bleichenbacher.
>
>Dr. Bleichenbacher had a real problem with the PKCS padding standards. In fact, one could say that he made it his life’s mission to destroy them. This vendetta reached its zenith in 2006, when he showed how to break common implementations of PKCS signature with a pencil and paper, shortly before driving a fireworks-laden minivan into the headquarters of RSA Data Security.
>
>(Ok, the last part did not happen. But the rest of it did.)
>
>Bleichenbacher took his first crack at PKCS in CRYPTO 1998. In a surprisingly readable paper, he proposed the first practical adaptive chosen ciphertext attack against “protocols using the PKCS #1” encryption standard. Since, as I’ve just mentioned, the major protocol that met this description was SSL, it was a pretty big deal."

You can find the original paper here: [Chosen Ciphertext Attacks Against Protocls Based on the RSA Encryption Standard PKCS#1](http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf).

Let's imagine we sent a random integer $c$ for decryption. What is the probability that no error will surface during unpadding? The first 2 octets of $EB$ should be $00 || 02$, the other octets should have at least one $00$. If $k$ is 256, then $P=\frac{1}{256^2}\cdot(1-(\frac{255}{256})^{254})\approx \frac{1}{104031}$ Seems way too small, but you can actually use it. The attack works as follows:

We chose the $c$, for which we want to find $m=c^d \space mod \space N$

For convenience we use $B=2^{8(k-2)},\space k=||N||$. We say that ciphertext is PKCS conforming if it decrypts to a PKCS conforming plaintext.

Basically, we choose integers $s$, compute $c'=cs^e\space mod \space N$ and send them to the oracle. If $c'$ passes the error check, then $2B \le ms\space mod \space N \lt 3B$. By collecting enough different $s$ we can derive $m$, this typically requires around $2^{20}$ ciphertexts, but this number varies widely.
The attack can be divided into three phases:
1. Blinding the ciphertext, creating $c_0$, that corresponds to unknown $m_0$
2. Finding small $s_i$, such that $m_0s_i\space mod \space N$ is PKCS-conforming. For every such $s_i$ the attacker computes intervals that must contain $m_0$ using previously known information
3. Starts when only one interval remains. The attacker has sufficient information about $m_0$ to choose $s_i$ such that $m_0s_i\space mod \space N$ is more likely to be PKCS conforming than a randomly chosen message. The size of $s_i$ is increased gradually, narrowing the possible range of $m_0$ until only one possible value remains. 

(Actually, when the interval is small enough, it is more efficient to just bruteforce the values locally than continue submitting queries to the oracle)

## Proof of Concepts

### General information

Since these libraries are aimed at embedded devices, using them on a regular PC with amd64 architectures comes with certain limits. The worst of them is the speed of computation. 

The MLA is distributed as source code, but the actual bigint computations are implemented in PIC architecture assembly. I had to rewrite them to amd64 architecture, but suffered a slowdown, since the procedures in C code relied of 16-bit computations in assembly routines. This makes RSA quite slow, even though it is executed "natively". It can take up to several days to complete the attack. On a device it would take significantly less. 

X-CUBE-CRYPTOLIB is distributed in compiled format. To use it on a PC I had to emulate the firmware with QEMU. Obviously it is a significant slowdown. What makes it even worse is that the only available interface to transport the data is emulated UART which is painfully slow (it takes 2 minutes to transmit 256 bytes). To deal with the interface problem I've implemented a debug hook (so QEMU is running with debugging) that transfers data to and from memory. This allows to cut at least the transmission emulation bottleneck.

Still in these conditions the attack is quite slow. So there are two versions of the attack for both platforms you can perform:

+ The full attack (will take a long time on MLA, an absurdly long time on ST)
+ The attack with precomputed successful steps

The second variant is basically running the algorithm beforehand with a python server which performs the same checks as the vulnerable library . It saves all the steps which produce the correct decryption outcome (these steps allow the attacker to narrow the plaintext space). The attacker only tries these with the vulnerable implementation later (so it's skipping bruteforce).

It's also worth noting that the X-CUBE-CRYPTOLIB library is protected against being used on non-ST devices (the check is performed by writing and reading bits from specific memory registers). QEMU fails this check, but fortunately instead of refusing to decrypt/encrypt data the routines just mask data during encryption and give back more data (including some of the random padding) during decryption. The mask can be rolled back as long as the plaintext contains only ASCII-7 characters, since all of them are less than 128. So the unmasking function also had to be implemented to use the library with QEMU.

There was only one change made to the MLA library: implementing bigint arithmetic in intel assembly instead of PIC.

There were no changes made to the ST library.

The rest of this article are instructions how to reproduce the issues (on Linux).

### Preliminary steps

MLA library is readily available here: https://www.microchip.com/mplab/microchip-libraries-for-applications, but you have to request X-CUBE-CRYPTOLIB in advance here (you'll have to register): https://www.st.com/en/embedded-software/x-cube-cryptolib.html. Or if you've already registered and are logged in: https://my.st.com/content/my_st_com/en/products/embedded-software/mcu-mpu-embedded-software/stm32-embedded-software/stm32cube-expansion-packages/x-cube-cryptolib.html.

To use RSA we first need to generate the private key. The private key will be used to create the speedup trace and it will be used by the servers.

Unpack the archive ["*Bleichenbacher_on_microcontrollers*.tar.gz"](https://github.com/Rumata888/bleichenbacher-in-microcontrollers/Bleichenbacher_on_microcontrollers.tar.gz). Go to  subfolder "*Preparation*".

List of files in *"Preparation"*:

+ requirements.txt (file with python requirements for *"create_traces_and_imports.py"* and python attack clients)
+ create_traces_and_imports.py (python script which parses a pem file, creates headers and imports for vulnerable servers and clients, also encrypts one message, which is to be decrypted by the attacking clients and creates a trace to show the attack without taking too much time)
+ initialize.sh (runs openssl to create a 2048-bit RSA key, then runs *"create_traces_and_imports.py"*)

You need to install openssl, python3, pip, python3-gmpy2 and pycryptodome. If on ubuntu, run:

```bash
sudo apt install openssl python3 python3-pip python3-gmpy2 && python3 -m pip install -r requirements.txt
```

Now you can run the initialization file which will create the keys, the trace and the headers for the future use. "initialize.sh" first creates an RSA key "private.pem" and then runs the "create_traces_and_imports.py". There are comments inside files, so you can look inside to see what's happening.

Run:

```bash
./initialize.sh
```

Files and folders created:

+ microchip_files
  + attacker_params.py
  + key_params.h
+ speedup
  + info.txt
  + trace.txt

The "info.txt" file contains information on how long it would take for the client to complete each variant of attack (based on my hardware, yours can be better).

### Microchip PoC

Install [Microchip Libraries for Applications (MLA)](https://www.microchip.com/mplab/microchip-libraries-for-applications). The latest version at the time of writing is "v2018_11_26". It has to be installed in a non-virtualized environment. For some reason they've implemented this check in the installer.

Go to the directory, where you've extracted all files from "Bleichenbacher_on_microcontrollers.tar.gz". Go to "Microchip/vulnerable_server"*.*

List of files in the directory:

+ bigint_helper_16bit_intel.S (rewritten *"bigint_helper_16bit.S"* from the bigint library inside MLA. It was written for PIC architecture, making the library unusable on a PC. I rewrote all functions in intel (x86_64) assembly, to use the same bigint library that crypto_sw in MLA uses)
+ bleichenbacher_oracle_mla.c (the main file containing high-level server functions)
+ crypto_support_params.h (enums and function definitions for cryptographic functions)
+ crypto_sw.patch (patchfile, which comments out one line in crypto_sw library to stop type collision when building on a PC)
+ crypto.c (contains all functions which initialize and deinitialize MLA's RSA implementation and functions that wrap around encryption and decryption routines)
+ do_patch.sh (a simple bash script to apply the patch)
+ makefile 
+ oracle_params.h (some server parameters)
+ support.c (decrytped message checking function)
+ support.h (check_message function and return values definitions and seed length definition)

Copy the folders "*bigint*" and "*crypto_sw*" from "~/microchip/mla/v2018_11_26/framework" to "*microchip_build*". Copy the file "*key_params.h*" from "*Preparation/microchip_files*" in the initialization phase to the *"Microchip/vulnerable_server"*. Run *do_patch.sh*. It will change one line in the crypto_sw library (there is a type definition collision because we are using system's stdint). And finally you can run make.

```bash
cd Microchip/vulnerable_server
cp -r ~/microchip/mla/v2018_11_26/framework/bigint .
cp -r ~/microchip/mla/v2018_11_26/framework/crypto_sw .
cp ../../Preparation/microchip_files/key_params.h .
./do_patch.sh
make
```

The file "*bleichenbacher_oracle_mla*" is the program containing the vulnerable oracle server using microchip's library.

Now open another terminal (let's call it "AttackerTerminal" and the previously used one "VictimTerminal"). Go to *"Attacker* in this newly created terminal and copy *"Preparation/attacker/attacker_params.py"* to *"Attacker"*. You can also copy the tracefile if you want to speedup the attack. Look in the *"Preparation/speedup/info.txt"* to see how much time you'd have to spend on each version of the attack (without speedup/skipping the initial bruteforce/just checking the trace) with the current key and encrypted message.

```bash
#AttackerTerminal
cp ../Preparation/attacker/attacker_params.py .
cp ../Preparation/speedup/trace.txt .
```

Now open the victim terminal and run *bleichenbacher_oracle_mla*. It will open port 13337 and listen for one incoming connection. This means that if you want to rerun the attack  you have to stop the attacker and rerun the server, then run the attacker script again.

```bash
#VictimTerminal
./bleichenbacher_oracle_mla
```

Depending on how you want to run the attack you have 3 options:

1. Run the full attack (you will have to wait for a long time, however)

   ```bash
   #AttackerTerminal
   python3 attacker.py
   ```
2. Skip the first part of the attack (finding the first s. This is the longest part of the whole attack)
   ```bash
   #AttackerTerminal
   python3 -t trace.txt -s
   ```

2. Run only the successful queries (taken from the trace). The quickest version of the attack.

   ```bash
   #AttackerTerminal
   python3 -t trace.txt
   ```

After the attack completes, the attacking script will print the decrypted message, it will login on the vulnerable server and ask it to give the flag, printing the final answer from the server.

### ST PoC

Download and unzip [qemu_stm32](https://github.com/beckus/qemu_stm32/archive/stm32_v0.1.3.zip).

```bash
wget https://github.com/beckus/qemu_stm32/archive/stm32_v0.1.2.zip
unzip stm32_v0.1.2.zip
cd qemu_stm32-stm32_v0.1.2
```

Install the necessary packages:

```bash
sudo apt install arm-none-eabi-gcc-arm-non-eabi-newlib gcc
```

Configure and build qemu:

```
./configure --extra-cflags="-w" --enable-debug --target-list="arm-softmmu"
make
```

If there is a problem with linking, which stems from undefined references to symbols "minor", "major", "makedev", then you need to add the following include to the file *"qemu_stm32-stm32_v0.1.2/hw/9pfs/virtio-9p.c"*:

```c
#include <sys/sysmacros.h>
```

The error is due to the changes in libc after version 2.28.

You can do it easily this way:

```bash
cd qemu_stm32-stm32_v0.1.2
cp ../stm32_qemu.patch .
cp ../do_qemu_patch.sh .
```

Now just configure and make it again.

The qemu executable, that can execute images for STM is located in *"qemu_stm32-stm32_v0.1.2/arm-softmmu"* and is named *"qemu-system-arm"*.

Now let's build the image. Go back to *"ST/vulnerable_server/binary"*. Download the [stm32_p103_demos](https://github.com/beckus/stm32_p103_demos/archive/v0.3.0.zip) archive and unzip it.

```bash
wget https://github.com/beckus/stm32_p103_demos/archive/v0.3.0.zip
unzip v0.3.0.zip 
```

Put the X-CUBE-CRYPTOLIB archive *"en.x-cube-cryptolib.zip"*  in the *"ST/binary"*  and unzip it. Copy the library files for STM32F1 to the *"stm32_p103_demos-0.3.0"*:

```bash
unzip en.x-cube-cryptolib.zip
cp -r STM32CubeExpansion_Crypto_V3.1.0/Fw_Crypto/STM32F1/Middlewares/ST/STM32_Cryptographic stm32_p103_demos-0.3.0/
```

Now you need to apply the patch containing vulnerable server's source code and changes to makefile and the linkage file (without it the compilation will fail during linkage).

```bash
cd stm32_p103_demos-0.3.0
cp ../do_demos_patch.sh .
cp ../stm32_p103_demos.patch .
./do_demos_patch.sh 
```

The list of files in the folder *"demos/bleich/"*:

+ main.c - the main file containing high-level functionality of the server
+ stm32f10x_conf.h - configuration file
+ support.c - message parsing and fixing
+ support.h - definitions for the use of support.c

You need to copy the parameters of the key:

```
cp ../../../../Preparation/st_files/key_params.h demos/bleich/
```

Now you can build the vulnerable server.

```bash
make bleich_ALL
```

Bear in mind, that if you create a new key and run create_imports... you will need to perform *make clean* first to rebuild with new parameters.

For this one you'll need 3 terminals:

+ Server QEMU terminal
+ Server GDB terminal
+ Attacker terminal

In the first terminal go to the *"<some_prefix>/ST/vulnerable_server/binary/qemu_stm32-stm32_v0.1.2/arm-softmmu"* folder and start qemu with gdb server:

```bash
#Server QEMU terminal
./qemu-system-arm -M stm32-p103 -kernel ../../stm32_p103_demos-0.3.0/demos/bleich/main.bin -gdb tcp::3333
```

In Server GDB terminal do the following:

+ Go to *"<some_prefix>/ST/vulnerable_server/"* 
+ install gdb-multiarch if it's not installed
+ run gdb-multiarch
+ load file *"binary/stm32_p103_demos-0.3.0/demos/bleich/main.elf"* (this is necessary for the script to work)
+ connect to qemu gdb server 
+ load python script *"<some_prefix>/ST/vulnerable_server/gdb_server/python-extender.py"*  (gdb has to use python3)

```bash
#Server GDB terminal
gdb-multiarch
file binary/stm32_p103_demos-0.3.0/demos/bleich/main.elf
target remote localhost:3333
source gdb_server/python-extender.py 
```

At this point this terminal should hang. This is ok, it's waiting for a connection from the server.

The steps to attack the server are the same as in Microchip PoC. If you want to do the attack again, first you have to stop qemu, then you need to kill gdb

```bash
pkill -9 gdb
```

Unfortunately, it can't exit itself because of python threads.  And then redo all the steps.

## Conclusion

As you can easily check yourself, two libraries distributed by popular vendors with millions of devices are vulnerable to a 22-year-old attack (by now it could get a bachelor's). So if you ever have to use cryptography with one of their chips, choose some well-tested open-source library instead (MBED-TLS is quite good, I hear).
