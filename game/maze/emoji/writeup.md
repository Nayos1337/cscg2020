# Maze - Emoji
The `Maze` series of challenges was one of my favorites in the CSCG. For all of these challenges I used the Linux version of the Game.

We are given a zip containing a game Executable and a few libraries and other assets of the game. For the first version of the game we were also given some sort of debug information on the game, however I never used that.

This is the first challenge I did for this game

## Exploration
Because this is the first challenges about the game, I had no idea what the game was about, so the first thing I did was to just to play it for a bit.

Maze is a Game were you play as a rabbit and you're stuck inside a maze (hence the name) and try to get to certain locations or do other things to get a flag.

In the case of this first challenge, we try to make a hidden Emoji. You can unlock Emojies by visiting certain places and show Emojies by pressing a key.  

The game showed a connecting screen, so I assumed that, the game would somehow interact with a server. So I set myself the goal to code a proxy for it, with which I maybe can alter the packets send to the sever. That would maybe allow me to display an emoji not yet unlocked and get the flag this way.

## Proxy development

So the first thing I did was to start the Burp HTTP Proxy and intercept all HTTP requests made by the game.

And to my surprise the game actually requested some data from some kind of API. The requests, that stood out to me, where the requests to `http://maze.liveoverflow/api/hostname`,  `http://maze.liveoverflow/api/min_port` and `http://maze.liveoverflow/api/max_port`. I assumed these were the host name and a port range for some kind of Game Server. So I used the burp Match & Replace feature to change the host name to localhost and the port range to 1337-1337, essentially forcing the client to port 1337.

I had a written template for a proxy in python (from this [Liveoverflow video](https://www.youtube.com/watch?v=iApNzWZG-10)), but I had to change a few things. The biggest being having to change to proxy from being a TCP proxy to being a UDP proxy, as this was the way the client and server communicate. That gave me hope for future challenges as a UDP connection is not guaranteed to be reliable, which could lead to being able to drop a few packets on purpose, causing some kind of teleport or something like that. But back to the proxy. After a few attempts I actually got the proxy to work and could start analyzing the packets...

... but after maybe an hour or so a gave up and came to the conclusion, that these packets are either encrypted or encoded in some other way.

## Disassembing
There was no other option besides opening a disassembler and analyzing the code.  So the first thing I noticed was, is that the actual binary, that is being run, is not that big. That means the main logic is implemented somewhere else.
The are 2 libraries shipped with this game:
* GameAssembly.so
* UnityPlayer.so

From the names only I decided, that `GameAssembly.so` would be the more interesting one, and I was right.
After looking through the zip a bit more I found a folder called `il2cpp_data`. And after a bit of goggling I found out about a tool called [Il2CppDumper](https://github.com/Perfare/Il2CppDumper), which essentially parses a file called `global-metadata.dat` and extracts some symbols out of it. To be honest I really don't know what exactly it is doing or why this file is there in the first place. But I think I at least understand what ilcpp is: It is used to generate C++ code based on a intermediate language used by Unity scripts. This C++ code is compiled and then run as part of the game. (Again I did not look into this that much, I only wanted to have the symbols.)

The Il2CppDumper generated a file (`script.json`) containing symbols with locations in the binary (GameAssembly.so) and a header file (`il2cpp.h`) containing a few structs that are used. After a long fight with ghidra I finally got the symbols and structs loaded up.

In the functions that were imported to Ghidra I searched for `Server` because I wanted to know how the encoding Algorithm for the packets worked. And after a bit of searching I found the function `ServerManager$$sendData`.  

Ghidra decompiled it like this (this code was heavily edited by me afterwards):

```c++
undefined8 ServerManager$$sendData(ServerManager_o *this,System_Byte_array *raw_in_buffer)

{
  System_Random_o *random;
  ...
  uint8_t randval2;
  uint randval;
  System_Byte_array *encrpted_out_buffer;
  ...
  ulong i;

  if (DAT_01234927 == '\0') {
    ....
  }
  else {
    encrpted_out_buffer =
         (System_Byte_array *)new?(Class$byte[],(ulong)(*(int *)&raw_in_buffer->max_length + 2));
    random = this->rand;
    randval = random.next();
    randval_dup = (ulong)randval;
    encrpted_out_buffer->m_Items[0] = (uint8_t)randval;
    random = this->rand;
    randval2 = random.next();
    encrpted_out_buffer->m_Items[1] = randval2;
    length_out = encrpted_out_buffer->max_length;
    if (0 < (int)raw_in_buffer->max_length) {
      length_out = 0x200000000;
      i = 0;
      length = (ulong)raw_in_buffer->max_length & 0xffffffff;
      ...
      do {
        encrpted_out_buffer->m_Items[(long)length_out >> 0x20] =
             raw_in_buffer->m_Items[i] ^ (byte)randval_dup;
        length_out_dup = (ulong)encrpted_out_buffer->max_length & 0xffffffff;
        randval = (uint)encrpted_out_buffer->m_Items[1] + ((uint)randval_dup & 0xff);
        randval_dup = (ulong)(randval + randval / 0xff);
        length_out = length_out + 0x40000000;
        i = i + 1;
      } while ((long)i < (long)(int)*(uint *)&raw_in_buffer->max_length);
    }
    ...
    if (this->client != (System_Net_Sockets_UdpClient_o *)0x0) {
      System.Net.Sockets.UdpClient$$Send
                ((System.Net.Sockets.UdpClient *)this->client,
                 (System_Net_Sockets_UdpClient_o)
                 CONCAT840(unaff_R14,
                           CONCAT832(unaff_R12,
                                     CONCAT824(unaff_RBX,
                                               CONCAT816(in_stack_ffffffffffffffd8,
                                                         CONCAT412(in_stack_ffffffffffffffd4,
                                                                   CONCAT48(
                                                in_stack_ffffffffffffffd0,
                                                CONCAT44(in_stack_ffffffffffffffcc,
                                                         in_stack_ffffffffffffffc8))))))),
                 (ulong)encrpted_out_buffer,length_out_dup);
      return CONCAT71((int7)(randval_dup >> 8),1);
    }
}
```
This is the function, that is supposed to be sending data to the Server.
The structs were imported from the `il2cpp.h` file. I only had to retype the variables. The `this` pointer, was easy as this looks (by the naming convention) like a method and not like a normal function. The second argument had to be some sort of buffer. I first thought, that it would just be a raw `byte[]` but with that the algorithm would have made no sense. Then there is the `encrpted_out_buffer`, I knew the type from it because it is allocated at the beginning of the function and I named it like this because it is the buffer actually being send to the server.

But enough of why I have named things like they are. Let's have a look at the algorithm.
It essentially starts at the beginning of the `else` block. First of all is the buffer `encrpted_out_buffer` allocated, it has a size of `len(raw_in_buffer) + 2`. Then we get the member `rand` from the `ServerManager` class. I had a bit of fear, that the server and the client would somehow exchange a seed to this random number generator and encrypt their packets with it. If they had done that would take a looot longer to code a proxy, so I just hoped for the best.
Now we call `next` on the random element (Ghidra actually decompiled this a lot worse, but somewhere in this weird code were the arguments `1` and `255`). So I assumed that we are generating a random byte here.
Then this random byte is stored at the beginning of the out buffer.
And a second random byte is generated and stored at the second position.
Now we get to the point were the real algorithm happens. First we pass a check, that assets, that we have at least on byte to send. Then we initialize  `length_out` with `0x200000000`, `i` with `0` and `length` with `raw_in_buffer->max_length`. Now we enter the `do-while` loop. Here the `length_out >> 0x20`th item of the `encrpted_out_buffer` is set to the xor between our random byte and the `i`th input byte. The next interesting thing happens if we skip one line. Here we see, how the `randval` is updated. It is incremented by the amount of `encrpted_out_buffer->m_Items[1]` which is the second randomly generated byte. In the next line it just adds everything thats greater than a byte onto it (just making it one byte). Then the counters are incremented and the loop continues.

If we would implemented such a algorithm in python it would look like this:
```python
import random
def encode(buff):
  out = []
  r1 = random.randint(0,255)
  r2 = random.randint(0,255)
  out.append(r1)
  out.append(r2)
  for n in buff:
    out.append(n ^ r1)
    r1 += r2
    r1 = r1 % 0xff + r1 // 0xff
  return bytes(out)
```

And a decode function could look like this:
```python
def decode(b):
    r1 = b[0]
    r2 = b[1]
    res = bytes([])
    b = b[2:]
    for i in range(len(b)):
        r1 %= 255
        res += bytes([b[i] ^ r1])
        r1 = (r1 + r2) % 255
        r1 += r1 // 0xff
    return res
```
We can now add the `decode` function to our proxy and we can also rewrite the parser:
```python
def parse(data, port, origin):
    # We only care for packets from the client for now
    if origin == "server":
        return
    arrow = "c --> s" if origin == "client" else "c <-- s"

    raw = decode(data)
    hexdump.hexdump(raw)
```

And now the packets seem much more useful

## Protocol
For now we just care about packets from the client to the server. If we just stand still in the game, we send packets like this:
```
00000000: 3C 33 2A E3 73 7C 86 D1  F4 F6 0C 0A 1D 00 00 00  <3*.s|..........
00000010: 00 00                                             ..
00000000: 3C 33 2A E3 73 7C 86 D1  F4 F6 D0 13 1D 00 00 00  <3*.s|..........
00000010: 00 00                                             ..
00000000: 3C 33 2A E3 73 7C 86 D1  F4 F6 90 1D 1D 00 00 00  <3*.s|..........
00000010: 00 00                                             ..
00000000: 3C 33 2A E3 73 7C 86 D1  F4 F6 55 27 1D 00 00 00  <3*.s|....U'....
00000010: 00 00                                             ..
00000000: 3C 33 2A E3 73 7C 86 D1  F4 F6 19 31 1D 00 00 00  <3*.s|.....1....
00000010: 00 00                                             ..
00000000: 3C 33 2A E3 73 7C 86 D1  F4 F6 DE 3A 1D 00 00 00  <3*.s|.....:....
00000010: 00 00                                             ..
00000000: 3C 33 2A E3 73 7C 86 D1  F4 F6 A0 44 1D 00 00 00  <3*.s|.....D....
00000010: 00 00                                             ..
00000000: 3C 33 2A E3 73 7C 86 D1  F4 F6 64 4E 1D 00 00 00  <3*.s|....dN....
00000010: 00 00                                             ..
00000000: 3C 33 2A E3 73 7C 86 D1  F4 F6 89 57 1D 00 00 00  <3*.s|.....W....
```
(If you already know a bit more about how the game works you can now hijack my account. Try it if you want)

Based on the starting of the start of the packet `<3` (a hearth) I concluded that this is a heartbeat.

If we move around a bit we send packet like that:
```
00000000: 50 2A E3 73 7C 86 D1 F4  F6 AE 86 45 00 00 00 00  P*.s|......E....
00000010: 00 14 28 26 00 00 00 00  00 81 C0 23 00 00 00 00  ..(&.......#....
00000020: 00 30 27 34 00 00 00 00  00 00 30 01 00 00        .0'4......0...
00000000: 3C 33 2A E3 73 7C 86 D1  F4 F6 F8 87 45 00 00 00  <3*.s|......E...
00000010: 00 00                                             ..
00000000: 50 2A E3 73 7C 86 D1 F4  F6 C7 8F 45 00 00 00 00  P*.s|......E....
00000010: 00 8D 34 26 00 51 00 00  00 3B F3 23 00 00 00 00  ..4&.Q...;.#....
00000020: 00 90 4F 06 00 00 00 00  00 00 40 03 00 00        ..O.......@...
00000000: 3C 33 2A E3 73 7C 86 D1  F4 F6 BB 91 45 00 00 00  <3*.s|......E...
00000010: 00 00
```
This seems to be position packets (the `P` at the beginning also matches that assumption)

But these just spam our output at the moment so we can edit our parser, to ignore them for now.
```python
def parse(data, port, origin):
    # We only care for packets from the client for now
    if origin == "server":
        return
    arrow = "c --> s" if origin == "client" else "c <-- s"

    raw = decode(data)
    if raw[0] == ord("<") or raw[0] == ord("P"):
        return
    hexdump.hexdump(raw)
```
Now our output is not flooded, so we can concentrate on the Emoji packet. If we press a number key to show one we get:
```
00000000: 45 2A E3 73 7C 86 D1 F4  F6 17                    E*.s|.....
```
If we show another one we get:
```
00000000: 45 2A E3 73 7C 86 D1 F4  F6 16                    E*.s|.....
```
The only thing that changes is the last byte. So we can send such a packet through the proxy to the server. But for that we have to alter our proxy.

```python
...
while True:
    x = input()
    args = x.split()
    try:
        if args[0] == "S":
            data = b"\0\0" + bytes.fromhex(args[1]) # easy way to encode
            p2s.forward(data)
            print("Data was send")
        if args[0] == "C":
            data = b"\0\0" + bytes.fromhex(args[1]) # easy way to encode
            g2p.forward(data)
            print("Data was send")
    except Exception as e:
        print('injector :', e)
```
Now we can just input:
```
S 452AE3737C86D1F4F600
S 452AE3737C86D1F4F601
S 452AE3737C86D1F4F602
S 452AE3737C86D1F4F603
...
```
And after a few tries we get to `S 452AE3737C86D1F4F60d` and the flag shows up:
![](https://raw.githubusercontent.com/Nayos1337/cscg2020/master/game/maze/emoji/flag1.png)
