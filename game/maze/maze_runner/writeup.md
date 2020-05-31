# Maze Runner
The `Maze` series of challenges was one of my favorites in the CSCG. For all of these challenges I used the Linux version of the Game.

We are given a zip containing a game Executable and a few libraries and other assets of the game. For the first version of the game we were also given some sort of debug information on the game, however I never used that.

This is the second challenge I did in this series. If you don't understand why or when I did something, then you can try reading the writeups to the challenges before this one : `Maze - Emoji`.

## Goal

For this challenge our goal is to run the Maze in a limited amount of time. Without any modification to the game this is not possible, so we somehow have to inject some code into the game, that makes us faster.

While searching through the `ilcpp.h` file I found the `Lightbug_CharacterControllerPro_Implementation_NormalMovement_o` struct.

```c
struct Lightbug_CharacterControllerPro_Implementation_NormalMovement_o {
  ....
	Lightbug_CharacterControllerPro_Implementation_CharacterStateController_o* CharacterState_characterStateController;
	Lightbug_CharacterControllerPro_Implementation_PlanarMovementParameters_o* planarMovementParameters;
	Lightbug_CharacterControllerPro_Implementation_VerticalMovementParameters_o* verticalMovementParameters;
	Lightbug_CharacterControllerPro_Implementation_ShrinkParameters_o* shrinkParameters;
    ....
	int32_t notGroundedJumpsLeft;
	float jumpTimer;
	bool isJumping;
	....
};
```
It contains the very interesting member `notGroundedJumpsLeft` and a pointer to a `Lightbug_CharacterControllerPro_Implementation_PlanarMovementParameters_o`.
```c
struct Lightbug_CharacterControllerPro_Implementation_PlanarMovementParameters_o {
	Lightbug_CharacterControllerPro_Implementation_PlanarMovementParameters_c *klass;
	void *monitor;
	float speed;
	float boostMultiplier;
	float notGroundedControl;
};
```
Which contains a speed parameter. I was fairly certain, that the game would use those variables, because we have `NormalMovement`.
So if we want to find a function that uses that struct we can search through the `script.json` file, which reveals:
```json
...
{
  "Address": 9131248,
  "Name": "Lightbug.CharacterControllerPro.Implementation.NormalMovement$$ProcessJump",
  "Signature": "void Lightbug_CharacterControllerPro_Implementation_NormalMovement__ProcessJump (Lightbug_CharacterControllerPro_Implementation_NormalMovement_o* this, float dt);"
}
...
```
I don't know why I used this function, but I did.

## Injection

I knew in theory how you would implement such a hijack, but I learned it from [Guided Hacking](https://www.youtube.com/user/L4DL4D2EUROPE) and he uses Windows. That's why it took a loooong time to get even a simple version done.

```c
#define _GNU_SOURCE
#include <link.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <errno.h>

#include <math.h>

#include "il2cpp_v2_1.h"

// Compiled using : gcc -shared -fPIC -o inj.so injection.c

#ifdef version1
  #define JUMP_HOOK_OFF 0x003ac110 // offset in v1
#else
  #define JUMP_HOOK_OFF 0x008b54f0 // offset in v2.1
#endif

#define SAVE_ALL __asm__("push %rax; push %rbx; push %rcx; push %rdx; push %rdi; push %rsi; push %r8; push %r9; \
                        push %r10;push %r11; push %r12; push %r13; push %r14;push %r15; sub $0x102, %rsp;  sub $0x102, %rbp;")

#define RESTORE_ALL __asm__("add $0x102, %rbp; add $0x102, %rsp; pop %r15; pop %r14; pop %r13; pop %r12; pop %r11; pop %r10; pop %r9;\
                        pop %r8; pop %rsi; pop %rdi; pop %rdx; pop %rcx; pop %rbx; pop %rax")



void* game_start = NULL;
uint8_t jmp_gateway[4096];
size_t pagesize = 0;


void hookJumping() {
  SAVE_ALL; // just to be sure we don't break anything
  printf("inside hook\n");
  RESTORE_ALL;
}


// somehow stolen from https://stackoverflow.com/questions/20381812/mprotect-always-returns-invalid-arguments
static inline void *pageof(const void* p)
{
  return  (void *)((size_t)p & (size_t)(~(pagesize - 1)));
}


int mprotect_page(void* addr, size_t len, int flags) {
    void* fromP = pageof(addr);
    void* toP = pageof(addr + len);
    size_t lenP = toP - fromP + pagesize;
    return mprotect(fromP, lenP, flags);
}



static int libarySearch(struct dl_phdr_info *info, size_t size, void *data)
{
   int length = strlen(info->dlpi_name);
   if (!strncmp((char *)(info->dlpi_name + length - 15), "GameAssembly.so", 15)) {
        assert(info->dlpi_phdr[0].p_type == PT_LOAD);
        game_start = (void *)(info->dlpi_addr + info->dlpi_phdr[0].p_vaddr);
        printf("Found Address : %14p\n", game_start);
   }
   return 0;
}


void* createTampolineHook(void* tohook, void* injection, uint8_t* gateway_data, size_t len) {

    //setting up gateway
    void* gateway = (void*)gateway_data;
    printf("Hooking : hooked %p to %p using gateway %p\n", tohook, injection, gateway);

    uint64_t relativeAddr64 = injection - gateway - 6;
    uint32_t relativeAddr32 = (uint32_t)relativeAddr64;

    *(uint8_t*) gateway             = 0x58;                        // pop rax
    *(uint8_t*) (gateway + 1)       = 0xe8;                        // call optcode
    *(uint32_t*)(gateway + 2)       = relativeAddr32;              // call operand

    memcpy(gateway + 6, tohook, len);

    *(uint8_t*)  (gateway + 6 + len)  = 0x50;                     // push rax
    *(uint32_t*) (gateway + 7 + len)  = 0xefb848;                 // mov rax,... part
    *(uint64_t *)(gateway + 9 + len)  = (uint64_t) (tohook + 13); // ...tohook part
    *(uint64_t *)(gateway + 17 + len) = 0xe0ff;                   // jmp rax

    //setting up tohook
    assert(mprotect_page(tohook, len, PROT_READ | PROT_WRITE) == 0);
    *(uint8_t *)tohook              = 0x50;                                 // push rax
    *(uint32_t *)(tohook+1)         = 0xefb848;                             // mov rax,... part
    *(uint64_t *)(tohook+3)         = (uint64_t)gateway;                    // ...gateway part
    *(uint16_t *)(tohook+11)        = 0xe0ff;                               // jmp rax
    *(uint8_t *)(tohook+13)         = 0x58;                                 // pop rax


    for (uint8_t* p = tohook+14; (uint64_t)p < (uint64_t)(tohook+len); p++) {
      *p = 0x90;
    }

    mprotect_page(tohook,len, PROT_READ | PROT_EXEC);
    mprotect_page(gateway,len+5, PROT_READ | PROT_EXEC);
    return gateway;
}



void* threadMain(void * ptr) {
    while(game_start == NULL) {
      dl_iterate_phdr(libarySearch, NULL);
      sleep(1);
    }
    sleep(1);
    close(1);
    close(2);
    dup2(0,1);
    dup2(0,2);
    puts("Restored stdout");
    pagesize = sysconf(_SC_PAGE_SIZE);

    void* jmpAddr = (void*) (game_start + JUMP_HOOK_OFF);
    createTampolineHook(jmpAddr, hookJumping, jmp_gateway, 14);

    return NULL;
}


void __attribute__ ((constructor)) initLibrary(void) {
    pthread_t thread;
    pthread_create(&thread, NULL, threadMain, NULL);
}

```
The code above gets compiled into an shared object, which is then `LD_PRELOAD`ed (ld.so(8)) into the game. With that the `initLibrary` function gets called, because it has the `constructor` attribute. This function then creates a new thread, so the normal game code can continue. In the thread we call  `dl_iterate_phdr` (dl_iterate_phdr(3)) which is a very useful function. It registers a callback function, that is then called for each shared library loaded. This includes the `GameAssembly.so` binary. (We need to do this in a loop because `GameAssembly.so` is not loaded via ldd and because of that it can take a bit until we get the start address).
In the end the hole point of this is to set `game_start` to the start address of `GameAssembly.so`. After this is done we reopen `stdout` and `stderr` using two `dup2` calls. We do this because the main game binary closes these and this would block us from debugging. And then finally we create the hook.
The hooking method I used, is not that nice, but it works.
It uses a gateway looking like this:
```asm
gateway:
  pop rax
  call hook
  [in tobehooked overwritten code here]
  push rax
  mov rax, back
  jmp rax
```
The function to be hooked gets changed to this:
```
tobehooked:
  push rax
  mov rax, gateway
  jmp rax
back:
  pop rax
  ...
```

If we now lunch the game `LD_PRELOAD="inj.so" ./Maze_v2.x86_64` we get
```
inside hook
inside hook
inside hook
inside hook
inside hook
inside hook
inside hook
inside hook
inside hook
inside hook
...
```
That means it actually works. Now we get to the real injection.

```c
void hookJumping(Lightbug_CharacterControllerPro_Implementation_NormalMovement_o* this) {
  SAVE_ALL; // just to be sure we don't break anything
  __asm("mov    %rdi,-0x8(%rbp)");   // the from us compile C acts on
                                     // `-0x8(%rbp)` but the pointer
                                     // is stored in `%rdi`
  this->notGroundedJumpsLeft = 0x1337;
  this->planarMovementParameters->speed = 12; // This is the max the  
                                              // server tollerates
  RESTORE_ALL;
}
```
We are now really fast compared to before. And we can actually do double/tripple/quadruple.. jumps. It is almost like we could fly.
And the race is also easily done.
![](https://raw.githubusercontent.com/Nayos1337/cscg2020/master/game/maze/maze_runner/flag2.png)
