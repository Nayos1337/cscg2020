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


void hookJumping(Lightbug_CharacterControllerPro_Implementation_NormalMovement_o* this) {
  SAVE_ALL; // just to be sure we don't break anything
  __asm("mov    %rdi,-0x8(%rbp)");   // the from us compile C acts on
                                     // `-   0x8(%rbp)` but the pointer
                                     // is stored in `%rdi`
  this->notGroundedJumpsLeft = 0x1337;
  this->planarMovementParameters->speed = 12;
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
