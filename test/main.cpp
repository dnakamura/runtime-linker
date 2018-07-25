#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include "objectdir.h"
#include <objfcn.h>
#include <stdio.h>

static const char *GetObjectName(const char *object){
    //TODO should add checks  for buffer overflow
    constexpr size_t BUFFER_SZ = 256;
    static char buffer[BUFFER_SZ] = {0};
    static char *buff_ptr = nullptr;

    if(buffer[0] == 0){
        strcpy(buffer, ObjectDir);
        buff_ptr = buffer + strlen(buffer);
    }
    strcpy(buff_ptr, object);
    buffer[BUFFER_SZ - 1] = 0;
    return buffer;
}

int main(int argc, char **argv){
    //void *dll = dlopen("./Object.o", RTLD_NOW);
    //printf("dlopen = %p\n", dll);
    ObjHandle  handle = objopen(GetObjectName("Object.c.o"), 0);
    printf("Handle = %p\n", handle);
    if(handle == NULL) return 1;

    void * foo =  objsym(handle, "foo");
    printf("foo=%p\n", foo);
    if( NULL != foo){
        int x = reinterpret_cast<int (*)()>(foo)();
        printf("foo() = %d\n", x);
    }

    void *bar = objsym(handle, "bar");
    printf("bar = %p\n", bar);
    if(NULL != bar){
        //puts("test");
        reinterpret_cast<void (*)(const char *)>(bar)("Hello World, from bar()");
        //puts("bye");
    }
    return 0;  
}