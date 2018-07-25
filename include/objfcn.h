#ifndef OBJFCN_H
#define OBJFCN_H

struct Object;
typedef struct Object *ObjHandle;

#ifdef __cplusplus
extern "C" {
#endif

/* Note: flags is ignored at the moment.
 only specified so signature is compatable with dlopen*/
ObjHandle objopen(const char *file, int flags);

void *objsym(ObjHandle handle, const char *sym);

#ifdef __cplusplus
}
#endif

#endif
