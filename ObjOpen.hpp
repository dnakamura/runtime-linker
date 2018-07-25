#ifndef OBJOPEN_HPP
#define OBJOPEN_HPP

struct Object;
typedef Object* ObjHandle;

// Note: flags is ignored at the moment.
// only specified so signature is compatable with dlopen

ObjHandle objopen(const char *file, int flags);

void *objsym(ObjHandle handle, const char *sym);

#endif