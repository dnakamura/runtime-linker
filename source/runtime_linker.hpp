#ifndef RUNTIME_LINKER_HPP
#define RUNTIME_LINKER_HPP

#include <elf.h>
#include <map>
#include <memory>
#include <utility>
#include <vector>

/* internal header */

typedef std::map<std::string, void *> SymTable;
typedef std::pair<void *, size_t> Mapping;


struct Object {
  Elf64_Ehdr header;
  FILE *file;
  Elf64_Shdr shstrtab;

  void *shstrs;
  size_t shstrs_size;
  // std::map<int, std::string> shstrs;
  std::map<int, void *> sections;
  SymTable symbols;
  std::vector<void *> symbolVector;

  Object();
  ~Object();
};


//Information used while loading an object, but discarded afterward
struct ObjectLoadData{
    std::unique_ptr<Object> object; //< The object to return, assuming everything works out
    FILE *f;

    inline ObjectLoadData();
    inline ~ObjectLoadData();
};

ObjectLoadData::ObjectLoadData():
    f(NULL){}

ObjectLoadData::~ObjectLoadData() {
    if(NULL != f){
        fclose(f);
    }
}

template<class T>
struct MallocDeleter {
    constexpr MallocDeleter() {}

    void operator()(T* ptr){
        free(ptr);
    }

};


// like a std::unique_ptr but for memory create with malloc()
template<class T>
using cunique_ptr = std::unique_ptr<T, MallocDeleter<T> >;

extern SymTable globalSymbols;
#endif
