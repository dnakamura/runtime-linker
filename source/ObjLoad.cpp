#include <elf.h>
#include <objfcn.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <map>
#include <string>
#include <vector>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <memory>

#include "spdlog/spdlog.h"
//#include "spdlog/sinks/stdout_color_sinks.h"

#include "runtime_linker.hpp"
//std::shared_ptr<spdlog::logger> _log;
auto _log = spdlog::stdout_color_mt("objload");


void *codeCache = NULL;
void *codeCachePtr = NULL;
void *dataCache = NULL;
void *dataCachePtr = NULL;

SymTable globalSymbols;

constexpr size_t CACHE_SIZE = 8 * 1024 * 1024;
static void *ReadSection(ObjHandle obj, Elf64_Shdr *section);



Object::Object() { shstrs = NULL; }
Object::~Object() {
  if (shstrs != NULL) free(shstrs);
  // for(auto mapping: sections)
}


// TODO we are currently assuming 64bit
/*
static void* alloc_exec_mem(size_t sz) {
    mmap(NULL, sz, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PROT)
}*/

int ReadStringTable(ObjHandle obj, const Elf64_Shdr *header) {
  if (header->sh_type != SHT_STRTAB) {
    _log->error("Section is not a string table");
    return -1;
  }

  void *shstrs = malloc(header->sh_size);
  if (!shstrs) {
    _log->error("failed to allocate memory");
    return -1;
  }
  auto oldpos = ftell(obj->file);
  int rc = 0;
  if (fseek(obj->file, header->sh_offset, SEEK_SET)) {
    _log->error("Failed to seek file");
    free(shstrs);
    rc = -1;
    goto end;
  }
  if (1 != fread(shstrs, header->sh_size, 1, obj->file)) {
    _log->error("failed to read strings");
    rc = -1;
    free(shstrs);
    goto end;
  }

  obj->shstrs = shstrs;
  obj->shstrs_size = header->sh_size;

end:
  fseek(obj->file, oldpos, SEEK_SET);
  return rc;
}

int ProcessProgBits(ObjHandle obj, int sect_num, const Elf64_Shdr *hdr) {
  if (!hdr->sh_flags & SHF_ALLOC) {
    _log->debug("Skipping section {} since it is not allocated", sect_num);
    return 0;
  }
  if (!hdr->sh_flags & SHF_INFO_LINK) {
    // DBG_LOG("Skipping section %d since it is an info section", sect_num);
    return 0;
  }

  if (hdr->sh_name >= obj->shstrs_size) {
    _log->error("Name for section {}({}) is out of bounds", sect_num, hdr->sh_name);
    return -1;
  }

  // check for bogus sections
  std::string sect_name(static_cast<const char *>(obj->shstrs) + hdr->sh_name);

  if (sect_name != ".text"
      //&& sect_name != ".data"
  ) {
    _log->info("Skipping unknown PROGBITS section {}", sect_name.c_str());
    return 0;
  }
  _log->debug("Loading section {}", sect_num);
  char **buffer_base = NULL;
  char **buffer = NULL;
  if (hdr->sh_flags & SHF_EXECINSTR) {
    buffer_base = reinterpret_cast<char **>(&codeCache);
    buffer = reinterpret_cast<char **>(&codeCachePtr);
  } else {
    buffer_base = reinterpret_cast<char **>(&dataCache);
    buffer = reinterpret_cast<char **>(&dataCachePtr);
  }

  if ((*buffer + hdr->sh_size) > (*buffer_base + BUFSIZ)) {
    _log->error("Error wont fit in cache");
    return -1;
  }

  if (fseek(obj->file, hdr->sh_offset, SEEK_SET)) {
    _log->error("Failed to seek");
    return -1;
  }
  if (1 != fread(*buffer, hdr->sh_size, 1, obj->file)) {
    _log->error("Failed to read section");
    return -1;
  }
  obj->sections[sect_num] = *buffer;

  *buffer += hdr->sh_size;

  return 0;
}

static void *ReadSection(ObjHandle obj, Elf64_Shdr *header) {
  /*if(header->sh_type != SHT_STRTAB){
      ERR_LOG("Section is not a string table");
      return -1;
  }*/

  void *data = malloc(header->sh_size);
  if (!data) {
    _log->error("failed to allocate memory");
    return NULL;
  }

  auto oldpos = ftell(obj->file);

  if (fseek(obj->file, header->sh_offset, SEEK_SET)) {
    _log->error("Failed to seek file");
    free(data);
    data = NULL;
    goto end;
  }

  if (1 != fread(data, header->sh_size, 1, obj->file)) {
    _log->error("failed to read section data");
    free(data);
    data = NULL;
    goto end;
  }

end:
  fseek(obj->file, oldpos, SEEK_SET);
  return data;
}

static int ProcessReloc(ObjHandle obj, Elf64_Rel *relocs, size_t sz,
                        uintptr_t sectLoadAddr) {
  return -1;
}

static int ProcessReloca(ObjHandle obj, Elf64_Rela *relocs, size_t sz,
                         uintptr_t sectLoadAddr) {
  const size_t count = sz / sizeof(Elf64_Rela);

  // TODO check for extra bytes
  for (size_t i = 0; i < count; ++i) {
    Elf64_Rela &reloc = relocs[i];
    int symIdx = ELF64_R_SYM(reloc.r_info);
    void *symAddr = obj->symbolVector[symIdx];
    uintptr_t patchPoint = sectLoadAddr + reloc.r_offset;

    if (symAddr == 0) {
      _log->error("Unexpected null symbol");
      return -1;
    }
    uintptr_t relocValue =
        reinterpret_cast<uintptr_t>(symAddr) + reloc.r_addend;

    switch (ELF64_R_TYPE(reloc.r_info)) {
      case R_X86_64_PC32:
      case R_X86_64_PLT32:  // Im pretty sure for object files this is the same
                            // as above
      {
        // TODO need to check for overflow
        *reinterpret_cast<uint32_t *>(patchPoint) =
            static_cast<uint32_t>(relocValue - patchPoint);
      } break;
      default:
        _log->error("Unsupported relocation type {}", ELF64_R_TYPE(reloc.r_info));
        return -1;
    }
  }
  return 0;
}

static int ProcessRelocs(ObjHandle obj, Elf64_Shdr *reloc) {
  // NOTE: sh_link is pointer to symbol table
  // We are dumb and are assuming only 1 symbol table
  auto it = obj->sections.find(reloc->sh_info);
  if (obj->sections.end() == it) {
    _log->info("skipping relocations for section {}", reloc->sh_info);
    // We didnt process this section, so ignore relocation
    return 0;
  }
  uintptr_t sectionLoadAddr = reinterpret_cast<uintptr_t>(it->second);
  void *sectionData = ReadSection(obj, reloc);
  if (!sectionData) {
    _log->error("Failed to read section data");
    return -1;
  }
  int rc = 0;
  switch (reloc->sh_type) {
    case SHT_REL:
      rc = ProcessReloc(obj, static_cast<Elf64_Rel *>(sectionData),
                        reloc->sh_size, sectionLoadAddr);
      break;
    case SHT_RELA:
      rc = ProcessReloca(obj, static_cast<Elf64_Rela *>(sectionData),
                         reloc->sh_size, sectionLoadAddr);
      break;
    default:
      _log->error("BAD section type");
      rc = -1;
  }
  free(sectionData);
  return rc;
}

static int ProcessSymbolTable(ObjHandle obj, Elf64_Shdr *symSection,
                       Elf64_Shdr *strInfo) {
  cunique_ptr<char> stringTable(static_cast<char *>(ReadSection(obj, strInfo)));
  if (!stringTable) {
    _log->error("Failed to read string table");
    return -1;
  }
  int rc = 0;
  Elf64_Sym *symtable = static_cast<Elf64_Sym *>(ReadSection(obj, symSection));
  const int num_symbols = symSection->sh_size / sizeof(Elf64_Sym);
  if (!symtable) {
    _log->error("Failed to read the symbol table");
    rc = -1;
    goto end;
  }

  if (symSection->sh_size % sizeof(Elf64_Sym) != 0) {
    _log->error("Section size error");
    rc = -1;
    goto end;
  }
  // TODO assert that the symbol vector has 0 elements
  for (int i = 0; i < num_symbols; ++i) {
    const Elf64_Sym &symbol = symtable[i];

    if (symbol.st_shndx == SHN_ABS || i == 0) {
      obj->symbolVector.push_back(NULL);
      continue;  // we probably dont need any of these symbols
                 // Plus it would be a bunch of work to even resolve them
    }

    if (symbol.st_shndx == SHN_UNDEF) {
      // we need to do a lookup of this symbol
      const char *symbolName = stringTable.get() + symbol.st_name;
      void *symbolAddr = objsym(NULL, symbolName);
      if (symbolAddr == NULL) {
        _log->info("Couldnt find symbol {} in objects, looking in native tables",
                symbolName);
        symbolAddr = dlsym(RTLD_DEFAULT, symbolName);
      }
      if (NULL == symbolAddr) {
        _log->error("Failed to resolve symbol {}", symbolName);
        // screw it, lets just pretend everything is fine and symbol address is
        // NULL
        symbolAddr = NULL;
      }
      obj->symbolVector.push_back(symbolAddr);
      continue;

    } else {
      std::string symbolName(stringTable.get() + symbol.st_name);
      //_log->debug("Adding symbol {}", stringTable + symbol.st_name);

      auto sectionLoad = obj->sections.find(symbol.st_shndx);
      if (sectionLoad == obj->sections.end()) {
        // ERR_LOG("Bad section index %d", symbol.st_shndx);
        // we didnt load this section, so lets assume we dont need the symbol :P
        obj->symbolVector.push_back(NULL);
        continue;
      }
      void *const symbolAddr =
          static_cast<char *>(sectionLoad->second) + symbol.st_value;
      obj->symbols[symbolName] = symbolAddr;
      obj->symbolVector.push_back(symbolAddr);

      if (ELF64_ST_BIND(symbol.st_info) & STB_GLOBAL) {
        globalSymbols[symbolName] = symbolAddr;
      }
    }
  }

end:
  if (symtable != NULL) free(symtable);
  return rc;
}

ObjHandle LoadElf(const Elf64_Ehdr &header, FILE *f) {
  ObjHandle object = NULL;

  void *secthdrs = malloc(header.e_shentsize * header.e_shnum);
  if (!secthdrs) {
    _log->error("failed to allocate memory for section headers");
    return NULL;
  }

  // Start reading the program headers
  if (fseek(f, header.e_shoff, SEEK_SET)) {
    fprintf(stderr, "fseek failed\n");
    return NULL;
  }

  if (1 != fread(secthdrs, header.e_shentsize * header.e_shnum, 1, f)) {
    _log->error("Failed to read section headers");
    return NULL;
  }
  object = new Object();
  object->header = header;
  object->file = f;
  std::vector<int> RelocationSections;

  // get the shstrtab
  if (ReadStringTable(object, reinterpret_cast<Elf64_Shdr *>(
                                  static_cast<char *>(secthdrs) +
                                  (header.e_shstrndx * header.e_shentsize)))) {
    _log->error("FAILED reading SHSTRS");
    goto fail;
  }

  for (int i = 0; i < header.e_shnum; ++i) {
    Elf64_Shdr *shdr = reinterpret_cast<Elf64_Shdr *>(
        static_cast<char *>(secthdrs) + (i * header.e_shentsize));
    if(shdr->sh_flags && SHF_INFO_LINK){
        //DBG_LOG("Skipping section %d since it is an information section", i);
        continue;
    }
    switch (shdr->sh_type) {
      case SHT_PROGBITS:

        if (ProcessProgBits(object, i, shdr)) {
          _log->error("Failed to process progbits for section {}", i);
          goto fail;
        }
        break;
      case SHT_REL:
      case SHT_RELA:
        RelocationSections.push_back(i);
        break;
      case SHT_SYMTAB: {
        // TODO should be bounds checking this
        Elf64_Shdr *strTable = reinterpret_cast<Elf64_Shdr *>(
            static_cast<char *>(secthdrs) +
            (shdr->sh_link * header.e_shentsize));
        if (ProcessSymbolTable(object, shdr, strTable)) {
          _log->error("Failed to process symbol table");
          goto fail;
        }
      }

      case SHT_STRTAB:
        continue;
        // ERR_LOG("Unhandled shdr type %d", shdr->sh_type);
        // goto fail;
      // Ignored headers
      case SHT_NULL:
      case SHT_NOTE:
      case SHT_NOBITS:  // TODO we may need to handle this
        continue;

      default:
        _log->error("Unknown shdr type {}, for idx {}", shdr->sh_type, i);
        goto fail;
    }
  }
  for (auto it = RelocationSections.begin(); it != RelocationSections.end();
       ++it) {
    Elf64_Shdr *shdr = reinterpret_cast<Elf64_Shdr *>(
        static_cast<char *>(secthdrs) + (*it * header.e_shentsize));
    _log->debug("Processing relocation section {}", *it);
    if (ProcessRelocs(object, shdr)) {
      _log->error("Failed to process relocation section {}", *it);
      goto fail;
    }
  }
end:
  free(secthdrs);
  return object;

fail:
  delete object;
  free(secthdrs);
  return NULL;
}

static int InitCache() {
  if (codeCache == NULL) {
    _log->info("Initializing code cache");
    codeCache = mmap(NULL, CACHE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (codeCache == MAP_FAILED) {
      // perror("C")
      perror("Code cache map failed");

      return -1;
    }
    codeCachePtr = codeCache;
  }
  if (dataCache == NULL) {
    dataCache = mmap(NULL, CACHE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (dataCache == MAP_FAILED) {
      perror("Data cache map failed");
      return -1;
    }
    dataCachePtr = dataCache;
  }
  return 0;
}

ObjHandle objopen(const char *file, int flags) {
  if (InitCache()) {
    return NULL;
  }
  FILE *f = fopen(file, "rb");
  ObjHandle handle = NULL;
  if (f == NULL) {
    _log->error("Failed to open file '{}'", file);
    return NULL;
  }

  Elf64_Ehdr header;
  memset(&header, 0, sizeof(header));
  if (1 != fread(&header, sizeof(header), 1, f)) {
    _log->error("Failed to read header");
    goto end;
  }

#define CHECK_IDENT(n) (header.e_ident[EI_MAG##n] == ELFMAG##n)
  if (!(CHECK_IDENT(0) && CHECK_IDENT(1) && CHECK_IDENT(2))) {
    _log->error("Bad magic {} {} {}", header.e_ident[0], header.e_ident[1],
            header.e_ident[2]);
    goto end;
  }
#undef CHECK_IDENT

  if (header.e_type != ET_REL) {
    _log->error("Bad Elf Type {}", header.e_type);
    goto end;
  }
  handle = LoadElf(header, f);
end:
  if (handle == NULL) fclose(f);
  return handle;
}

void *objsym(ObjHandle handle, const char *sym) {
  std::string symbolName(sym);
  _log->debug("Looking up symbol {}", sym);
  if (NULL == handle) {
    auto it = globalSymbols.find(symbolName);
    if (globalSymbols.end() == it) {
      return NULL;
    } else {
      return it->second;
    }
  } else {
    auto it = handle->symbols.find(symbolName);
    if (handle->symbols.end() == it) {
      _log->debug("Symbol not found in table");
      return NULL;
    } else {
      return it->second;
    }
  }
}
