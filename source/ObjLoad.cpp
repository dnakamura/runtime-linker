#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <objfcn.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "logging.hpp"
#include "runtime_linker.hpp"
using namespace objload;
// std::shared_ptr<spdlog::logger> _log;

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
  log::progbits->trace("Processing progbits section {}", sect_num);
  if (!hdr->sh_flags & SHF_ALLOC) {
    log::progbits->debug("Skipping section {} since it is not allocated",
                         sect_num);
    return 0;
  }
  if (!hdr->sh_flags & SHF_INFO_LINK) {
    log::progbits->debug("Skipping section {} since it is an info section",
                         sect_num);
    return 0;
  }

  if (hdr->sh_name >= obj->shstrs_size) {
    log::progbits->error("Name for section {}({}) is out of bounds", sect_num,
                         hdr->sh_name);
    return -1;
  }

  // check for bogus sections
  std::string sect_name(static_cast<const char *>(obj->shstrs) + hdr->sh_name);

  if (sect_name != ".text"
      //&& sect_name != ".data"
      ) {
    log::progbits->info("Skipping unknown PROGBITS section {}",
                        sect_name.c_str());
    return 0;
  }
  log::progbits->debug("Loading section {}", sect_num);
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
    log::progbits->error("Error wont fit in cache");
    return -1;
  }

  if (fseek(obj->file, hdr->sh_offset, SEEK_SET)) {
    log::progbits->error("Failed to seek");
    return -1;
  }
  if (1 != fread(*buffer, hdr->sh_size, 1, obj->file)) {
    log::progbits->error("Failed to read section");
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
      log::reloc->error("Unexpected null symbol");
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
        }
        break;
      default:
        log::reloc->error("Unsupported relocation type {}",
                          ELF64_R_TYPE(reloc.r_info));
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
    log::reloc->info("skipping relocations for section {}", reloc->sh_info);
    // We didnt process this section, so ignore relocation
    return 0;
  }
  uintptr_t sectionLoadAddr = reinterpret_cast<uintptr_t>(it->second);
  void *sectionData = ReadSection(obj, reloc);
  if (!sectionData) {
    log::reloc->error("Failed to read section data");
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
      log::reloc->error("BAD section type");
      rc = -1;
  }
  free(sectionData);
  return rc;
}

static int ProcessSymbolTable(ObjHandle obj, Elf64_Shdr *symSection,
                              Elf64_Shdr *strInfo) {
  cunique_ptr<char> stringTable(static_cast<char *>(ReadSection(obj, strInfo)));
  if (!stringTable) {
    log::symtab->error("Failed to read string table");
    return -1;
  }
  int rc = 0;
  Elf64_Sym *symtable = static_cast<Elf64_Sym *>(ReadSection(obj, symSection));
  const int num_symbols = symSection->sh_size / sizeof(Elf64_Sym);
  if (!symtable) {
    log::symtab->error("Failed to read the symbol table");
    rc = -1;
    goto end;
  }

  if (symSection->sh_size % sizeof(Elf64_Sym) != 0) {
    log::symtab->error("Section size error");
    rc = -1;
    goto end;
  }
  // TODO assert that the symbol vector has 0 elements
  log::symtab->debug("Processing {} symbols from symbol table", num_symbols);
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
        log::symtab->info(
            "Couldnt find symbol {} in objects, looking in native tables",
            symbolName);
        symbolAddr = dlsym(RTLD_DEFAULT, symbolName);
      }
      if (NULL == symbolAddr) {
        log::symtab->error("Failed to resolve symbol {}", symbolName);
        // screw it, lets just pretend everything is fine and symbol address is
        // NULL
        symbolAddr = NULL;
      }
      obj->symbolVector.push_back(symbolAddr);
      continue;

    } else {
      std::string symbolName(stringTable.get() + symbol.st_name);

      auto sectionLoad = obj->sections.find(symbol.st_shndx);
      if (sectionLoad == obj->sections.end()) {
        log::symtab->error("Bad section index {} for symbol {}",
                           symbol.st_shndx, symbolName);
        // we didnt load this section, so lets assume we dont need the symbol :P
        obj->symbolVector.push_back(NULL);
        continue;
      }

      void *const symbolAddr =
          static_cast<char *>(sectionLoad->second) + symbol.st_value;
      log::symtab->debug("Loaded symbol {} at addr {}", symbolName, symbolAddr);
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

int LoadElf(const Elf64_Ehdr &header, ObjectLoadData *loadData) {
  void *secthdrs = malloc(header.e_shentsize * header.e_shnum);
  if (!secthdrs) {
    _log->error("failed to allocate memory for section headers");
    return -1;
  }

  // Start reading the program headers
  if (fseek(loadData->f, header.e_shoff, SEEK_SET)) {
    fprintf(stderr, "fseek failed\n");
    return -1;
  }

  if (1 !=
      fread(secthdrs, header.e_shentsize * header.e_shnum, 1, loadData->f)) {
    _log->error("Failed to read section headers");
    return -1;
  }
  loadData->object = std::make_unique<Object>();
  loadData->object->header = header;
  loadData->object->file = loadData->f;  // TODO we should get rid of this
  std::vector<int> RelocationSections;

  // get the shstrtab
  if (ReadStringTable(loadData->object.get(),
                      reinterpret_cast<Elf64_Shdr *>(
                          static_cast<char *>(secthdrs) +
                          (header.e_shstrndx * header.e_shentsize)))) {
    _log->error("FAILED reading SHSTRS");
    return -1;
  }

  for (int i = 0; i < header.e_shnum; ++i) {
    Elf64_Shdr *shdr = reinterpret_cast<Elf64_Shdr *>(
        static_cast<char *>(secthdrs) + (i * header.e_shentsize));
    /*if(shdr->sh_flags && SHF_INFO_LINK){

        _log->info("Skipping section {} since it is an information section", i);
        continue;
    }*/
    switch (shdr->sh_type) {
      case SHT_PROGBITS:

        if (ProcessProgBits(loadData->object.get(), i, shdr)) {
          _log->error("Failed to process progbits for section {}", i);
          return -1;
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
        if (ProcessSymbolTable(loadData->object.get(), shdr, strTable)) {
          _log->error("Failed to process symbol table");
          return -1;
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
        return -1;
    }
  }
  for (auto it = RelocationSections.begin(); it != RelocationSections.end();
       ++it) {
    Elf64_Shdr *shdr = reinterpret_cast<Elf64_Shdr *>(
        static_cast<char *>(secthdrs) + (*it * header.e_shentsize));
    _log->debug("Processing relocation section {}", *it);
    if (ProcessRelocs(loadData->object.get(), shdr)) {
      _log->error("Failed to process relocation section {}", *it);
      return -1;
    }
  }
end:
  free(secthdrs);
  return 0;
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
    return nullptr;
  }
  std::unique_ptr<ObjectLoadData> loadData = std::make_unique<ObjectLoadData>();

  FILE *f = fopen(file, "rb");
  if (nullptr == f) {
    _log->error("Failed to open file '{}'", file);
    return nullptr;
  }
  loadData->f = f;

  Elf64_Ehdr header;
  memset(&header, 0, sizeof(header));
  if (1 != fread(&header, sizeof(header), 1, f)) {
    _log->error("Failed to read header");
    return nullptr;
  }

#define CHECK_IDENT(n) (header.e_ident[EI_MAG##n] == ELFMAG##n)
  if (!(CHECK_IDENT(0) && CHECK_IDENT(1) && CHECK_IDENT(2))) {
    _log->error("Bad magic {} {} {}", header.e_ident[0], header.e_ident[1],
                header.e_ident[2]);
    return nullptr;
  }
#undef CHECK_IDENT

  if (header.e_type != ET_REL) {
    _log->error("Bad Elf Type {}", header.e_type);
    return nullptr;
  }
  int rc = LoadElf(header, loadData.get());
  if (0 == rc) {
    return std::move(loadData->object.release());
  }
  return nullptr;
}
