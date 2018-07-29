#include "logging.hpp"
#include "objfcn.h"
#include "runtime_linker.hpp"

using namespace objload;

void *objsym(ObjHandle handle, const char *sym) {
  std::string symbolName(sym);
  log::objsym->debug("Looking up symbol {}", sym);
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
      log::objsym->debug("Symbol not found in table");
      return NULL;
    } else {
      return it->second;
    }
  }
}
