#ifndef OBJLOAD_LOGGING_HPP
#define OBJLOAD_LOGGING_HPP

#define SPDLOG_DEBUG_ON
#define SPDLOG_TRACE_ON

#ifdef DEFINE_LOGGERS
#define LOGGER_DEF
#else
#define LOGGER_DEF extern
#endif

#include "spdlog/logger.h"

namespace objload {
typedef std::shared_ptr<spdlog::logger> log_ptr;

LOGGER_DEF log_ptr _log;  // deprecated

namespace log {
LOGGER_DEF log_ptr progbits;
LOGGER_DEF log_ptr reloc;
LOGGER_DEF log_ptr symtab;
LOGGER_DEF log_ptr objsym;
}
}

#endif
