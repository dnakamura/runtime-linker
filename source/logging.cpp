#define DEFINE_LOGGERS
#include "logging.hpp"
#include <spdlog/sinks/sink.h>
#include <spdlog/sinks/ansicolor_sink.h>
#include <memory>
using namespace objload;

//ansicolor_stderr_sink_mt
namespace {
    std::shared_ptr<spdlog::sinks::sink> console_sink;
}

static void initializeLogging() __attribute__((constructor));

static void initializeLogger(log_ptr& logger, const char *name){
    logger = std::make_shared<spdlog::logger>(name, console_sink);
    logger->set_level(spdlog::level::trace);
}

static void initializeLogging() { 
    console_sink = std::make_shared<spdlog::sinks::ansicolor_stderr_sink_mt>();

    initializeLogger(_log, "objload"); //TODO deprecated
    initializeLogger(log::symtab, "symtab");
    initializeLogger(log::progbits, "progbits");
    initializeLogger(log::reloc, "reloc");
    initializeLogger(log::objsym, "objsym");
}
