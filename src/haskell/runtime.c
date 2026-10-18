// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#define _GNU_SOURCE
#include <Rts.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>

static void runtime_defaults(void)
{
    // The embedding node owns its signals. Do not parse GHCRTS or node argv.
    RtsFlags.MiscFlags.install_signal_handlers = false;
}

static void initialize_runtime(void)
{
    // RTS workers outlive a libconsensus consumer. Keep their code and its
    // transitive runtime dependencies mapped even after that consumer dlcloses.
    Dl_info self;
    if (!dladdr((void*)&initialize_runtime, &self) ||
        !dlopen(self.dli_fname, RTLD_NOW | RTLD_NODELETE)) abort();
    int argc = 1;
    char name[] = "elements-haskell";
    char* argv[] = {name, NULL};
    char** args = argv;
    RtsConfig config = defaultRtsConfig;
    config.rts_opts_enabled = RtsOptsIgnoreAll;
    config.rts_opts_suggestions = false;
    config.defaultsHook = runtime_defaults;
    hs_init_ghc(&argc, &args, config);
}

// Shared by every C++ adapter instance, including dynamically loaded consumers.
void elements_hs_runtime_init(void)
{
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    if (pthread_once(&once, initialize_runtime) != 0) abort();
}
