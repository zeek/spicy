// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include "hilti/rt/global-state.h"

#include <hilti/rt/configuration.h>
#include <hilti/rt/context.h>
#include <hilti/rt/logging.h>

using namespace hilti::rt;
using namespace hilti::rt::detail;

// Not memory-managed through smart pointer, need to control when we release
// it.
GlobalState* detail::__global_state = nullptr;

GlobalState::GlobalState()
    : share_st([]() {
          aco_thread_init(nullptr);

          return std::unique_ptr<aco_share_stack_t, void (*)(aco_share_stack_t*)>(aco_share_stack_new(Fiber::StackSize),
                                                                                  [](aco_share_stack_t* ss) {
                                                                                      aco_share_stack_destroy(ss);
                                                                                  });
      }()),
      main_co([]() {
          return std::unique_ptr<aco_t, void (*)(aco_t*)>(aco_create(nullptr, nullptr, 0, nullptr, nullptr),
                                                          [](aco_t* co) {
                                                              aco_destroy(co);
                                                              aco_gtls_co = nullptr;
                                                          });
      }()) {}

GlobalState* detail::createGlobalState() {
    __global_state = new GlobalState(); // NOLINT (cppcoreguidelines-owning-memory)
    return __global_state;
}

GlobalState::~GlobalState() { HILTI_RT_DEBUG("libhilti", "destroying global state"); }
