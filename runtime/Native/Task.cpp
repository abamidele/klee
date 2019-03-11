/*
 * Copyright (c) 2019 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "Task.h"

Task *gCurrent = nullptr;

extern "C" {

LiftedFunc *__kleemill_get_lifted_function(Memory *, addr_t pc);

void __kleemill_log_state(State *state);

inline static void LogGPR64(char *&os, addr_t val, const char *reg_name){
  os = &os[sprintf(os, "  %s %016llx\n", reg_name, val)];
}

Memory * __remill_log_state(State *state, Memory *memory){
 /*
 char buff[512];
 auto os = &buff[0];
 LogGPR64(os, state->gpr.rip.aword, "RIP");
 LogGPR64(os, state->gpr.rsp.aword, "RSP");
 LogGPR64(os, state->gpr.rbp.aword, "RBP");
 LogGPR64(os, state->gpr.rax.aword, "RAX");
 LogGPR64(os, state->gpr.rbx.aword, "RBX");
 LogGPR64(os, state->gpr.rcx.aword, "RCX");
 LogGPR64(os, state->gpr.rdx.aword, "RDX");
 LogGPR64(os, state->gpr.rsi.aword, "RSI");
 LogGPR64(os, state->gpr.rdi.aword, "RDI");
 LogGPR64(os, state->gpr.r8.aword, "R8");
 LogGPR64(os, state->gpr.r9.aword, "R9");
 LogGPR64(os, state->gpr.r10.aword, "R10");
 LogGPR64(os, state->gpr.r11.aword, "R11");
 LogGPR64(os, state->gpr.r12.aword, "R12");
 LogGPR64(os, state->gpr.r13.aword, "R13");
 LogGPR64(os, state->gpr.r14.aword, "R14");
 LogGPR64(os, state->gpr.r15.aword, "R15");
 os[0] = '\n';
 os[1] = 0;
 puts(buff);
 */
 return memory;
}

Memory * __remill_function_call(State &state, addr_t pc, Memory *memory) {
  auto &task = reinterpret_cast<Task &>(state);
  if (CanContinue(task.location)) {
    task.time_stamp_counter += 1000;
    task.location = kTaskStoppedAtCallTarget;
    task.status = kTaskStatusRunnable;
    task.last_pc = pc;
    task.continuation = __kleemill_get_lifted_function(memory, pc);
    return task.continuation(state, task.last_pc, memory);
  }
  return memory;
}

Memory * __remill_function_return(State &state, addr_t pc, Memory *memory) {

  auto &task = reinterpret_cast<Task &>(state);
  if (CanContinue(task.location)) {
    task.time_stamp_counter += 1000;
    task.location = kTaskStoppedAtReturnTarget;
    task.status = kTaskStatusRunnable;
    task.last_pc = pc;
    task.continuation = __kleemill_get_lifted_function(memory, pc);
    return task.continuation(state, task.last_pc, memory);
  }
  return memory;
}

Memory * __remill_jump(State &state, addr_t pc, Memory *memory) {

  auto &task = reinterpret_cast<Task &>(state);
  if (CanContinue(task.location)) {
    task.time_stamp_counter += 1000;
    task.location = kTaskStoppedAtJumpTarget;
    task.status = kTaskStatusRunnable;
    task.last_pc = pc;
    task.continuation = __kleemill_get_lifted_function(memory, pc);
    return task.continuation(state, task.last_pc, memory);
  }
  return memory;
}

Memory *__kleemill_at_error(State &state, addr_t ret_addr, Memory *memory) {

  auto task = reinterpret_cast<Task &>(state);
  task.status = kTaskStatusError;
  task.location = kTaskStoppedAtError;
  puts("Error; unwinding\n");
  return memory;
}

Memory *__kleemill_at_unhandled_hypercall(State &state, addr_t ret_addr,
                                          Memory *memory) {

  auto task = reinterpret_cast<Task &>(state);
  task.status = kTaskStatusError;
  task.location = kTaskStoppedAtError;
  puts("Unhandled hypercall; unwinding\n");
  return memory;
}

Memory * __remill_missing_block(State &state, addr_t pc, Memory *memory) {

  auto &task = reinterpret_cast<Task &>(state);
  puts("MISSING BLOCK");
  if (CanContinue(task.location)) {
    task.status = kTaskStatusError;
    task.location = kTaskStoppedAtError;
    task.continuation = __kleemill_at_error;
    task.last_pc = pc;
    //return task.continuation(state, task.last_pc, memory);
  }
  return memory;
}

Memory * __remill_error(State &state, addr_t pc, Memory *memory) {

  auto &task = reinterpret_cast<Task &>(state);
  if (CanContinue(task.location)) {
    task.status = kTaskStatusError;
    task.location = kTaskStoppedAtError;
    task.continuation = __kleemill_at_error;
    task.last_pc = pc;
    //return task.continuation(state, task.last_pc, memory);
  }
  return memory;
}

uint8_t __remill_undefined_8(void) {
  return 0;
}

uint16_t __remill_undefined_16(void) {
  return 0;
}

uint32_t __remill_undefined_32(void) {
  return 0;
}

uint64_t __remill_undefined_64(void) {
  return 0;
}

float32_t __remill_undefined_f32(void) {
  return 0;
}

float64_t __remill_undefined_f64(void) {
  return 0;
}

Memory *__remill_barrier_load_load(Memory *memory) {
  gCurrent->time_stamp_counter += 200;
  return memory;
}

Memory *__remill_barrier_load_store(Memory *memory) {
  gCurrent->time_stamp_counter += 200;
  return memory;
}

Memory *__remill_barrier_store_load(Memory *memory) {
  gCurrent->time_stamp_counter += 200;
  return memory;
}

Memory *__remill_barrier_store_store(Memory *memory) {
  gCurrent->time_stamp_counter += 200;
  return memory;
}

Memory *__remill_atomic_begin(Memory *memory) {
  gCurrent->time_stamp_counter += 200;
  return memory;
}

Memory *__remill_atomic_end(Memory *memory) {
  gCurrent->time_stamp_counter += 200;
  return memory;
}

Memory *__remill_compare_exchange_memory_8(Memory *memory, addr_t addr,
                                           uint8_t &expected, uint8_t desired) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_8(memory, addr);
  if (current == expected) {
    memory = __remill_write_memory_8(memory, addr, desired);
  }
  expected = current;
  return memory;
}

Memory *__remill_compare_exchange_memory_16(Memory *memory, addr_t addr,
                                            uint16_t &expected,
                                            uint16_t desired) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_16(memory, addr);
  if (current == expected) {
    memory = __remill_write_memory_16(memory, addr, desired);
  }
  expected = current;
  return memory;
}

Memory *__remill_compare_exchange_memory_32(Memory *memory, addr_t addr,
                                            uint32_t &expected,
                                            uint32_t desired) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_32(memory, addr);
  if (current == expected) {
    memory = __remill_write_memory_32(memory, addr, desired);
  }
  expected = current;
  return memory;
}

Memory *__remill_compare_exchange_memory_64(Memory *memory, addr_t addr,
                                            uint64_t &expected,
                                            uint64_t desired) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_64(memory, addr);
  if (current == expected) {
    memory = __remill_write_memory_64(memory, addr, desired);
  }
  expected = current;
  return memory;
}

Memory *__remill_compare_exchange_memory_128(Memory *memory, addr_t addr,
                                             uint128_t &expected,
                                             uint128_t &desired) {
  gCurrent->time_stamp_counter += 400;
  const auto lo = __remill_read_memory_64(memory, addr);
  const auto hi = __remill_read_memory_64(memory, addr + 8);
  const auto current = static_cast<uint128_t>(lo)
      | (static_cast<uint128_t>(hi) << 64);
  if (current == expected) {
    memory = __remill_write_memory_64(memory, addr,
                                      static_cast<uint64_t>(desired));
    memory = __remill_write_memory_64(memory, addr + 8,
                                      static_cast<uint64_t>(desired >> 64));
  }
  expected = current;
  return memory;
}

Memory *__remill_fetch_and_add_8(Memory *memory, addr_t addr, uint8_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_8(memory, addr);
  const uint8_t next = current + value;
  memory = __remill_write_memory_8(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_add_16(Memory *memory, addr_t addr,
                                  uint16_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_16(memory, addr);
  const uint16_t next = current + value;
  memory = __remill_write_memory_16(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_add_32(Memory *memory, addr_t addr,
                                  uint32_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_32(memory, addr);
  const uint32_t next = current + value;
  memory = __remill_write_memory_32(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_add_64(Memory *memory, addr_t addr,
                                  uint64_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_64(memory, addr);
  const uint64_t next = current + value;
  memory = __remill_write_memory_64(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_sub_8(Memory *memory, addr_t addr, uint8_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_8(memory, addr);
  const uint8_t next = current - value;
  memory = __remill_write_memory_8(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_sub_16(Memory *memory, addr_t addr,
                                  uint16_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_16(memory, addr);
  const uint16_t next = current - value;
  memory = __remill_write_memory_16(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_sub_32(Memory *memory, addr_t addr,
                                  uint32_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_32(memory, addr);
  const uint32_t next = current - value;
  memory = __remill_write_memory_32(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_sub_64(Memory *memory, addr_t addr,
                                  uint64_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_64(memory, addr);
  const uint64_t next = current - value;
  memory = __remill_write_memory_64(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_and_8(Memory *memory, addr_t addr, uint8_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_8(memory, addr);
  const uint8_t next = current & value;
  memory = __remill_write_memory_8(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_and_16(Memory *memory, addr_t addr,
                                  uint16_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_16(memory, addr);
  const uint16_t next = current & value;
  memory = __remill_write_memory_16(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_and_32(Memory *memory, addr_t addr,
                                  uint32_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_32(memory, addr);
  const uint32_t next = current & value;
  memory = __remill_write_memory_32(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_and_64(Memory *memory, addr_t addr,
                                  uint64_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_64(memory, addr);
  const uint64_t next = current & value;
  memory = __remill_write_memory_64(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_or_8(Memory *memory, addr_t addr, uint8_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_8(memory, addr);
  const uint8_t next = current | value;
  memory = __remill_write_memory_8(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_or_16(Memory *memory, addr_t addr, uint16_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_16(memory, addr);
  const uint16_t next = current | value;
  memory = __remill_write_memory_16(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_or_32(Memory *memory, addr_t addr, uint32_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_32(memory, addr);
  const uint32_t next = current | value;
  memory = __remill_write_memory_32(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_or_64(Memory *memory, addr_t addr, uint64_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_64(memory, addr);
  const uint64_t next = current | value;
  memory = __remill_write_memory_64(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_xor_8(Memory *memory, addr_t addr, uint8_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_8(memory, addr);
  const uint8_t next = current ^ value;
  memory = __remill_write_memory_8(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_xor_16(Memory *memory, addr_t addr,
                                  uint16_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_16(memory, addr);
  const uint16_t next = current ^ value;
  memory = __remill_write_memory_16(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_xor_32(Memory *memory, addr_t addr,
                                  uint32_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_32(memory, addr);
  const uint32_t next = current ^ value;
  memory = __remill_write_memory_32(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_xor_64(Memory *memory, addr_t addr,
                                  uint64_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_64(memory, addr);
  const uint64_t next = current ^ value;
  memory = __remill_write_memory_64(memory, addr, next);
  value = current;
  return memory;
}

extern "C" linux_task *__kleemill_create_task(State *state,
                                              Memory *memory);

int main(int argc, char *argv[3], char *envp[]) {
  if (argc != 3) {
    return EXIT_FAILURE;
  } else if (strcmp("klee-exec", argv[0])) {
    return EXIT_FAILURE;
  }

  __kleemill_init();

  Memory *memory = nullptr;
  memcpy(&memory, argv[2], sizeof(memory));

  State *state = reinterpret_cast<State *>(argv[1]);
  Task *task = __kleemill_create_task(state, memory);

  __kleemill_schedule();
  __kleemill_fini();
  return EXIT_SUCCESS;
}

}  // extern C
