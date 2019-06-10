//===-- SpecialFunctionHandler.cpp ----------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
#include "CoreStats.h"
#include "ExternalDispatcher.h"
#include "StatsTracker.h"
#include "glog/logging.h"

#include "SpecialFunctionHandler.h"

#include "Executor.h"
#include "Memory.h"
#include "MemoryManager.h"
#include "TimingSolver.h"
#include "klee/MergeHandler.h"
#include "Searcher.h"

#include "klee/ExecutionState.h"
#include "klee/Internal/Module/KInstruction.h"
#include "klee/Internal/Module/KModule.h"
#include "klee/Internal/Support/Debug.h"
#include "klee/Internal/Support/ErrorHandling.h"
#include "klee/OptionCategories.h"
#include "klee/SolverCmdLine.h"
#include "klee/ExprBuilder.h"
#include "PTree.h"

#include "llvm-c/Core.h"
#include "llvm/ADT/Twine.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include "llvm/Support/Compiler.h"
#include "llvm/Support/SwapByteOrder.h"

#include <algorithm>
#include <cassert>
#include <climits>
#include <cstring>
#include <limits>
#include <type_traits>

#include <errno.h>
#include <fcntl.h>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_set>

#include "../Native/Arch/X86/Log.cpp"
#include "remill/Arch/X86/Runtime/State.h"
#include "remill/BC/Util.h"

#include <fstream>
#include <sstream>
#include <algorithm>

using namespace llvm;
using namespace klee;

namespace {
cl::opt<bool>
    ReadablePosix("readable-posix-inputs", cl::init(false),
                  cl::desc("Prefer creation of POSIX inputs (command-line "
                           "arguments, files, etc.) with human readable bytes. "
                           "Note: option is expensive when creating lots of "
                           "tests (default=false)"));

cl::opt<bool>
    SilentKleeAssume("silent-klee-assume", cl::init(false),
                     cl::desc("Silently terminate paths with an infeasible "
                              "condition given to klee_assume() rather than "
                              "emitting an error (default=false)"));
} // namespace
/// \todo Almost all of the demands in this file should be replaced
/// with terminateState calls.

///

// FIXME: We are more or less committed to requiring an intrinsic
// library these days. We can move some of this stuff there,
// especially things like realloc which have complicated semantics
// w.r.t. forking. Among other things this makes delayed query
// dispatch easier to implement.
static SpecialFunctionHandler::HandlerInfo handlerInfo[] = {
#define add(name, handler, ret)                                                \
  { name, &SpecialFunctionHandler::handler, false, ret, false }
#define addDNR(name, handler)                                                  \
  { name, &SpecialFunctionHandler::handler, true, false, false }
    addDNR("__assert_rtn", handleAssertFail),
    addDNR("__assert_fail", handleAssertFail),
    addDNR("_assert", handleAssert),
    addDNR("abort", handleAbort),
    addDNR("_exit", handleExit),
    {"exit", &SpecialFunctionHandler::handleExit, true, false, true},
    addDNR("klee_abort", handleAbort),
    addDNR("klee_silent_exit", handleSilentExit),
    addDNR("klee_report_error", handleReportError),
    add("calloc", handleCalloc, true),
    add("free", handleFree, false),
    add("klee_assume", handleAssume, false),
    add("klee_check_memory_access", handleCheckMemoryAccess, false),
    add("klee_get_valuef", handleGetValue, true),
    add("klee_get_valued", handleGetValue, true),
    add("klee_get_valuel", handleGetValue, true),
    add("klee_get_valuell", handleGetValue, true),
    add("klee_get_value_i32", handleGetValue, true),
    add("klee_get_value_i64", handleGetValue, true),
    add("klee_define_fixed_object", handleDefineFixedObject, false),
    add("klee_get_obj_size", handleGetObjSize, true),
    add("klee_get_errno", handleGetErrno, true),
#ifndef __APPLE__
    add("__errno_location", handleErrnoLocation, true),
#else
    add("__error", handleErrnoLocation, true),
#endif
    add("klee_is_symbolic", handleIsSymbolic, true),
    add("klee_make_symbolic", handleMakeSymbolic, false),
    add("klee_mark_global", handleMarkGlobal, false),
    add("klee_open_merge", handleOpenMerge, false),
    add("klee_close_merge", handleCloseMerge, false),
    add("klee_prefer_cex", handlePreferCex, false),
    add("klee_posix_prefer_cex", handlePosixPreferCex, false),
    add("klee_print_expr", handlePrintExpr, false),
    add("klee_print_range", handlePrintRange, false),
    add("klee_set_forking", handleSetForking, false),
    add("klee_stack_trace", handleStackTrace, false),
    add("klee_warning", handleWarning, false),
    add("klee_warning_once", handleWarningOnce, false),
    add("klee_alias_function", handleAliasFunction, false),
    add("malloc", handleMalloc, true),
    add("memalign", handleMemalign, true),
    add("realloc", handleRealloc, true),

    // operator delete[](void*)
    add("_ZdaPv", handleDeleteArray, false),
    // operator delete(void*)
    add("_ZdlPv", handleDelete, false),

    // operator new[](unsigned int)
    add("_Znaj", handleNewArray, true),
    // operator new(unsigned int)
    add("_Znwj", handleNew, true),

    // FIXME-64: This is wrong for 64-bit long...

    // operator new[](unsigned long)
    add("_Znam", handleNewArray, true),
    // operator new(unsigned long)
    add("_Znwm", handleNew, true),

    // Run clang with -fsanitize=signed-integer-overflow and/or
    // -fsanitize=unsigned-integer-overflow
    add("__ubsan_handle_add_overflow", handleAddOverflow, false),
    add("__ubsan_handle_sub_overflow", handleSubOverflow, false),
    add("__ubsan_handle_mul_overflow", handleMulOverflow, false),
    add("__ubsan_handle_divrem_overflow", handleDivRemOverflow, false),

    // __remill function handling implementations

    add("__kleemill_get_lifted_function", handle__kleemill_get_lifted_function,
        true),
    add("__kleemill_can_write_byte", handle__kleemill_can_write_byte, true),
    add("__kleemill_can_read_byte", handle__kleemill_can_read_byte, true),
    add("__kleemill_free_memory", handle__kleemill_free_memory, true),
    add("__kleemill_allocate_memory", handle__kleemill_allocate_memory, true),
    add("__kleemill_protect_memory", handle__kleemill_protect_memory, true),
    add("__kleemill_is_mapped_address", handle__kleemill_is_mapped_address,
        true),
    add("__kleemill_find_unmapped_address",
        handle__kleemill_find_unmapped_address, true),
    add("__kleemill_log_state", handle__kleemill_log_state, false),

    add("__remill_write_memory_64", handle__remill_write_64, true),
    add("__remill_write_memory_32", handle__remill_write_32, true),
    add("__remill_write_memory_16", handle__remill_write_16, true),
    add("__remill_write_memory_8", handle__remill_write_8, true),
   
    add("__remill_read_memory_64", handle__remill_read_64, true),
    add("__remill_read_memory_32", handle__remill_read_32, true),
    add("__remill_read_memory_16", handle__remill_read_16, true),
    add("__remill_read_memory_8", handle__remill_read_8, true),
    
    add("llvm.ctpop.i32", handle__llvm_ctpop, true),
    add("klee_overshift_check", handle__klee_overshift_check, false),
    add("my_fstat", handle__fstat64, true),
    add("stat64", handle__stat64, true),
    add("my_openat", handle_openat64, true),
    add("get_fstat_index", handle_get_fstat_index, true),
    add("get_dirent_index", handle_get_dirent_index, true),
    add("get_dirent_name", handle_get_dirent_name, true),
    add("my_readdir", handle__my_readdir, true),
    add("klee_init_remill_memory", handle_klee_init_remill_mem, false),
    //add("__remill_symbolize_read", handle__remill_symbolize_read, true),
    add("__remill_check_range", handle__remill_symbolic_address, true), 
    add("__remill_search_symbolic_memory",
            handle__remill_assert_address, true),
    add("__remill_get_min_address", handle__remill_min_address, true),
    add("__remill_get_max_address", handle__remill_max_address, true),
    
    add("__remill_search_symbolic_byte", 
            handle__remill_search_byte, false),
    
    add("__remill_search_symbolic_byte_array", 
            handle__remill_search_byte_array, false),
    add("__remill_get_array_option", 
            handle__remill_get_array_option, true),
 



#undef addDNR
#undef add
};


void SpecialFunctionHandler::handle__remill_get_array_option( ExecutionState &state, 
        KInstruction *target, std::vector<ref<Expr>> &arguments) {
  
  auto new_str = arguments[0];
  auto min  = arguments[1];
  auto max = arguments[2];

  auto new_uint = llvm::dyn_cast<ConstantExpr>(new_str) 
      -> getZExtValue();
  auto max_uint = llvm::dyn_cast<ConstantExpr>(max)
      -> getZExtValue();
  auto min_uint = llvm::dyn_cast<ConstantExpr>(min)
      -> getZExtValue();

}


void SpecialFunctionHandler::handle__remill_min_address(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
    
    auto addr_val = executor.toUnique(state, arguments[0]);
    auto range = executor.solver->getRange(state, addr_val);

    auto min = llvm::dyn_cast<klee::ConstantExpr>(range.first);
    auto max = llvm::dyn_cast<klee::ConstantExpr>(range.second);
    
    // min value should either be concrete or unsat
    // LOG(INFO) << "range in min address: is " << min->getZExtValue()
    //     << " - " << max -> getZExtValue();
    
    executor.bindLocal(target, 
            state, ConstantExpr::create( min->getZExtValue(), 64));
}

void SpecialFunctionHandler::handle__remill_max_address(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
    
    auto addr_val = executor.toUnique(state, arguments[0]);
    auto range = executor.solver->getRange(state, addr_val);

    auto max = llvm::dyn_cast<klee::ConstantExpr>(range.second);
    
    LOG(INFO) << "range in max address: is " << max -> getZExtValue();
    
    executor.bindLocal(target, 
            state, ConstantExpr::create( max->getZExtValue(), 64));
   
}

ref<Expr> SpecialFunctionHandler::runtime_write_8(
        ExecutionState &state, uint64_t addr_uint, 
        ref<Expr> value_val, ref<Expr> mem_ptr) {
  
  auto mem = executor.Memory(state);
  if (isa<ConstantExpr>(value_val)) {
    auto val = llvm::dyn_cast<ConstantExpr>(value_val)->getZExtValue();
    if (val == klee::native::symbolic_byte) {
      mem->symbolic_memory.erase(addr_uint);
    }

    if (!mem->TryWrite(addr_uint, static_cast<uint8_t>(val))) {
      LOG(ERROR) << "Failed 1-byte write of 0x" << std::hex << val
        << " to address 0x" << addr_uint << " in address space ";
      return Expr::createPointer(0);
    }
  
  } else {
    if (!mem->TryWrite(addr_uint, klee::native::symbolic_byte)) {
      LOG(ERROR) << "Failed 1-byte write of 0x" << std::hex << klee::native::symbolic_byte
        << " to address 0x" << addr_uint << " in address space ";
      return Expr::createPointer(0);
    }
    mem->symbolic_memory[addr_uint] = value_val;
  }
  return mem_ptr;
}

ref<Expr> SpecialFunctionHandler::runtime_write_16(
        ExecutionState &state, uint64_t addr_uint, 
        ref<Expr> value_val, ref<Expr> mem_ptr) {

  ExprBuilder *builder = createDefaultExprBuilder();
  auto byte1 = builder->Extract(value_val, 0,8);
  auto byte2 = builder->Extract(value_val, 8,8);
  (void) runtime_write_8(state, addr_uint, byte1, mem_ptr);
  (void) runtime_write_8(state, addr_uint + 1, byte2, mem_ptr);
  return mem_ptr;
}

ref<Expr> SpecialFunctionHandler::runtime_write_32(
        ExecutionState &state, uint64_t addr_uint, 
        ref<Expr> value_val, ref<Expr> mem_ptr) {
  
  ExprBuilder *builder = createDefaultExprBuilder();
  auto byte1 = builder->Extract(value_val, 0,16);
  auto byte2 = builder->Extract(value_val, 16,16);
  (void) runtime_write_16(state, addr_uint, byte1, mem_ptr);
  (void) runtime_write_16(state, addr_uint + 2, byte2, mem_ptr);
  return mem_ptr;
}

ref<Expr> SpecialFunctionHandler::runtime_write_64(
        ExecutionState &state, uint64_t addr_uint, 
        ref<Expr> value_val, ref<Expr> mem_ptr) {
  
  ExprBuilder *builder = createDefaultExprBuilder();
  auto b1 = builder->Extract(value_val, 0,32);
  auto b2 = builder->Extract(value_val, 32,32);
  (void) runtime_write_32(state, addr_uint, b1, mem_ptr);
  (void) runtime_write_32(state, addr_uint + 4, b2, mem_ptr);
  return mem_ptr;
}

ref<Expr> SpecialFunctionHandler::runtime_read_8(
        ExecutionState &state, uint64_t addr_uint) {
  auto mem = executor.Memory(state);
  uint8_t value_uint = ~static_cast<uint8_t>(0);
  if (!mem->TryRead(addr_uint, &value_uint)) {
    LOG(ERROR) << "Failed 1-byte read from address 0x" << addr_uint;
  }
  if (value_uint == klee::native::symbolic_byte) {
    auto sym_pair = mem->symbolic_memory.find(addr_uint);
    if (sym_pair != mem->symbolic_memory.end()){
        return sym_pair->second;
    } 
  }
  return ConstantExpr::create(value_uint, 8);
}

ref<Expr> SpecialFunctionHandler::runtime_read_16(
        ExecutionState &state, uint64_t addr_uint) {
    
    ExprBuilder *builder = createDefaultExprBuilder();
    auto byte1 = runtime_read_8(state, addr_uint);
    auto byte2 = runtime_read_8(state, addr_uint + 1);
    return builder->Concat(byte2, byte1);
}

ref<Expr> SpecialFunctionHandler::runtime_read_32(
        ExecutionState &state, uint64_t addr_uint) {
  
  ExprBuilder *builder = createDefaultExprBuilder();
  auto byte1 = runtime_read_16(state, addr_uint);
  auto byte2 = runtime_read_16(state, addr_uint + 2);
  return builder->Concat(byte2, byte1);
}

ref<Expr> SpecialFunctionHandler::runtime_read_64(
        ExecutionState &state, uint64_t addr_uint) {
  ExprBuilder *builder = createDefaultExprBuilder();
  auto byte1 = runtime_read_32(state, addr_uint);
  auto byte2 = runtime_read_32(state, addr_uint + 4);
  return builder->Concat(byte2, byte1);
}

void SpecialFunctionHandler::handle__remill_search_byte(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
    // unconstrained or uninstrumented byte range branching
    ref<Expr> byte_val = executor.toUnique(state, arguments[0]);
    auto range = executor.solver->getRange(state, byte_val);

    auto min = llvm::dyn_cast<klee::ConstantExpr>(range.first);
    auto max = llvm::dyn_cast<klee::ConstantExpr>(range.second);
  
    LOG(INFO) << "range for symbolic byte";
    auto min_uint = min->getZExtValue();
    auto max_uint = max->getZExtValue();
    
    std::vector<ref<Expr>> constraints;
    std::vector<ExecutionState*> branches;
 
    for (uint8_t curr = min_uint; curr < max_uint; ++curr) {
      const ref<Expr> constr = EqExpr::create(byte_val, ConstantExpr::create(curr, 8));
      constraints.push_back(constr);
    }

    executor.branch(state, constraints , branches);
}

void SpecialFunctionHandler::handle__remill_search_byte_array(
  ExecutionState &state, KInstruction *target,
  std::vector<ref<Expr>> &arguments) {
  // unconstrained or uninstrumented byte range branching
  static uint64_t batch_size = 1;

  auto min = llvm::dyn_cast<klee::ConstantExpr>(executor.toUnique(state, arguments[0]));
  auto max = llvm::dyn_cast<klee::ConstantExpr>(executor.toUnique(state, arguments[1]));

  auto min_uint = min->getZExtValue();
  auto max_uint = max->getZExtValue();
  LOG(INFO) << min_uint << "-> " << max_uint;
  std::vector<ref<Expr>> constraints;
  std::vector<ExecutionState*> branches;

  generate_concrete_array(state, true, min_uint, max_uint); 
  
  for (uint64_t i=0; i < batch_size; ++i) {
    //printf("i is : %d\n", i);
    auto concrete_array = generate_concrete_array(state,false,0,0);
    /*
    std::stringstream arr;
    for (auto& i:concrete_array){
      arr << (int)i << " ";
    }

    LOG(INFO) << "array: " << arr.str();
    */
    constraints.push_back(
          build_array_expr(state, concrete_array, min_uint));
  }

  executor.branch(state, constraints, branches);
}

std::vector<uint8_t> SpecialFunctionHandler::generate_concrete_array(
    ExecutionState &state, bool new_array, uint64_t start, 
    uint64_t stop) {
    LOG(INFO) << "hit the generate case!";
    
    static std::vector<uint8_t>(concrete_array);
    static std::vector<std::pair<uint8_t, uint8_t>> range_cache;
    static uint8_t min;
    static uint8_t max;
    static int curr;
    
    const auto &solver = executor.solver;
    auto mem = executor.Memory(state);

    if (new_array) {
      // figure out another way to do this
      concrete_array = std::vector<uint8_t>();
      range_cache = std::vector<std::pair<uint8_t, uint8_t>>();
      min = start;
      max = stop;

      for (auto curr=start; curr<=stop; ++curr){
        auto byte_expr_pair = mem->symbolic_memory.find(curr);
        if (byte_expr_pair == mem ->symbolic_memory.end()){
          LOG(FATAL) << "out of bounds error in array concretization";
        }
        auto byte_expr = byte_expr_pair->second;
        // should add err checking but currently assume start/stop are symbolid
        auto range = solver->getRange(state, byte_expr);
        concrete_array.push_back(
            llvm::dyn_cast<ConstantExpr>(range.first) -> getZExtValue());

        range_cache.push_back( 
            std::pair<uint8_t, uint8_t >(
              llvm::dyn_cast<ConstantExpr>(range.first) -> getZExtValue(),
              llvm::dyn_cast<ConstantExpr>(range.second) -> getZExtValue()
            ));
      }
      return concrete_array;
    }
    
    auto concr_str = concrete_array;
    
    if ( concrete_array[curr] == range_cache[curr].second){
      concrete_array[curr] = range_cache[curr].first;
    } else {
      ++concrete_array[curr];
    }

    curr = (curr + 1) % (max - min + 1);
    //for (auto &i:concr_str){
    //  LOG(INFO) << "byte is " << (int)i;
    //}
    return concr_str;
}

ref<Expr> SpecialFunctionHandler::build_array_expr(
        ExecutionState &state, 
        const std::vector<uint8_t >& concrete_array,
          uint64_t start ) {
  
  auto sym_mem = executor.Memory(state) -> symbolic_memory;
  ExprBuilder *builder = createDefaultExprBuilder();
  LOG(INFO) << "concreter_array len is " << concrete_array.size();

  auto expr = builder -> Eq(sym_mem.find(start)->second, 
                ConstantExpr::create( concrete_array[0], 8));

  for (int i=1; i < concrete_array.size(); ++i) {
    auto eq = builder->Eq(sym_mem.find(start + i)->second, 
                ConstantExpr::create( concrete_array[i], 8));
    expr = builder -> And(eq, expr);
  }
  expr->dump();
  delete builder;
  return expr;
}


void SpecialFunctionHandler::handle__remill_assert_address(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  
  auto addr = executor.toUnique(state, arguments[0]);
  auto min = llvm::dyn_cast<klee::ConstantExpr>(arguments[1]);
  auto max = llvm::dyn_cast<klee::ConstantExpr>(arguments[2]);

  auto min_uint = min->getZExtValue();
  auto max_uint = max->getZExtValue();

  auto mem = executor.Memory(state);
  uint64_t curr = min_uint;
  // find min and max
 // is current mapped?
 // if not TODO()continue
 // if not mapped handle it later
 // take curr and round it up to the next page boundary
 // ask is curr satisfiable
 // if not sat continue
 // if sat

 // in first address == current -> state that returns out
 // second address > current copy current and save with injected assumption of the address
 // save executionstate and also save the arguments to this method and the address size so we 
 // can callback and pass in the right arguments
 // assert  that address == current
 // bindlocal the next sat address

  while ( curr <= max_uint ) {
    ++curr;
    LOG(INFO) << "curr at this iteration is " << curr;
    ref<Expr> constr = EqExpr::create(addr, ConstantExpr::create(curr, 64));
    if (mem->IsMapped(curr)) {
      LOG(INFO) << "is mapped";
      bool res;
      (void) executor.solver->mayBeTrue(state, constr, res);
      LOG(INFO) << "after solver query";
      if (res) {
        LOG(INFO) <<  curr << " is a valid address";
        executor.bindLocal(target, state, ConstantExpr::create(curr, 64));
        return;
      } else {
        LOG(INFO) << "is not a valid query";
      }
    } else {
     LOG(ERROR) << "address: " << curr << " is not mapped";
    // TODO(sai) properly handled unmapped addresses
    }
  }

  executor.bindLocal(target, state, ConstantExpr::create(min_uint, 64));
}

void SpecialFunctionHandler::handle__remill_symbolic_address(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto addr_expression = executor.toUnique(state, arguments[0]);
  auto range = executor.solver->getRange(state, addr_expression);
  auto min = llvm::dyn_cast<klee::ConstantExpr>(range.first);
  auto max = llvm::dyn_cast<klee::ConstantExpr>(range.second);

  auto min_uint = min->getZExtValue();
  auto max_uint = max->getZExtValue();
  LOG(INFO) << "RANGE: " << min_uint << "-" << max_uint;
  executor.bindLocal(target, state, 
        ConstantExpr::create( !(min_uint == max_uint) , Expr::Bool));
}


void SpecialFunctionHandler::handle_klee_init_remill_mem(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
    LOG(INFO) << "Initialized klee's concrete address space";
    auto memory_val = executor.toUnique(state, arguments[0]);
    auto memory_uint = llvm::dyn_cast<ConstantExpr>(memory_val)->getZExtValue();
    
    auto mem = executor.Memory(memory_uint);
    state.concreteMemory = 
        std::unique_ptr<klee::native::AddressSpace>(new klee::native::AddressSpace(*mem));
}


void SpecialFunctionHandler::handle__kleemill_log_state(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {}

void SpecialFunctionHandler::handle_openat64(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto dirfd_val = executor.toUnique(state, arguments[0]);
  auto dirfd_uint = llvm::dyn_cast<ConstantExpr>(dirfd_val)->getZExtValue();

  auto pathname_val = executor.toUnique(state, arguments[1]);
  auto pathname_uint =
      llvm::dyn_cast<ConstantExpr>(pathname_val)->getZExtValue();
  auto pathname = reinterpret_cast<char *>(pathname_uint);

  auto flags_val = executor.toUnique(state, arguments[2]);
  auto flags_uint = llvm::dyn_cast<ConstantExpr>(flags_val)->getZExtValue();

  auto mode_val = executor.toUnique(state, arguments[3]);
  auto mode_uint = llvm::dyn_cast<ConstantExpr>(mode_val)->getZExtValue();

  auto open_status = openat(dirfd_uint, pathname, flags_uint, mode_uint);

  if (open_status == -1) {
    executor.bindLocal(target, state,
                       ConstantExpr::create(open_status, Expr::Int32));
    errno = ENOENT;
  } else {
    executor.bindLocal(target, state,
                       ConstantExpr::create(open_status, Expr::Int64));
    errno = 0;
  }
}

void SpecialFunctionHandler::set_up_fstat_struct(struct stat *info) {
  fstat_vector.clear();
  fstat_vector.push_back(static_cast<uint64_t>(info->st_dev));
  fstat_vector.push_back(static_cast<uint64_t>(info->st_ino));
  fstat_vector.push_back(static_cast<uint64_t>(info->st_mode));
  fstat_vector.push_back(static_cast<uint64_t>(info->st_nlink));
  fstat_vector.push_back(static_cast<uint64_t>(info->st_uid));
  fstat_vector.push_back(static_cast<uint64_t>(info->st_gid));
  fstat_vector.push_back(static_cast<uint64_t>(info->st_rdev));
  fstat_vector.push_back(static_cast<uint64_t>(info->st_size));
  fstat_vector.push_back(static_cast<uint64_t>(info->st_blksize));
  fstat_vector.push_back(static_cast<uint64_t>(info->st_blocks));
}

void SpecialFunctionHandler::handle_get_fstat_index(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto fstat_index_val = executor.toUnique(state, arguments[0]);
  auto index_uint =
      llvm::dyn_cast<ConstantExpr>(fstat_index_val)->getZExtValue();

  executor.bindLocal(
      target, state,
      ConstantExpr::create(fstat_vector[index_uint], Expr::Int64));
}

void SpecialFunctionHandler::handle_get_dirent_name(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  executor.bindLocal(
      target, state,
      Expr::createPointer(reinterpret_cast<uintptr_t>(dirent_entry.d_name)));
}

void SpecialFunctionHandler::handle_get_dirent_index(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto dirent_index_val = executor.toUnique(state, arguments[0]);
  auto index_uint =
      llvm::dyn_cast<ConstantExpr>(dirent_index_val)->getZExtValue();
  unsigned field;
  switch (index_uint) {
  case 0: {
    field = dirent_entry.d_ino;
  }
  case 1: {
    field = dirent_entry.d_off;
  }
  case 2: {
    field = dirent_entry.d_reclen;
  }
  case 3: {
    field = dirent_entry.d_type;
  }
  }
  executor.bindLocal(target, state, ConstantExpr::create(field, Expr::Int64));
}

void SpecialFunctionHandler::set_up_dirent_struct(struct dirent *info) {
  dirent_entry.d_ino = info->d_ino;
  dirent_entry.d_off = info->d_off;
  dirent_entry.d_reclen = info->d_reclen;
  dirent_entry.d_type = info->d_type;
  strcpy(dirent_entry.d_name, info->d_name);
}

void SpecialFunctionHandler::handle__my_readdir(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto dir_val = executor.toUnique(state, arguments[0]);
  auto dir_uint = llvm::dyn_cast<ConstantExpr>(dir_val)->getZExtValue();

  auto dir = reinterpret_cast<DIR *>(dir_uint);
  auto dirent = readdir(dir);

  // must set errno
  if (!dirent) {
    executor.bindLocal(target, state, ConstantExpr::create(false, Expr::Bool));
  } else {
    set_up_dirent_struct(dirent);
    executor.bindLocal(target, state, ConstantExpr::create(true, Expr::Bool));
  }
}

void SpecialFunctionHandler::handle__fstat64(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  auto fd_val = executor.toUnique(state, arguments[0]);
  auto fd_uint = llvm::dyn_cast<ConstantExpr>(fd_val)->getZExtValue();

  auto stat_val = executor.toUnique(state, arguments[1]);
  auto stat_uint = llvm::dyn_cast<ConstantExpr>(stat_val)->getZExtValue();

  auto stat = reinterpret_cast<struct stat *>(stat_uint);
  auto stat_ret = fstat(fd_uint, stat);

  // must set errno
  if (stat_ret == -1) {
    executor.bindLocal(target, state,
                       ConstantExpr::create(stat_ret, Expr::Int32));
    errno = EFAULT;
  } else {
    set_up_fstat_struct(stat);
    executor.bindLocal(target, state,
                       ConstantExpr::create(stat_ret, Expr::Int64));
    errno = 0;
  }
}

void SpecialFunctionHandler::handle__stat64(ExecutionState &state,
                                            KInstruction *target,
                                            std::vector<ref<Expr>> &arguments) {
  auto path_val = executor.toUnique(state, arguments[0]);
  auto path_uint = llvm::dyn_cast<ConstantExpr>(path_val)->getZExtValue();
  const char *pathname = reinterpret_cast<char *>(path_uint);

  auto stat_val = executor.toUnique(state, arguments[1]);
  auto stat_uint = llvm::dyn_cast<ConstantExpr>(stat_val)->getZExtValue();

  auto stat_struct = reinterpret_cast<struct stat *>(stat_uint);
  auto stat_ret = stat(pathname, stat_struct);

  // msust set errno
  if (stat_ret == -1) {
    executor.bindLocal(target, state,
                       ConstantExpr::create(stat_ret, Expr::Int32));
    errno = EFAULT;
  } else {
    executor.bindLocal(target, state,
                       ConstantExpr::create(stat_ret, Expr::Int64));
    errno = 0;
  }
}

void SpecialFunctionHandler::handle__klee_overshift_check(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  auto shift_val = executor.toUnique(state, arguments[0]);
  auto shift_uint = llvm::dyn_cast<ConstantExpr>(shift_val)->getZExtValue();

  auto bitWidth_val = executor.toUnique(state, arguments[1]);
  auto bitWidth_uint =
      llvm::dyn_cast<ConstantExpr>(bitWidth_val)->getZExtValue();

  if (shift_uint >= bitWidth_uint) {
    LOG(ERROR) << "overshift has occured";
  }
}

void SpecialFunctionHandler::handle__kleemill_can_read_byte(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  //auto mem_val = executor.toUnique(state, arguments[0]);
  //auto mem_uint = llvm::dyn_cast<ConstantExpr>(mem_val)->getZExtValue();

  //LOG(INFO) << "addressspace num is " << mem_uint;
  auto addr_val = executor.toUnique(state, arguments[1]);
  auto addr_uint = llvm::dyn_cast<ConstantExpr>(addr_val)->getZExtValue();

  auto mem = executor.Memory(state);

  bool can_read = mem->CanRead(addr_uint);

  executor.bindLocal(target, state, ConstantExpr::create(can_read, Expr::Bool));
}

void SpecialFunctionHandler::handle__kleemill_can_write_byte(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  //auto mem_val = executor.toUnique(state, arguments[0]);
  //auto mem_uint = llvm::dyn_cast<ConstantExpr>(mem_val)->getZExtValue();

  //LOG(INFO) << "addressspace num is " << mem_uint;

  auto addr_val = executor.toUnique(state, arguments[1]);
  auto addr_uint = llvm::dyn_cast<ConstantExpr>(addr_val)->getZExtValue();

  auto mem = executor.Memory(state);

  bool can_write = mem->CanWrite(addr_uint);

  executor.bindLocal(target, state,
                     ConstantExpr::create(can_write, Expr::Bool));
}

void SpecialFunctionHandler::handle__kleemill_free_memory(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto mem_val = executor.toUnique(state, arguments[0]);
  //auto mem_uint = llvm::dyn_cast<ConstantExpr>(mem_val)->getZExtValue();


  auto where_val = executor.toUnique(state, arguments[1]);
  auto where_uint = llvm::dyn_cast<ConstantExpr>(where_val)->getZExtValue();

  auto size_val = executor.toUnique(state, arguments[2]);
  auto size_uint = llvm::dyn_cast<ConstantExpr>(size_val)->getZExtValue();

  auto mem = executor.Memory(state);

  mem->RemoveMap(where_uint, size_uint);

  executor.bindLocal(target, state, mem_val);
}

void SpecialFunctionHandler::handle__kleemill_allocate_memory(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto mem_val = executor.toUnique(state, arguments[0]);
  //auto mem_uint = llvm::dyn_cast<ConstantExpr>(mem_val)->getZExtValue();

  //LOG(INFO) << "addressspace num is " << mem_uint;

  auto where_val = executor.toUnique(state, arguments[1]);
  auto where_uint = llvm::dyn_cast<ConstantExpr>(where_val)->getZExtValue();

  auto size_val = executor.toUnique(state, arguments[2]);
  auto size_uint = llvm::dyn_cast<ConstantExpr>(size_val)->getZExtValue();

  auto name_val = executor.toUnique(state, arguments[3]);
  auto name_uint = llvm::dyn_cast<ConstantExpr>(name_val)->getZExtValue();
  auto name_char = reinterpret_cast<char *>(name_uint);

  auto offset_val = executor.toUnique(state, arguments[4]);
  auto offset_uint = llvm::dyn_cast<ConstantExpr>(offset_val)->getZExtValue();

  auto mem = executor.Memory(state);
  mem->AddMap(where_uint, size_uint, name_char, offset_uint);
  executor.bindLocal(target, state, mem_val);
}

void SpecialFunctionHandler::handle__kleemill_protect_memory(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto mem_val = executor.toUnique(state, arguments[0]);
  //auto mem_uint = llvm::dyn_cast<ConstantExpr>(mem_val)->getZExtValue();

  //LOG(INFO) << "addressspace num is " << mem_uint;

  auto where_val = executor.toUnique(state, arguments[1]);
  auto where_uint = llvm::dyn_cast<ConstantExpr>(where_val)->getZExtValue();

  auto size_val = executor.toUnique(state, arguments[2]);
  auto size_uint = llvm::dyn_cast<ConstantExpr>(size_val)->getZExtValue();

  auto can_read_val = executor.toUnique(state, arguments[3]);
  auto can_read_uint =
      llvm::dyn_cast<ConstantExpr>(can_read_val)->getZExtValue();

  auto can_write_val = executor.toUnique(state, arguments[4]);
  auto can_write_uint =
      llvm::dyn_cast<ConstantExpr>(can_write_val)->getZExtValue();

  auto can_exec_val = executor.toUnique(state, arguments[5]);
  auto can_exec_uint =
      llvm::dyn_cast<ConstantExpr>(can_exec_val)->getZExtValue();

  auto mem = executor.Memory(state);

  mem->SetPermissions(where_uint, size_uint, static_cast<bool>(can_read_uint),
                      static_cast<bool>(can_write_uint),
                      static_cast<bool>(can_exec_uint));
  executor.bindLocal(target, state, mem_val);
}

void SpecialFunctionHandler::handle__kleemill_is_mapped_address(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  //auto mem_val = executor.toUnique(state, arguments[0]);
  //auto mem_uint = llvm::dyn_cast<ConstantExpr>(mem_val)->getZExtValue();

  //LOG(INFO) << "addressspace num is " << mem_uint;
  auto where_val = executor.toUnique(state, arguments[1]);
  auto where_uint = llvm::dyn_cast<ConstantExpr>(where_val)->getZExtValue();

  auto mem = executor.Memory(state);

  bool is_mapped = mem->IsMapped(where_uint);

  executor.bindLocal(target, state,
                     ConstantExpr::create(is_mapped, Expr::Bool));
}

void SpecialFunctionHandler::handle__kleemill_find_unmapped_address(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  //auto mem_val = executor.toUnique(state, arguments[0]);
  //auto mem_uint = llvm::dyn_cast<ConstantExpr>(mem_val)->getZExtValue();

  //LOG(INFO) << "addressspace num is " << mem_uint;
  auto base_val = executor.toUnique(state, arguments[1]);
  auto base_uint = llvm::dyn_cast<ConstantExpr>(base_val)->getZExtValue();

  auto limit_val = executor.toUnique(state, arguments[2]);
  auto limit_uint = llvm::dyn_cast<ConstantExpr>(limit_val)->getZExtValue();

  auto size_val = executor.toUnique(state, arguments[3]);
  auto size_uint = llvm::dyn_cast<ConstantExpr>(size_val)->getZExtValue();

  auto mem = executor.Memory(state);

  uint64_t hole = 0;
  if (mem->FindHole(base_uint, limit_uint, size_uint, &hole)) {
    executor.bindLocal(target, state, ConstantExpr::create(hole, Expr::Int64));
  } else {
    executor.bindLocal(target, state, ConstantExpr::create(0, Expr::Int64));
  }
}

void SpecialFunctionHandler::handle__remill_symbolize_read (
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto addr_val = executor.toUnique(state, arguments[0]);
  uint64_t addr_uint = llvm::dyn_cast<klee::ConstantExpr>(addr_val) -> getZExtValue();
  auto mem = executor.Memory(state);
  uint8_t value_uint = ~static_cast<uint8_t>(0);
  if (!mem->TryRead(addr_uint, &value_uint)) {
    LOG(ERROR) << "Failed 1-byte read from address 0x" << addr_uint
               << " in address space ";
  }
  
  if (value_uint == klee::native::symbolic_byte) {
    LOG(INFO) << "concrete byte was equal to symbolic byte";
    auto sym_pair = mem->symbolic_memory.find(addr_uint);
    if (sym_pair != mem->symbolic_memory.end()) {
        LOG(INFO) << "proceed with symbolic read because addr existed in space";
        executor.bindLocal(target, state, sym_pair->second);
        return;
    } 
  }
  //LOG(INFO) << "concrete read";
  executor.bindLocal(target, state, 
              executor.replaceReadWithSymbolic( state,
                  ConstantExpr::create(value_uint, Expr::Int8)));

}

void SpecialFunctionHandler::handle__remill_read_8(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto mem_val = executor.toUnique(state, arguments[0]);
  auto mem_uint = llvm::dyn_cast<ConstantExpr>(mem_val)->getZExtValue();
  auto addr_val = executor.toUnique(state, arguments[1]);
  auto mem = executor.Memory(state);
  
  if (llvm::isa<ConstantExpr>(addr_val)) {
    uint64_t addr_uint = llvm::dyn_cast<klee::ConstantExpr>(addr_val) -> getZExtValue();
    executor.bindLocal(target, state, runtime_read_8(state, addr_uint));
  } else {
    auto range = executor.solver->getRange(state, addr_val);
    auto min = llvm::dyn_cast<klee::ConstantExpr>(range.first);
    auto max = llvm::dyn_cast<klee::ConstantExpr>(range.second);

    auto min_uint = min->getZExtValue();
    auto max_uint = max->getZExtValue();

    auto mem_cont = new MemoryAccessContinuation( &state, addr_val, true, 
            min_uint, max_uint, min_uint + 1, mem_val, 8);
    
    executor.scheduleMemContinuation(*mem_cont);
  }
}

void SpecialFunctionHandler::handle__remill_read_16(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
    
  auto mem_val = executor.toUnique(state, arguments[0]);
  auto addr_val = executor.toUnique(state, arguments[1]);

  
  if (isa<ConstantExpr>(addr_val)){
    auto addr_uint = dyn_cast<ConstantExpr>(addr_val) -> getZExtValue();
    executor.bindLocal(target, state, runtime_read_16(state, addr_uint));
  } else {
    auto range = executor.solver->getRange(state, addr_val);
    auto min = llvm::dyn_cast<klee::ConstantExpr>(range.first);
    auto max = llvm::dyn_cast<klee::ConstantExpr>(range.second);
    auto min_uint = min->getZExtValue();
    auto max_uint = max->getZExtValue();
    auto mem_cont = new MemoryAccessContinuation( &state, addr_val, true, 
            min_uint, max_uint, min_uint + 1, mem_val, 16);
    
    executor.scheduleMemContinuation(*mem_cont);
  }
}

void SpecialFunctionHandler::handle__remill_read_32(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  
  auto mem_val = executor.toUnique(state, arguments[0]);
  auto addr_val = executor.toUnique(state, arguments[1]);

  if (isa<ConstantExpr>(addr_val)){
    auto addr_uint = dyn_cast<ConstantExpr>(addr_val) -> getZExtValue();
    executor.bindLocal(target, state, runtime_read_32(state, addr_uint));
  } else {
    auto range = executor.solver->getRange(state, addr_val);
    auto min = llvm::dyn_cast<klee::ConstantExpr>(range.first);
    auto max = llvm::dyn_cast<klee::ConstantExpr>(range.second);
    auto min_uint = min->getZExtValue();
    auto max_uint = max->getZExtValue();
    auto mem_cont = new MemoryAccessContinuation( &state, addr_val, true, 
            min_uint, max_uint, min_uint + 1, mem_val, 32);
    
    executor.scheduleMemContinuation(*mem_cont);
  }
}

void SpecialFunctionHandler::handle__remill_read_64(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  
  auto mem_val = executor.toUnique(state, arguments[0]);
  auto addr_val = executor.toUnique(state, arguments[1]);

  if (isa<ConstantExpr>(addr_val)){
    auto addr_uint = dyn_cast<ConstantExpr>(addr_val) -> getZExtValue();
    executor.bindLocal(target, state, runtime_read_64(state, addr_uint));
  } else {
    auto range = executor.solver->getRange(state, addr_val);
    auto min = llvm::dyn_cast<klee::ConstantExpr>(range.first);
    auto max = llvm::dyn_cast<klee::ConstantExpr>(range.second);
    auto min_uint = min->getZExtValue();
    auto max_uint = max->getZExtValue();
    auto mem_cont = new MemoryAccessContinuation( &state, addr_val, true, 
            min_uint, max_uint, min_uint + 1, mem_val, 64);
    
    executor.scheduleMemContinuation(*mem_cont);
  }
}

void SpecialFunctionHandler::handle__remill_write_8(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto mem_val = executor.toUnique(state, arguments[0]);
  auto mem_uint = llvm::dyn_cast<ConstantExpr>(mem_val)->getZExtValue();
  auto addr_val = executor.toUnique(state, arguments[1]);
  auto value_val = executor.toUnique(state, arguments[2]);
 
  if (isa<ConstantExpr>(addr_val)){
    auto addr_uint = llvm::dyn_cast<ConstantExpr>(addr_val)->getZExtValue();
    executor.bindLocal(target, state, runtime_write_8(state, addr_uint, value_val, mem_val));
  } else {
    auto range = executor.solver->getRange(state, addr_val);
    auto min = llvm::dyn_cast<klee::ConstantExpr>(range.first);
    auto max = llvm::dyn_cast<klee::ConstantExpr>(range.second);
    
    auto min_uint = min->getZExtValue();
    auto max_uint = max->getZExtValue();
    
    auto mem_cont = new MemoryAccessContinuation( &state, addr_val, false, 
            min_uint, max_uint + 1, min_uint + 1, mem_val, 8);

    mem_cont->val_to_write = value_val;
    
    executor.scheduleMemContinuation(*mem_cont);
  }
}


void SpecialFunctionHandler::handle__remill_write_16(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  
  auto mem_val = executor.toUnique(state, arguments[0]);
  auto addr_val = executor.toUnique(state, arguments[1]);
  auto value_val = executor.toUnique(state, arguments[2]);
  if (isa<ConstantExpr>(addr_val)) {
    auto addr_uint = dyn_cast<ConstantExpr>(addr_val) -> getZExtValue();
    executor.bindLocal(target, state, 
        runtime_write_16(state, addr_uint, value_val, mem_val));
  } else {
    auto range = executor.solver->getRange(state, addr_val);
    auto min = llvm::dyn_cast<klee::ConstantExpr>(range.first);
    auto max = llvm::dyn_cast<klee::ConstantExpr>(range.second);
    
    auto min_uint = min->getZExtValue();
    auto max_uint = max->getZExtValue();
    
    auto mem_cont = new MemoryAccessContinuation( &state, addr_val, false, 
            min_uint, max_uint + 1, min_uint + 1, mem_val, 16);

    mem_cont->val_to_write = value_val;
    executor.scheduleMemContinuation(*mem_cont);
  }
}


void SpecialFunctionHandler::handle__remill_write_32(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  
  auto mem_val = executor.toUnique(state, arguments[0]);
  auto addr_val = executor.toUnique(state, arguments[1]);
  auto value_val = executor.toUnique(state, arguments[2]);
  if (isa<ConstantExpr>(addr_val)) {
    auto addr_uint = dyn_cast<ConstantExpr>(addr_val) -> getZExtValue();
    executor.bindLocal(target, state, 
        runtime_write_32(state, addr_uint, value_val, mem_val));
  } else {
    auto range = executor.solver->getRange(state, addr_val);
    auto min = llvm::dyn_cast<klee::ConstantExpr>(range.first);
    auto max = llvm::dyn_cast<klee::ConstantExpr>(range.second);
    
    auto min_uint = min->getZExtValue();
    auto max_uint = max->getZExtValue();
    
    auto mem_cont = new MemoryAccessContinuation( &state, addr_val, false, 
            min_uint, max_uint + 1, min_uint + 1, mem_val, 32);

    mem_cont->val_to_write = value_val;
    executor.scheduleMemContinuation(*mem_cont);
  }
}


void SpecialFunctionHandler::handle__remill_write_64(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  auto mem_val = executor.toUnique(state, arguments[0]);
  auto addr_val = executor.toUnique(state, arguments[1]);
  auto value_val = executor.toUnique(state, arguments[2]);
  if (isa<ConstantExpr>(addr_val)) {
    auto addr_uint = dyn_cast<ConstantExpr>(addr_val) -> getZExtValue();
    executor.bindLocal(target, state, 
        runtime_write_64(state, addr_uint, value_val, mem_val));
  } else {
    auto range = executor.solver->getRange(state, addr_val);
    auto min = llvm::dyn_cast<klee::ConstantExpr>(range.first);
    auto max = llvm::dyn_cast<klee::ConstantExpr>(range.second);
    
    auto min_uint = min->getZExtValue();
    auto max_uint = max->getZExtValue();
    
    auto mem_cont = new MemoryAccessContinuation( &state, addr_val, false, 
            min_uint, max_uint + 1, min_uint + 1, mem_val, 64);

    mem_cont->val_to_write = value_val;
    executor.scheduleMemContinuation(*mem_cont);
  }

}


void SpecialFunctionHandler::handle__llvm_ctpop(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  auto pc_val = executor.toUnique(state, arguments[0]);
  auto pc_uint = llvm::dyn_cast<ConstantExpr>(pc_val)->getZExtValue();

  auto ctop_val = __builtin_popcount(pc_uint);
  LOG(INFO) << ctop_val << " : LLVM CTPOP VALUE";
  executor.bindLocal(target, state,
                     ConstantExpr::create(ctop_val, Expr::Int32));
}

void SpecialFunctionHandler::handle__kleemill_get_lifted_function(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  //auto mem_val = executor.toUnique(state, arguments[0]);
  //auto mem_uint = llvm::dyn_cast<ConstantExpr>(mem_val)->getZExtValue();

  auto pc_val = executor.toUnique(state, arguments[1]);
  auto pc_uint = llvm::dyn_cast<ConstantExpr>(pc_val)->getZExtValue();

  auto mem = executor.Memory(state);
  auto func = executor.GetLiftedFunction(mem, pc_uint);

  // LOG(INFO)
  //    << "Indirect branch lookup " << std::hex << pc_uint << std::dec
  //    << " in address space " << mem_uint;

  executor.bindLocal(target, state,
                     Expr::createPointer(reinterpret_cast<uintptr_t>(func)));
}

SpecialFunctionHandler::const_iterator SpecialFunctionHandler::begin() {
  return SpecialFunctionHandler::const_iterator(handlerInfo);
}

SpecialFunctionHandler::const_iterator SpecialFunctionHandler::end() {
  // NULL pointer is sentinel
  return SpecialFunctionHandler::const_iterator(0);
}

SpecialFunctionHandler::const_iterator &SpecialFunctionHandler::const_iterator::
operator++() {
  ++index;
  if (index >= SpecialFunctionHandler::size()) {
    // Out of range, return .end()
    base = 0; // Sentinel
    index = 0;
  }

  return *this;
}

int SpecialFunctionHandler::size() {
  return sizeof(handlerInfo) / sizeof(handlerInfo[0]);
}

SpecialFunctionHandler::SpecialFunctionHandler(Executor &_executor)
    : executor(_executor) {}

void SpecialFunctionHandler::prepare(
    llvm::Module *mod, std::vector<const char *> &preservedFunctions) {
  unsigned N = size();

  for (unsigned i = 0; i < N; ++i) {
    HandlerInfo &hi = handlerInfo[i];
    Function *f = mod->getFunction(hi.name);

    // No need to create if the function doesn't exist, since it cannot
    // be called in that case.
    if (f && (!hi.doNotOverride || f->isDeclaration())) {
      preservedFunctions.push_back(hi.name);
      // Make sure NoReturn attribute is set, for optimization and
      // coverage counting.
      if (hi.doesNotReturn)
        f->addFnAttr(Attribute::NoReturn);

      // Change to a declaration since we handle internally (simplifies
      // module and allows deleting dead code).
      if (!f->isDeclaration())
        f->deleteBody();
    }
  }
}

void SpecialFunctionHandler::bind(llvm::Module *mod) {
  unsigned N = sizeof(handlerInfo) / sizeof(handlerInfo[0]);

  for (unsigned i = 0; i < N; ++i) {
    HandlerInfo &hi = handlerInfo[i];
    Function *f = mod->getFunction(hi.name);

    if (f && (!hi.doNotOverride || f->isDeclaration()))
      handlers[f] = std::make_pair(hi.handler, hi.hasReturnValue);
  }
}

bool SpecialFunctionHandler::handle(ExecutionState &state, Function *f,
                                    KInstruction *target,
                                    std::vector<ref<Expr>> &arguments) {
  handlers_ty::iterator it = handlers.find(f);
  if (it != handlers.end()) {
    Handler h = it->second.first;
    bool hasReturnValue = it->second.second;
    // FIXME: Check this... add test?
    if (!hasReturnValue && !target->inst->use_empty()) {
      executor.terminateStateOnExecError(
          state, "expected return value from void special function");
    } else {
      (this->*h)(state, target, arguments);
    }
    return true;
  } else {
    return false;
  }
}

/****/

// reads a concrete string from memory
std::string SpecialFunctionHandler::readStringAtAddress(ExecutionState &state,
                                                        ref<Expr> addressExpr) {
  ObjectPair op;
  addressExpr = executor.toUnique(state, addressExpr);
  if (!isa<ConstantExpr>(addressExpr)) {
    executor.terminateStateOnError(
        state, "Symbolic string pointer passed to one of the klee_ functions",
        Executor::TerminateReason::User);
    return "";
  }
  ref<ConstantExpr> address = cast<ConstantExpr>(addressExpr);
  if (!state.addressSpace.resolveOne(address, op)) {
    executor.terminateStateOnError(
        state, "Invalid string pointer passed to one of the klee_ functions",
        Executor::TerminateReason::User);
    return "";
  }
  bool res __attribute__((unused));
  assert(executor.solver->mustBeTrue(
             state, EqExpr::create(address, op.first->getBaseExpr()), res) &&
         res && "XXX interior pointer unhandled");
  const MemoryObject *mo = op.first;
  const ObjectState *os = op.second;

  char *buf = new char[mo->size];

  unsigned i;
  for (i = 0; i < mo->size - 1; i++) {
    ref<Expr> cur = os->read8(i);
    cur = executor.toUnique(state, cur);
    assert(isa<ConstantExpr>(cur) &&
           "hit symbolic char while reading concrete string");
    buf[i] = cast<ConstantExpr>(cur)->getZExtValue(8);
  }
  buf[i] = 0;

  std::string result(buf);
  delete[] buf;
  return result;
}

/****/

void SpecialFunctionHandler::handleAbort(ExecutionState &state,
                                         KInstruction *target,
                                         std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 0 && "invalid number of arguments to abort");
  executor.terminateStateOnError(state, "abort failure", Executor::Abort);
}

void SpecialFunctionHandler::handleExit(ExecutionState &state,
                                        KInstruction *target,
                                        std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 && "invalid number of arguments to exit");
  executor.terminateStateOnExit(state);
}

void SpecialFunctionHandler::handleSilentExit(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 && "invalid number of arguments to exit");
  executor.terminateState(state);
}

void SpecialFunctionHandler::handleAliasFunction(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 2 &&
         "invalid number of arguments to klee_alias_function");
  std::string old_fn = readStringAtAddress(state, arguments[0]);
  std::string new_fn = readStringAtAddress(state, arguments[1]);
  KLEE_DEBUG_WITH_TYPE("alias_handling", llvm::errs()
                                             << "Replacing " << old_fn
                                             << "() with " << new_fn << "()\n");
  if (old_fn == new_fn)
    state.removeFnAlias(old_fn);
  else
    state.addFnAlias(old_fn, new_fn);
}

void SpecialFunctionHandler::handleAssert(ExecutionState &state,
                                          KInstruction *target,
                                          std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 3 && "invalid number of arguments to _assert");
  executor.terminateStateOnError(
      state, "ASSERTION FAIL: " + readStringAtAddress(state, arguments[0]),
      Executor::Assert);
}

void SpecialFunctionHandler::handleAssertFail(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 4 &&
         "invalid number of arguments to __assert_fail");
  executor.terminateStateOnError(
      state, "ASSERTION FAIL: " + readStringAtAddress(state, arguments[0]),
      Executor::Assert);
}

void SpecialFunctionHandler::handleReportError(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 4 &&
         "invalid number of arguments to klee_report_error");

  // arguments[0], arguments[1] are file, line
  executor.terminateStateOnError(
      state, readStringAtAddress(state, arguments[2]), Executor::ReportError,
      readStringAtAddress(state, arguments[3]).c_str());
}

void SpecialFunctionHandler::handleOpenMerge(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  if (!UseMerge) {
    klee_warning_once(0, "klee_open_merge ignored, use '-use-merge'");
    return;
  }

  state.openMergeStack.push_back(
      ref<MergeHandler>(new MergeHandler(&executor, &state)));

  if (DebugLogMerge)
    llvm::errs() << "open merge: " << &state << "\n";
}

void SpecialFunctionHandler::handleCloseMerge(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  if (!UseMerge) {
    klee_warning_once(0, "klee_close_merge ignored, use '-use-merge'");
    return;
  }
  Instruction *i = target->inst;

  if (DebugLogMerge)
    llvm::errs() << "close merge: " << &state << " at " << i << '\n';

  if (state.openMergeStack.empty()) {
    std::ostringstream warning;
    warning << &state << " ran into a close at " << i
            << " without a preceding open";
    klee_warning("%s", warning.str().c_str());
  } else {
    assert(executor.inCloseMerge.find(&state) == executor.inCloseMerge.end() &&
           "State cannot run into close_merge while being closed");
    executor.inCloseMerge.insert(&state);
    state.openMergeStack.back()->addClosedState(&state, i);
    state.openMergeStack.pop_back();
  }
}

void SpecialFunctionHandler::handleNew(ExecutionState &state,
                                       KInstruction *target,
                                       std::vector<ref<Expr>> &arguments) {
  // XXX should type check args
  assert(arguments.size() == 1 && "invalid number of arguments to new");

  executor.executeAlloc(state, arguments[0], false, target);
}

void SpecialFunctionHandler::handleDelete(ExecutionState &state,
                                          KInstruction *target,
                                          std::vector<ref<Expr>> &arguments) {
  // FIXME: Should check proper pairing with allocation type (malloc/free,
  // new/delete, new[]/delete[]).

  // XXX should type check args
  assert(arguments.size() == 1 && "invalid number of arguments to delete");
  executor.executeFree(state, arguments[0]);
}

void SpecialFunctionHandler::handleNewArray(ExecutionState &state,
                                            KInstruction *target,
                                            std::vector<ref<Expr>> &arguments) {
  // XXX should type check args
  assert(arguments.size() == 1 && "invalid number of arguments to new[]");
  executor.executeAlloc(state, arguments[0], false, target);
}

void SpecialFunctionHandler::handleDeleteArray(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  // XXX should type check args
  assert(arguments.size() == 1 && "invalid number of arguments to delete[]");
  executor.executeFree(state, arguments[0]);
}

void SpecialFunctionHandler::handleMalloc(ExecutionState &state,
                                          KInstruction *target,
                                          std::vector<ref<Expr>> &arguments) {
  // XXX should type check args
  assert(arguments.size() == 1 && "invalid number of arguments to malloc");
  executor.executeAlloc(state, arguments[0], false, target);
}

void SpecialFunctionHandler::handleMemalign(ExecutionState &state,
                                            KInstruction *target,
                                            std::vector<ref<Expr>> &arguments) {
  if (arguments.size() != 2) {
    executor.terminateStateOnError(state,
                                   "Incorrect number of arguments to "
                                   "memalign(size_t alignment, size_t size)",
                                   Executor::User);
    return;
  }

  std::pair<ref<Expr>, ref<Expr>> alignmentRangeExpr =
      executor.solver->getRange(state, arguments[0]);
  ref<Expr> alignmentExpr = alignmentRangeExpr.first;
  auto alignmentConstExpr = dyn_cast<ConstantExpr>(alignmentExpr);

  if (!alignmentConstExpr) {
    executor.terminateStateOnError(
        state, "Could not determine size of symbolic alignment",
        Executor::User);
    return;
  }

  uint64_t alignment = alignmentConstExpr->getZExtValue();

  // Warn, if the expression has more than one solution
  if (alignmentRangeExpr.first != alignmentRangeExpr.second) {
    klee_warning_once(
        0, "Symbolic alignment for memalign. Choosing smallest alignment");
  }

  executor.executeAlloc(state, arguments[1], false, target, false, 0,
                        alignment);
}

void SpecialFunctionHandler::handleAssume(ExecutionState &state,
                                          KInstruction *target,
                                          std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 && "invalid number of arguments to klee_assume");

  ref<Expr> e = arguments[0];

  if (e->getWidth() != Expr::Bool)
    e = NeExpr::create(e, ConstantExpr::create(0, e->getWidth()));

  bool res;
  bool success __attribute__((unused)) =
      executor.solver->mustBeFalse(state, e, res);
  assert(success && "FIXME: Unhandled solver failure");
  if (res) {
    if (SilentKleeAssume) {
      executor.terminateState(state);
    } else {
      executor.terminateStateOnError(
          state, "invalid klee_assume call (provably false)", Executor::User);
    }
  } else {
    executor.addConstraint(state, e);
  }
}

void SpecialFunctionHandler::handleIsSymbolic(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 &&
         "invalid number of arguments to klee_is_symbolic");

  executor.bindLocal(
      target, state,
      ConstantExpr::create(!isa<ConstantExpr>(arguments[0]), Expr::Int32));
}

void SpecialFunctionHandler::handlePreferCex(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 2 &&
         "invalid number of arguments to klee_prefex_cex");

  ref<Expr> cond = arguments[1];
  if (cond->getWidth() != Expr::Bool)
    cond = NeExpr::create(cond, ConstantExpr::alloc(0, cond->getWidth()));

  Executor::ExactResolutionList rl;
  executor.resolveExact(state, arguments[0], rl, "prefex_cex");

  assert(rl.size() == 1 &&
         "prefer_cex target must resolve to precisely one object");

  rl[0].first.first->cexPreferences.push_back(cond);
}

void SpecialFunctionHandler::handlePosixPreferCex(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  if (ReadablePosix)
    return handlePreferCex(state, target, arguments);
}

void SpecialFunctionHandler::handlePrintExpr(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 2 &&
         "invalid number of arguments to klee_print_expr");

  std::string msg_str = readStringAtAddress(state, arguments[0]);
  llvm::errs() << msg_str << ":" << arguments[1] << "\n";
}

void SpecialFunctionHandler::handleSetForking(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 &&
         "invalid number of arguments to klee_set_forking");
  ref<Expr> value = executor.toUnique(state, arguments[0]);

  if (ConstantExpr *CE = dyn_cast<ConstantExpr>(value)) {
    state.forkDisabled = CE->isZero();
  } else {
    executor.terminateStateOnError(
        state, "klee_set_forking requires a constant arg", Executor::User);
  }
}

void SpecialFunctionHandler::handleStackTrace(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  state.dumpStack(outs());
}

void SpecialFunctionHandler::handleWarning(ExecutionState &state,
                                           KInstruction *target,
                                           std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 &&
         "invalid number of arguments to klee_warning");

  std::string msg_str = readStringAtAddress(state, arguments[0]);
  klee_warning("%s: %s", state.stack.back().kf->function->getName().data(),
               msg_str.c_str());
}

void SpecialFunctionHandler::handleWarningOnce(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 &&
         "invalid number of arguments to klee_warning_once");

  std::string msg_str = readStringAtAddress(state, arguments[0]);
  klee_warning_once(0, "%s: %s",
                    state.stack.back().kf->function->getName().data(),
                    msg_str.c_str());
}

void SpecialFunctionHandler::handlePrintRange(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 2 &&
         "invalid number of arguments to klee_print_range");

  std::string msg_str = readStringAtAddress(state, arguments[0]);
  llvm::errs() << msg_str << ":" << arguments[1];
  if (!isa<ConstantExpr>(arguments[1])) {
    // FIXME: Pull into a unique value method?
    ref<ConstantExpr> value;
    bool success __attribute__((unused)) =
        executor.solver->getValue(state, arguments[1], value);
    assert(success && "FIXME: Unhandled solver failure");
    bool res;
    success = executor.solver->mustBeTrue(
        state, EqExpr::create(arguments[1], value), res);
    assert(success && "FIXME: Unhandled solver failure");
    if (res) {
      llvm::errs() << " == " << value;
    } else {
      llvm::errs() << " ~= " << value;
      std::pair<ref<Expr>, ref<Expr>> res =
          executor.solver->getRange(state, arguments[1]);
      llvm::errs() << " (in [" << res.first << ", " << res.second << "])";
    }
  }
  llvm::errs() << "\n";
}

void SpecialFunctionHandler::handleGetObjSize(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  // XXX should type check args
  assert(arguments.size() == 1 &&
         "invalid number of arguments to klee_get_obj_size");
  Executor::ExactResolutionList rl;
  executor.resolveExact(state, arguments[0], rl, "klee_get_obj_size");
  for (Executor::ExactResolutionList::iterator it = rl.begin(), ie = rl.end();
       it != ie; ++it) {
    executor.bindLocal(
        target, *it->second,
        ConstantExpr::create(it->first.first->size,
                             executor.kmodule->targetData->getTypeSizeInBits(
                                 target->inst->getType())));
  }
}

void SpecialFunctionHandler::handleGetErrno(ExecutionState &state,
                                            KInstruction *target,
                                            std::vector<ref<Expr>> &arguments) {
  // XXX should type check args
  assert(arguments.size() == 0 &&
         "invalid number of arguments to klee_get_errno");
#ifndef WINDOWS
  int *errno_addr = executor.getErrnoLocation(state);
#else
  int *errno_addr = nullptr;
#endif

  // Retrieve the memory object of the errno variable
  ObjectPair result;
  bool resolved = state.addressSpace.resolveOne(
      ConstantExpr::create((uint64_t)errno_addr, Expr::Int64), result);
  if (!resolved)
    executor.terminateStateOnError(state, "Could not resolve address for errno",
                                   Executor::User);
  executor.bindLocal(target, state, result.second->read(0, Expr::Int32));
}

void SpecialFunctionHandler::handleErrnoLocation(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  // Returns the address of the errno variable
  assert(arguments.size() == 0 &&
         "invalid number of arguments to __errno_location/__error");

#ifndef WINDOWS
  int *errno_addr = executor.getErrnoLocation(state);
#else
  int *errno_addr = nullptr;
#endif

  executor.bindLocal(
      target, state,
      ConstantExpr::create((uint64_t)errno_addr,
                           executor.kmodule->targetData->getTypeSizeInBits(
                               target->inst->getType())));
}

void SpecialFunctionHandler::handleCalloc(ExecutionState &state,
                                          KInstruction *target,
                                          std::vector<ref<Expr>> &arguments) {
  // XXX should type check args
  assert(arguments.size() == 2 && "invalid number of arguments to calloc");

  ref<Expr> size = MulExpr::create(arguments[0], arguments[1]);
  executor.executeAlloc(state, size, false, target, true);
}

void SpecialFunctionHandler::handleRealloc(ExecutionState &state,
                                           KInstruction *target,
                                           std::vector<ref<Expr>> &arguments) {
  // XXX should type check args
  assert(arguments.size() == 2 && "invalid number of arguments to realloc");
  ref<Expr> address = arguments[0];
  ref<Expr> size = arguments[1];

  Executor::StatePair zeroSize =
      executor.fork(state, Expr::createIsZero(size), true);

  if (zeroSize.first) { // size == 0
    executor.executeFree(*zeroSize.first, address, target);
  }
  if (zeroSize.second) { // size != 0
    Executor::StatePair zeroPointer =
        executor.fork(*zeroSize.second, Expr::createIsZero(address), true);

    if (zeroPointer.first) { // address == 0
      executor.executeAlloc(*zeroPointer.first, size, false, target);
    }
    if (zeroPointer.second) { // address != 0
      Executor::ExactResolutionList rl;
      executor.resolveExact(*zeroPointer.second, address, rl, "realloc");

      for (Executor::ExactResolutionList::iterator it = rl.begin(),
                                                   ie = rl.end();
           it != ie; ++it) {
        executor.executeAlloc(*it->second, size, false, target, false,
                              it->first.second);
      }
    }
  }
}

void SpecialFunctionHandler::handleFree(ExecutionState &state,
                                        KInstruction *target,
                                        std::vector<ref<Expr>> &arguments) {
  // XXX should type check args
  assert(arguments.size() == 1 && "invalid number of arguments to free");
  executor.executeFree(state, arguments[0]);
}

void SpecialFunctionHandler::handleCheckMemoryAccess(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 2 &&
         "invalid number of arguments to klee_check_memory_access");

  ref<Expr> address = executor.toUnique(state, arguments[0]);
  ref<Expr> size = executor.toUnique(state, arguments[1]);
  if (!isa<ConstantExpr>(address) || !isa<ConstantExpr>(size)) {
    executor.terminateStateOnError(
        state, "check_memory_access requires constant args", Executor::User);
  } else {
    ObjectPair op;

    if (!state.addressSpace.resolveOne(cast<ConstantExpr>(address), op)) {
      executor.terminateStateOnError(state, "check_memory_access: memory error",
                                     Executor::Ptr, NULL,
                                     executor.getAddressInfo(state, address));
    } else {
      ref<Expr> chk = op.first->getBoundsCheckPointer(
          address, cast<ConstantExpr>(size)->getZExtValue());
      if (!chk->isTrue()) {
        executor.terminateStateOnError(
            state, "check_memory_access: memory error", Executor::Ptr, NULL,
            executor.getAddressInfo(state, address));
      }
    }
  }
}

void SpecialFunctionHandler::handleGetValue(ExecutionState &state,
                                            KInstruction *target,
                                            std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 &&
         "invalid number of arguments to klee_get_value");

  executor.executeGetValue(state, arguments[0], target);
}

void SpecialFunctionHandler::handleDefineFixedObject(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 2 &&
         "invalid number of arguments to klee_define_fixed_object");
  assert(isa<ConstantExpr>(arguments[0]) &&
         "expect constant address argument to klee_define_fixed_object");
  assert(isa<ConstantExpr>(arguments[1]) &&
         "expect constant size argument to klee_define_fixed_object");

  uint64_t address = cast<ConstantExpr>(arguments[0])->getZExtValue();
  uint64_t size = cast<ConstantExpr>(arguments[1])->getZExtValue();
  MemoryObject *mo =
      executor.memory->allocateFixed(address, size, state.prevPC->inst);
  executor.bindObjectInState(state, mo, false);
  mo->isUserSpecified = true; // XXX hack;
}

void SpecialFunctionHandler::handleMakeSymbolic(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  std::string name;
  std::stringstream name_stream;

  if (arguments.size() != 3) {
    executor.terminateStateOnError(state,
                                   "Incorrect number of arguments to "
                                   "klee_make_symbolic(void*, size_t, char*)",
                                   Executor::User);
    return;
  }

  name = arguments[2]->isZero() ? "" : readStringAtAddress(state, arguments[2]);
  static int id;
  if (name.length() == 0) {
    name_stream << "unnamed" << ++id;
    name = name_stream.str();
    LOG(INFO) << "klee_make_symbolic: renamed empty name to " << name;
  }

  Executor::ExactResolutionList rl;
  executor.resolveExact(state, arguments[0], rl, "make_symbolic");

  for (Executor::ExactResolutionList::iterator it = rl.begin(), ie = rl.end();
       it != ie; ++it) {
    const MemoryObject *mo = it->first.first;
    mo->setName(name);

    const ObjectState *old = it->first.second;
    ExecutionState *s = it->second;

    if (old->readOnly) {
      executor.terminateStateOnError(*s, "cannot make readonly object symbolic",
                                     Executor::User);
      return;
    }

    // FIXME: Type coercion should be done consistently somewhere.
    bool res;
    bool success __attribute__((unused)) = executor.solver->mustBeTrue(
        *s,
        EqExpr::create(
            ZExtExpr::create(arguments[1], Context::get().getPointerWidth()),
            mo->getSizeExpr()),
        res);
    assert(success && "FIXME: Unhandled solver failure");

    if (res) {
      executor.executeMakeSymbolic(*s, mo, name);
    } else {
      executor.terminateStateOnError(
          *s, "wrong size given to klee_make_symbolic[_name]", Executor::User);
    }
  }
}

void SpecialFunctionHandler::handleMarkGlobal(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 &&
         "invalid number of arguments to klee_mark_global");

  Executor::ExactResolutionList rl;
  executor.resolveExact(state, arguments[0], rl, "mark_global");

  for (Executor::ExactResolutionList::iterator it = rl.begin(), ie = rl.end();
       it != ie; ++it) {
    const MemoryObject *mo = it->first.first;
    assert(!mo->isLocal);
    mo->isGlobal = true;
  }
}

void SpecialFunctionHandler::handleAddOverflow(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  executor.terminateStateOnError(state, "overflow on addition",
                                 Executor::Overflow);
}

void SpecialFunctionHandler::handleSubOverflow(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  executor.terminateStateOnError(state, "overflow on subtraction",
                                 Executor::Overflow);
}

void SpecialFunctionHandler::handleMulOverflow(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  executor.terminateStateOnError(state, "overflow on multiplication",
                                 Executor::Overflow);
}

void SpecialFunctionHandler::handleDivRemOverflow(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  executor.terminateStateOnError(state, "overflow on division or remainder",
                                 Executor::Overflow);
}
