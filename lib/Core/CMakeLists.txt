#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#

klee_add_component(kleeCore
  AddressSpace.cpp
  MergeHandler.cpp
  CallPathManager.cpp
  Context.cpp
  CoreStats.cpp
  ExecutionState.cpp
  Executor.cpp
  ExecutorTimers.cpp
  ExecutorUtil.cpp
  ExternalDispatcher.cpp
  ImpliedValue.cpp
  Memory.cpp
  MemoryManager.cpp
  PTree.cpp
  Searcher.cpp
  SeedInfo.cpp
  SpecialFunctionHandler.cpp
  StatsTracker.cpp
  TimingSolver.cpp
  UserSearcher.cpp

  TraceManager.cpp
  TraceLifter.cpp
  Program/AddressSpace.cpp
  Program/MappedRange.cpp
  Program/ShadowMemory.cpp

  Util/AreaAllocator.cpp
  Util/Hash.cpp
  Util/Timer.cpp
  Util/Util.cpp
  Util/ZoneAllocator.cpp

  xxHash/xxhash.c
)

# TODO: Work out what the correct LLVM components are for
# kleeCore.
set(LLVM_COMPONENTS
  core
  support
)

if ("${LLVM_PACKAGE_VERSION}" VERSION_EQUAL "3.6" OR
    "${LLVM_PACKAGE_VERSION}" VERSION_GREATER "3.6")
  list(APPEND LLVM_COMPONENTS mcjit executionengine native)
else()
  list(APPEND LLVM_COMPONENTS jit engine)
endif()

# remill                                                                                                          
if(NOT TARGET remill)
  if("${PLATFORM_NAME}" STREQUAL "windows")
    set(REMILL_FINDPACKAGE_HINTS HINTS "${CMAKE_INSTALL_PREFIX}/remill/lib")
  endif()
  find_package(remill REQUIRED ${REMILL_FINDPACKAGE_HINTS})
endif()

klee_get_llvm_libs(LLVM_LIBS ${LLVM_COMPONENTS})
target_link_libraries(kleeCore PUBLIC ${LLVM_LIBS})
target_link_libraries(kleeCore PRIVATE
  remill
  kleeBasic
  kleeModule
  kleaverSolver
  kleaverExpr
  kleeSupport
)
