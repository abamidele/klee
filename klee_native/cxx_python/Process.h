/*
 * Copyright (c) 2019 Trail of Bits, Inc.
 */

#pragma once
#include "CxxPython.h"
#include "Native/Memory/MappedRange.h"
#include "Native/Memory/AddressSpace.h"

namespace klee_native {
namespace py {

class Process : public PythonObject<Process> {
public:
  static bool TryAddToModule(PyObject *module);
  Process(pid_t pid);
  ~Process(void);

  //DEFINE_PYTHON_KWARG(execve_args, std::vector<void *>);
  DEFINE_PYTHON_KWARG(pid, uint64_t);
  DEFINE_PYTHON_CONSTRUCTOR(Process);

  PyObject *Memory(void);

  pid_t pid;
};

} // namespace py
} //  namespace klee_native
