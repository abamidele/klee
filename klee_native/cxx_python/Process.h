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
  Process(const std::string& pid_);
  ~Process(void);

  //DEFINE_PYTHON_KWARG(execve_args, std::vector<void *>);
  DEFINE_PYTHON_KWARG(pid, std::string);
  DEFINE_PYTHON_CONSTRUCTOR(Process, pid_kwarg pid);

  //PyObject *Memory(void);

  std::string pid;
};


} // namespace py
} //  namespace klee_native
