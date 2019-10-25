/*
 * Copyright (c) 2019 Trail of Bits, Inc.
 */

#include "CxxPython.h"
#include "Process.h"

#include <cstring>
#include <iostream>

namespace klee_native {
namespace py {

namespace {

struct ModuleState {
  PyObject *error;
};

static PyMethodDef gModuleMethods[] = {
  {}   // Sentinel.
};

static struct PyModuleDef gModuleDef = {
  PyModuleDef_HEAD_INIT,
  "klee_native_api",
  "klee symbolic execution API for native binaries",
  sizeof(struct ModuleState),
  gModuleMethods,
  nullptr,
  nullptr,
  nullptr,
  nullptr
};

}  // namespace

PyMODINIT_FUNC PyInit_klee_native_api(void) {
  auto m = PyModule_Create(&gModuleDef);
  if (!m) {
    return nullptr;
  }

  if (!Process::TryAddToModule(m)){
    return nullptr;
  }

  return m;
}

}  // namespace py
}  // namespace klee_native
