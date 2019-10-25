#include "Process.h"

namespace klee_native{
namespace py {
namespace {

DEFINE_PYTHON_METHOD(Process, Memory, memory);

static PyMethodDef gProcessMethods[] = {
    PYTHON_METHOD(memory, "Retrieves an address space object for the corresponding Process"),
    PYTHON_METHOD_SENTINEL,
};

} // namespace

Process::Process(pid_t pid):
  pid(pid) {}

PyObject * Process::Memory(void){
  PyObject *a;
  uint64_t b = 1337;
  convert::ToI64(a,&b);
  return a;
}


bool Process::TryAddToModule(PyObject *module) {
  gType.tp_name = "klee_native.Process";
  PyType_Ready(&gType);
  gType.tp_name = "klee_native.Process";
  gType.tp_doc = "Contains memory information about a given process";
  gType.tp_methods = gProcessMethods;
  if (0 != PyType_Ready(&gType)) {
    return false;
  }

  Py_INCREF(&gType);
  return !PyModule_AddObject(
      module, "Process", reinterpret_cast<PyObject *>(&gType));
}

} // namespace py
} // namespace klee_native
