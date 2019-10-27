#include "Process.h"

namespace klee_native{
namespace py {


namespace {

//DEFINE_PYTHON_METHOD(klee_native::py::Process, Memory, memory);
static std::string gDefault = "12345";

static PyMethodDef gProcessMethods[] = {
//    PYTHON_METHOD(memory, "Retrieves an address space object for the corresponding Process"),
//    PYTHON_METHOD_SENTINEL,
};

static std::string getPid(Process::pid_kwarg pid) {
  return pid ? *pid: gDefault;
}

} // namespace

Process::Process(const std::string& pid_):
  pid(pid_) {}


Process::Process(pid_kwarg pid)
    : Process(getPid(pid)) {}

Process::~Process(void) {}

/*
PyObject * Process::Memory(void) {
  PyObject *a;
  uint64_t b = 1337;
  convert::ToI64(a,&b);
  return a;
}
*/

bool Process::TryAddToModule(PyObject *module) {
  PyType_Ready(&gType);
  gType.tp_name = "klee_native.Process";
  gType.tp_doc = "Contains memory information about a given process";
  gType.tp_methods = gProcessMethods;
  if (0 != PyType_Ready(&gType)) {
    return false;
  }

  Py_INCREF(&gType);
  return!PyModule_AddObject(
      module, "Process", reinterpret_cast<PyObject *>(&gType));
}


} // namespace py
} // namespace klee_native
