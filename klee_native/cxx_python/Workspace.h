/*
 * Copyright (c) 2019 Trail of Bits, Inc.
 */

#pragma once

#include <memory>
#include <string>

#include "CxxPython.h"
#include "Code.h"
#include "Entity.h"
#include "Token.h"

#include "multiplier/RPC/Search.pb.h"

namespace mu {
namespace py {

class BackendConnection;
class Stream;

// Lets us interface with a multiplier backend workspace.
class Workspace : public PythonObject<Workspace> {
 public:
  // Tries to add the `Workspace` type to the `mu_backend_api` module.
  static bool TryAddToModule(PyObject *module);

  // Tries to connect with the backend at address `address`.
  Workspace(const std::string &address);
  
  // Frees connection resources, and possibly shuts down gRPC.
  ~Workspace(void);

  // Performs an entity search.
  DEFINE_PYTHON_ARG(pattern, std::string);
  DEFINE_PYTHON_KWARG(filter, unsigned);
  DEFINE_PYTHON_KWARG(pattern_kind, int);

  BorrowedPythonPtr<Stream> SearchCode(pattern_arg pattern);

  BorrowedPythonPtr<Stream> SearchEntities(
      pattern_arg pattern, filter_kwarg opt_filter,
      pattern_kind_kwarg opt_pattern_kind);

  BorrowedPythonPtr<Stream> SearchMacroEntities(
      pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind);

  BorrowedPythonPtr<Stream> SearchEnumEntities(
      pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind);

  BorrowedPythonPtr<Stream> SearchStructureEntities(
      pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind);

  BorrowedPythonPtr<Stream> SearchClassEntities(
      pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind);

  BorrowedPythonPtr<Stream> SearchProtocolEntities(
      pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind);

  BorrowedPythonPtr<Stream> SearchUnionEntities(
      pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind);

  BorrowedPythonPtr<Stream> SearchTypeAliasEntities(
      pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind);

  BorrowedPythonPtr<Stream> SearchFunctionEntities(
      pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind);

  BorrowedPythonPtr<Stream> SearchVariableEntities(
      pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind);

  BorrowedPythonPtr<Stream> SearchFieldEntities(
      pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind);

  BorrowedPythonPtr<Stream> SearchEnumeratorEntities(
      pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind);

  BorrowedPythonPtr<Stream> SearchMethodEntities(
      pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind);

  BorrowedPythonPtr<Stream> SearchParameterEntities(
      pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind);

  BorrowedPythonPtr<Stream> SearchCallableEntities(
      pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind);

  BorrowedPythonPtr<Stream> SearchObjectEntities(
      pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind);

  DEFINE_PYTHON_ARG(token, BorrowedPythonPtr<Token>);
  BorrowedPythonPtr<Entity> FindEntityByToken(token_arg token);

  DEFINE_PYTHON_KWARG(address, std::string);
  DEFINE_PYTHON_CONSTRUCTOR(Workspace, address_kwarg address);

  BorrowedPythonPtr<Code> FindCodeContainingToken(token_arg token);

  const std::string address;
  const std::shared_ptr<BackendConnection> connection;

 private:
  Workspace(void) = delete;
};

}  // namespace py
}  // namespace mu
