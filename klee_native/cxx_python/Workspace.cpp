/*
 * Copyright (c) 2019 Trail of Bits, Inc.
 */

#include "Workspace.h"

#include <atomic>
#include <grpcpp/grpcpp.h>

#include "Backend.h"
#include "Entity.h"
#include "Stream.h"

#include "multiplier/Workspace/Config.h"

namespace mu {
namespace py {
namespace {

DEFINE_PYTHON_METHOD(Workspace, SearchEntities, search_entities);
DEFINE_PYTHON_METHOD(Workspace, SearchMacroEntities, search_macro_entities);
DEFINE_PYTHON_METHOD(Workspace, SearchEnumEntities, search_enum_entities);
DEFINE_PYTHON_METHOD(Workspace, SearchStructureEntities, search_structure_entities);
DEFINE_PYTHON_METHOD(Workspace, SearchClassEntities, search_class_entities);
DEFINE_PYTHON_METHOD(Workspace, SearchProtocolEntities, search_protocol_entities);
DEFINE_PYTHON_METHOD(Workspace, SearchUnionEntities, search_union_entities);
DEFINE_PYTHON_METHOD(Workspace, SearchTypeAliasEntities, search_type_alias_entities);
DEFINE_PYTHON_METHOD(Workspace, SearchFunctionEntities, search_function_entities);
DEFINE_PYTHON_METHOD(Workspace, SearchVariableEntities, search_variable_entities);
DEFINE_PYTHON_METHOD(Workspace, SearchFieldEntities, search_field_entities);
DEFINE_PYTHON_METHOD(Workspace, SearchEnumeratorEntities, search_enumerator_entities);
DEFINE_PYTHON_METHOD(Workspace, SearchMethodEntities, search_method_entities);
DEFINE_PYTHON_METHOD(Workspace, SearchParameterEntities, search_parameter_entities);
DEFINE_PYTHON_METHOD(Workspace, SearchCallableEntities, search_callable_entities);
DEFINE_PYTHON_METHOD(Workspace, SearchObjectEntities, search_object_entities);
DEFINE_PYTHON_METHOD(Workspace, SearchCode, search_code);
DEFINE_PYTHON_METHOD(Workspace, FindEntityByToken, find_entity_by_token);
DEFINE_PYTHON_METHOD(Workspace, FindCodeContainingToken, find_code_containing_token);

static PyMethodDef gWorkspaceMethods[] = {
  PYTHON_METHOD(search_entities, "Generate a sequence of entities whose fully qualified names match some search criteria."),
  PYTHON_METHOD(search_macro_entities, "Generate a sequence of macro entities whose fully qualified names match some search criteria."),
  PYTHON_METHOD(search_enum_entities, "Generate a sequence of enum entities whose fully qualified names match some search criteria."),
  PYTHON_METHOD(search_structure_entities, "Generate a sequence of structure entities whose fully qualified names match some search criteria."),
  PYTHON_METHOD(search_class_entities, "Generate a sequence of class entities whose fully qualified names match some search criteria."),
  PYTHON_METHOD(search_protocol_entities, "Generate a sequence of protocol entities whose fully qualified names match some search criteria."),
  PYTHON_METHOD(search_union_entities, "Generate a sequence of union entities whose fully qualified names match some search criteria."),
  PYTHON_METHOD(search_type_alias_entities, "Generate a sequence of type alias entities whose fully qualified names match some search criteria."),
  PYTHON_METHOD(search_function_entities, "Generate a sequence of function entities whose fully qualified names match some search criteria."),
  PYTHON_METHOD(search_variable_entities, "Generate a sequence of variable (locals, globals, NOT parameters or static fields of classes/structures/unions) entities whose fully qualified names match some search criteria."),
  PYTHON_METHOD(search_field_entities, "Generate a sequence of field (instance and class) entities whose fully qualified names match some search criteria."),
  PYTHON_METHOD(search_enumerator_entities, "Generate a sequence of enumerator entities whose fully qualified names match some search criteria."),
  PYTHON_METHOD(search_method_entities, "Generate a sequence of method (instance and class) entities whose fully qualified names match some search criteria."),
  PYTHON_METHOD(search_parameter_entities, "Generate a sequence of function parameter entities whose fully qualified names match some search criteria."),
  PYTHON_METHOD(search_callable_entities, "Generate a sequence of function and method entities whose fully qualified names match some search criteria."),
  PYTHON_METHOD(search_object_entities, "Generate a sequence of object entities (classes, structures, unions) whose fully qualified names match some search criteria."),
  PYTHON_METHOD(search_code, "Generate a sequence of code objects that contain tokens matching some pattern text."),
  PYTHON_METHOD(find_entity_by_token, "Return the entity corresponding to the given Token, if there is one."),
  PYTHON_METHOD(find_code_containing_token, "Return the Code containing a given token."),
  PYTHON_METHOD_SENTINEL,
};

// Return the address for connecting.
static std::string GetAddress(Workspace::address_kwarg opt_address) {
  return opt_address ? *opt_address : Config::gBackendAddress;
}

static std::shared_ptr<BackendConnection> TryConnect(std::string address) {
  auto maybe_c = BackendConnection::TryConnect(address);
  if (maybe_c) {
    return *maybe_c;

  } else {
    llvm::handleAllErrors(
        maybe_c.takeError(),
        [=] (llvm::StringError &e) {
          PythonErrorStreamer(PyExc_ConnectionError)
              << "Unable to connect with Multiplier backend at '"
              << address << "': " << e.getMessage();
        });
    return std::shared_ptr<BackendConnection>();
  }
}

// Generator consuming a stream producing `rpc::Code` items, and generating
// `Code` Python objects.
class CodeGenerator : public Generator {
 public:
  virtual ~CodeGenerator(void) = default;

  explicit CodeGenerator(
      const std::shared_ptr<BackendConnection> &connection_,
      const BackendResultStreamPtr<rpc::Code> &stream_)
      : connection(connection_),
        stream(stream_) {}

  // Fetch the next `main` function.
  BorrowedPythonPtr<PyObject> Next(void) override {
    if (stream.Next(&code)) {
      return Code::New(connection, std::move(code));
    } else {
      return nullptr;
    }
  }

 private:
  const std::shared_ptr<BackendConnection> connection;
  const BackendResultStreamPtr<rpc::Code> stream;
  rpc::Code code;
};

// Generator consuming a stream producing `rpc::Entity` items, and generating
// `Entity` Python objects.
class EntityGenerator : public Generator {
 public:
  virtual ~EntityGenerator(void) = default;

  explicit EntityGenerator(
      const std::shared_ptr<BackendConnection> &connection_,
      const BackendResultStreamPtr<rpc::Entity> &stream_)
      : connection(connection_),
        stream(stream_) {}

  // Fetch the next `main` function.
  BorrowedPythonPtr<PyObject> Next(void) override {
    if (stream.Next(&entity)) {
      return Entity::New(connection, std::move(entity));
    } else {
      return nullptr;
    }
  }

 private:
  const std::shared_ptr<BackendConnection> connection;
  const BackendResultStreamPtr<rpc::Entity> stream;
  rpc::Entity entity;
};

}  // namespace

// Tries to connect with the backend at address `address`.
Workspace::Workspace(const std::string &address_)
    : address(address_),
      connection(TryConnect(address)) {}

// Python constructor; tries to connect to the backend, and takes an optional
// keyword argument for the address.
Workspace::Workspace(address_kwarg opt_address)
    : Workspace(GetAddress(opt_address)) {}

// Frees connection resources, and possibly shuts down gRPC.
Wxorkspace::~Workspace(void) {}

BorrowedPythonPtr<Entity> Workspace::FindEntityByToken(token_arg token) {
  if (!connection) {
    PythonErrorStreamer(PyExc_ConnectionError)
        << "Unable to connect with backend at address '" << address << "'";
    return nullptr;
  }

  rpc::Entity entity;
  if (!connection->TryGetEntityByTokenId((*token)->id, &entity)) {
    return nullptr;
  }

  return Entity::New(connection, std::move(entity));
}

BorrowedPythonPtr<Code> Workspace::FindCodeContainingToken(token_arg token) {
  if (!connection) {
    PythonErrorStreamer(PyExc_ConnectionError)
        << "Unable to connect with backend at address '" << address << "'";
    return nullptr;
  }

  auto &tok = *token;

  rpc::Code code;
  if (tok->loc.IsValid() &&
      connection->TryGetCodeContainingTokenId(tok->loc, &code)) {
    return Code::New(connection, std::move(code));

  } else if (tok->id.IsValid() &&
             connection->TryGetCodeContainingTokenId(tok->id, &code)) {
    return Code::New(connection, std::move(code));

  } else {
    return nullptr;
  }
}

// Performs a code search, that returns a stream of `rpc::Code`.
BorrowedPythonPtr<Stream> Workspace::SearchCode(pattern_arg pattern) {
  rpc::CodeSearchRequest req;
  req.set_pattern(*pattern);

  std::unique_ptr<Generator> gen(new CodeGenerator(
      connection, connection->SearchCode(req)));

  return Stream::New(std::move(gen));
}

// Performs an entity search.
BorrowedPythonPtr<Stream> Workspace::SearchEntities(
    pattern_arg pattern, filter_kwarg opt_filter,
    pattern_kind_kwarg opt_pattern_kind) {
  rpc::EntityIndexQueryParameters params;

  auto filt_all = (1U << static_cast<unsigned>(rpc::EntityType_ARRAYSIZE)) - 1U;
  const auto filt = opt_filter ? *opt_filter : filt_all;

  if (filt & ~filt_all) {
    PythonErrorStreamer(PyExc_ValueError)
        << "Invalid bitmask passed to 'filter' keyword argument of "
        << "Workspace.search_entities(); make sure to use only the "
        << "'multiplier.FILTER_*_ENTITIES' variables for making a filter mask";
    return nullptr;
  }

  const int pattern_kind = opt_pattern_kind ? *opt_pattern_kind
                                             : rpc::CASE_SENSITIVE_FIXED_STRING;

  if (!rpc::FilterSyntax_IsValid(pattern_kind)) {
    PythonErrorStreamer(PyExc_ValueError)
        << "Invalid value passed to 'pattern' keyword argument of "
        << "Workspace.search_entities(); make sure to use only the "
        << "'multiplier.PATTERN_*' variables for specifying the pattern kind";
    return nullptr;
  }

  params.set_pattern(*pattern);
  params.set_filter_syntax(static_cast<rpc::FilterSyntax>(pattern_kind));

  for (auto i = 0; i < rpc::EntityType_ARRAYSIZE; ++i) {
    const auto mask = 1U << static_cast<unsigned>(i);
    if (mask & filt) {
      params.add_type_filter(static_cast<rpc::EntityType>(i));
    }
  }

  std::unique_ptr<Generator> gen(new EntityGenerator(
      connection, connection->SearchEntities(params)));

  return Stream::New(std::move(gen));
}

BorrowedPythonPtr<Stream> Workspace::SearchMacroEntities(
    pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind) {
  return SearchEntities(pattern, static_cast<unsigned>(1U << rpc::MACROS),
                        opt_pattern_kind);
}

BorrowedPythonPtr<Stream> Workspace::SearchEnumEntities(
    pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind) {
  return SearchEntities(pattern, static_cast<unsigned>(1U << rpc::ENUMS),
                        opt_pattern_kind);
}

BorrowedPythonPtr<Stream> Workspace::SearchStructureEntities(
    pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind) {
  return SearchEntities(pattern, static_cast<unsigned>(1U << rpc::STRUCTURES),
                        opt_pattern_kind);
}

BorrowedPythonPtr<Stream> Workspace::SearchClassEntities(
    pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind) {
  return SearchEntities(pattern, static_cast<unsigned>(1U << rpc::CLASSES),
                        opt_pattern_kind);
}

BorrowedPythonPtr<Stream> Workspace::SearchProtocolEntities(
    pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind) {
  return SearchEntities(pattern, static_cast<unsigned>(1U << rpc::PROTOCOLS),
                        opt_pattern_kind);
}

BorrowedPythonPtr<Stream> Workspace::SearchUnionEntities(
    pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind) {
  return SearchEntities(pattern, static_cast<unsigned>(1U << rpc::UNIONS),
                        opt_pattern_kind);
}

BorrowedPythonPtr<Stream> Workspace::SearchTypeAliasEntities(
    pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind) {
  return SearchEntities(pattern, static_cast<unsigned>(1U << rpc::TYPE_ALIASES),
                        opt_pattern_kind);
}

BorrowedPythonPtr<Stream> Workspace::SearchFunctionEntities(
    pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind) {
  return SearchEntities(pattern, static_cast<unsigned>(1U << rpc::FUNCTIONS),
                        opt_pattern_kind);
}

BorrowedPythonPtr<Stream> Workspace::SearchVariableEntities(
    pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind) {
  return SearchEntities(pattern, static_cast<unsigned>(1U << rpc::VARIABLES),
                        opt_pattern_kind);
}

BorrowedPythonPtr<Stream> Workspace::SearchFieldEntities(
    pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind) {
  return SearchEntities(pattern, static_cast<unsigned>(1U << rpc::FIELDS),
                        opt_pattern_kind);
}

BorrowedPythonPtr<Stream> Workspace::SearchEnumeratorEntities(
    pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind) {
  return SearchEntities(
      pattern, static_cast<unsigned>(1U << rpc::ENUM_CONSTANTS),
      opt_pattern_kind);
}

BorrowedPythonPtr<Stream> Workspace::SearchMethodEntities(
    pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind) {
  return SearchEntities(pattern, static_cast<unsigned>(1U << rpc::METHODS),
                        opt_pattern_kind);
}

BorrowedPythonPtr<Stream> Workspace::SearchParameterEntities(
    pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind) {
  return SearchEntities(pattern, static_cast<unsigned>(1U << rpc::PARAMETERS),
                        opt_pattern_kind);
}

BorrowedPythonPtr<Stream> Workspace::SearchCallableEntities(
    pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind) {
  return SearchEntities(
      pattern,
      static_cast<unsigned>(1U << rpc::FUNCTIONS) |
      static_cast<unsigned>(1U << rpc::METHODS),
      opt_pattern_kind);
}

BorrowedPythonPtr<Stream> Workspace::SearchObjectEntities(
    pattern_arg pattern, pattern_kind_kwarg opt_pattern_kind) {
  return SearchEntities(
      pattern,
      static_cast<unsigned>(1U << rpc::STRUCTURES) |
      static_cast<unsigned>(1U << rpc::UNIONS) |
      static_cast<unsigned>(1U << rpc::CLASSES),
      opt_pattern_kind);
}

// Tries to add the `Workspace` type to the `mu_backend_api` module.
bool Workspace::TryAddToModule(PyObject *m) {
  gType.tp_name = "multiplier.Workspace";
  gType.tp_doc = "Persistent connection to a multiplier backend.";
  gType.tp_methods = gWorkspaceMethods;
  if (0 != PyType_Ready(&gType)) {
    return false;
  }

  Py_INCREF(&gType);
  return !PyModule_AddObject(
      m, "Workspace", reinterpret_cast<PyObject *>(&gType));
}

}  // namespace py
}  // namespace mu
