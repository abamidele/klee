/*
 * Copyright (c) 2019 Trail of Bits, Inc.
 */

#include "Code.h"

#include <cstdint>
#include <unordered_map>
#include <vector>

#include "multiplier/RPC/Code.pb.h"
#include "multiplier/RPC/Token.h"

#include "Entity.h"
#include "Token.h"

namespace mu {
namespace py {
namespace {

DEFINE_PYTHON_METHOD(Code, Tokens, tokens);
DEFINE_PYTHON_METHOD(Code, DefinedEntities, defined_entities);
DEFINE_PYTHON_METHOD(Code, EntitiesReferencedBy, entities_referenced_by);

static PyMethodDef gCodeMethods[] = {
  PYTHON_METHOD(tokens, "Returns a tuple of post-processed tokens that make up this code."),
  PYTHON_METHOD(defined_entities, "Returns a tuple of entities defined in this code."),
  PYTHON_METHOD(entities_referenced_by, "Returns a tuple of entities defined in this code."),
  PYTHON_METHOD_SENTINEL
};

// Go mask off macro uses and substitutions so that the code we end up getting
// only refers to the expanded macros.
static void MaskExpansions(std::vector<bool> &token_mask,
                           const rpc::MacroExpansion &expansion) {
  auto begin = static_cast<size_t>(expansion.use_begin());
  auto exp_begin = static_cast<size_t>(expansion.expansion_begin());
  auto exp_end = static_cast<size_t>(expansion.expansion_end());

  if (begin > exp_begin ||
      exp_begin > exp_end ||
      exp_end >= token_mask.size()) {
    return;
  }

  for (auto i = begin; i < exp_begin; ++i) {
    token_mask[i] = false;
  }

  for (const auto &sub_expansion : expansion.expansions()) {
    MaskExpansions(token_mask, sub_expansion);
  }
}

}  // namespace

Code::~Code(void) {}

Code::Code(void)
    : token_list_id(0) {
  PythonErrorStreamer(PyExc_TypeError)
      << "Not allowed to instantiate multiplier.Code directly from Python";
}

Code::Code(const std::shared_ptr<BackendConnection> &connection,
           rpc::Code &&code)
    : token_list_id(static_cast<size_t>(code.token_list_id())) {

  std::vector<bool> token_mask;
  token_mask.assign(static_cast<size_t>(code.tokens().tokens_size()), true);
  for (const auto &macro_context : code.tokens().macro_contexts()) {
    MaskExpansions(token_mask, macro_context.expansion());
  }

  Py_ssize_t num_tokens = 0;
  auto next_i = 0;
  for (auto &&is_visible : token_mask) {
    const auto i = next_i++;
    if (!is_visible) {
      continue;
    } else {
      const auto &tok = code.tokens().tokens(i);
      const TokenId tok_id(tok.id());
      switch (tok_id.TokenKind()) {
        case rpc::TOK_EMPTY:
        case rpc::TOK_WHITESPACE:
        case rpc::TOK_LINE_CONTINUATION:
        case rpc::TOK_COMMENT:
        case rpc::MACRO_CONTEXT:
          is_visible = false;
          break;
        default:
          if (tok.data().empty()) {
            is_visible = false;
          } else {
            ++num_tokens;
          }
          break;
      }
      ++num_tokens;
    }
  }

  std::vector<SharedPythonPtr<Entity>> defs;

  std::unordered_map<uint64_t, std::vector<SharedPythonPtr<Entity>>> tok_to_ent;
  for (auto &xref : *(code.mutable_referenced_entities())) {
    const TokenId from_tok_id(xref.from_token_id());
    if (from_tok_id.TokenListId() != token_list_id
        || from_tok_id.TokenOffset() >= token_mask.size()
        || !token_mask[from_tok_id.TokenOffset()]) {
      continue;
    }

    auto py_ent = Entity::New(connection, std::move(*xref.mutable_to_entity()));
    if (!py_ent) {
      return;
    }

    // Check if this entity is defined here.
    TokenId ent_tok_id(py_ent->token_id);
    if (ent_tok_id.TokenListId() == token_list_id) {
      defs.emplace_back(py_ent.Acquire());
    }

    tok_to_ent[from_tok_id.TokenOffset()].push_back(py_ent.Give());
  }

  definitions.Take(PyTuple_New(static_cast<Py_ssize_t>(defs.size())));
  if (!definitions) {
    return;
  }

  // Collect the defined entities into a tuple.
  next_i = 0;
  for (auto &ent : defs) {
    const auto i = next_i++;
    PyTuple_SET_ITEM(definitions.Get(), i, ent.Release().Get());
  }

  for (auto &offset_ents : tok_to_ent) {
    if (offset_ents.second.empty()) {
      continue;
    }

    auto &refs = references[offset_ents.first];

    refs.Take(PyTuple_New(static_cast<Py_ssize_t>(offset_ents.second.size())));
    if (!refs) {
      return;
    }

    auto next_j = 0;
    for (auto &ent : offset_ents.second) {
      const auto j = next_j++;
      PyTuple_SET_ITEM(refs.Get(), j, ent.Release().Get());
    }
  }

  std::vector<SharedPythonPtr<Token>> py_toks;
  size_t next_token_offset = 0;
  for (auto &tok : *(code.mutable_tokens()->mutable_tokens())) {
    const auto token_offset = next_token_offset++;
    if (!token_mask[token_offset]) {
      continue;
    }

    const TokenId id(tok.id());
    const auto loc_id = TokenId::Create(id.TokenKind(), token_list_id,
                                        token_offset);

    auto py_tok = Token::New(std::move(tok), loc_id);
    if (!py_tok) {
      return;
    }

    py_toks.push_back(py_tok.Give());
  }

  tokens.Take(PyTuple_New(static_cast<Py_ssize_t>(py_toks.size())));
  if (!tokens) {
    return;
  }

  next_i = 0;
  for (auto &py_tok : py_toks) {
    const auto i = next_i++;
    PyTuple_SET_ITEM(tokens.Get(), i, py_tok.Release().Get());
  }
}

// Returns the tuple of tokens that makes up this code.
BorrowedPythonPtr<PyObject> Code::Tokens(void) {
  if (!tokens) {
    return PyTuple_New(0);
  } else {
    return tokens.Borrow();
  }
}

// Returns the tuple of entities defined in this code.
BorrowedPythonPtr<PyObject> Code::DefinedEntities(void) {
  if (!definitions) {
    return PyTuple_New(0);
  } else {
    return definitions.Borrow();
  }
}

// Returns a tuple of entities referenced by a particular token.
BorrowedPythonPtr<PyObject> Code::EntitiesReferencedBy(token_arg token) {
  auto &tok = *token;
  if (tok->loc.TokenListId() != token_list_id) {
    PythonErrorStreamer(PyExc_ValueError)
        << "Can't find entities referenced by token " << tok->loc
        << " that does not belong to the code itself (token_list_id="
        << token_list_id << ").";
    return nullptr;
  }

  const auto token_offset = tok->loc.TokenOffset();
  if (!references.count(token_offset)) {
    return PyTuple_New(0);
  }

  auto &refs = references[token_offset];
  if (!refs) {
    return PyTuple_New(0);
  }

  return refs.Borrow();
}

// Tries to add the `Code` type to the `mu_backend_api` module.
bool Code::TryAddToModule(PyObject *m) {
  gType.tp_name = "multiplier.Code";
  gType.tp_doc = "Represents code associated with one or more entities.";
  gType.tp_methods = gCodeMethods;
  gType.tp_flags |= Py_TPFLAGS_IS_ABSTRACT;
  gType.tp_iter = [] (PyObject *self_) -> PyObject * {
    auto self = reinterpret_cast<Code *>(self_);
    return PyObject_GetIter(self->tokens.Get());
  };

  if (0 != PyType_Ready(&gType)) {
    return false;
  }

  Py_INCREF(&gType);
  return !PyModule_AddObject(
      m, "Entity", reinterpret_cast<PyObject *>(&gType));
}

}  // namespace py
}  // namespace mu