#ifndef LASSO_PROVIDER_H
#define LASSO_PROVIDER_H

#include <napi.h>

// Include libxml2 headers before lasso.h to avoid extern "C" template conflict
#include <libxml/tree.h>
#include <libxml/parser.h>

#include <lasso/lasso.h>

namespace lasso_js {

// Provider is a simple wrapper - providers are created/managed by Server
// This file provides utility functions for provider operations

// No class needed for now - providers are returned as plain objects from Server.getProvider()

} // namespace lasso_js

#endif // LASSO_PROVIDER_H
