#include "utils.h"
#include <sstream>

namespace lasso_js {

static bool g_lasso_initialized = false;

bool IsLassoInitialized() {
  return g_lasso_initialized;
}

void SetLassoInitialized(bool initialized) {
  g_lasso_initialized = initialized;
}

Napi::Error LassoError(Napi::Env env, int rc, const char* context) {
  std::ostringstream msg;
  if (context) {
    msg << context << ": ";
  }
  msg << "Lasso error " << rc;

  // Get error message from Lasso if available
  const char* error_msg = lasso_strerror(rc);
  if (error_msg) {
    msg << " - " << error_msg;
  }

  return Napi::Error::New(env, msg.str());
}

void ThrowIfError(Napi::Env env, int rc, const char* context) {
  if (rc != 0) {
    throw LassoError(env, rc, context);
  }
}

std::string GCharToString(const gchar* str) {
  if (str == nullptr) {
    return "";
  }
  return std::string(str);
}

gchar* StringToGChar(const std::string& str) {
  return g_strdup(str.c_str());
}

} // namespace lasso_js
