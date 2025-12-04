#ifndef LASSO_UTILS_H
#define LASSO_UTILS_H

#include <napi.h>
#include <lasso/lasso.h>
#include <string>

namespace lasso_js {

// Error handling
Napi::Error LassoError(Napi::Env env, int rc, const char* context = nullptr);
void ThrowIfError(Napi::Env env, int rc, const char* context = nullptr);

// String conversion helpers
std::string GCharToString(const gchar* str);
gchar* StringToGChar(const std::string& str);

// Check if Lasso is initialized
bool IsLassoInitialized();
void SetLassoInitialized(bool initialized);

} // namespace lasso_js

#endif // LASSO_UTILS_H
