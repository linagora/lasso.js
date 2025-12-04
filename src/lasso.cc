#include <napi.h>
#include <lasso/lasso.h>
#include <string>
#include "utils.h"
#include "server.h"
#include "login.h"
#include "logout.h"
#include "identity.h"
#include "session.h"

namespace lasso_js {

/**
 * Initialize Lasso library
 * Must be called before any other Lasso function
 */
Napi::Value Init(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (IsLassoInitialized()) {
    return Napi::Boolean::New(env, true);
  }

  int rc = lasso_init();
  if (rc != 0) {
    throw LassoError(env, rc, "lasso_init");
  }

  SetLassoInitialized(true);
  return Napi::Boolean::New(env, true);
}

/**
 * Shutdown Lasso library
 * Should be called when done using Lasso
 */
Napi::Value Shutdown(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!IsLassoInitialized()) {
    return Napi::Boolean::New(env, true);
  }

  int rc = lasso_shutdown();
  if (rc != 0) {
    throw LassoError(env, rc, "lasso_shutdown");
  }

  SetLassoInitialized(false);
  return Napi::Boolean::New(env, true);
}

/**
 * Check Lasso library version
 * @returns {string} Lasso version string
 * Note: This returns the version the binding was compiled against.
 * Update LASSO_JS_VERSION in binding.gyp when upgrading Lasso.
 */
Napi::Value CheckVersion(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

#ifdef LASSO_JS_VERSION
  return Napi::String::New(env, LASSO_JS_VERSION);
#else
  return Napi::String::New(env, "unknown");
#endif
}

/**
 * Check if Lasso is initialized
 * @returns {boolean} true if initialized
 */
Napi::Value IsInitialized(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  return Napi::Boolean::New(env, IsLassoInitialized());
}

/**
 * Module initialization
 */
Napi::Object InitModule(Napi::Env env, Napi::Object exports) {
  // Core functions
  exports.Set("init", Napi::Function::New(env, Init));
  exports.Set("shutdown", Napi::Function::New(env, Shutdown));
  exports.Set("checkVersion", Napi::Function::New(env, CheckVersion));
  exports.Set("isInitialized", Napi::Function::New(env, IsInitialized));

  // Classes
  Server::Init(env, exports);
  Login::Init(env, exports);
  Logout::Init(env, exports);
  Identity::Init(env, exports);
  Session::Init(env, exports);

  // Constants - HTTP methods
  Napi::Object httpMethod = Napi::Object::New(env);
  httpMethod.Set("NONE", Napi::Number::New(env, LASSO_HTTP_METHOD_NONE));
  httpMethod.Set("GET", Napi::Number::New(env, LASSO_HTTP_METHOD_GET));
  httpMethod.Set("POST", Napi::Number::New(env, LASSO_HTTP_METHOD_POST));
  httpMethod.Set("REDIRECT", Napi::Number::New(env, LASSO_HTTP_METHOD_REDIRECT));
  httpMethod.Set("SOAP", Napi::Number::New(env, LASSO_HTTP_METHOD_SOAP));
  httpMethod.Set("ARTIFACT_GET", Napi::Number::New(env, LASSO_HTTP_METHOD_ARTIFACT_GET));
  httpMethod.Set("ARTIFACT_POST", Napi::Number::New(env, LASSO_HTTP_METHOD_ARTIFACT_POST));
  exports.Set("HttpMethod", httpMethod);

  // Constants - Signature methods
  Napi::Object signatureMethod = Napi::Object::New(env);
  signatureMethod.Set("RSA_SHA1", Napi::Number::New(env, LASSO_SIGNATURE_METHOD_RSA_SHA1));
  signatureMethod.Set("RSA_SHA256", Napi::Number::New(env, LASSO_SIGNATURE_METHOD_RSA_SHA256));
  signatureMethod.Set("RSA_SHA384", Napi::Number::New(env, LASSO_SIGNATURE_METHOD_RSA_SHA384));
  signatureMethod.Set("RSA_SHA512", Napi::Number::New(env, LASSO_SIGNATURE_METHOD_RSA_SHA512));
  exports.Set("SignatureMethod", signatureMethod);

  // Constants - Name ID formats
  Napi::Object nameIdFormat = Napi::Object::New(env);
  nameIdFormat.Set("UNSPECIFIED", Napi::String::New(env, LASSO_SAML2_NAME_IDENTIFIER_FORMAT_UNSPECIFIED));
  nameIdFormat.Set("EMAIL", Napi::String::New(env, LASSO_SAML2_NAME_IDENTIFIER_FORMAT_EMAIL));
  nameIdFormat.Set("PERSISTENT", Napi::String::New(env, LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT));
  nameIdFormat.Set("TRANSIENT", Napi::String::New(env, LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT));
  nameIdFormat.Set("ENCRYPTED", Napi::String::New(env, LASSO_SAML2_NAME_IDENTIFIER_FORMAT_ENCRYPTED));
  nameIdFormat.Set("KERBEROS", Napi::String::New(env, LASSO_SAML2_NAME_IDENTIFIER_FORMAT_KERBEROS));
  exports.Set("NameIdFormat", nameIdFormat);

  return exports;
}

NODE_API_MODULE(lasso, InitModule)

} // namespace lasso_js
