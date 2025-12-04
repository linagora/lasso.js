#include "logout.h"
#include "identity.h"
#include "session.h"
#include "utils.h"

namespace lasso_js {

Napi::FunctionReference Logout::constructor;

Napi::Object Logout::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function func = DefineClass(env, "Logout", {
    // Methods
    InstanceMethod("initRequest", &Logout::InitRequest),
    InstanceMethod("buildRequestMsg", &Logout::BuildRequestMsg),
    InstanceMethod("processRequestMsg", &Logout::ProcessRequestMsg),
    InstanceMethod("validateRequest", &Logout::ValidateRequest),
    InstanceMethod("buildResponseMsg", &Logout::BuildResponseMsg),
    InstanceMethod("processResponseMsg", &Logout::ProcessResponseMsg),
    InstanceMethod("getNextProviderId", &Logout::GetNextProviderId),

    // Getters/Setters
    InstanceAccessor("identity", &Logout::GetIdentity, &Logout::SetIdentity),
    InstanceAccessor("session", &Logout::GetSession, &Logout::SetSession),
    InstanceAccessor("msgUrl", &Logout::GetMsgUrl, nullptr),
    InstanceAccessor("msgBody", &Logout::GetMsgBody, nullptr),
  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  exports.Set("Logout", func);
  return exports;
}

Logout::Logout(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<Logout>(info), logout_(nullptr) {
  Napi::Env env = info.Env();

  if (info.Length() < 1) {
    throw Napi::TypeError::New(env, "Expected Server as first argument");
  }

  Napi::Object serverObj = info[0].As<Napi::Object>();
  Server* server = Napi::ObjectWrap<Server>::Unwrap(serverObj);
  if (!server || !server->GetServer()) {
    throw Napi::TypeError::New(env, "Invalid Server object");
  }

  server_ref_ = Napi::Persistent(serverObj);

  logout_ = lasso_logout_new(server->GetServer());
  if (!logout_) {
    throw Napi::Error::New(env, "Failed to create Lasso logout");
  }
}

Logout::~Logout() {
  if (logout_) {
    g_object_unref(logout_);
    logout_ = nullptr;
  }
  server_ref_.Reset();
}

/**
 * Initialize a logout request
 * @param providerId - Target provider to notify (optional)
 * @param method - HTTP method
 */
Napi::Value Logout::InitRequest(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  gchar* providerId = nullptr;
  if (info.Length() > 0 && info[0].IsString()) {
    std::string providerIdStr = info[0].As<Napi::String>().Utf8Value();
    providerId = g_strdup(providerIdStr.c_str());
  }

  LassoHttpMethod method = LASSO_HTTP_METHOD_REDIRECT;
  if (info.Length() > 1 && info[1].IsNumber()) {
    method = static_cast<LassoHttpMethod>(info[1].As<Napi::Number>().Int32Value());
  }

  int rc = lasso_logout_init_request(logout_, providerId, method);
  g_free(providerId);
  ThrowIfError(env, rc, "lasso_logout_init_request");

  return env.Undefined();
}

/**
 * Build the LogoutRequest message
 */
Napi::Value Logout::BuildRequestMsg(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  int rc = lasso_logout_build_request_msg(logout_);
  ThrowIfError(env, rc, "lasso_logout_build_request_msg");

  Napi::Object result = Napi::Object::New(env);

  LassoProfile* profile = LASSO_PROFILE(logout_);
  if (profile->msg_url) {
    result.Set("responseUrl", Napi::String::New(env, profile->msg_url));
  }
  if (profile->msg_body) {
    result.Set("responseBody", Napi::String::New(env, profile->msg_body));
  }
  result.Set("httpMethod", Napi::Number::New(env, profile->http_request_method));

  return result;
}

/**
 * Process an incoming LogoutRequest
 * @param message - The SAML LogoutRequest
 * @param method - HTTP method
 */
Napi::Value Logout::ProcessRequestMsg(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    throw Napi::TypeError::New(env, "Expected message string as first argument");
  }

  std::string message = info[0].As<Napi::String>().Utf8Value();

  gchar* msg = g_strdup(message.c_str());
  int rc = lasso_logout_process_request_msg(logout_, msg);
  g_free(msg);
  ThrowIfError(env, rc, "lasso_logout_process_request_msg");

  return env.Undefined();
}

/**
 * Validate the logout request
 */
Napi::Value Logout::ValidateRequest(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  int rc = lasso_logout_validate_request(logout_);
  ThrowIfError(env, rc, "lasso_logout_validate_request");

  return env.Undefined();
}

/**
 * Build the LogoutResponse message
 */
Napi::Value Logout::BuildResponseMsg(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  int rc = lasso_logout_build_response_msg(logout_);
  ThrowIfError(env, rc, "lasso_logout_build_response_msg");

  Napi::Object result = Napi::Object::New(env);

  LassoProfile* profile = LASSO_PROFILE(logout_);
  if (profile->msg_url) {
    result.Set("responseUrl", Napi::String::New(env, profile->msg_url));
  }
  if (profile->msg_body) {
    result.Set("responseBody", Napi::String::New(env, profile->msg_body));
  }
  result.Set("httpMethod", Napi::Number::New(env, profile->http_request_method));

  return result;
}

/**
 * Process an incoming LogoutResponse
 * @param message - The SAML LogoutResponse
 */
Napi::Value Logout::ProcessResponseMsg(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    throw Napi::TypeError::New(env, "Expected message string as first argument");
  }

  std::string message = info[0].As<Napi::String>().Utf8Value();

  gchar* msg = g_strdup(message.c_str());
  int rc = lasso_logout_process_response_msg(logout_, msg);
  g_free(msg);
  ThrowIfError(env, rc, "lasso_logout_process_response_msg");

  return env.Undefined();
}

/**
 * Get the next provider to notify (for IdP-initiated SLO)
 * @returns Provider ID or null
 */
Napi::Value Logout::GetNextProviderId(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  char* providerId = lasso_logout_get_next_providerID(logout_);
  if (!providerId) {
    return env.Null();
  }

  Napi::String result = Napi::String::New(env, providerId);
  g_free(providerId);

  return result;
}

// ===== Getters/Setters =====

Napi::Value Logout::GetIdentity(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  LassoProfile* profile = LASSO_PROFILE(logout_);
  if (!profile->identity) {
    return env.Null();
  }

  return Identity::NewInstance(env, profile->identity);
}

void Logout::SetIdentity(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (value.IsNull() || value.IsUndefined()) {
    LassoProfile* profile = LASSO_PROFILE(logout_);
    if (profile->identity) {
      lasso_identity_destroy(profile->identity);
      profile->identity = nullptr;
    }
    return;
  }

  Napi::Object identityObj = value.As<Napi::Object>();
  Identity* identity = Napi::ObjectWrap<Identity>::Unwrap(identityObj);
  if (identity && identity->GetIdentity()) {
    lasso_profile_set_identity_from_dump(LASSO_PROFILE(logout_),
      lasso_identity_dump(identity->GetIdentity()));
  }
}

Napi::Value Logout::GetSession(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  LassoProfile* profile = LASSO_PROFILE(logout_);
  if (!profile->session) {
    return env.Null();
  }

  return Session::NewInstance(env, profile->session);
}

void Logout::SetSession(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (value.IsNull() || value.IsUndefined()) {
    LassoProfile* profile = LASSO_PROFILE(logout_);
    if (profile->session) {
      lasso_session_destroy(profile->session);
      profile->session = nullptr;
    }
    return;
  }

  Napi::Object sessionObj = value.As<Napi::Object>();
  Session* session = Napi::ObjectWrap<Session>::Unwrap(sessionObj);
  if (session && session->GetSession()) {
    lasso_profile_set_session_from_dump(LASSO_PROFILE(logout_),
      lasso_session_dump(session->GetSession()));
  }
}

Napi::Value Logout::GetMsgUrl(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  LassoProfile* profile = LASSO_PROFILE(logout_);
  if (!profile->msg_url) {
    return env.Null();
  }

  return Napi::String::New(env, profile->msg_url);
}

Napi::Value Logout::GetMsgBody(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  LassoProfile* profile = LASSO_PROFILE(logout_);
  if (!profile->msg_body) {
    return env.Null();
  }

  return Napi::String::New(env, profile->msg_body);
}

} // namespace lasso_js
