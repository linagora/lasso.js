#include "login.h"
#include "identity.h"
#include "session.h"
#include "utils.h"

namespace lasso_js {

Napi::FunctionReference Login::constructor;

Napi::Object Login::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function func = DefineClass(env, "Login", {
    // IdP methods
    InstanceMethod("processAuthnRequestMsg", &Login::ProcessAuthnRequestMsg),
    InstanceMethod("validateRequestMsg", &Login::ValidateRequestMsg),
    InstanceMethod("buildAssertion", &Login::BuildAssertion),
    InstanceMethod("buildResponseMsg", &Login::BuildResponseMsg),

    // SP methods
    InstanceMethod("initAuthnRequest", &Login::InitAuthnRequest),
    InstanceMethod("buildAuthnRequestMsg", &Login::BuildAuthnRequestMsg),
    InstanceMethod("processResponseMsg", &Login::ProcessResponseMsg),
    InstanceMethod("acceptSso", &Login::AcceptSso),

    // Common methods
    InstanceMethod("setNameId", &Login::SetNameId),
    InstanceMethod("setAttributes", &Login::SetAttributes),

    // Getters/Setters
    InstanceAccessor("identity", &Login::GetIdentity, &Login::SetIdentity),
    InstanceAccessor("session", &Login::GetSession, &Login::SetSession),
    InstanceAccessor("remoteProviderId", &Login::GetRemoteProviderId, nullptr),
    InstanceAccessor("nameId", &Login::GetNameId, nullptr),
    InstanceAccessor("nameIdFormat", &Login::GetNameIdFormat, nullptr),
    InstanceAccessor("relayState", &Login::GetRelayState, &Login::SetRelayState),
    InstanceAccessor("msgUrl", &Login::GetMsgUrl, nullptr),
    InstanceAccessor("msgBody", &Login::GetMsgBody, nullptr),
  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  exports.Set("Login", func);
  return exports;
}

Login::Login(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<Login>(info), login_(nullptr) {
  Napi::Env env = info.Env();

  if (info.Length() < 1) {
    throw Napi::TypeError::New(env, "Expected Server as first argument");
  }

  // Check if argument is a Server instance
  Napi::Object serverObj = info[0].As<Napi::Object>();
  Server* server = Napi::ObjectWrap<Server>::Unwrap(serverObj);
  if (!server || !server->GetServer()) {
    throw Napi::TypeError::New(env, "Invalid Server object");
  }

  // Keep reference to server to prevent GC
  server_ref_ = Napi::Persistent(serverObj);
  // Prevent the reference destructor from throwing during V8 shutdown
  server_ref_.SuppressDestruct();

  login_ = lasso_login_new(server->GetServer());
  if (!login_) {
    throw Napi::Error::New(env, "Failed to create Lasso login");
  }
}

Login::~Login() {
  // Only cleanup if lasso is still initialized
  // During V8 shutdown, lasso may already be shut down
  if (login_ && IsLassoInitialized()) {
    g_object_unref(login_);
  }
  login_ = nullptr;
  // Note: Don't call server_ref_.Reset() here.
  // Calling Reset() during V8 shutdown can throw Napi::Error,
  // and throwing from a destructor calls std::terminate().
  // The Napi::Reference destructor handles cleanup safely.
}

// ===== IdP Methods =====

/**
 * Process an incoming AuthnRequest (IdP)
 * @param message - The SAML AuthnRequest (base64 or URL-encoded)
 * @param method - HTTP method (GET=redirect, POST=form)
 */
Napi::Value Login::ProcessAuthnRequestMsg(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    throw Napi::TypeError::New(env, "Expected message string as first argument");
  }

  std::string message = info[0].As<Napi::String>().Utf8Value();
  LassoHttpMethod method = LASSO_HTTP_METHOD_REDIRECT;

  if (info.Length() > 1 && info[1].IsNumber()) {
    method = static_cast<LassoHttpMethod>(info[1].As<Napi::Number>().Int32Value());
  }

  int rc = lasso_login_process_authn_request_msg(login_, message.c_str());
  ThrowIfError(env, rc, "lasso_login_process_authn_request_msg");

  return env.Undefined();
}

/**
 * Validate the AuthnRequest (IdP)
 */
Napi::Value Login::ValidateRequestMsg(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  int rc = lasso_login_validate_request_msg(
    login_,
    TRUE,  // authentication_result
    FALSE  // is_consent_obtained
  );
  ThrowIfError(env, rc, "lasso_login_validate_request_msg");

  return env.Undefined();
}

/**
 * Build a SAML assertion for the authenticated user (IdP)
 * @param authenticationMethod - e.g., "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
 * @param authenticationInstant - When authentication occurred (optional)
 */
Napi::Value Login::BuildAssertion(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  std::string authMethod = LASSO_SAML2_AUTHN_CONTEXT_PASSWORD;
  if (info.Length() > 0 && info[0].IsString()) {
    authMethod = info[0].As<Napi::String>().Utf8Value();
  }

  std::string authInstant;
  if (info.Length() > 1 && info[1].IsString()) {
    authInstant = info[1].As<Napi::String>().Utf8Value();
  }

  int rc = lasso_login_build_assertion(
    login_,
    authMethod.c_str(),
    authInstant.empty() ? nullptr : authInstant.c_str(),
    nullptr, // reauthenticateOnPassive
    nullptr, // notBefore
    nullptr  // notOnOrAfter
  );
  ThrowIfError(env, rc, "lasso_login_build_assertion");

  return env.Undefined();
}

/**
 * Build the SAML Response message (IdP)
 * @returns {{ responseUrl: string, responseBody?: string, httpMethod: number }}
 */
Napi::Value Login::BuildResponseMsg(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  int rc = lasso_login_build_response_msg(login_, nullptr);
  ThrowIfError(env, rc, "lasso_login_build_response_msg");

  Napi::Object result = Napi::Object::New(env);

  LassoProfile* profile = LASSO_PROFILE(login_);
  if (profile->msg_url) {
    result.Set("responseUrl", Napi::String::New(env, profile->msg_url));
  }
  if (profile->msg_body) {
    result.Set("responseBody", Napi::String::New(env, profile->msg_body));
  }
  result.Set("httpMethod", Napi::Number::New(env, profile->http_request_method));

  if (profile->msg_relayState) {
    result.Set("relayState", Napi::String::New(env, profile->msg_relayState));
  }

  return result;
}

// ===== SP Methods =====

/**
 * Initialize an AuthnRequest (SP)
 * @param providerId - Target IdP entity ID (optional)
 * @param method - HTTP method to use
 */
Napi::Value Login::InitAuthnRequest(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  const char* providerId = nullptr;
  std::string providerIdStr;
  if (info.Length() > 0 && info[0].IsString()) {
    providerIdStr = info[0].As<Napi::String>().Utf8Value();
    providerId = providerIdStr.c_str();
  }

  LassoHttpMethod method = LASSO_HTTP_METHOD_REDIRECT;
  if (info.Length() > 1 && info[1].IsNumber()) {
    method = static_cast<LassoHttpMethod>(info[1].As<Napi::Number>().Int32Value());
  }

  int rc = lasso_login_init_authn_request(login_, providerId, method);
  ThrowIfError(env, rc, "lasso_login_init_authn_request");

  return env.Undefined();
}

/**
 * Build the AuthnRequest message (SP)
 * @returns {{ responseUrl: string, responseBody?: string, httpMethod: number }}
 */
Napi::Value Login::BuildAuthnRequestMsg(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  int rc = lasso_login_build_authn_request_msg(login_);
  ThrowIfError(env, rc, "lasso_login_build_authn_request_msg");

  Napi::Object result = Napi::Object::New(env);

  LassoProfile* profile = LASSO_PROFILE(login_);
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
 * Process a SAML Response (SP)
 * @param message - The SAML Response
 */
Napi::Value Login::ProcessResponseMsg(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    throw Napi::TypeError::New(env, "Expected message string as first argument");
  }

  std::string message = info[0].As<Napi::String>().Utf8Value();

  gchar* msg = g_strdup(message.c_str());
  int rc = lasso_login_process_response_msg(login_, msg);
  g_free(msg);
  ThrowIfError(env, rc, "lasso_login_process_response_msg");

  return env.Undefined();
}

/**
 * Accept the SSO (SP)
 */
Napi::Value Login::AcceptSso(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  int rc = lasso_login_accept_sso(login_);
  ThrowIfError(env, rc, "lasso_login_accept_sso");

  return env.Undefined();
}

// ===== Common Methods =====

/**
 * Set the NameID for the assertion (IdP)
 * @param nameId - The name identifier value
 * @param format - The name ID format (optional)
 */
Napi::Value Login::SetNameId(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    throw Napi::TypeError::New(env, "Expected nameId string as first argument");
  }

  std::string nameId = info[0].As<Napi::String>().Utf8Value();
  std::string format = LASSO_SAML2_NAME_IDENTIFIER_FORMAT_UNSPECIFIED;

  if (info.Length() > 1 && info[1].IsString()) {
    format = info[1].As<Napi::String>().Utf8Value();
  }

  // Create SAML2 NameID
  gchar* nameIdStr = g_strdup(nameId.c_str());
  LassoSaml2NameID* nameIdObj = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(nameIdStr));
  g_free(nameIdStr);
  if (!nameIdObj) {
    throw Napi::Error::New(env, "Failed to create NameID");
  }

  nameIdObj->Format = g_strdup(format.c_str());

  // Set on the profile
  LassoProfile* profile = LASSO_PROFILE(login_);
  if (profile->nameIdentifier) {
    lasso_node_destroy(LASSO_NODE(profile->nameIdentifier));
  }
  profile->nameIdentifier = LASSO_NODE(nameIdObj);

  return env.Undefined();
}

/**
 * Set user attributes in the assertion (IdP)
 * @param attributes - Array of { name, nameFormat?, values: string[] }
 */
Napi::Value Login::SetAttributes(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsArray()) {
    throw Napi::TypeError::New(env, "Expected array of attributes");
  }

  // Note: Setting attributes requires accessing the assertion directly
  // This is a simplified implementation
  // Full implementation would iterate through the attributes and add them

  return env.Undefined();
}

// ===== Getters/Setters =====

Napi::Value Login::GetIdentity(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  LassoProfile* profile = LASSO_PROFILE(login_);
  if (!profile->identity) {
    return env.Null();
  }

  return Identity::NewInstance(env, profile->identity);
}

void Login::SetIdentity(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (value.IsNull() || value.IsUndefined()) {
    LassoProfile* profile = LASSO_PROFILE(login_);
    if (profile->identity) {
      lasso_identity_destroy(profile->identity);
      profile->identity = nullptr;
    }
    return;
  }

  Napi::Object identityObj = value.As<Napi::Object>();
  Identity* identity = Napi::ObjectWrap<Identity>::Unwrap(identityObj);
  if (identity && identity->GetIdentity()) {
    lasso_profile_set_identity_from_dump(LASSO_PROFILE(login_),
      lasso_identity_dump(identity->GetIdentity()));
  }
}

Napi::Value Login::GetSession(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  LassoProfile* profile = LASSO_PROFILE(login_);
  if (!profile->session) {
    return env.Null();
  }

  return Session::NewInstance(env, profile->session);
}

void Login::SetSession(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (value.IsNull() || value.IsUndefined()) {
    LassoProfile* profile = LASSO_PROFILE(login_);
    if (profile->session) {
      lasso_session_destroy(profile->session);
      profile->session = nullptr;
    }
    return;
  }

  Napi::Object sessionObj = value.As<Napi::Object>();
  Session* session = Napi::ObjectWrap<Session>::Unwrap(sessionObj);
  if (session && session->GetSession()) {
    lasso_profile_set_session_from_dump(LASSO_PROFILE(login_),
      lasso_session_dump(session->GetSession()));
  }
}

Napi::Value Login::GetRemoteProviderId(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  LassoProfile* profile = LASSO_PROFILE(login_);
  if (!profile->remote_providerID) {
    return env.Null();
  }

  return Napi::String::New(env, profile->remote_providerID);
}

Napi::Value Login::GetNameId(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  LassoProfile* profile = LASSO_PROFILE(login_);
  if (!profile->nameIdentifier) {
    return env.Null();
  }

  LassoSaml2NameID* nameId = LASSO_SAML2_NAME_ID(profile->nameIdentifier);
  if (!nameId || !nameId->content) {
    return env.Null();
  }

  return Napi::String::New(env, nameId->content);
}

Napi::Value Login::GetNameIdFormat(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  LassoProfile* profile = LASSO_PROFILE(login_);
  if (!profile->nameIdentifier) {
    return env.Null();
  }

  LassoSaml2NameID* nameId = LASSO_SAML2_NAME_ID(profile->nameIdentifier);
  if (!nameId || !nameId->Format) {
    return env.Null();
  }

  return Napi::String::New(env, nameId->Format);
}

Napi::Value Login::GetRelayState(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  LassoProfile* profile = LASSO_PROFILE(login_);
  if (!profile->msg_relayState) {
    return env.Null();
  }

  return Napi::String::New(env, profile->msg_relayState);
}

void Login::SetRelayState(const Napi::CallbackInfo& info, const Napi::Value& value) {
  LassoProfile* profile = LASSO_PROFILE(login_);

  if (value.IsNull() || value.IsUndefined()) {
    g_free(profile->msg_relayState);
    profile->msg_relayState = nullptr;
    return;
  }

  std::string relayState = value.As<Napi::String>().Utf8Value();
  g_free(profile->msg_relayState);
  profile->msg_relayState = g_strdup(relayState.c_str());
}

Napi::Value Login::GetMsgUrl(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  LassoProfile* profile = LASSO_PROFILE(login_);
  if (!profile->msg_url) {
    return env.Null();
  }

  return Napi::String::New(env, profile->msg_url);
}

Napi::Value Login::GetMsgBody(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  LassoProfile* profile = LASSO_PROFILE(login_);
  if (!profile->msg_body) {
    return env.Null();
  }

  return Napi::String::New(env, profile->msg_body);
}

} // namespace lasso_js
