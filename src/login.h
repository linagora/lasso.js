#ifndef LASSO_LOGIN_H
#define LASSO_LOGIN_H

#include <napi.h>
#include <lasso/lasso.h>
#include "server.h"

namespace lasso_js {

class Login : public Napi::ObjectWrap<Login> {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);

  Login(const Napi::CallbackInfo& info);
  ~Login();

  LassoLogin* GetLogin() const { return login_; }

 private:
  static Napi::FunctionReference constructor;

  // IdP methods
  Napi::Value ProcessAuthnRequestMsg(const Napi::CallbackInfo& info);
  Napi::Value ValidateRequestMsg(const Napi::CallbackInfo& info);
  Napi::Value BuildAssertion(const Napi::CallbackInfo& info);
  Napi::Value BuildResponseMsg(const Napi::CallbackInfo& info);

  // SP methods
  Napi::Value InitAuthnRequest(const Napi::CallbackInfo& info);
  Napi::Value BuildAuthnRequestMsg(const Napi::CallbackInfo& info);
  Napi::Value ProcessResponseMsg(const Napi::CallbackInfo& info);
  Napi::Value AcceptSso(const Napi::CallbackInfo& info);

  // Common methods
  Napi::Value SetNameId(const Napi::CallbackInfo& info);
  Napi::Value SetAttributes(const Napi::CallbackInfo& info);

  // Getters/Setters
  Napi::Value GetIdentity(const Napi::CallbackInfo& info);
  void SetIdentity(const Napi::CallbackInfo& info, const Napi::Value& value);
  Napi::Value GetSession(const Napi::CallbackInfo& info);
  void SetSession(const Napi::CallbackInfo& info, const Napi::Value& value);
  Napi::Value GetRemoteProviderId(const Napi::CallbackInfo& info);
  Napi::Value GetNameId(const Napi::CallbackInfo& info);
  Napi::Value GetNameIdFormat(const Napi::CallbackInfo& info);
  Napi::Value GetRelayState(const Napi::CallbackInfo& info);
  void SetRelayState(const Napi::CallbackInfo& info, const Napi::Value& value);
  Napi::Value GetMsgUrl(const Napi::CallbackInfo& info);
  Napi::Value GetMsgBody(const Napi::CallbackInfo& info);

  LassoLogin* login_;
  Napi::ObjectReference server_ref_;
};

} // namespace lasso_js

#endif // LASSO_LOGIN_H
