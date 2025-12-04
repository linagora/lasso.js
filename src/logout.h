#ifndef LASSO_LOGOUT_H
#define LASSO_LOGOUT_H

#include <napi.h>
#include <lasso/lasso.h>
#include "server.h"

namespace lasso_js {

class Logout : public Napi::ObjectWrap<Logout> {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);

  Logout(const Napi::CallbackInfo& info);
  ~Logout();

  LassoLogout* GetLogout() const { return logout_; }

 private:
  static Napi::FunctionReference constructor;

  // Methods
  Napi::Value InitRequest(const Napi::CallbackInfo& info);
  Napi::Value BuildRequestMsg(const Napi::CallbackInfo& info);
  Napi::Value ProcessRequestMsg(const Napi::CallbackInfo& info);
  Napi::Value ValidateRequest(const Napi::CallbackInfo& info);
  Napi::Value BuildResponseMsg(const Napi::CallbackInfo& info);
  Napi::Value ProcessResponseMsg(const Napi::CallbackInfo& info);
  Napi::Value GetNextProviderId(const Napi::CallbackInfo& info);

  // Getters/Setters
  Napi::Value GetIdentity(const Napi::CallbackInfo& info);
  void SetIdentity(const Napi::CallbackInfo& info, const Napi::Value& value);
  Napi::Value GetSession(const Napi::CallbackInfo& info);
  void SetSession(const Napi::CallbackInfo& info, const Napi::Value& value);
  Napi::Value GetMsgUrl(const Napi::CallbackInfo& info);
  Napi::Value GetMsgBody(const Napi::CallbackInfo& info);

  LassoLogout* logout_;
  Napi::ObjectReference server_ref_;
};

} // namespace lasso_js

#endif // LASSO_LOGOUT_H
