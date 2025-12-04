#ifndef LASSO_SESSION_H
#define LASSO_SESSION_H

#include <napi.h>

// Include libxml2 headers before lasso.h to avoid extern "C" template conflict
#include <libxml/tree.h>
#include <libxml/parser.h>

#include <lasso/lasso.h>

namespace lasso_js {

class Session : public Napi::ObjectWrap<Session> {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  static Napi::Object NewInstance(Napi::Env env, LassoSession* session);

  Session(const Napi::CallbackInfo& info);
  ~Session();

  LassoSession* GetSession() const { return session_; }

 private:
  static Napi::FunctionReference constructor;

  // Static methods
  static Napi::Value FromDump(const Napi::CallbackInfo& info);

  // Instance methods
  Napi::Value Dump(const Napi::CallbackInfo& info);
  Napi::Value GetAssertions(const Napi::CallbackInfo& info);
  Napi::Value GetProviderIndex(const Napi::CallbackInfo& info);

  // Getters
  Napi::Value IsEmpty(const Napi::CallbackInfo& info);
  Napi::Value IsDirty(const Napi::CallbackInfo& info);

  LassoSession* session_;
  bool owns_session_;
};

} // namespace lasso_js

#endif // LASSO_SESSION_H
