#ifndef LASSO_IDENTITY_H
#define LASSO_IDENTITY_H

#include <napi.h>
#include <lasso/lasso.h>

namespace lasso_js {

class Identity : public Napi::ObjectWrap<Identity> {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  static Napi::Object NewInstance(Napi::Env env, LassoIdentity* identity);

  Identity(const Napi::CallbackInfo& info);
  ~Identity();

  LassoIdentity* GetIdentity() const { return identity_; }

 private:
  static Napi::FunctionReference constructor;

  // Static methods
  static Napi::Value FromDump(const Napi::CallbackInfo& info);

  // Instance methods
  Napi::Value Dump(const Napi::CallbackInfo& info);

  // Getters
  Napi::Value IsEmpty(const Napi::CallbackInfo& info);

  LassoIdentity* identity_;
  bool owns_identity_;
};

} // namespace lasso_js

#endif // LASSO_IDENTITY_H
