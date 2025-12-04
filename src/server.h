#ifndef LASSO_SERVER_H
#define LASSO_SERVER_H

#include <napi.h>

// Include libxml2 headers before lasso.h to avoid extern "C" template conflict
#include <libxml/tree.h>
#include <libxml/parser.h>

#include <lasso/lasso.h>

namespace lasso_js {

class Server : public Napi::ObjectWrap<Server> {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  static Napi::Object NewInstance(Napi::Env env, LassoServer* server);

  Server(const Napi::CallbackInfo& info);
  ~Server();

  LassoServer* GetServer() const { return server_; }

 private:
  static Napi::FunctionReference constructor;

  // Static methods
  static Napi::Value FromBuffers(const Napi::CallbackInfo& info);
  static Napi::Value FromDump(const Napi::CallbackInfo& info);

  // Instance methods
  Napi::Value AddProvider(const Napi::CallbackInfo& info);
  Napi::Value AddProviderFromBuffer(const Napi::CallbackInfo& info);
  Napi::Value GetProvider(const Napi::CallbackInfo& info);
  Napi::Value Dump(const Napi::CallbackInfo& info);

  // Getters
  Napi::Value GetEntityId(const Napi::CallbackInfo& info);

  LassoServer* server_;
  bool owns_server_;
};

} // namespace lasso_js

#endif // LASSO_SERVER_H
