#include "session.h"
#include "utils.h"

namespace lasso_js {

Napi::FunctionReference Session::constructor;

Napi::Object Session::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function func = DefineClass(env, "Session", {
    // Static methods
    StaticMethod("fromDump", &Session::FromDump),

    // Instance methods
    InstanceMethod("dump", &Session::Dump),
    InstanceMethod("getAssertions", &Session::GetAssertions),
    InstanceMethod("getProviderIndex", &Session::GetProviderIndex),

    // Getters
    InstanceAccessor("isEmpty", &Session::IsEmpty, nullptr),
    InstanceAccessor("isDirty", &Session::IsDirty, nullptr),
  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  exports.Set("Session", func);
  return exports;
}

Napi::Object Session::NewInstance(Napi::Env env, LassoSession* session) {
  Napi::Object obj = constructor.New({});
  Session* wrapper = Napi::ObjectWrap<Session>::Unwrap(obj);

  // Create a copy of the session
  if (session) {
    gchar* dump = lasso_session_dump(session);
    if (dump) {
      wrapper->session_ = lasso_session_new_from_dump(dump);
      g_free(dump);
    }
  }
  wrapper->owns_session_ = true;

  return obj;
}

Session::Session(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<Session>(info), session_(nullptr), owns_session_(true) {
  // Create a new empty session
  session_ = lasso_session_new();
}

Session::~Session() {
  if (session_ && owns_session_) {
    lasso_session_destroy(session_);
    session_ = nullptr;
  }
}

/**
 * Restore a session from a dump string
 * @param dump - Session dump string
 */
Napi::Value Session::FromDump(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    throw Napi::TypeError::New(env, "Expected dump string as first argument");
  }

  std::string dump = info[0].As<Napi::String>().Utf8Value();

  LassoSession* session = lasso_session_new_from_dump(dump.c_str());
  if (!session) {
    throw Napi::Error::New(env, "Failed to restore session from dump");
  }

  Napi::Object obj = constructor.New({});
  Session* wrapper = Napi::ObjectWrap<Session>::Unwrap(obj);

  // Replace the default session with the restored one
  if (wrapper->session_) {
    lasso_session_destroy(wrapper->session_);
  }
  wrapper->session_ = session;
  wrapper->owns_session_ = true;

  return obj;
}

/**
 * Dump session to string
 */
Napi::Value Session::Dump(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!session_) {
    return env.Null();
  }

  gchar* dump = lasso_session_dump(session_);
  if (!dump) {
    return env.Null();
  }

  Napi::String result = Napi::String::New(env, dump);
  g_free(dump);

  return result;
}

/**
 * Get assertions for a provider
 * @param providerId - Provider entity ID
 * @returns Array of assertion XML strings
 */
Napi::Value Session::GetAssertions(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    throw Napi::TypeError::New(env, "Expected providerId string as first argument");
  }

  std::string providerId = info[0].As<Napi::String>().Utf8Value();

  GList* assertions = lasso_session_get_assertions(session_, providerId.c_str());
  if (!assertions) {
    return Napi::Array::New(env, 0);
  }

  // Count assertions
  guint count = g_list_length(assertions);
  Napi::Array result = Napi::Array::New(env, count);

  guint i = 0;
  for (GList* l = assertions; l != nullptr; l = l->next, i++) {
    LassoNode* node = LASSO_NODE(l->data);
    if (node) {
      gchar* xml = lasso_node_dump(node);
      if (xml) {
        result.Set(i, Napi::String::New(env, xml));
        g_free(xml);
      }
    }
  }

  return result;
}

/**
 * Get session indexes for a provider
 * @param providerId - Provider entity ID
 * @returns First session index or null
 */
Napi::Value Session::GetProviderIndex(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    throw Napi::TypeError::New(env, "Expected providerId string as first argument");
  }

  std::string providerId = info[0].As<Napi::String>().Utf8Value();

  GList* indexes = lasso_session_get_session_indexes(session_, providerId.c_str(), NULL);
  if (!indexes || !indexes->data) {
    return env.Null();
  }

  const char* index = static_cast<const char*>(indexes->data);
  Napi::String result = Napi::String::New(env, index);

  g_list_free_full(indexes, g_free);
  return result;
}

/**
 * Check if session is empty
 */
Napi::Value Session::IsEmpty(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!session_) {
    return Napi::Boolean::New(env, true);
  }

  return Napi::Boolean::New(env, lasso_session_is_empty(session_));
}

/**
 * Check if session is dirty (modified)
 */
Napi::Value Session::IsDirty(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!session_) {
    return Napi::Boolean::New(env, false);
  }

  return Napi::Boolean::New(env, session_->is_dirty);
}

} // namespace lasso_js
