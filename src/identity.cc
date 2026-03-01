#include "identity.h"
#include "utils.h"

namespace lasso_js {

Napi::FunctionReference Identity::constructor;

Napi::Object Identity::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function func = DefineClass(env, "Identity", {
    // Static methods
    StaticMethod("fromDump", &Identity::FromDump),

    // Instance methods
    InstanceMethod("dump", &Identity::Dump),

    // Getters
    InstanceAccessor("isEmpty", &Identity::IsEmpty, nullptr),
  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  exports.Set("Identity", func);
  return exports;
}

Napi::Object Identity::NewInstance(Napi::Env env, LassoIdentity* identity) {
  Napi::Object obj = constructor.New({});
  Identity* wrapper = Napi::ObjectWrap<Identity>::Unwrap(obj);

  // Create a copy of the identity
  if (identity) {
    gchar* dump = lasso_identity_dump(identity);
    if (dump) {
      LassoIdentity* newIdentity = lasso_identity_new_from_dump(dump);
      g_free(dump);
      // Security: Check if restoration succeeded before assigning
      if (newIdentity) {
        // Destroy the default identity created by constructor
        if (wrapper->identity_) {
          lasso_identity_destroy(wrapper->identity_);
        }
        wrapper->identity_ = newIdentity;
      } else {
        // Restoration failed: throw error instead of silently using empty identity
        throw Napi::Error::New(env, "Failed to restore LassoIdentity from dump");
      }
    }
  }
  wrapper->owns_identity_ = true;

  return obj;
}

Identity::Identity(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<Identity>(info), identity_(nullptr), owns_identity_(true) {
  // Create a new empty identity
  identity_ = lasso_identity_new();
}

Identity::~Identity() {
  // Only cleanup if lasso is still initialized
  if (identity_ && owns_identity_ && IsLassoInitialized()) {
    lasso_identity_destroy(identity_);
  }
  identity_ = nullptr;
}

/**
 * Restore an identity from a dump string
 * @param dump - Identity dump string
 */
Napi::Value Identity::FromDump(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    throw Napi::TypeError::New(env, "Expected dump string as first argument");
  }

  std::string dump = info[0].As<Napi::String>().Utf8Value();

  LassoIdentity* identity = lasso_identity_new_from_dump(dump.c_str());
  if (!identity) {
    throw Napi::Error::New(env, "Failed to restore identity from dump");
  }

  Napi::Object obj = constructor.New({});
  Identity* wrapper = Napi::ObjectWrap<Identity>::Unwrap(obj);

  // Replace the default identity with the restored one
  if (wrapper->identity_) {
    lasso_identity_destroy(wrapper->identity_);
  }
  wrapper->identity_ = identity;
  wrapper->owns_identity_ = true;

  return obj;
}

/**
 * Dump identity to string
 */
Napi::Value Identity::Dump(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!identity_) {
    return env.Null();
  }

  gchar* dump = lasso_identity_dump(identity_);
  if (!dump) {
    return env.Null();
  }

  Napi::String result = Napi::String::New(env, dump);
  g_free(dump);

  return result;
}

/**
 * Check if identity is empty
 */
Napi::Value Identity::IsEmpty(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!identity_) {
    return Napi::Boolean::New(env, true);
  }

  // Check if identity has any federations by checking if dump is minimal
  gchar* dump = lasso_identity_dump(identity_);
  bool isEmpty = !dump || strlen(dump) < 50;  // Empty identity has minimal XML
  g_free(dump);

  return Napi::Boolean::New(env, isEmpty);
}

} // namespace lasso_js
