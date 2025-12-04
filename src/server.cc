#include "server.h"
#include "utils.h"

namespace lasso_js {

Napi::FunctionReference Server::constructor;

Napi::Object Server::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function func = DefineClass(env, "Server", {
    // Static methods
    StaticMethod("fromBuffers", &Server::FromBuffers),
    StaticMethod("fromDump", &Server::FromDump),

    // Instance methods
    InstanceMethod("addProvider", &Server::AddProvider),
    InstanceMethod("addProviderFromBuffer", &Server::AddProviderFromBuffer),
    InstanceMethod("getProvider", &Server::GetProvider),
    InstanceMethod("dump", &Server::Dump),

    // Getters
    InstanceAccessor("entityId", &Server::GetEntityId, nullptr),
  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  exports.Set("Server", func);
  return exports;
}

Napi::Object Server::NewInstance(Napi::Env env, LassoServer* server) {
  Napi::Object obj = constructor.New({});
  Server* wrapper = Napi::ObjectWrap<Server>::Unwrap(obj);
  wrapper->server_ = server;
  wrapper->owns_server_ = true;
  return obj;
}

Server::Server(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<Server>(info), server_(nullptr), owns_server_(false) {
  // Default constructor - server will be set by static factory methods
}

Server::~Server() {
  if (server_ && owns_server_) {
    g_object_unref(server_);
    server_ = nullptr;
  }
}

/**
 * Create a server from metadata, private key, and certificate buffers
 * @param metadata - IdP/SP metadata XML as string or Buffer
 * @param privateKey - Private key PEM as string or Buffer
 * @param certificate - Certificate PEM as string or Buffer
 * @param privateKeyPassword - Optional password for private key
 */
Napi::Value Server::FromBuffers(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 3) {
    throw Napi::TypeError::New(env,
      "Expected at least 3 arguments: metadata, privateKey, certificate");
  }

  std::string metadata;
  std::string privateKey;
  std::string certificate;
  std::string password;

  // Get metadata
  if (info[0].IsString()) {
    metadata = info[0].As<Napi::String>().Utf8Value();
  } else if (info[0].IsBuffer()) {
    Napi::Buffer<char> buf = info[0].As<Napi::Buffer<char>>();
    metadata = std::string(buf.Data(), buf.Length());
  } else {
    throw Napi::TypeError::New(env, "metadata must be a string or Buffer");
  }

  // Get private key
  if (info[1].IsString()) {
    privateKey = info[1].As<Napi::String>().Utf8Value();
  } else if (info[1].IsBuffer()) {
    Napi::Buffer<char> buf = info[1].As<Napi::Buffer<char>>();
    privateKey = std::string(buf.Data(), buf.Length());
  } else {
    throw Napi::TypeError::New(env, "privateKey must be a string or Buffer");
  }

  // Get certificate
  if (info[2].IsString()) {
    certificate = info[2].As<Napi::String>().Utf8Value();
  } else if (info[2].IsBuffer()) {
    Napi::Buffer<char> buf = info[2].As<Napi::Buffer<char>>();
    certificate = std::string(buf.Data(), buf.Length());
  } else {
    throw Napi::TypeError::New(env, "certificate must be a string or Buffer");
  }

  // Get optional password
  if (info.Length() > 3 && info[3].IsString()) {
    password = info[3].As<Napi::String>().Utf8Value();
  }

  // Create Lasso server
  LassoServer* server = lasso_server_new_from_buffers(
    metadata.c_str(),
    privateKey.c_str(),
    password.empty() ? nullptr : password.c_str(),
    certificate.c_str()
  );

  if (!server) {
    throw Napi::Error::New(env, "Failed to create Lasso server from buffers");
  }

  return NewInstance(env, server);
}

/**
 * Restore a server from a dump string
 * @param dump - Server dump string
 */
Napi::Value Server::FromDump(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    throw Napi::TypeError::New(env, "Expected dump string as first argument");
  }

  std::string dump = info[0].As<Napi::String>().Utf8Value();

  LassoServer* server = lasso_server_new_from_dump(dump.c_str());
  if (!server) {
    throw Napi::Error::New(env, "Failed to restore Lasso server from dump");
  }

  return NewInstance(env, server);
}

/**
 * Add a provider (SP or IdP) from metadata file
 * @param providerId - Entity ID of the provider
 * @param metadata - Path to metadata file
 */
Napi::Value Server::AddProvider(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 2) {
    throw Napi::TypeError::New(env,
      "Expected at least 2 arguments: providerId, metadataPath");
  }

  if (!info[0].IsString() || !info[1].IsString()) {
    throw Napi::TypeError::New(env, "providerId and metadataPath must be strings");
  }

  std::string providerId = info[0].As<Napi::String>().Utf8Value();
  std::string metadataPath = info[1].As<Napi::String>().Utf8Value();

  std::string publicKey;
  std::string caCert;

  if (info.Length() > 2 && info[2].IsString()) {
    publicKey = info[2].As<Napi::String>().Utf8Value();
  }
  if (info.Length() > 3 && info[3].IsString()) {
    caCert = info[3].As<Napi::String>().Utf8Value();
  }

  int rc = lasso_server_add_provider(
    server_,
    LASSO_PROVIDER_ROLE_SP, // Default to SP, will be determined by metadata
    metadataPath.c_str(),
    publicKey.empty() ? nullptr : publicKey.c_str(),
    caCert.empty() ? nullptr : caCert.c_str()
  );

  ThrowIfError(env, rc, "lasso_server_add_provider");
  return env.Undefined();
}

/**
 * Add a provider from metadata buffer
 * @param providerId - Entity ID of the provider
 * @param metadata - Metadata XML as string or Buffer
 * @param publicKey - Optional public key PEM
 */
Napi::Value Server::AddProviderFromBuffer(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 2) {
    throw Napi::TypeError::New(env,
      "Expected at least 2 arguments: providerId, metadata");
  }

  if (!info[0].IsString()) {
    throw Napi::TypeError::New(env, "providerId must be a string");
  }

  std::string providerId = info[0].As<Napi::String>().Utf8Value();
  std::string metadata;

  // Get metadata
  if (info[1].IsString()) {
    metadata = info[1].As<Napi::String>().Utf8Value();
  } else if (info[1].IsBuffer()) {
    Napi::Buffer<char> buf = info[1].As<Napi::Buffer<char>>();
    metadata = std::string(buf.Data(), buf.Length());
  } else {
    throw Napi::TypeError::New(env, "metadata must be a string or Buffer");
  }

  std::string publicKey;
  if (info.Length() > 2 && info[2].IsString()) {
    publicKey = info[2].As<Napi::String>().Utf8Value();
  }

  int rc = lasso_server_add_provider_from_buffer(
    server_,
    LASSO_PROVIDER_ROLE_SP, // Default to SP
    metadata.c_str(),
    publicKey.empty() ? nullptr : publicKey.c_str(),
    nullptr // CA cert
  );

  ThrowIfError(env, rc, "lasso_server_add_provider_from_buffer");
  return env.Undefined();
}

/**
 * Get a provider by entity ID
 * @param providerId - Entity ID of the provider
 * @returns Provider info object or null
 */
Napi::Value Server::GetProvider(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    throw Napi::TypeError::New(env, "Expected providerId string as first argument");
  }

  std::string providerId = info[0].As<Napi::String>().Utf8Value();

  LassoProvider* provider = lasso_server_get_provider(server_, providerId.c_str());
  if (!provider) {
    return env.Null();
  }

  // Return provider info as object
  Napi::Object result = Napi::Object::New(env);
  result.Set("entityId", Napi::String::New(env, providerId));

  const char* metadata = lasso_provider_get_metadata_one(provider, "EntityDescriptor");
  if (metadata) {
    result.Set("metadata", Napi::String::New(env, metadata));
  }

  return result;
}

/**
 * Dump server configuration to string
 * Can be used to restore server later with fromDump()
 */
Napi::Value Server::Dump(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  gchar* dump = lasso_server_dump(server_);
  if (!dump) {
    throw Napi::Error::New(env, "Failed to dump server");
  }

  Napi::String result = Napi::String::New(env, dump);
  g_free(dump);

  return result;
}

/**
 * Get the entity ID of this server (IdP or SP)
 */
Napi::Value Server::GetEntityId(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!server_ || !LASSO_IS_PROVIDER(server_)) {
    return env.Null();
  }

  const char* entityId = LASSO_PROVIDER(server_)->ProviderID;
  if (!entityId) {
    return env.Null();
  }

  return Napi::String::New(env, entityId);
}

} // namespace lasso_js
