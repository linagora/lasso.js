#ifndef LASSO_JS_SECURE_STRING_H
#define LASSO_JS_SECURE_STRING_H

#include <string>
#include <cstring>

// Platform-specific secure memory clearing
#if defined(__APPLE__)
  // macOS: use memset_s (C11) - available since macOS 10.9
  #define __STDC_WANT_LIB_EXT1__ 1
  #include <string.h>
  #define HAVE_MEMSET_S 1
#elif defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__)
  #include <strings.h>  // for explicit_bzero
  #define HAVE_EXPLICIT_BZERO 1
#elif defined(_WIN32)
  #include <windows.h>
  #define HAVE_SECURE_ZERO_MEMORY 1
#endif

namespace lasso_js {

/**
 * SecureString - A string wrapper that securely erases its contents on destruction
 *
 * This class ensures that sensitive data like private keys and passwords
 * are zeroed out in memory when they go out of scope, preventing memory
 * disclosure attacks.
 */
class SecureString {
public:
  SecureString() = default;

  SecureString(const std::string& s) : data_(s) {}

  SecureString(const char* s) : data_(s ? s : "") {}

  SecureString(const char* s, size_t len) : data_(s, len) {}

  // Move constructor
  SecureString(SecureString&& other) noexcept : data_(std::move(other.data_)) {
    // Clear the moved-from string
    other.secure_clear();
  }

  // Move assignment
  SecureString& operator=(SecureString&& other) noexcept {
    if (this != &other) {
      secure_clear();
      data_ = std::move(other.data_);
      other.secure_clear();
    }
    return *this;
  }

  // Copy constructor - make a secure copy
  SecureString(const SecureString& other) : data_(other.data_) {}

  // Copy assignment
  SecureString& operator=(const SecureString& other) {
    if (this != &other) {
      secure_clear();
      data_ = other.data_;
    }
    return *this;
  }

  // Destructor - securely erase the data
  ~SecureString() {
    secure_clear();
  }

  const char* c_str() const { return data_.c_str(); }

  bool empty() const { return data_.empty(); }

  size_t size() const { return data_.size(); }

  // Allow assignment from std::string
  SecureString& operator=(const std::string& s) {
    secure_clear();
    data_ = s;
    return *this;
  }

private:
  std::string data_;

  // Securely zero out the string contents using platform-specific functions
  void secure_clear() {
    if (!data_.empty()) {
#if defined(HAVE_MEMSET_S)
      memset_s(&data_[0], data_.size(), 0, data_.size());
#elif defined(HAVE_EXPLICIT_BZERO)
      explicit_bzero(&data_[0], data_.size());
#elif defined(HAVE_SECURE_ZERO_MEMORY)
      SecureZeroMemory(&data_[0], data_.size());
#else
      // Fallback: use volatile to prevent compiler optimization
      volatile char* p = &data_[0];
      size_t n = data_.size();
      while (n--) {
        *p++ = 0;
      }
#endif
      data_.clear();
    }
  }
};

} // namespace lasso_js

#endif // LASSO_JS_SECURE_STRING_H
