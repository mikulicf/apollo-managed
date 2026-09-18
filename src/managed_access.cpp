/**
 * @file src/managed_access.cpp
 * @brief Host-side enforcement of short-lived management policy.
 */
#include "managed_access.h"

#include "config.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <map>
#include <mutex>
#include <openssl/pem.h>
#include <sstream>
#include <stdexcept>

namespace managed_access {
  namespace {
    using clock = std::chrono::steady_clock;

    struct entry_t {
      crypto::p_named_cert_t client;
      clock::time_point deadline;
    };

    std::mutex mutex;
    std::map<std::string, entry_t> entries;
    std::string previous_document;
    clock::time_point next_read {};

    std::string fingerprint(X509 *certificate) {
      unsigned char digest[EVP_MAX_MD_SIZE];
      unsigned int length = 0;
      if (!certificate || X509_digest(certificate, EVP_sha256(), digest, &length) != 1 || length != 32) {
        return {};
      }
      static constexpr char hex[] = "0123456789abcdef";
      std::string result;
      for (unsigned int i = 0; i < length; ++i) {
        result += hex[digest[i] >> 4];
        result += hex[digest[i] & 15];
      }
      return result;
    }

    std::string client_uuid(const std::string &fingerprint) {
      // Stable UUID for Windows display identity; authorization still uses all 256 bits.
      return fingerprint.substr(0, 8) + "-" + fingerprint.substr(8, 4) + "-" +
             fingerprint.substr(12, 4) + "-" + fingerprint.substr(16, 4) + "-" + fingerprint.substr(20, 12);
    }

    void refresh_locked() {
      const auto steady_now = clock::now();
      if (steady_now < next_read) {
        return;
      }
      next_read = steady_now + std::chrono::milliseconds(500);
      try {
        std::ifstream stream(config::managed_policy_file, std::ios::binary);
        if (!stream) {
          // Missing policy is an explicit fail-closed state, including after restart.
          entries.clear();
          previous_document.clear();
          return;
        }
        std::string document(512 * 1024 + 1, '\0');
        stream.read(document.data(), document.size());
        document.resize(static_cast<size_t>(stream.gcount()));
        if (document.empty() || document.size() > 512 * 1024) {
          throw std::runtime_error("Invalid policy size");
        }
        if (document == previous_document) {
          // Reading the same file never extends monotonic lease deadlines.
          return;
        }
        const auto policy = nlohmann::json::parse(document);
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        const auto issued = policy.at("server_time").get<int64_t>();
        const auto expires = policy.at("valid_until").get<int64_t>();
        if (policy.at("protocol").get<int>() != 1 || issued > now + 30 || issued < now - 120 ||
            expires <= now || expires > issued + 90 || !policy.at("leases").is_array() || policy.at("leases").size() > 64) {
          throw std::runtime_error("Invalid policy validity");
        }
        std::map<std::string, entry_t> updated;
        for (const auto &lease : policy.at("leases")) {
          const auto until = std::min(lease.at("expires_at").get<int64_t>(), expires);
          if (until <= now) {
            continue;
          }
          const auto pem = lease.at("certificate").get<std::string>();
          if (pem.size() > 8192) {
            throw std::runtime_error("Invalid certificate size");
          }
          auto bio = std::unique_ptr<BIO, decltype(&BIO_free)>(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free);
          auto cert = std::unique_ptr<X509, decltype(&X509_free)>(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), &X509_free);
          auto hash = fingerprint(cert.get());
          if (hash.empty() || hash != lease.at("fingerprint").get<std::string>() ||
              X509_cmp_current_time(X509_get0_notBefore(cert.get())) >= 0 || X509_cmp_current_time(X509_get0_notAfter(cert.get())) <= 0) {
            throw std::runtime_error("Invalid policy certificate");
          }
          auto client = std::make_shared<crypto::named_cert_t>();
          client->name = lease.at("username").get<std::string>();
          client->uuid = client_uuid(hash);
          client->cert = pem;
          client->perm = static_cast<crypto::PERM>(static_cast<uint32_t>(crypto::PERM::_all_inputs) | static_cast<uint32_t>(crypto::PERM::_all_actions) | static_cast<uint32_t>(crypto::PERM::clipboard_read) | static_cast<uint32_t>(crypto::PERM::clipboard_set));
          client->enable_legacy_ordering = false;
          client->allow_client_commands = false;
          client->always_use_virtual_display = false;
          const auto deadline = steady_now + std::chrono::seconds(std::min<int64_t>(until - now, 90));
          auto existing = updated.find(hash);
          if (existing == updated.end() || existing->second.deadline < deadline) {
            updated[hash] = {std::move(client), deadline};
          }
        }
        entries = std::move(updated);
        previous_document = std::move(document);
      } catch (...) {
        entries.clear();
        previous_document.clear();
      }
    }
  }  // namespace

  bool enabled() {
    return !config::managed_policy_file.empty();
  }

  void refresh() {
    if (!enabled()) {
      return;
    }
    std::lock_guard lock(mutex);
    refresh_locked();
  }

  crypto::p_named_cert_t authorize(X509 *certificate) {
    std::lock_guard lock(mutex);
    refresh_locked();
    const auto found = entries.find(fingerprint(certificate));
    if (found == entries.end() || clock::now() >= found->second.deadline) {
      return {};
    }
    return found->second.client;
  }

  bool allowed(const std::string &uuid) {
    if (!enabled()) {
      return true;
    }
    std::lock_guard lock(mutex);
    refresh_locked();
    return std::any_of(entries.begin(), entries.end(), [&](const auto &item) {
      return item.second.client->uuid == uuid && clock::now() < item.second.deadline;
    });
  }
}  // namespace managed_access
