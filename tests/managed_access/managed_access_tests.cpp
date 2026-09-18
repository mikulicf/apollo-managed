#include "managed_access.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace config {
  std::string managed_policy_file;
}

namespace {
  using namespace std::chrono_literals;
  using json = nlohmann::json;
  using bio_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
  using key_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
  using key_context_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
  using x509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;

  constexpr auto refresh_interval = 550ms;
  int certificate_serial = 1;

  struct certificate_t {
    key_ptr key {nullptr, &EVP_PKEY_free};
    x509_ptr cert {nullptr, &X509_free};
    std::string pem;
    std::string fingerprint;
  };

  [[noreturn]] void fail(const std::string &message) {
    throw std::runtime_error(message);
  }

  void require(bool condition, const std::string &message) {
    if (!condition) {
      fail(message);
    }
  }

  std::int64_t unix_time() {
    return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch()
    )
      .count();
  }

  key_ptr generate_key() {
    key_context_ptr context {EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), &EVP_PKEY_CTX_free};
    require(context != nullptr, "failed to allocate key context");
    require(EVP_PKEY_keygen_init(context.get()) == 1, "failed to initialize key generation");
    require(EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 2048) == 1, "failed to select RSA key size");
    EVP_PKEY *raw_key = nullptr;
    require(EVP_PKEY_keygen(context.get(), &raw_key) == 1, "failed to generate key");
    return key_ptr {raw_key, &EVP_PKEY_free};
  }

  std::string certificate_pem(X509 *certificate) {
    bio_ptr output {BIO_new(BIO_s_mem()), &BIO_free};
    require(output != nullptr, "failed to allocate certificate output buffer");
    require(PEM_write_bio_X509(output.get(), certificate) == 1, "failed to encode certificate");
    BUF_MEM *memory = nullptr;
    BIO_get_mem_ptr(output.get(), &memory);
    require(memory != nullptr, "failed to read encoded certificate");
    return {memory->data, memory->length};
  }

  std::string certificate_fingerprint(X509 *certificate) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    require(X509_digest(certificate, EVP_sha256(), digest, &length) == 1 && length == 32, "failed to fingerprint certificate");
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(length * 2);
    for (unsigned int i = 0; i < length; ++i) {
      result += hex[digest[i] >> 4];
      result += hex[digest[i] & 15];
    }
    return result;
  }

  certificate_t issue_certificate(
    std::string common_name,
    X509 *issuer_certificate = nullptr,
    EVP_PKEY *issuer_key = nullptr,
    long not_before_seconds = -60,
    long not_after_seconds = 3600
  ) {
    auto key = generate_key();
    x509_ptr certificate {X509_new(), &X509_free};
    require(certificate != nullptr, "failed to allocate certificate");
    require(X509_set_version(certificate.get(), 2) == 1, "failed to set certificate version");
    require(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), certificate_serial++) == 1, "failed to set certificate serial");
    require(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), not_before_seconds) != nullptr, "failed to set certificate start time");
    require(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), not_after_seconds) != nullptr, "failed to set certificate end time");
    require(X509_set_pubkey(certificate.get(), key.get()) == 1, "failed to set certificate key");

    auto *subject = X509_get_subject_name(certificate.get());
    require(subject != nullptr, "failed to access certificate subject");
    require(X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(common_name.c_str()), -1, -1, 0) == 1, "failed to set certificate common name");

    auto *issuer_name = issuer_certificate ? X509_get_subject_name(issuer_certificate) : subject;
    require(X509_set_issuer_name(certificate.get(), issuer_name) == 1, "failed to set certificate issuer");
    require(X509_sign(certificate.get(), issuer_key ? issuer_key : key.get(), EVP_sha256()) > 0, "failed to sign certificate");

    auto pem = certificate_pem(certificate.get());
    auto fingerprint = certificate_fingerprint(certificate.get());
    return {std::move(key), std::move(certificate), std::move(pem), std::move(fingerprint)};
  }

  json lease(const certificate_t &certificate, std::int64_t expires_at, std::string username = "alice") {
    return {
      {"expires_at", expires_at},
      {"certificate", certificate.pem},
      {"fingerprint", certificate.fingerprint},
      {"username", std::move(username)},
    };
  }

  json policy(std::int64_t issued, std::int64_t valid_until, json leases) {
    return {
      {"protocol", 1},
      {"server_time", issued},
      {"valid_until", valid_until},
      {"leases", std::move(leases)},
    };
  }

  void wait_for_refresh_window() {
    std::this_thread::sleep_for(refresh_interval);
  }

  void write_document(const std::filesystem::path &path, const std::string &document, bool wait = true) {
    if (wait) {
      wait_for_refresh_window();
    }
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(static_cast<bool>(output), "failed to open test policy file");
    output << document;
    output.close();
    require(static_cast<bool>(output), "failed to write test policy file");
    managed_access::refresh();
  }

  void write_policy(const std::filesystem::path &path, const json &document, bool wait = true) {
    write_document(path, document.dump(), wait);
  }

  void remove_policy(const std::filesystem::path &path) {
    wait_for_refresh_window();
    std::error_code error;
    std::filesystem::remove(path, error);
    require(!error, "failed to remove test policy file: " + error.message());
    managed_access::refresh();
  }

  bool has_all_permissions(crypto::PERM granted, crypto::PERM requested) {
    return static_cast<std::uint32_t>(granted & requested) == static_cast<std::uint32_t>(requested);
  }

  void test_exact_certificate_and_permissions(
    const std::filesystem::path &path,
    const certificate_t &authorized,
    const certificate_t &unknown,
    const certificate_t &derived
  ) {
    const auto now = unix_time();
    write_policy(path, policy(now, now + 20, json::array({lease(authorized, now + 20)})), false);

    auto client = managed_access::authorize(authorized.cert.get());
    require(client != nullptr, "the exact leased certificate was denied");
    require(client->name == "alice", "the policy username was not retained");
    require(managed_access::authorize(unknown.cert.get()) == nullptr, "an unknown certificate was authorized");
    require(managed_access::authorize(derived.cert.get()) == nullptr, "a certificate derived from the leased signer was authorized");
    require(managed_access::authorize(nullptr) == nullptr, "a null certificate was authorized");
    require(managed_access::allowed(client->uuid), "the authorized client's UUID was denied");

    require(has_all_permissions(client->perm, crypto::PERM::_all_inputs), "input permissions were not granted");
    require(has_all_permissions(client->perm, crypto::PERM::_all_actions), "action permissions were not granted");
    require(has_all_permissions(client->perm, crypto::PERM::clipboard_read), "clipboard read was not granted");
    require(has_all_permissions(client->perm, crypto::PERM::clipboard_set), "clipboard set was not granted");
    require(!has_all_permissions(client->perm, crypto::PERM::server_cmd), "server command permission was granted");
    require(!has_all_permissions(client->perm, crypto::PERM::file_upload), "file upload permission was granted");
    require(!has_all_permissions(client->perm, crypto::PERM::file_dwnload), "file download permission was granted");
    require(!client->allow_client_commands, "client commands were enabled");
  }

  void test_fail_closed_documents(const std::filesystem::path &path, const certificate_t &authorized) {
    auto install_valid_policy = [&]() {
      const auto now = unix_time();
      write_policy(path, policy(now, now + 20, json::array({lease(authorized, now + 20)})));
      require(managed_access::authorize(authorized.cert.get()) != nullptr, "valid setup policy was denied");
    };

    install_valid_policy();
    remove_policy(path);
    require(managed_access::authorize(authorized.cert.get()) == nullptr, "missing policy retained authorization");

    install_valid_policy();
    write_document(path, "{not-json");
    require(managed_access::authorize(authorized.cert.get()) == nullptr, "invalid JSON retained authorization");

    install_valid_policy();
    const auto now = unix_time();
    write_policy(path, policy(now - 10, now - 1, json::array({lease(authorized, now + 20)})));
    require(managed_access::authorize(authorized.cert.get()) == nullptr, "expired policy retained authorization");

    install_valid_policy();
    auto bad_lease = lease(authorized, now + 20);
    bad_lease["fingerprint"] = std::string(64, '0');
    write_policy(path, policy(now, now + 20, json::array({bad_lease})));
    require(managed_access::authorize(authorized.cert.get()) == nullptr, "mismatched certificate fingerprint retained authorization");
  }

  void test_expiry_and_renewal(const std::filesystem::path &path, const certificate_t &authorized) {
    wait_for_refresh_window();
    auto now = unix_time();
    write_policy(path, policy(now, now + 1, json::array({lease(authorized, now + 1)})), false);
    require(managed_access::authorize(authorized.cert.get()) != nullptr, "short lease was denied before expiry");
    std::this_thread::sleep_for(1100ms);
    require(managed_access::authorize(authorized.cert.get()) == nullptr, "expired lease remained authorized");

    wait_for_refresh_window();
    now = unix_time();
    write_policy(path, policy(now, now + 1, json::array({lease(authorized, now + 1, "before-renewal")})), false);
    auto original = managed_access::authorize(authorized.cert.get());
    require(original != nullptr, "renewal setup lease was denied");

    wait_for_refresh_window();
    now = unix_time();
    write_policy(path, policy(now, now + 3, json::array({lease(authorized, now + 3, "after-renewal")})), false);
    auto renewed = managed_access::authorize(authorized.cert.get());
    require(renewed != nullptr && renewed->name == "after-renewal", "updated lease was not loaded");
    std::this_thread::sleep_for(600ms);
    renewed = managed_access::authorize(authorized.cert.get());
    require(renewed != nullptr, "renewed lease expired at its original deadline");
  }

  void test_removal_invalidates_lookup_but_not_existing_value(
    const std::filesystem::path &path,
    const certificate_t &authorized
  ) {
    const auto now = unix_time();
    write_policy(path, policy(now, now + 20, json::array({lease(authorized, now + 20, "retained-object")})));
    auto existing = managed_access::authorize(authorized.cert.get());
    require(existing != nullptr, "removal setup lease was denied");
    const auto uuid = existing->uuid;

    const auto update_time = unix_time();
    write_policy(path, policy(update_time, update_time + 20, json::array()));
    require(existing->name == "retained-object", "existing named certificate value became invalid memory");
    require(managed_access::authorize(authorized.cert.get()) == nullptr, "removed certificate remained authorized");
    require(!managed_access::allowed(uuid), "removed UUID remained allowed through an existing named certificate pointer");
  }

  void test_policy_bounds(const std::filesystem::path &path, const certificate_t &authorized) {
    auto now = unix_time();
    write_policy(path, policy(now + 60, now + 80, json::array({lease(authorized, now + 80)})));
    require(managed_access::authorize(authorized.cert.get()) == nullptr, "policy issued too far in the future was accepted");

    now = unix_time();
    write_policy(path, policy(now, now + 91, json::array({lease(authorized, now + 91)})));
    require(managed_access::authorize(authorized.cert.get()) == nullptr, "policy exceeding the 90-second TTL was accepted");

    now = unix_time();
    json sixty_four = json::array();
    for (int index = 0; index < 64; ++index) {
      sixty_four.push_back(lease(authorized, now + 20, "lease-" + std::to_string(index)));
    }
    write_policy(path, policy(now, now + 20, std::move(sixty_four)));
    require(managed_access::authorize(authorized.cert.get()) != nullptr, "64-lease boundary policy was denied");

    now = unix_time();
    json sixty_five = json::array();
    for (int index = 0; index < 65; ++index) {
      sixty_five.push_back(lease(authorized, now + 20, "lease-" + std::to_string(index)));
    }
    write_policy(path, policy(now, now + 20, std::move(sixty_five)));
    require(managed_access::authorize(authorized.cert.get()) == nullptr, "65-lease policy was accepted");

    now = unix_time();
    write_policy(path, policy(now + 30, now + 120, json::array({lease(authorized, now + 120)})));
    require(managed_access::authorize(authorized.cert.get()) != nullptr, "future-issued policy at both accepted boundaries was denied");
  }

  void run_tests(const std::filesystem::path &path) {
    config::managed_policy_file = path.string();
    require(managed_access::enabled(), "managed access did not enable for a configured policy path");

    auto authorized = issue_certificate("authorized-client");
    auto unknown = issue_certificate("unknown-client");
    auto derived = issue_certificate("derived-client", authorized.cert.get(), authorized.key.get());

    test_exact_certificate_and_permissions(path, authorized, unknown, derived);
    test_fail_closed_documents(path, authorized);
    test_expiry_and_renewal(path, authorized);
    test_removal_invalidates_lookup_but_not_existing_value(path, authorized);
    test_policy_bounds(path, authorized);
  }
}  // namespace

int main() {
  const auto path = std::filesystem::temp_directory_path() /
                    ("apollo-managed-access-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
                     ".json");
  try {
    run_tests(path);
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    std::cout << "managed access policy tests passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    std::cerr << "managed access policy tests failed: " << error.what() << '\n';
    return 1;
  }
}
