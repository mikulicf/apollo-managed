/**
 * @file src/managed_access.h
 * @brief Expiring, exact-certificate authorization for centrally managed hosts.
 */
#pragma once

#include "crypto.h"

namespace managed_access {
  // An empty policy path leaves normal Apollo operation unchanged.
  bool enabled();
  crypto::p_named_cert_t authorize(X509 *certificate);
  bool allowed(const std::string &client_uuid);
  void refresh();
}  // namespace managed_access
