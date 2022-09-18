#ifndef PAM_OAUTH2_DEVICE_CONFIG_HPP
#define PAM_OAUTH2_DEVICE_CONFIG_HPP

#include <map>
#include <set>
#include <string>

class Config {
 public:
  void load(const char *path);
  std::string client_id, client_secret, scope, device_endpoint, token_endpoint,
      userinfo_endpoint, username_attribute, ldap_basedn, ldap_user,
      ldap_passwd, ldap_filter, ldap_attr;
  bool require_mfa, qr_show, token_user_gen;
  std::set<std::string> ldap_hosts;
  int qr_error_correction_level;
  std::map<std::string, std::set<std::string>> usermap;
};

#endif  // PAM_OAUTH2_DEVICE_CONFIG_HPP
