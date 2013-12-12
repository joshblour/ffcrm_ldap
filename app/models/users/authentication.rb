Authentication.instance_eval do
  verify_password_method :valid_ldap_credentials?
  find_by_login_method :find_by_username
end
