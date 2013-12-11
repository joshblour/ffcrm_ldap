require 'net/ldap'
module FfcrmLdap
  class LDAPAccess
    class << self
      # Attempts to bind to LDAP using the given username and password
      # returns true if successful, false otherwise.
      def authenticate(uid, password)
        ldap = connect()
        result = ldap.bind_as(
          :base => Config.base,
          :login => uid,
          :password => password)
        return !!result
      end

      def get_user_details(uid)
        ldap = connect()

        results = ldap.search(
          :filter => Net::LDAP::Filter.eq(Config.attribute.to_s, uid.to_s) )
        if results and results.size > 0
          details = {}
          results[0].each do |name, values|
            details[name] = values[0].dup
          end
          details
        else
          nil
        end
      end

      protected

      def connect()
        return Net::LDAP.new(
          :host => Config.host,
          :port => Config.port,
          :base => Config.base,
          :encryption => Config.ssl ? :simple_tls : nil #,
          # :auth => {
          #         :method => :simple,
          #         :username => Config.bind_dn,
          #         :password => Config.bind_passwd }
          )
      end
    end

    class Config
      def self.method_missing(name, *args)
        if config.has_key?(name.to_s)
          config[name.to_s]
        else
          super
        end
      end

      @config = nil
      def self.config
        @config ||= YAML.load_file(File.join(Rails.root, %w(config ldap.yml)))[Rails.env]
      end
    end
  end
end
