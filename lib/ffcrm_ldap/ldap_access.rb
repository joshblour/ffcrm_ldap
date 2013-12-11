require 'net/ldap'
module FfcrmLdap
  module LdapAdapter

    def self.valid_credentials?(login, password_plaintext)
      puts 'starting validation'
      options = { :login => login, :password => password_plaintext }
      resource = LdapConnect.new(options)
      puts 'inspect resource'
      puts resource.inspect
      resource.authorized? ? resource : nil
    end
    
    def self.get_user_details(login)
      options = { :login => login }
      resource = LdapConnect.new(options)
      resource.get_user_details
    end
    
    class LdapConnect

      attr_reader :ldap, :login

      def initialize(params = {})
        ldap_config = YAML.load(ERB.new(File.read("#{Rails.root}/config/ldap.yml")).result)[Rails.env]
        ldap_options = params
        ldap_config["ssl"] = :simple_tls if ldap_config["ssl"] === true
        ldap_options[:encryption] = ldap_config["ssl"].to_sym if ldap_config["ssl"]

        @ldap = Net::LDAP.new(ldap_options)
        @ldap.host = ldap_config["host"]
        @ldap.port = ldap_config["port"]
        @ldap.base = ldap_config["base"]
        @attribute = ldap_config["attribute"]

        @login = params[:login]
        @password = params[:password]
        @new_password = params[:new_password]
      end

      def dn
        puts("LDAP dn lookup: #{@attribute}=#{@login}")
        ldap_entry = search_for_login
        if ldap_entry.nil?
          "#{login}@group-ips.local"
        else
          ldap_entry.dn
        end
      end

      def authenticate!
        @ldap.auth(dn, @password)
        @ldap.bind
      end

      def authenticated?
        authenticate!
      end

      def authorized?
        puts("Authorizing user #{dn}")
        authenticated?
      end

      def ldap_entry
        search_for_login
      end

      # Searches the LDAP for the login
      #
      # @return [Object] the LDAP entry found; nil if not found
      def search_for_login
        puts("LDAP search for login: #{@attribute}=#{@login}")
        filter = Net::LDAP::Filter.eq(@attribute.to_s, @login.to_s)
        ldap_entry = nil
        @ldap.search(:filter => filter) {|entry| ldap_entry = entry}
        ldap_entry
      end
      
      def get_user_details

        results = @ldap.search(
          :filter => Net::LDAP::Filter.eq(@attribute.to_s, @login.to_s)
          )
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

    end

  end
end
