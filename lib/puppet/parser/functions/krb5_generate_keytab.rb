require 'puppet/util/krb5'

module Puppet::Parser::Functions
  newfunction(:krb5_generate_keytab, :type => :rvalue, :arity => 1, :doc => %q{
Generate a keytab for the given principals, and return a puppet file server URL
that can be used to send it to a client.

This function takes a list of principals as it's only argument: they will be
included in the generated keytab. If any of them does not have an explicit realm,
the default one from the 'krb5_default_realm' option in puppet.conf will be used.
}) \
  do |args|
    def default_realm
      Puppet.settings.use(:krb5)
      realm = Puppet.settings[:krb5_default_realm]
      if realm == nil || realm.empty?
        raise Puppet::Error("Kerberos default realm needed, but not set up in puppet.conf")
      end

      realm
    end

    principals = args[0]
    if ! principals.is_a?(Enumerable) || ! principals.all? { |p| p.is_a?(String) }
      raise Puppet::ParseError("Invalid parameter: must be a sequence of strings")
    end

    principals = principals.map { |p|
      p.include?('@') ? p : (p + '@' + default_realm)
    }

    begin
      Puppet::Util::Krb5.kadmin_instance.add_principal(args[0])
    rescue StandardError => e
      raise Puppet::ParseError, e.class.name + ": " + e.to_s
    end
  end
end
