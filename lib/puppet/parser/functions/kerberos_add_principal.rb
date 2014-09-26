require 'puppet/util/krb5'

module Puppet::Parser::Functions
  newfunction(:kerberos_add_principal, :type => :rvalue, :arity => 1, :doc => "
Create a new kerberos principal with a random password. Returns the full name
of the created principal on success, or raises an exception on failure.
") do |args|
    require 'puppet/util'

    name = args[0]
    if name == nil || name.empty?
      raise Puppet::ParseError,
        "kerberos_add_principal(): Invalid name"
    end

    KerberosUtils.add_principal()
  end
end
