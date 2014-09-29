require 'puppet/util/krb5'

module Puppet::Parser::Functions
  newfunction(:krb5_ensure_principal, :type => :rvalue, :arity => 1, :doc => %q{
Create a new kerberos principal if it does not exist. Returns the full name
of the new or existing principal on success, or raises an exception on failure.
%}) \
  do |args|
    name = args[0]
    kadmin = Puppet::Util::Krb5.kadmin_instance

    begin
      princ = kadmin.get_principal(name)
      if not princ
        kadmin.add_principal(name)
      else
        princ.name
      end
    rescue StandardError => e
      raise Puppet::ParseError, e.class.name + ": " + e.to_s
    end
  end
end
