require 'puppet/util/krb5'

module Puppet::Parser::Functions.newfunction(:krb5_add_principal,
  :type => :rvalue, :arity => 1, :doc => %q{
Create a new kerberos principal with a random password. Returns the full name
of the created principal on success, or raises an exception on failure.
}) \
do |args|
  begin
    Puppet::Util::Krb5.principal_check_name(args[0])
  rescue ArgumentError => e
    raise Puppet::ParseError, e.message
  end

  begin
    Puppet::Util::Krb5.kadmin_instance.add_principal(args[0])
  rescue StandardError => e
    raise Puppet::Error, e.message
  end
end
