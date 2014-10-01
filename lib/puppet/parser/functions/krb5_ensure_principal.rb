require 'puppet/util/krb5'

module Puppet::Parser::Functions.newfunction(:krb5_ensure_principal,
  :type => :rvalue, :arity => 1, :doc => %q{
Create a new kerberos principal if it does not exist. Returns the full name
of the new or existing principal on success, or raises an exception on failure.
%}) \
do |args|
  begin
    Puppet::Util::Krb5.principal_check_name(args[0])
  rescue ArgumentError => e
    raise Puppet::ParseError, e.message
  end
  
  begin
    kadmin = Puppet::Util::Krb5.kadmin_instance

    princ = kadmin.get_principal(args[0])
    princ ? princ.name : kadmin.add_principal(args[0])
  rescue StandardError => e
    raise Puppet::Error, e.message
  end
end
