require 'puppet/util/krb5'

Puppet::Parser::Functions.newfunction(:krb5_ensure_principal,
  :type => :rvalue, :arity => 1, :doc => %q{
Create a new kerberos principal if it does not exist. Returns the full name
of the new or existing principal on success, or raises an exception on failure.
%}) \
do |args|
  begin
    kadmin = Puppet::Util::Krb5.kadmin_instance
    princ = kadmin.get_principal(args[0])
    princ ? princ.name : kadmin.add_principal(args[0], :randkey => true)
  rescue ArgumentError, Puppet::Util::Krb5::KerberosError => e
    raise Puppet::ParseError, "Failed ensuring principal #{args[0]}: #{e}",
      e.backtrace
  end
end
