require 'puppet/util/krb5'

Puppet::Parser::Functions.newfunction(:krb5_add_principal,
  :type => :rvalue, :arity => 1, :doc => %q{
Create a new kerberos principal with a random password. Returns the full name
of the created principal on success, or raises an exception on failure.
}) \
do |args|
  begin
    kadmin = Puppet::Util::Krb5.kadmin_instance
    kadmin.add_principal(args[0], :randkey => true)
  rescue ArgumentError, Puppet::Util::Krb5::KerberosError => e
    raise Puppet::ParseError, "Failed creating principal #{args[0]}: #{e}",
      e.backtrace
  end
end
