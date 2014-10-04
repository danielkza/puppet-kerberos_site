require 'puppet/util/krb5'

Puppet::Parser::Functions.newfunction(:krb5_list_principals,
  :type => :rvalue, :arity => 1, :doc => %q{
Looks up a list of principals matching a pattern in a Kerberos server.
Returns an array with the names of the matching principals
%}) \
do |args|
  begin
    kadmin = Puppet::Util::Krb5.kadmin_instance
    kadmin.list_principals(args[0])
  rescue ArgumentError, Puppet::Util::Krb5::KerberosError => e
    raise Puppet::ParseError, "Failed listing principals: #{e}", e.backtrace
  end
end
