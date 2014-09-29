require 'puppet/util/krb5'

module Puppet::Parser::Functions
  newfunction(:krb5_list_principals, :type => :rvalue, :arity => 1, :doc => %q{
Looks up a list of principals matching a pattern in a Kerberos server.
Returns an array with the names of the matching principals
%}) \
  do |args|
    begin
      Puppet::Util::Krb5.kadmin_instance.list_principals(args[0])
    rescue StandardError => e
      puts e.backtrace.join("\n\t")
      raise Puppet::ParseError, e.class.name + ": " + e.to_s
    end
  end
end
