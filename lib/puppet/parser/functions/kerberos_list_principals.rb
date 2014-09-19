module Puppet::Parser::Functions
  newfunction(:kerberos_list_principals, :type => :rvalue, :arity => 1, :doc => "
Looks up a list of principals matching a pattern in a Kerberos server. Returns
an array with the names of the matching principals.
") do |args|
    require 'puppet/util'

    pattern = args[0]
    if pattern == nil || pattern.empty?
      raise Puppet::ParseError,
        "kerberos_list_principals(): Invalid pattern"
    end

    command = KerberosbUtil.kadmin_command
    command << ['-q', "listprincs #{pattern}"]
    
    out = Puppet.Util.Execution.execute(command, {
      :failonfail => true, :combine => false
    })
    principals = out.split("\n").grep(/^[^@]+@[^@]+$/)
    principals
  end
end
