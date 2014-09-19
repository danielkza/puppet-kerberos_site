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

    command = KerberosUtil.kadmin_command
    command << ['-q', "addprinc -randkey #{name}"]
    
    out = Puppet.Util.Execution.execute(command, {
      :failonfail => true, :combine => false
    })

    out.split("\n").each do |line|
      if line.include?("created")
        match = /"([^"]+@[^"]+)"/.match(line)
        if match and match[1]
          return match[1]
        end
      end
    end

    raise Puppet::ParseError,
      "kerberos_add_principal(): Failed to match principal name in output"
  end
end
