require 'open3'
require 'date'

module KerberosUtils
  class KerberosError < Exception
  end

  def self.kadmin_command
    ["kadmin.local"]
  end
   
  def self.execute(*cmd)
    Open3.capture3(*cmd)
  end

  def self.add_principal(name)
    if name == nil || name.empty?
      raise ArgumentError,
        "add_principal: Invalid name"
    end

    command = kadmin_command
    command += ['-q', "addprinc -randkey #{name}"]
    
    out_s, err_s, status = self.execute(*command)
    if status.exitstatus != 0
      raise KerberosError,
        "add_principal: kadmin failed with status #{status.exitstatus}"
    end

    out_s.split("\n").each do |line|
      if line.include?("created")
        match = /"([^"]+@[^"]+)"/.match(line)
        if match and match[1]
          return match[1]
        end
      end
    end

    raise KerberosError,
      "add_principal: failed to match kadmin output"
  end

  def self.list_principals(pattern)
    if pattern == nil || pattern.empty?
      raise ArgumentError,
        "list_principals: Invalid pattern"
    end

    command = kadmin_command
    command += ['-q', "listprincs #{pattern}"]
    
    out_s, err_s, status = self.execute(*command)
    if status.exitstatus != 0
      raise KerberosError,
        "list_principals: kadmin failed with status #{status.exitstatus}"
    end

    principals = out_s.split("\n").grep(/^[^@ ]+@[^@ ]+$/)
    principals
  end

  Principal = Struct.new("Principal",
    :name,
    :expiration_date,
    :pw_last_change_date,
    :pw_expiration_date,
    :max_ticket_life,
    :last_modified_date,
    :last_modified_principal,
    :attributes,
    :policy,
    :max_renewable_ticket_life,
    :auth_last_success,
    :auth_last_fail,
    :auth_fail_count
  )

  def self.get_principal(name)
    if name == nil || name.empty?
      raise ArgumentError,
        "get_principal: Invalid name"
    end

    command = kadmin_command
    command += ['-q', "getprinc -terse #{name}"]
    
    out_s, err_s, status = self.execute(*command)
    if status.exitstatus != 0
      raise KerberosError,
        "get_principal: kadmin failed with status #{status.exitstatus}"
    end

    fields = nil
    out_s.split("\n").each do |line|
      if line.start_with?("\"#{name}")
        fields = line.split("\t")
        break
      end
    end

    if fields == nil
      return nil
    end

    n = -1

    f_str = lambda {
      fields[n += 1].gsub(/(^")|("$)/, '')
    }
    
    f_int = lambda {
      fields[n += 1].to_i
    }
    
    f_time = lambda {
      ts = fields[n += 1].to_i
      if ts == 0
        nil
      else
        Time.at(ts).to_datetime
      end
    }

    p = Principal.new()

    p.name                      = f_str.call
    p.expiration_date           = f_time.call
    p.pw_last_change_date       = f_time.call
    p.pw_expiration_date        = f_time.call
    p.max_ticket_life           = f_int.call
    p.last_modified_principal   = f_str.call
    p.last_modified_date        = f_time.call
    p.attributes                = f_int.call
    n += 2
    p.policy                    = f_str.call
    p.max_renewable_ticket_life = f_int.call
    p.auth_last_success         = f_time.call
    p.auth_last_fail            = f_time.call
    p.auth_fail_count           = f_int.call
 
    if p.policy == "[none]"
      p.policy = nil
    end

    p
  end
end
