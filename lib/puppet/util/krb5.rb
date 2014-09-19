require 'open3'
require 'date'

class KerberosError < RuntimeError
  def self.from_kadmin(message, exitstatus = 0)
    self.new("kadmin failed (status #{exitstatus}): #{message}")
  end
end

class KerberosUtils
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

  def initialize(opts = {})
    @principal = opts[:principal]
    @password = opts[:password]
    @use_keytab = opts[:use_keytab]
    @keytab_file = opts[:keytab_file]
    @realm = opts[:realm]
    @cred_cache = opts[:cred_cache]
    @local = opts[:local]
    @server = opts[:server]
    @extra_options = opts[:extra_options]
  end

  attr_accessor :principal, :password, :use_keytab, :keytab_file, :realm,
                :cred_cache, :local, :server, :extra_options

  def kadmin_find_error_message(err_s)
    err_s.split(/\n+/).find { |line|
      line =~ /^(\w+):/ && Regexp.last_match[1].casecmp("warning") != 0
    }
  end

  protected :kadmin_find_error_message

  def kadmin_execute(kadmin_command, opts = {})
    cmd = if @local
      ["kadmin.local"]
    else
      ["kadmin"]
    end

    cmd += ['-r', @realm] if @realm
    cmd += ['-p', @principal] if @principal
    if @use_keytab
      cmd << '-k'
      cmd += ['-t', @keytab_file] if @keytab_file
    end
    cmd += ['-c', @cred_cache] if @cred_cache
    cmd += ['-s', @server] if @server
    cmd += @extra_options if @extra_options
    cmd += ['-q', kadmin_command]

    if @password
      opts[:stdin_data] = "#{@password}\n" + (opts[:stdin_data] || "")
    end

    out_s, err_s, status = Open3.capture3(*cmd, opts)

    if status.exitstatus != 0
      message = kadmin_find_error_message(err_s)
      raise KerberosError.from_kadmin(message, status.exitstatus)
    end

    [out_s, err_s, status]
  end

  protected :kadmin_find_error_message

  def add_principal(principal, opts = {})
    if principal == nil || principal.empty?
      raise ArgumentError,
        "add_principal: Invalid principal"
    end

    pw = opts.delete(:pw)

    cmd = ["addprinc"]
    opts.each do |key, value|
      if [TrueClass, FalseClass].include?(value.class)
        cmd << (value ? "+#{key}" : "-#{key}")
      else
        cmd << "-#{key}"
        if value != nil
          value = value.to_s
          cmd << (value.include?(" ") ? "\"#{value}\"" : value)
        end  
      end
    end

    cmd << principal

    exec_opts = if pw
      {:stdin_data => "#{pw}\n" * 2}
    else
      {}
    end

    out_s, err_s, status = kadmin_execute(cmd.join(' '), exec_opts)
    out_s.split("\n").each do |line|
      if line.include?("created")
        match = /"([^"]+@[^"]+)"/.match(line)
        if match
          return match[1]
        end
      end
    end

    message = kadmin_find_error_message(err_s)
    raise KerberosError.from_kadmin(message)
  end

  def list_principals(pattern)
    if pattern == nil || pattern.empty?
      raise ArgumentError,
        "list_principals: Invalid pattern"
    end

    out_s, err_s, status = kadmin_execute("listprincs \"#{pattern}\"")

    principals = out_s.split("\n").grep(/^[^@ ]+@[^@ ]+$/)
    if principals.empty?
      message = kadmin_find_error_message(err_s)
      if message
        raise KerberosError.from_kadmin(message)
      end
    end

    principals
  end

  def get_principal(principal)
    if principal == nil || principal.empty?
      raise ArgumentError,
        "get_principal: Invalid principal name"
    end

    out_s, err_s, status = kadmin_execute("getprinc -terse \"#{principal}\"")

    fields = nil
    out_s.split("\n").each do |line|
      if line.include?("\t")
        fields = line.split("\t")
        break
      end
    end

    if fields == nil
      message = kadmin_find_error_message(err_s)
      if message
        raise KerberosError.from_kadmin(message, status.exitstatus)
      else
        return nil
      end
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
      ts == 0 ? nil : Time.at(ts).to_datetime
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

  def keytab_add(principal, keytab_file = nil, is_principal_glob = false, 
                 no_rand_keys = false)
    if principal == nil || principal.empty?
      raise ArgumentError,
        "keytab_add: Invalid principal"
    end

    cmd = ["ktadd"]
    cmd += ["-k", "\"#{keytab_file}\""] if keytab_file
    cmd << '-norandkey' if no_rand_keys
    cmd << '-glob' if is_principal_glob
    cmd << "\"#{principal}\""   

    out_s, err_s, status = self.kadmin_execute(cmd.join(' '))
    num_entries_added = out_s.split("\n").count { |line|
      line.include?("added to keytab")
    }

    if num_entries_added == 0
      message = kadmin_find_error_message(err_s)
      raise KerberosError.from_kadmin(message)
    end

    num_entries_added
  end
end
