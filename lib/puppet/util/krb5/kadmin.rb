require 'open3'
require 'time'
require 'date'

#module Puppet::Util::Krb5
module Krb5
  class KerberosError < RuntimeError
    def self.from_kadmin(message, exitstatus = 0)
      self.new("kadmin failed (status #{exitstatus}): #{message}")
    end
  end

  KEYTAB_KVNO_ALL = 'all'
  KEYTAB_KVNO_OLD = 'old'

  Principal = Struct.new("Principal",
    :name,
    :expiration_date,
    :pw_last_change_date,
    :pw_expiration_date,
    :max_ticket_life,
    :last_modified_principal,
    :last_modified_date,
    :attributes,
    :key_version,
    :master_key_version,
    :policy,
    :max_renewable_ticket_life,
    :auth_last_success,
    :auth_last_fail,
    :auth_fail_count
  )

  class Kadmin
    def initialize(opts = {})
      @bin = opts[:bin] || 'kadmin'
      @local_bin = opts[:local_bin] || 'kadmin.local'

      @realm = opts[:realm]
      @principal = opts[:principal]

      @local = opts[:local]
      @server = opts[:server]

      @password = opts[:password]
      @use_keytab = opts[:use_keytab]
      @keytab_file = opts[:keytab_file]
      @cred_cache = opts[:cred_cache]

      @extra_options = opts[:extra_options]

      auth_options_count = [@password, @use_keytab, @cred_cache].compact.length
      if @local && (@server || auth_options_count > 0)
        raise ArgumentError,
          'Server, password, keytab or cred_cache cannot be specified with local'
      elsif auth_options_count != 1
        raise ArgumentError,
          'Exactly one authentication method (use_keytab, cred_cache or password) must be used'
      end
    end

    attr_reader :bin, :local_bin, :realm, :principal, :local, :server,
                :password, :use_keytab, :keytab_file, :cred_cache,
                :extra_options

    def add_principal(principal, opts = {})
      principal_check_name(principal)
      
      principal_add_or_modify(principal, false, opts)
    end

    def modify_principal(principal, opts = {})
      principal_check_name(principal)
      
      principal_add_or_modify(principal, true, opts)
    end

    def list_principals(pattern = '*')
      principal_check_pattern(pattern)

      out, err, status = execute_query(['listprincs',  pattern])

      principals = out.split("\n").grep(/^[^@ ]+@[^@ ]+$/)
      if principals.empty?
        message = find_error_message(err)
        raise KerberosError.from_kadmin(message) if message
      end

      principals
    end

    def get_principal(principal)
      principal_check_name(principal)

      out, err, status = execute_query(['getprinc', '-terse', principal])

      fields = out.split("\n").find{ |line| line.include?("\t") }
      if fields == nil
        message = find_error_message(err)
        return nil if message && message =~ /principal does not exist/i

        raise KerberosError.from_kadmin(message, status.exitstatus)
      end

      fields_enum = fields.split("\t").each
      
      f_str = lambda { unquote_field(fields_enum.next) }
      f_int = lambda { fields_enum.next.to_i }
      f_nonzero = lambda { f_int.call.nonzero? }
      f_time = lambda {
        ts = f_int.call.nonzero?
        ts && Time.at(ts).to_datetime
      }

      # Mappings of the fields to their corresponding types, with example output
      # for each. To see what each of they mean, check the members of the
      # Principal struct.

      field_types = [
        f_str, f_time,             # "example@EXAMPLE.COM" 0
        f_time, f_time, f_nonzero, # 1411876750 0 86400
        f_str, f_time,             # "example/admin@EXAMPLE.COM" 1411888618
        f_int,                     # 0
        f_int, f_int,              # 1 1
        f_str,                     # [none]
        f_nonzero,                 # 0
        f_time, f_time, f_int      # 0 0 0
      ]

      begin
        p = Principal.new(*field_types.map(&:call))
      rescue TypeError
        raise KerberosError,
          "Failed to parse principal information from kadmin output"
      end
   
      p.policy == "[none]" if p.policy = nil
      p
    end

    def keytab_add(principal_or_pattern, is_glob = false, keytab_file = nil,
                   no_rand_keys = false)
      if !is_glob
        principal_check_name(principal_or_pattern)
      else
        principal_check_pattern(principal_or_pattern)
      end

      query = ['ktadd',
        *(["-k", "\"#{keytab_file}\""] if keytab_file),
        *('-norandkey' if no_rand_keys),
        *('-glob' if is_glob),
        principal_or_pattern
      ]   

      out, err, status = self.execute_query(query)

      num_entries_added = out.split("\n").count { |line|
        line.downcase.include?("added to keytab")
      }

      if num_entries_added == 0
        message = find_error_message(err)
        raise KerberosError.from_kadmin(message)
      end

      num_entries_added
    end
    
    def keytab_remove(principal, key_version, keytab_file = nil)
      principal_check_name(principal)

      if key_version.is_a?(Integer)
        if key_version <= 0
          raise ArgumentError, "Invalid numeric key version"
        end
      elsif ! [KEYTAB_KVNO_ALL, KEYTAB_KVNO_OLD].include?(key_version)
        raise ArgumentError, "Invalid key version"
      end

      query = [
        'ktremove',
        *(["-k", "\"#{keytab_file}\""] if keytab_file),
         principal,
         key_version.to_s]
      
      out, err, status = self.execute_query(query)

      num_entries_removed = out.split("\n").count { |line|
        line.downcase.include?("removed from keytab")
      }

      if num_entries_removed == 0
        message = find_error_message(err)
        raise KerberosError.from_kadmin(message)
      end

      num_entries_removed
    end

    protected

    def find_error_message(text)
      text.split(/\n+/).find do |line|
        match = /^(\w+):/.match(line)
        match && (match[1].casecmp("warning") != 0)
      end
    end

    def execute_query(query, env = {}, opts = {})
      query_str = query.map { |elm|
        !elm.include?(" ") ? elm : ('"' + elm.gsub('"', '""') + '"')
      }.join(' ')

      cmd = [
        @local ? @local_bin : @bin,
        *(['-r', @realm] if @realm),
        *(['-p', @principal] if @principal),
        '-q', query_str
      ]

      if !@local
        if @cred_cache
          cmd += ['-c', @cred_cache]
        elsif @use_keytab
          cmd += ['-k', *(['-t', @keytab_file] if @keytab_file)]
        end

        cmd += ['-s', @server] if @server
      end

      cmd += @extra_options if @extra_options
      
      if @password
        opts[:stdin_data] = "#{@password}\n" + (opts[:stdin_data] || "")
      end

      env['LANG'] ||= 'C'
      env['LC_ALL'] ||= 'C'

      puts "Executing kadmin: #{cmd.to_s}"
      out, err, status = Open3.capture3(env, *cmd, opts)

      if status.exitstatus != 0
        message = find_error_message(err)
        raise KerberosError.from_kadmin(message, status.exitstatus)
      end

      [out, err, status]
    end

    def principal_check_name(principal)
      if principal == nil || principal.empty?
        raise ArgumentError, 'Invalid principal name'
      end
    end

    def principal_check_pattern(pattern)
      if pattern == nil || pattern.empty?
        raise ArgumentError, 'Invalid principal pattern'
      end
    end

    def unquote_field(s)
      if s[0] == ?"
        if s.length >= 2 && s[-1] == ?"
          return s[1..-2].gsub('""', ?")
        end
      elsif !s.empty?
        return s
      end

      raise TypeError, "Invalid string field"
    end

    def is_boolean(v)
      [TrueClass, FalseClass].any?(&v.method(:is_a?))
    end
    
    def format_datetime(time)
      time.strftime('%Y-%m-%d %H:%M:%S %z')
    end

    def principal_query_params(opts = {})
      attrs = opts.delete(:attributes) || {}

      params = opts.map do |k, v|
        if is_boolean(v)
          v ? ["-#{k}"] : []
        else
          if v.is_a?(DateTime)
            v = format_datetime(v)
          elsif v.is_a?(Integer)
            v = v.to_s
          elsif !v.is_a?(String)
            raise ArgumentError, "Invalid value for option #{k}"
          end

          ["-#{k}", v]
        end
      end

      attrs.each do |k, v|
        if v != nil
          if !is_boolean(v)
            raise ArgumentError, "Invalid value for attribute #{k}"
          end
          params << (v ? '+' : '-') + k.to_s
        end
      end

      params
    end

    def principal_add_or_modify(principal, modify = false, opts = {})
      principal_check_name(principal)
      opts = opts.clone

      password = opts.delete(:pw)
      query = [modify ? 'modprinc' : 'addprinc', *principal_query_params(opts),
               principal]

      out, err, status = execute_query(query, {},
        :stdin_data => ("#{password}\n" * 2 if password))

      out.split("\n").each do |line|
        match = /principal "([^"]+)" (created|modified)/i.match(line)
        return match[1] if match
      end

      message = find_error_message(err)
      raise KerberosError.from_kadmin(message)
    end
  end
end
