require 'puppet/util/krb5/kadmin'
require 'puppet/util/krb5/ktutil'
require 'puppet/util/krb5/config'

module Puppet::Util::Krb5
  class KerberosError < RuntimeError
    def self.from_command(command, message, exitstatus = 0)
      self.new("#{command} failed (status #{exitstatus}): #{message}")
    end
  end

  Principal = Struct.new("Principal",
    :name,
    :expiration_date,
    :pw_last_change_time,
    :pw_expiration_time,
    :max_ticket_life,
    :last_modified_principal,
    :last_modified_time,
    :attributes,
    :key_version,
    :master_key_version,
    :policy,
    :max_renewable_ticket_life,
    :auth_last_success,
    :auth_last_fail,
    :auth_fail_count
  )

  module_function

  def principal_check_name(principal)
    if principal == nil || principal.empty?
      raise ArgumentError, "Invalid principal name - '#{name}'"
    end
  end

  def principal_check_pattern(pattern)
    if pattern == nil || pattern.empty?
      raise ArgumentError, "Invalid principal pattern - '#{pattern}'"
    end
  end

  @kadmin_instance = nil

  def kadmin_new
    setting_names = [:bin, :local_bin, :realm, :principal, :password,
                     :use_keytab, :keytab_file, :local, :server, :cred_cache,
                     :extra_options]

    opts = setting_names.each.with_object(Hash.new) do |setting, h|
      key = "krb5_kadmin_#{setting}".to_sym
      value = Puppet.settings[key]
      value = nil if value.is_a?(String) && value.empty?
      
      h[setting] = value
    end

    Puppet.info("kopts: #{opts.to_s}")

    Kadmin.new(opts)
  end
  
  def kadmin_instance
    @kadmin_instance ||= kadmin_new
  end
  
  def ktutil_new(path)
    Ktutil.new(path, Puppet.settings[:krb5_ktutil_bin])
  end
end
