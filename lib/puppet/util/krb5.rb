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

  def principal_check_name(principal)
    if principal == nil || principal.empty?
      raise ArgumentError, 'Invalid principal name'
    end
  end

  module_function :principal_check_name

  def principal_check_pattern(pattern)
    if pattern == nil || pattern.empty?
      raise ArgumentError, 'Invalid principal pattern'
    end
  end

  module_function :principal_check_pattern
end

require 'puppet/util/krb5/kadmin'
require 'puppet/util/krb5/ktutil'
require 'puppet/util/krb5/config'
