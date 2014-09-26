require 'puppet/util/krb5'

Puppet::Type.newtype(:kerberos_principal) do
  @doc = "Manage a Kerberos principal"

  ensurable

  newparam(:name) do
    desc "Name of the principal (without the realm)"
    isnamevar
  end

  newproperty(:password) do
    desc %q{Password to use for this principal.
      
      If not set, a random key will be generated instead
    %}
    
    validate do |v|
      unless v == nil || (v === String && !v.empty?) do
        raise ArgumentError, "Invalid or empty password"
      end
      super
    }
  end

  newproperty(:expiration_date) do
    desc %q{Expiration date for the principal, if wanted.

      Valid values are described in the MIT Kerberos documentation
      (http://web.mit.edu/kerberos/krb5-1.12/doc/basic/date_format.html)
    %}

    validate do |v| {
      unless v == nil || v === String do
        raise ArgumentError, "Invalid expiration date"
      super
    }
  end

  newproperty(:password_expiration_date) do
    desc %q{Expiration date for the principal's password, if wanted.

      Valid values are described in the MIT Kerberos documentation
      (http://web.mit.edu/kerberos/krb5-1.12/doc/basic/date_format.html)
    %}

    validate do |v| {
      unless v == nil || v === String do
        raise ArgumentError, "Invalid password expiration date"
      end
      super
    }
  end

  newproperty(:max_renewable_ticket_life) do
    desc "%q{Maximum lifetime of renewable tickets, in seconds (0, undefined or nil for unlimited)"
    validate do |v| {
      unless v == nil || (v === Integer && v >= 0) do
        raise ArgumentError, "Invalid renewable ticket life"
      end
      super
    }
  end

  newproperty(:max_ticket_life) do
    desc "%q{Maximum lifetime of granted tickets, in seconds (0, undefined or nil for unlimited)"
    validate do |v| {
      unless v == nil || (v === Integer && v >= 0) do
        raise ArgumentError, "Invalid ticket life"
      end
      super
    }
  end

  newproperty(:policy) do
    desc %q{Name of the password policy for the principal.

      An undefined value corresponds to using the default password policy, if
      any is defined in the Kerberos server. To ensure no policy is used
      instead, use 'none' as a value.
    %}

    validate do |v| {
      unless v === nil || (v == String && !v.empty?) do
        raise ArgumentError, "Invalid policy"
      end
      super
    }

    munge do |v| {
      if v == 'none' then
        nil
      else
        super
      end
    }
  end

  newparam(:options) do
    desc %q{Options for creation of the principal as a hash
      
      Every option accepted by the `addprinc` command can be specified as a key.
      Values should correspond to how the parameter is expected by kadmin,
      according to the following mappings:
      - Parameters enabled that receive no values and start with only a dash in
        kadmin, must correspond to the string 'enable' in the hash to be enabled,
        or anything else to be disabled.
      - Parameters that are enabled or disabled by being preceded with either
        '+' or '-' in kadmin must have, correspondly, values of `true` or `false`
        in the hash
      - Parameters that need values in kadmin use their corresponding values in
        the hash, which must be integers, strings
    %}

    validate do |h|
      unless h === Hash && hash.values.all? { |v|
        v === Integer || v === String
      } do
        raise ArgumentError, "Invalid options hash"
      end
      super
    }
  end

  def create
    KerberosUtil.from_config()


end
