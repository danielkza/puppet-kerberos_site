require 'puppet/util/krb5'

module Puppet::Parser::Functions
  newfunction(:krb5_generate_keytab, :type => :rvalue, :arity => 1, :doc => %q{
Generate a keytab for the given principals, and return a puppet file server URL
that can be used to send it to a client.

This function takes a list of principals as it's only argument: they will be
included in the generated keytab. If any of them does not have an explicit realm,
the default one from the 'krb5_default_realm' option in puppet.conf will be used.
}) \
  do |args|
    principal_names = args[0]
    if ! principal_names.is_a?(Enumerable) || ! principal_names.all? { |p| p.is_a?(String) }
      raise Puppet::ParseError,
        "Invalid parameter: must be a sequence of strings")
    end

    keytab_dir = Puppet.settings[:krb5_keytab_dir]
    if ! keytab_dir || ! File.directory?(keytab_dir)
      raise Puppet::Error,
        "Unconfigured or missing keytab dir - '#{keytab_dir}'"
    end

    kadmin = Puppet::Util::Krb5.kadmin_instance
    keytab_paths = principal_names.map do |n|
      p = kadmin.get_principal(n)
      if ! p
        raise Puppet::Error,
          "Principal #{n} not found in Kerberos database"
      end

      keytab_path = File.join(keytab_dir, p.name)
      if File.exists?(keytab_path)
        if File.mtime(keytab_path) < p.last_modified_time
          function_info("Keytab for principal #{p.name} is outdated, regenerating")
          File.rm(keytab_path)
        else
          return keytab_path
        end

        kadmin.keytab_add(p.name, false, keytab_path)
      end

      keytab_path
    end



        kadmin.keytab_add(p.name, false, keytab_path, )



    principal = kadmin_instance.get_principal()

    trusted_data = lookupvar('trusted')
    certname = trusted_data && trusted_data.is_a?(Hash) && trusted_data['certname']

    if ! certname
      raise Puppet::Error,
        "Failed to retrieve trusted certname for current node"
    end

    host_keytab_dir = File.join(keytab_dir, certname)
    if ! File.directory?(host_keytab_dir)
      begin
        File.mkdir(host_keytab_dir, :mode => 0700)
      rescue SystemCallError => e
        raise Puppet::Error, "Failed to create keytab directory: #{e}"
      end
    end

    host_keytab_dir = Pathname.new(keytab_dir) + 

    begin
      Puppet::Util::Krb5.kadmin_instance.add_principal(args[0])
    rescue StandardError => e
      raise Puppet::ParseError, e.class.name + ": " + e.to_s
    end
  end
end
