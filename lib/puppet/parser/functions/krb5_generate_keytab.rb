require 'digest'
require 'puppet/util/krb5'

module Puppet::Parser::Functions
  newfunction(:krb5_generate_keytab, :type => :rvalue, :arity => 1, :doc => %q{
Generate a keytab for the given princs, and return a puppet file server URL
that can be used to send it to a client.

This function takes a list of princs as it's only argument: they will be
included in the generated keytab. If any of them does not have an explicit realm,
the default one from the 'krb5_default_realm' option in puppet.conf will be used.
}) \
  do |args|
    # Validate principal names
    princ_names = args[0]
    if (! princ_names.is_a?(Enumerable) ||
        princ_names.any? { |p| ! p.is_a?(String) })
      raise Puppet::ParseError,
        "Invalid parameter: must be a non-empty sequence of strings"
    end

    # Puppet should create the keytab directory for us: bail without trying
    # to create it if it does not exist
    keytab_dir = Puppet.settings[:krb5_keytab_dir]
    if ! keytab_dir || ! File.directory?(keytab_dir)
      raise Puppet::Error,
        "Unconfigured or missing keytab dir - '#{keytab_dir}'"
    end

    mount_point = Puppet.settings[:krb5_keytab_mount_point]
    if ! mount_point || mount_point.empty?
      raise Puppet::Error,
        "File server mount point for keytabs not set"
    end

    # Retrieve the node's certificate name from the trusted node data 
    trusted_data = lookupvar('trusted')
    certname = trusted_data[:certname]
    raise Puppet::Error, "Failed to retrieve trusted certname" unless certname

    # Create the subdirectories of the keytab dir as needed
    keytab_dirs = [:principals, certname].reduce({}) do { |h, t|
      path = File.join(keytab_dir, t.to_s)
      File.mkdir(path, :mode => 0700) unless File.directory?(path)
      h[t] = path
      h
    }

    # Lookup all princs at once to fail early if one is missing.
    # Sorted order is needed so the generated hash of the combination of the
    # principal names is predictable
    kadmin = Puppet::Util::Krb5.kadmin_instance()
    princs = princ_names.map { |name|
      kadmin.get_principal(name) or raise Puppet::Error,
        "Principal #{n} not found in Kerberos database"
    }.sort_by(&:name)

    princs_max_mtime = princs.map(&:last_modified_time).max

    # Hash the combination of the principal names and use it as the lookup key
    # for the combined keytab
    md5 = Digest::MD5.new
    princs.each { |p| md5 << p.name }
    combined_id = Digest.hexencode(md5.digest)

    # Generate the path to a keytab and a temporary file to use for keytab
    # generation
    def keytab_paths(type, name)
      keytab = File.join(keytab_dirs[type], name)
      temp_keytab = keytab + ':' + DateTime.now().iso8601 + '.keytab'
      keytab << '.keytab'
      [keytab, temp_keytab]
    end

    # Check if a keytab needs to be regenerated, either because it is missing
    # or because it is outdated
    def keytab_needs_regen?(path, name = nil, mtime)
      if ! File.exists?(path) || File.mtime(path) < mtime
        status = keytab_mtime ? 'outdated' : 'missing'
        function_info("Keytab for #{name} is #{status}, regenerating") if name
        true
      else
        false
      end
    end

    # Replace a keytab with a different file, applying correct permissions and
    # file times
    def keytab_replace(src, dest, mtime)
      FileUtils.mv(src, dest)
      File.chmod(0600, dest)
      File.utime(File.atime(dest), mtime)
    end

    # Check if the combined keytab is up to date first: if it is, we don't
    # need to do anything else
    combined_keytab, combined_tmp_keytab = 
      keytab_paths(certname, combined_id)

    if keytab_needs_regen(combined_keytab, nil, princs_max_mtime)
      # Check each principal individually and update the keytabs accordingly
      princ_keytabs = princs.each do |princ|
        princ_keytab, princ_tmp_keytab =
          keytab_paths(:principals, princ.name)
        mtime = princ.last_modified_time

        if keytab_needs_regen(princ_keytab, princ.name, mtime)
          kadmin.keytab_add(princ.name, false, princ_tmp_keytab)
          keytab_replace(princ_tmp_keytab, princ_keytab, mtime)
        end

        princ_keytab
      end

      # Generated the combined keytab from all the principal keytabs
      ktutil = Puppet::Util::Krb5::KtUtil.new(combined_tmp_keytab)
      princ_keytabs.each(&ktutil.method(:add_keytab))
      ktutil.generate()

      keytab_replace(combined_tmp_keytab, combined_keytab, princs_max_mtime)
    end

    "puppet://#{mount_point}/#{File.basename(combined_keytab)}"
  end
end
