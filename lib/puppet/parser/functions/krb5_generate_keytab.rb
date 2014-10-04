require 'digest'
require 'puppet/util/krb5'

Puppet::Parser::Functions.newfunction(:krb5_generate_keytab,
  :type => :rvalue, :arity => 1, :doc => %q{
Generate a keytab for the given principals, and return the content.
}) \
do |args|
  # Validate parameter
  if args[0].is_a?(String)
    princ_names = [args[0]]
  elsif args[0].is_a?(Array)
    if args[0].empty?
      raise Puppet::ParseError, 'Principal list must not be empty'
    end

    princ_names = args[0]
  else
    raise Puppet::ParseError,
      'Invalid parameter: must be a string or list of strings'
  end

  princ_names.each do |name|
    begin
      Puppet::Util::Krb5.principal_check_name(name)
    rescue ArgumentError => e
      raise Puppet::ParseError, e.message, e.backtrace
    end
  end

  # Puppet should create the keytab directory for us: bail without trying
  # to create it if it does not exist
  keytab_dir = Puppet.settings[:krb5_keytab_dir]
  unless keytab_dir && Puppet::FileSystem.directory?(keytab_dir)
    raise Puppet::ParseError,
      "Unconfigured or missing keytab dir - '#{keytab_dir}'"
  end

  # Retrieve the node's certificate name from the trusted node data 
  trusted_data = lookupvar('trusted')
  certname = trusted_data['certname']
  unless certname
    raise Puppet::ParseError,
      'Failed to retrieve certname from trusted node data'
  end

  def keytab_dir_maybe_create(path)
    begin
      Dir.mkdir(path, 0700) unless Puppet::FileSystem.directory?(path)
    rescue SystemCallError => e
      raise Puppet::ParseError, "Failed to create keytab subdirectory: #{e}",
        e.backtrace
    end
  end

  # Create the subdirectories of the keytab dir as needed
  keytab_dirs = {:principals => 'principals', :host => certname}.tap do |h|
    h.each do |k, v|
      h[k] = v = File.join(keytab_dir, v)
      keytab_dir_maybe_create(v)
    end
  end

  # Lookup all principals at once to fail early if one is missing.
  # Sorted order is needed so the generated hash of the combination of the
  # principal names is predictable
  begin
    kadmin = Puppet::Util::Krb5.kadmin_instance
    princs = princ_names.map { |name|
      kadmin.get_principal(name) or raise Puppet::ParseError,
        "Principal #{n} not found in Kerberos database"
    }.sort_by(&:name)
  rescue Pupppet::Util::Krb5::KerberosError => e
    raise Puppet::ParseError,
      "Failed to retrieve Kerberos principal information: #{e}", e.backtrace
  end

  # Hash the combination of the principal names and versions, and use it as the
  # lookup key for the combined keytab
  combined_id = Digest::MD5.new.tap { |m|
    princs.each do |p|
      m << "#{p.name}|#{p.master_key_version}|#{p.key_version}|"
    end
  }.hexdigest

  # Regenerate a keytab, if needed, by running the given block
  def keytab_maybe_regen(path, new_path = nil, &block)
    if Puppet::FileSystem.exist?(path)
      unless Puppet::FileSystem.file?(path)
        raise Puppet::ParseError, "Keytab exists but is not a file - '#{path}'"
      end

      return path
    end

    new_path ||= path
    
    # Puppet::Util::replace_file could be used, but it creates a file
    # automatically and opens it.
    # Unfortunately, kadmin can't seem to handle writing to empty files: it
    # tries to read them first and breaks.
    # So we just open a tempfile and close (unlinking it) right away instead,
    # and just grab the path for our own use.

    tmp_file = Puppet::FileSystem::Uniquefile.new(
      Puppet::FileSystem.basename_string(new_path),
      Puppet::FileSystem.dir_string(new_path))

    tmp_path = tmp_file.path
    tmp_file.close!

    yield tmp_path

    begin
      File.rename(tmp_path, new_path)
      Puppet::FileSystem.chmod(0600, new_path)
    rescue SystemCallError => e
      raise Puppet::ParseError, "Failed to store keytab: #{e}", e.backtrace
    end

    new_path
  end

  combined_keytab = File.join(keytab_dirs[:host], combined_id + '.keytab')

  princs_max_mtime = princs.map(&:last_modified_time).max
  keytab_maybe_regen(combined_keytab) do |combined_tmp|
    # Check each principal individually and update the keytabs accordingly

    princ_keytabs = princs.map do |princ|
      clean_princ_name = princ.name.gsub(?/, ?$)
      
      princ_keytab_dir = File.join(keytab_dirs[:principals], clean_princ_name)
      keytab_dir_maybe_create(princ_keytab_dir)

      # We must increment the key version number of a possible newly generated
      # keytab, since it will have a new key.
      old_kt, new_kt = [princ.key_version, princ.key_version + 1].map do |kvno|
        File.join(princ_keytab_dir,
                  "#{princ.master_key_version}-#{kvno}.keytab")
      end
      
      keytab_maybe_regen(old_kt, new_kt) do |tmp_kt|
        begin
          kadmin.keytab_add(princ.name, false, tmp_kt)
        rescue Pupppet::Util::Krb5::KerberosError => e
          raise Puppet::ParseError,
            "Failed retrieving keytab for principal #{princ.name}: #{e}",
            e.backtrace
        end
      end
    end

    # Generated the combined keytab from all the principal keytabs
    begin
      ktutil = Puppet::Util::Krb5.ktutil_new(combined_tmp)
      princ_keytabs.each(&ktutil.method(:add_keytab))
      ktutil.write
    rescue Puppet::Util::Krb5::KerberosError => e
      raise Puppet::ParseError,
        "Failed combining keytabs for host #{certname}: #{e}", e.backtrace
    end
  end

  begin
    Puppet::FileSystem.binread(combined_keytab)
  rescue SystemCallError => e
    raise Puppet::ParseError,
      "Failed reading combined keytab for host #{certname}: #{e}", e.backtrace
  end
end
