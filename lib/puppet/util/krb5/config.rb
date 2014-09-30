require 'puppet'
require 'puppet/util/krb5/kadmin'

module Puppet
  define_settings(:main,
    :krb5_default_realm => {
      :type    => :string,
      :desc    => %q{
Default realm to append to principal names
%}  },
    :krb5_keytab_dir => {
      :default => '$vardir/keytabs',
      :type    => :directory,
      :create  => true,
      :owner   => 'service',
      :group   => 'service',
      :mode    => '01600',
      :desc    => %q{
Directory where generated keytabs for hosts are stored
%}  },
    :krb5_keytab_mount_point => {
      :default => 'keytabs',
      :desc    => %q{
Puppet file server mountpoint where keytabs should be retrieved from. Should be
set up to serve files from subdirectories of 'krb5_keytab_dir' matching FQDNs
for hosts. Like the following example:

  [keytabs]
    path $krb5_keytab_dir/%H
    allow *
%}  },
    :krb5_kadmin_bin => {
      :desc    => %q{
Name or path to the kadmin executable. Omit or clear to look up in PATH.
%}  },
    :krb5_kadmin_local_bin => {
      :desc    => %q{
Name or path to the kadmin.local executable. Omit or clear to look up in PATH.
%}  },
    :krb5_kadmin_realm => {
      :desc    => %q{
Realm to connect to kadmin with. Omit or clear to use system default.
%}  },
    :krb5_kadmin_principal => {
      :desc    => %q{
Principal to connect to kadmin with. Omit or clear to use system default.
%}  },
    :krb5_kadmin_password => {
      :desc    => %q{
Password to connect to kadmin with. Considering using a keytab instead.
%}  },
    :krb5_kadmin_use_keytab => {
      :default => true,
      :type    => :boolean,
      :desc    => %q{
Whether to connect to kadmin using a keytab instead of a password.
If krb5_kadmin_keytab_file is unset or empty, the default system keytab will be
used.
%}  },
    :krb5_kadmin_keytab_file => {
      :type    => :file,
      :create  => false,
      :desc    => %q{
Keytab file to use if krb5_kadmin_use_keytab is set. Omit or clear to use system
default.
%}  },
    :krb5_kadmin_local => {
      :default => false,
      :type    => :boolean,
      :desc    => %q{
Whether to connect to kadmin through a local socket (using the kadmin.local
utility).
%}  },
    :krb5_kadmin_server => {
      :desc    => %q{
Address of the kadmin server to connect to. Omit or clear to use system default.
%}  },
    :krb5_kadmin_cred_cache => {
      :type    => :file,
      :create  => false,
      :desc    => %q{
Credentials cache file to use. Omit or clear to use system default.
%}  },
    :krb5_kadmin_extra_options => {
      :desc    => %q{
Extra options to pass directly to kadmin
%}  },
    :krb5_ktutil_bin => {
      :desc    => %q{
Name or path to the ktutil executable. Omit or clear to look up in PATH.
%}  }
  )
end

module Puppet::Util::Krb5
  @@setting_names = [:bin, :local_bin, :realm, :principal, :password,
                     :use_keytab, :keytab_file, :local, :server, :cred_cache,
                     :extra_options]
  @@kadmin_instance = nil

  def self.kadmin_from_settings
    opts = Hash[@@setting_names.map { |n|
      key = "krb5_kadmin_#{n}".to_sym
      value = Puppet.settings[key]
      value = nil if value.is_a?(String) && value.empty?

      [n, value] 
    }]

    Kadmin.new(opts)
  end

  def self.kadmin_instance
    @@kadmin_instance ||= kadmin_from_settings
  end
end
