require 'io/wait'

module Krb5
  class Ktutil
    def initialize(path, ktutil_bin = nil)
      if ! path || ! path.is_a?(String) || path.empty?
        raise ArgumentError, "Invalid path"
      end

      @dest = path
      @bin = ktutil_bin || 'ktutil'
      @keytabs = []
    end

    def add_keytab(path)
      keytabs << path
    end

    def generate
      if @keytabs.empty?
        raise ArgumentError, "No keytabs added, nothing to generate"
      end

      env = {'LANG' => 'C', 'LC_ALL' => 'C'}

      commands = @keytabs.map { |kt| "read_kt #{kt}" }
      commands << "write_kt #{@dest}" << "quit" 

      Open3.Popen3(env, [@bin]) do |in_f, out_f, err_f, thread|
        out_f.wait_readable()
        out = read_available(out_f)

        err_f.wait_readable(1)
        

        if err_f.ready?
          err = read_available(err)


        out_f.wait_readable()
        @keytabs.each do |kt|

          out.puts()

    private

    def read_available(io)
      res = ""
      begin
        while true
          res += io.read_nonblock(64)
        end
      rescue IO::WaitReadable
      end

      res
    end


