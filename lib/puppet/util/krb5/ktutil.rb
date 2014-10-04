require 'open3'

module Puppet::Util::Krb5
class Ktutil
  @@exec_env = {'LANG' => 'C', 'LC_ALL' => 'C'}
  
  def initialize(path, ktutil_bin = nil)
    unless path && path.is_a?(String) && ! path.empty?
      raise ArgumentError, 'Invalid destination path'
    end

    @dest = path
    @bin = ktutil_bin || 'ktutil'
    @keytabs = []
  end

  def add_keytab(path)
    unless File.readable?(path)
      raise IOError, "Keytab does not exist or is not readable - '#{path}'"
    end

    @keytabs << File.absolute_path(path)
    self
  end

  def <<(path)
    add_keytab(path)
  end

  def write
    if @keytabs.empty?
      raise RuntimeError, 'No keytabs added, nothing to generate'
    end

    commands = @keytabs.map { |kt| "read_kt #{kt}" }
    commands << "write_kt #{@dest}"

    # We need to use the array form of command: if we pass a single string it
    # will go through shell expansion, which we do not want
    cmd = [@bin, File.basename(@bin)]
    out_text = String.new
    error_text = String.new

    process = Open3.popen3(@@exec_env, cmd) do |in_f, out_f, err_f, thread|     
      command_done = ready_for_command = false
      out_done = err_done = false
      commands_enum = commands.each
      out_buf = String.new
      err_buf = String.new

      # Interact with the ktutil command. Since our only way to know whether
      # each command succeeded or not is looking at stderr, but we can't block
      # by ignoring stdout, we must do something a little more complicated.
      loop do
        # Wait for either stdout or stderr to be ready for reading. If they both
        # have been closed already, break out early.
        read_set = [!out_done ? out_f : nil, !err_done ? err_f : nil].compact
        break if read_set.empty?
        read_set = IO.select(read_set)[0]

        # Read from stdout and accumulate it's contents. Then check if we received
        # a prompt: if positive, we know we can know send a new command if
        # everything went okay, or that we have an error message otherwise.
        if read_set.include?(out_f)
          begin
            out_f.read_nonblock(512, out_buf)
          rescue EOFError
            out_done = true
          else
            command_done = true if out_buf =~ /:\s+$/
            out_text << out_buf
          end
        end

        # Read from stderr: if we do have something, it means an error was thrown,
        # and that we should refrain from sending any more commands.
        # Do not bail straight away, but keep running so we can get the complete
        # message: we know it is done when we get a prompt indicator in stdout,
        # or when the outputs are closed.
        if read_set.include?(err_f)
          ready_for_command = false

          begin
            err_f.read_nonblock(512, err_buf)
          rescue EOFError
            err_done = true
          else
            error_text << err_buf
          end
        end

        # We received a prompt indicator: we should now break with an error
        # message, or send out the next command
        if command_done
          break unless error_text.empty?
          ready_for_command = true
        end

        if ready_for_command
          begin
            command = commands_enum.next
          rescue StopIteration
            command = 'quit'
          end

          command_done = false
          ready_for_command = false
          in_f.puts(command)
        end
      end

      thread.value
    end

    unless process.exitstatus == 0 && error_text.empty? 
      error_msg = error_text.each_line.first
      error_msg.chomp! if error_msg

      raise KerberosError.from_command('ktutil', error_msg, process.exitstatus)
    end

    @keytabs.length
  end
end
end

