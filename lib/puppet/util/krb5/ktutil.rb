require 'open3'

module Puppet::Util::Krb5
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
    @keytabs << path
    self
  end

  def <<(path)
    add_keytab(path)
  end

  def write
    if @keytabs.empty?
      raise ArgumentError, 'No keytabs added, nothing to generate'
    end

    commands = @keytabs.map { |kt| "read_kt #{kt}" }
    commands << "write_kt #{@dest}"

    command_done = ready_for_command = false
    out_done = err_done = false
    out_text = ''
    err_text = ''
    commands_enum = commands.each

    # Interact with the ktutil command. Since our only way to know whether
    # each command succeeded or not is looking at stderr, but we can't block
    # by ignoring stdout, we must do something a little more complicated.
    #
    # We always read from both stdout and stderr when possible, accumulating
    # their contents until we get the prompt indicator.
    #
    # If there was an error, we bail out. Otherwise, we know we can send
    # a new command. If we haven't sent all the commands, we send one,
    # then go back to reading until the command completes. Otherwise, we
    # send a quit command, and simply wait until ktutil closes both streams,
    # at which point we'll bail out.

    env = {'LANG' => 'C', 'LC_ALL' => 'C'}
    in_f, out_f, err_f, wait_thr = Open3.popen3(env, @bin)

    while true
      read_set = [!out_done ? out_f : nil, !err_done ? err_f : nil].compact
      break if read_set.empty?
      read_set = IO.select(read_set)[0]

      if read_set.include?(out_f)
        begin
          out_text += out_f.read_nonblock(512)
        rescue EOFError
          out_done = true
        else
          command_done = true if out_text =~ /:\s+$/
        end
      end

      if read_set.include?(err_f)
        ready_for_command = false

        begin
          err_text += err_f.read_nonblock(512)
        rescue EOFError
          err_done = true
        end
      end

      if command_done
        break if ! err_text.empty?
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

    [in_f, out_f, err_f].each(&:close)
    status = wait_thr.value
    errors = err_text.split("\n")

    if !errors.empty? || status.exitstatus != 0
      msg = errors.first || '(no message)'
      raise KerberosError.from_command('ktutil', msg, status.exitstatus)
    end
  end
end
end

