import pytest

from src.honeyengage.virtual_env.vfs import FSDirectory, FSFile, VirtualFileSystem
from src.honeyengage.virtual_env.virtual_shell import ProcessData, ShellTerminationError, VirtualShell


@pytest.fixture
def vfs_and_shell():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")
  
  etc = FSDirectory("etc")
  passwd = FSFile("passwd", size=1024)
  etc.add_child(passwd)
  
  root_dir = FSDirectory("root")
  secret = FSFile("secret.txt", size=50)
  root_dir.add_child(secret)
  
  vfs.root.add_child(etc)
  vfs.root.add_child(root_dir)
  
  vfs.current_directory = root_dir
  vfs.cwd_path = "/root"
  
  shell = VirtualShell(vfs)
  
  return vfs, shell


def test_pwd_initial_state(vfs_and_shell):
  vfs, shell = vfs_and_shell
  response = shell.execute_command("pwd")
  assert response == "/root\r\n"


def test_ls_current_directory(vfs_and_shell):
  vfs, shell = vfs_and_shell
  response = shell.execute_command("ls")
  assert response == "secret.txt\r\n"

def test_ls_empty_directory(vfs_and_shell):
  vfs, shell = vfs_and_shell
  vfs.current_directory.add_child(FSDirectory("empty_dir"))
  shell.execute_command("cd empty_dir")
  
  response = shell.execute_command("ls")
  assert response == ""

def test_cd_absolute_path(vfs_and_shell):
  vfs, shell = vfs_and_shell
  
  response = shell.execute_command("cd /etc")
  
  assert response == ""
  assert vfs.cwd_path == "/etc"
  assert vfs.current_directory.name == "etc"

def test_cd_parent_directory(vfs_and_shell):
  vfs, shell = vfs_and_shell
  
  shell.execute_command("cd ..")
  assert vfs.cwd_path == "/"
  
  shell.execute_command("cd ..")
  assert vfs.cwd_path == "/"

def test_cd_relative_path(vfs_and_shell):
  vfs, shell = vfs_and_shell
  
  shell.execute_command("cd /")
  shell.execute_command("cd etc")
  
  assert vfs.cwd_path == "/etc"

def test_cd_invalid_directory(vfs_and_shell):
  vfs, shell = vfs_and_shell
  
  response = shell.execute_command("cd /false_folder")
  assert response == "-bash: cd: /false_folder: No such file or directory\r\n"
  
  assert vfs.cwd_path == "/root"

def test_cd_to_file_fails(vfs_and_shell):
  vfs, shell = vfs_and_shell
  
  response = shell.execute_command("cd secret.txt")
  assert response == "-bash: cd: secret.txt: Not a directory\r\n"
  assert vfs.cwd_path == "/root"


def test_echo_simple(vfs_and_shell):
  vfs, shell = vfs_and_shell
  response = shell.execute_command("echo hello")
  assert response == "hello\r\n"

def test_echo_multiple_words(vfs_and_shell):
  vfs, shell = vfs_and_shell
  response = shell.execute_command("echo hello world from honeyengage")
  assert response == "hello world from honeyengage\r\n"

def test_echo_empty(vfs_and_shell):
  vfs, shell = vfs_and_shell
  response = shell.execute_command("echo")
  assert response == "\r\n"


def test_touch_creates_file(vfs_and_shell):
  vfs, shell = vfs_and_shell
  response = shell.execute_command("touch newfile.txt")
  assert response == ""
  
  ls_response = shell.execute_command("ls")
  assert "newfile.txt" in ls_response

def test_touch_missing_operand(vfs_and_shell):
  vfs, shell = vfs_and_shell
  output = shell.execute_command("touch")
  assert "touch: missing file operand" in output

def test_touch_existing_file(vfs_and_shell):
  vfs, shell = vfs_and_shell
  shell.execute_command("touch existing.txt")
  
  response = shell.execute_command("touch existing.txt")
  assert response == ""

def test_mkdir_p_creates_missing_parents(vfs_and_shell):
  vfs, _ = vfs_and_shell

  assert vfs.mkdir_p("/home/dir1/dir2", uid=0, gid=0, size=4096, mode="drwxr-xr-x")
  assert vfs.isdir("/home")
  assert vfs.isdir("/home/dir1")
  assert vfs.isdir("/home/dir1/dir2")

def test_mkfile_p_creates_missing_parents(vfs_and_shell):
  vfs, _ = vfs_and_shell

  assert vfs.mkfile_p("/home/dir1/dir2/file1.txt", uid=0, gid=0, size=0, mode="-rw-r--r--")
  assert vfs.isdir("/home")
  assert vfs.isdir("/home/dir1")
  assert vfs.isdir("/home/dir1/dir2")
  assert vfs.isfile("/home/dir1/dir2/file1.txt")


def test_mkdir_creates_directory(vfs_and_shell):
  vfs, shell = vfs_and_shell
  response = shell.execute_command("mkdir newdir")
  assert response == ""
  
  ls_response = shell.execute_command("ls")
  assert "newdir" in ls_response

def test_mkdir_missing_operand(vfs_and_shell):
  vfs, shell = vfs_and_shell
  output = shell.execute_command("mkdir")
  assert "mkdir: missing operand" in output

def test_mkdir_existing_directory(vfs_and_shell):
  vfs, shell = vfs_and_shell
  shell.execute_command("mkdir existingdir")
  
  response = shell.execute_command("mkdir existingdir")
  assert "mkdir: cannot create directory 'existingdir': File exists" in response


def test_rm_deletes_file(vfs_and_shell):
  vfs, shell = vfs_and_shell
  shell.execute_command("touch temp.txt")

  ls_response_1 = shell.execute_command("ls")
  assert "temp.txt" in ls_response_1
  
  response = shell.execute_command("rm temp.txt")
  assert response == ""
  
  ls_response_2 = shell.execute_command("ls")
  assert "temp.txt" not in ls_response_2

def test_rm_missing_operand(vfs_and_shell):
  vfs, shell = vfs_and_shell
  output = shell.execute_command("rm")
  assert "rm: missing operand" in output

def test_rm_nonexistent_file(vfs_and_shell):
  vfs, shell = vfs_and_shell
  response = shell.execute_command("rm nonexistent.txt")
  assert response == "rm: cannot remove 'nonexistent.txt': No such file or directory\r\n"

def test_rm_directory_fails(vfs_and_shell):
  vfs, shell = vfs_and_shell
  shell.execute_command("mkdir somedir")
  
  response = shell.execute_command("rm somedir")
  assert response == "rm: cannot remove 'somedir': Is a directory\r\n"


def test_rmdir_deletes_directory(vfs_and_shell):
  vfs, shell = vfs_and_shell
  shell.execute_command("mkdir tempdir")

  ls_response_1 = shell.execute_command("ls")
  assert "tempdir" in ls_response_1
  
  response = shell.execute_command("rmdir tempdir")
  assert response == ""
  
  ls_response_2 = shell.execute_command("ls")
  assert "tempdir" not in ls_response_2

def test_rmdir_missing_operand(vfs_and_shell):
  vfs, shell = vfs_and_shell
  output = shell.execute_command("rmdir")
  assert "rmdir: missing operand" in output

def test_rmdir_nonexistent_directory(vfs_and_shell):
  vfs, shell = vfs_and_shell
  response = shell.execute_command("rmdir nonexistentdir")
  assert response == "rmdir: failed to remove 'nonexistentdir': No such file or directory\r\n"

def test_rmdir_file_fails(vfs_and_shell):
  vfs, shell = vfs_and_shell
  shell.execute_command("touch somefile")
  
  response = shell.execute_command("rmdir somefile")
  assert response == "rmdir: failed to remove 'somefile': Not a directory\r\n"

def test_rmdir_nonempty_directory_fails(vfs_and_shell):
  vfs, shell = vfs_and_shell
  shell.execute_command("mkdir somedir")
  shell.execute_command("touch somedir/file.txt")
  
  response = shell.execute_command("rmdir somedir")
  assert response == "rmdir: failed to remove 'somedir': Directory not empty\r\n"


def test_cat_existing_file(vfs_and_shell):
  vfs, shell = vfs_and_shell
  shell.execute_command("echo secret content > secret.txt")
  response = shell.execute_command("cat secret.txt")
  assert "secret content" in response

def test_cat_nonexistent_file(vfs_and_shell):
  vfs, shell = vfs_and_shell
  response = shell.execute_command("cat nonexistent.txt")
  assert response == "cat: nonexistent.txt: No such file or directory\r\n"


def test_whoami_returns_current_user(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("whoami")
  
  assert "root" in output.strip()
  assert len(output.strip().split("\n")) == 1


def test_id_returns_user_info(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("id")
  
  assert "uid=" in output
  assert "gid=" in output
  assert "groups=" in output


def test_uname_basic(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output_basica = virtual_shell.execute_command("uname")
  
  assert "Linux" in output_basica.strip()

def test_uname_all(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output_completa = virtual_shell.execute_command("uname -a")
  
  assert "Linux" in output_completa


def test_hostname_returns_machine_name(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("hostname")
  
  assert len(output.strip()) > 0


def test_users_returns_logged_in_users(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("users")
  
  assert "root" in output


def test_date_returns_current_time(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("date")
  
  assert len(output.strip()) > 0
  assert any(str(year) in output for year in range(2020, 2030)) or "UTC" in output or "CET" in output


def test_uptime_returns_system_uptime(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("uptime")
  
  assert "up" in output
  assert "load average" in output


def test_free_returns_memory_info(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("free")
  
  assert "Mem:" in output
  assert "Swap:" in output
  assert "total" in output.lower()


def test_w_and_who_return_logged_users(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output_w = virtual_shell.execute_command("w")
  output_who = virtual_shell.execute_command("who")
  
  assert "root" in output_w or "daniel" in output_w
  assert "pts/" in output_w or "tty" in output_w
  
  assert "root" in output_who or "daniel" in output_who
  assert "pts/" in output_who or "tty" in output_who


def test_ps_returns_process_list(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("ps")
  
  assert "PID" in output
  assert "TTY" in output
  assert "COMMAND" in output
  assert "ps" in output


def test_grep_finds_matching_lines(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  virtual_shell.execute_command("echo 'line1\nline2\nline3' > testfile.txt")
  
  output = virtual_shell.execute_command("grep line2 testfile.txt")
  
  assert "line2" in output
  assert "line1" not in output
  assert "line3" not in output

def test_grep_no_matches(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  virtual_shell.execute_command("echo 'line1\nline2\nline3' > testfile.txt")
  
  output = virtual_shell.execute_command("grep nomatch testfile.txt")
  
  assert output == ""

def test_grep_file_not_found(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("grep something nonexistent.txt")
  
  assert "No such file or directory" in output

def test_grep_missing_operand(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("grep")
  
  assert "Usage: grep [OPTIONS] PATTERN [FILE...]" in output

def test_grep_pattern_only(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("grep pattern")
  
  assert "Usage: grep [OPTIONS] PATTERN [FILE...]" in output


def test_head_returns_first_lines(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  virtual_shell.execute_command("echo -e 'line1\nline2\nline3\nline4' > testfile.txt")
  
  output = virtual_shell.execute_command("head -n 2 testfile.txt")
  
  assert "line1" in output
  assert "line2" in output
  assert "line3" not in output
  assert "line4" not in output

def test_head_file_not_found(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("head -n 2 nonexistent.txt")
  
  assert "No such file or directory" in output

def test_head_missing_operand(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("head -n 2")
  
  assert "Usage: head [OPTIONS] FILE" in output


def test_tail_returns_last_lines(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  virtual_shell.execute_command("echo -e 'line1\nline2\nline3\nline4' > testfile.txt")
  
  output = virtual_shell.execute_command("tail -n 2 testfile.txt")
  
  assert "line3" in output
  assert "line4" in output
  assert "line1" not in output
  assert "line2" not in output

def test_tail_file_not_found(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("tail -n 2 nonexistent.txt")
  
  assert "No such file or directory" in output

def test_tail_missing_operand(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("tail -n 2")
  
  assert "Usage: tail [OPTIONS] FILE" in output


def test_wc_counts_lines_words_bytes(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  virtual_shell.execute_command("echo -e 'line1 line1\nline2 line2\nline3 line3' > testfile.txt")
  
  output = virtual_shell.execute_command("wc testfile.txt")
  
  assert "3" in output
  assert "6" in output
  assert "36" in output

def test_wc_file_not_found(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("wc nonexistent.txt")
  
  assert "No such file or directory" in output

def test_wc_missing_operand(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("wc")
  
  assert "Usage: wc [OPTIONS] FILE" in output


def test_ifconfig_returns_network_info(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("ifconfig")
  
  assert "inet " in output
  assert "HWaddr " in output
  assert "lo" in output or "eth0" in output


def test_netstat_returns_network_connections(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("netstat")

  assert "Proto" in output
  assert "Local Address" in output
  assert "Foreign Address" in output
  assert "ESTABLISHED" in output


def test_netstat_listening_filter_reflects_actual_connection_state(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("netstat -tuln")

  assert "ESTABLISHED" not in output


def test_ping_returns_ping_output(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("ping -c 3 8.8.8.8")
        
  assert "PING 8.8.8.8" in output
  assert "bytes from 8.8.8.8" in output
  assert "icmp_seq=1" in output
  assert "packet loss" in output


def test_clear_clears_screen(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("clear")
  
  assert output == "\033[H\033[2J" or output == "\033[H\033[J"


@pytest.mark.parametrize(
  "command, expected_reason, expected_message",
  [
    ("shutdown now", "System shutdown requested", "The system is going down for power off NOW!"),
    ("poweroff", "System power off requested", "The system is going down for power off NOW!"),
    ("reboot", "System reboot requested", "The system is going down for reboot NOW!"),
    ("/sbin/reboot", "System reboot requested", "The system is going down for reboot NOW!"),
  ],
)
def test_termination_commands_disconnect(command, expected_reason, expected_message, vfs_and_shell):
  _, shell = vfs_and_shell

  with pytest.raises(ShellTerminationError) as excinfo:
    shell.execute_command(command)

  assert expected_reason == excinfo.value.exit_reason
  assert expected_message in excinfo.value.output


def test_env_returns_environment_variables(vfs_and_shell):
  _, shell = vfs_and_shell
  output = shell.execute_command("env")

  assert "PATH=" in output
  assert "HOME=" in output
  assert "USER=" in output
  assert "SHELL=" in output


def test_separate_sessions_do_not_share_filesystem_mutations():
  vfs_a = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs_a.root = FSDirectory("/")
  root_a = FSDirectory("root")
  vfs_a.root.add_child(root_a)
  vfs_a.current_directory = root_a
  vfs_a.cwd_path = "/root"
  shell_a = VirtualShell(vfs_a)

  vfs_b = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs_b.root = FSDirectory("/")
  root_b = FSDirectory("root")
  vfs_b.root.add_child(root_b)
  vfs_b.current_directory = root_b
  vfs_b.cwd_path = "/root"
  shell_b = VirtualShell(vfs_b)

  shell_a.execute_command("touch attacker_a_file.txt")

  assert "attacker_a_file.txt" in root_a.children
  assert "attacker_a_file.txt" not in root_b.children

  shell_b.execute_command("touch attacker_b_file.txt")

  assert "attacker_b_file.txt" in root_b.children
  assert "attacker_b_file.txt" not in root_a.children


def test_separate_sessions_do_not_share_injected_processes():
  vfs_a = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs_a.root = FSDirectory("/")
  shell_a = VirtualShell(vfs_a)

  vfs_b = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs_b.root = FSDirectory("/")
  shell_b = VirtualShell(vfs_b)

  baseline_process_count = len(shell_b.process_list)

  shell_a.inject_fake_process(ProcessData(
    user="root",
    pid=31337,
    cpu_usage=0.0,
    memory_usage=0.0,
    vsz=0,
    rss=0,
    tty="tty1",
    stat="S",
    start_time="00:00",
    time="0:00",
    command="malicious-cnc-beacon",
  ))

  assert any(p.pid == 31337 for p in shell_a.process_list)
  assert len(shell_b.process_list) == baseline_process_count
  assert not any(p.pid == 31337 for p in shell_b.process_list)


def test_non_root_user_home_is_under_home_not_bare_slash_user():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")
  shell = VirtualShell(vfs, user="alice")
  shell.set_current_user("alice")

  assert shell.environ["HOME"] == "/home/alice"
  assert vfs.cwd_path == "/home/alice"


def test_root_user_home_is_unchanged():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")
  shell = VirtualShell(vfs, user="root")

  assert shell.environ["HOME"] == "/root"


def test_cd_home_succeeds_for_non_root_user():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")
  shell = VirtualShell(vfs, user="user")
  shell.set_current_user("user")

  response = shell.execute_command("cd $HOME")

  assert response == ""
  assert vfs.cwd_path == "/home/user"


def test_cd_with_no_arguments_goes_to_current_users_home():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")
  shell = VirtualShell(vfs, user="user")
  shell.set_current_user("user")

  shell.execute_command("cd")

  assert vfs.cwd_path == "/home/user"


def test_prompt_shows_tilde_for_non_root_home():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")
  shell = VirtualShell(vfs, user="user")
  shell.set_current_user("user")

  assert shell.get_prompt() == "user@ubuntu:~$ "


def test_sh_dash_c_executes_the_given_command():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")
  shell = VirtualShell(vfs)

  response = shell.execute_command("sh -c 'echo hello world'")

  assert response == "hello world\r\n"

def test_sh_dash_c_strips_double_quotes():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")
  shell = VirtualShell(vfs)

  response = shell.execute_command('sh -c "echo hi"')

  assert response == "hi\r\n"


def test_sh_reads_script_from_stdin_pipe():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")
  shell = VirtualShell(vfs)

  response = shell.execute_command("echo 'echo piped' | sh")

  assert response == "piped\r\n"


def test_sh_never_falls_back_to_the_generic_internal_error_message():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")
  shell = VirtualShell(vfs)

  response = shell.execute_command("sh -c 'nonexistent_tool_xyz'")

  assert "internal error" not in response


def test_bash_dash_c_behaves_the_same_as_sh():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")
  shell = VirtualShell(vfs)

  response = shell.execute_command("bash -c 'echo hello'")

  assert response == "hello\r\n"


def test_crontab_list_reports_no_crontab_for_current_user():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")
  shell = VirtualShell(vfs, user="user")

  response = shell.execute_command("crontab -l")

  assert response == "no crontab for user\r\n"


def test_crontab_install_from_missing_file_reports_not_found():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")
  shell = VirtualShell(vfs)

  response = shell.execute_command("crontab /tmp/does_not_exist")

  assert response == "crontab: /tmp/does_not_exist: No such file or directory\r\n"
  assert "internal error" not in response


def test_crontab_never_falls_back_to_the_generic_internal_error_message():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")
  shell = VirtualShell(vfs)

  response = shell.execute_command("crontab -e")

  assert "internal error" not in response


def test_scp_reports_unresolvable_remote_host():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")
  shell = VirtualShell(vfs)

  response = shell.execute_command("scp adversary@adversary-host:/tmp/file /tmp/dest/")

  assert response == "ssh: Could not resolve hostname adversary-host: Name or service not known\r\n"


def test_scp_never_leaks_raw_null_bytes():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")
  shell = VirtualShell(vfs)

  response = shell.execute_command("scp user@host:/tmp/x /tmp/y")

  assert "\x00" not in response

