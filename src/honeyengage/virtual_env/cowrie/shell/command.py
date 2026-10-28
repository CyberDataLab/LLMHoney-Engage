import time
import random

START_TIME = time.time() - random.random() * 100 * 86400.0 # up to 100 days in seconds

class MockProcess:
    def __init__(self, pid, name):
        self.pid = pid
        self.name = name

class MockServer:
    def __init__(self):
        self.startTime = START_TIME
        self.process = [MockProcess(1, "init"), MockProcess(2, "bash"), MockProcess(1234, "ps")]
        self.users = []

class MockUser:
    """Simulates the user object that Cowrie expects"""
    def __init__(self, username, uid=0, gid=0, home=None, shell="/bin/bash"):
        self.username = username
        self.uid = uid
        self.gid = gid
        self.home = home if home is not None else ("/root" if username == "root" else f"/home/{username}")
        self.shell = shell
        self.logintime = time.time() - random.random() * 100 * 86400.0 # up to 100 days ago
        self.client_ip = "192.168.1.100"
        self.server = MockServer()
        self.server.users.append(self)

class MockProtocol:
    """Simulates the network protocol that Cowrie commands expect"""
    def __init__(self, vfs, current_user="root", uid=0, gid=0):
        self.fs = vfs
        self.user = MockUser(current_user, uid=uid, gid=gid)
        self.logintime = self.user.logintime
        self.cwd = vfs.cwd_path
        self.terminal = self
        self.startTime = START_TIME
        self.output_buffer = ""
        self.hostname = "ubuntu"
        self.clientIP = "192.168.1.100"
        self.realClientPort = 51123
        self.kippoIP = "10.0.2.15"
        self.kippoIPv6 = "2001:db8::15"
        self.server = self.user.server

    def uptime(self):
        return time.time() - self.startTime
    
    def write(self, data):
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")
        self.output_buffer += data
    
    @property
    def transport(self):
        return self

class HoneyPotCommand:
    def __init__(self, protocol, *args):
        self.protocol = protocol
        self.args = list(args)
        self.output_buffer = ""
        
        self.fs = self.protocol.fs
        
    def write(self, data: str):
        self.output_buffer += data
    
    def writeBytes(self, data: bytes):
        self.output_buffer += data.decode("utf-8", errors="replace")

    def errorWrite(self, data: str):
        self.write(data)

    def check_arguments(self, application, args):
        files = []
        for arg in args:
            path = self.fs.resolve_path(arg, self.protocol.cwd)
            if self.fs.isdir(path):
                self.errorWrite(
                    f"{application}: error reading `{arg}': Is a directory\n"
                )
                continue
            files.append(path)
        return files
    
    def set_input_data(self, data: bytes) -> None:
        self.input_data = data

    def start(self) -> None:
        self.call()
        self.exit()

    def exit(self):
        pass

    def call(self):
        pass