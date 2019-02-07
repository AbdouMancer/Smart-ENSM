import telnetlib
import time
class Telnet:
    def __init__(self):
        tn = None
    def connect(self,host,port,user,password,enablePassword):
        self.tn = telnetlib.Telnet(host,port)
        self.tn.read_until(b"Username: ")
        self.tn.write(user.encode('ascii') + b"\n")
        if password:
            self.tn.read_until(b"Password: ")
            self.tn.write(password.encode('ascii') + b"\n")
        self.tn.write(b"enable \n")
        self.tn.write(enablePassword.encode('ascii')+b"\n")
    def execute(self,cmd):
        self.tn.write(cmd.encode('ascii')+b"\n")
    def readUntil(self,word):
        self.tn.read_until(word)
    def close(self):
        self.tn.write(b"exit\n")
        self.tn.read_all()

