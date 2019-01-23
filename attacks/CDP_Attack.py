import os
from tools.telnet import Telnet
from tools.ssh_v2 import SshVersionII

class CDP:
    def __init__(self,server_ip,host,configDirectory):
        self.exist = True
        self.server_ip = server_ip
        self.host = host
        self.configDirectory = configDirectory
    def checkByTelnet(self,telnet):
        telnet.execute("show cdp neigh | redirect tftp://"+self.server_ip+"/"+self.host+"_cdp_config")
        telnet.readUntil(b"!")
        telnet.readUntil(b"#")
        output = open(self.configDirectory+"/"+self.host+"_cdp_config").read().strip()
        if output=="% CDP is not enabled":
            print("device "+self.host+" is not vulnerable to cdp attacks")
        else:
            print("device "+self.host+" is vulnerable to cdp attacks")
            telnet.execute("conf t")
            telnet.execute("no cdp run")
            telnet.execute("end")
        os.remove(self.configDirectory+"/"+self.host+"_cdp_config")

    def checkBySSH(self,ssh):
        output = ssh.exec("show cdp neighbors | redirect tftp://"+self.server_ip+"/"+self.host+"_cdp_config")
        output = open(self.configDirectory+"/"+self.host+"_cdp_config").read().strip()
        if output=="% CDP is not enabled":
            print("device "+self.host+" is not vulnerable to cdp attacks")
        else:
            print("device "+self.host+" is vulnerable to cdp attacks")
            ssh.conf("no cdp run")
        os.remove(self.configDirectory+"/"+self.host+"_cdp_config")

    def check(self,accessMethod):
        if isinstance(accessMethod,Telnet):
            self.checkByTelnet(accessMethod)
        elif isinstance(accessMethod,SshVersionII):
            self.checkBySSH(accessMethod)
