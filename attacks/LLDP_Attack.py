import os
from tools.telnet import Telnet
from tools.ssh_v2 import SshVersionII

class LLDP:
    def __init__(self,server_ip,host,configDirectory):
        self.exist = True
        self.server_ip = server_ip
        self.host = host
        self.configDirectory = configDirectory
    def checkByTelnet(self,telnet):
        telnet.execute("show lldp neigh | redirect tftp://"+self.server_ip+"/"+self.host+"_lldp_config")
        telnet.readUntil(b"!")
        telnet.readUntil(b"#")
        output = open(self.configDirectory+"/"+self.host+"_lldp_config").read().strip()
        if output=="% LLDP is not enabled":
            print("device "+self.host+" is not vulnerable to lldp attacks")
        else:
            print("device "+self.host+" is vulnerable to lldp attacks")
            telnet.execute("conf t")
            telnet.execute("no lldp run")
            telnet.execute("end")
        os.remove(self.configDirectory+"/"+self.host+"_lldp_config")

    def checkBySSH(self,ssh):
        output = ssh.exec("show lldp neighbors | redirect tftp://"+self.server_ip+"/"+self.host+"_lldp_config")
        output = open(self.configDirectory+"/"+self.host+"_lldp_config").read().strip()
        if output=="% LLDP is not enabled":
            print("device "+self.host+" is not vulnerable to lldp attacks")
        else:
            print("device "+self.host+" is vulnerable to lldp attacks")
            ssh.conf("no lldp run")
        os.remove(self.configDirectory+"/"+self.host+"_lldp_config")

    def check(self,accessMethod):
        if isinstance(accessMethod,Telnet):
            self.checkByTelnet(accessMethod)
        elif isinstance(accessMethod,SshVersionII):
            self.checkBySSH(accessMethod)

