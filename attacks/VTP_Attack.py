import os
from tools.telnet import Telnet
from tools.ssh_v2 import SshVersionII

class VTP:
    def __init__(self,server_ip,host,configDirectory):
        self.exist = True
        self.server_ip = server_ip
        self.host = host
        self.configDirectory = configDirectory

    def checkByTelnet(self,telnet):
        telnet.execute("show vtp status | redirect tftp://"+self.server_ip+"/"+self.host+"_vtp_config")
        telnet.readUntil(b"!")
        telnet.readUntil(b"#")
        output = open(self.configDirectory+"/"+self.host+"_vtp_config").read().strip()
        mode = self.getMode(output)
        if "Transparent" in mode or "Off" in mode:
            print("device "+self.host+" is not vulnerable to vtp attacks")
        else:
            print("device "+self.host+" is vulnerable to vtp attacks")
            telnet.execute("conf t")
            telnet.execute("vtp domain cisco")
            telnet.execute("vtp password cisco")
            telnet.execute("vtp mode transparent")
            telnet.execute("end")
        os.remove(self.configDirectory+"/"+self.host+"_vtp_config")

    def checkBySSH(self,ssh):
        output = ssh.exec("show vtp status | redirect tftp://"+self.server_ip+"/"+self.host+"_vtp_config")
        output = open(self.configDirectory+"/"+self.host+"_vtp_config").read().strip()
        mode = self.getMode(output)
        if "Transparent" in mode or "Off" in mode:
            print("device "+self.host+" is not vulnerable to vtp attacks")
        else:
            print("device "+self.host+" is vulnerable to vtp attacks")
            ssh.conf("vtp domain cisco")
            ssh.conf("vtp password cisco")
            ssh.conf("vtp mode transparent")
        os.remove(self.configDirectory+"/"+self.host+"_vtp_config")

    def check(self,accessMethod):
        if isinstance(accessMethod,Telnet):
            self.checkByTelnet(accessMethod)
        elif isinstance(accessMethod,SshVersionII):
            self.checkBySSH(accessMethod)

    def getMode(self,show):
        lines = show.split('\n')
        for line in lines:
            if "VTP Operating Mode" in line:
                return line
