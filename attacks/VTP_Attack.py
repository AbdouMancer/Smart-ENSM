import os
from tools.telnet import Telnet
from tools.ssh_v2 import SshVersionII
import re

class VTP:
    def __init__(self,server_ip,host,configDirectory):
        self.exist = True
        self.server_ip = server_ip
        self.host = host
        self.configDirectory = configDirectory

    def checkByTelnet(self,telnet,running_config):
        telnet.execute("show vtp password | redirect tftp://"+self.server_ip+"/"+self.host+"_vtp_password")
        telnet.readUntil(b"!")
        telnet.readUntil(b"#")
        output = open(self.configDirectory+"/"+self.host+"_vtp_password").read().strip()
        os.remove(self.configDirectory+"/"+self.host+"_vtp_password")
        return self.getMissedCommands(running_config,output)


    def checkBySSH(self,ssh,running_config):
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

    def check(self,accessMethod,running_config):
        if isinstance(accessMethod,Telnet):
            return self.checkByTelnet(accessMethod,running_config)
        elif isinstance(accessMethod,SshVersionII):
            return self.checkBySSH(accessMethod,running_config)

    def getMissedCommands(self,running_config,output):
        commandsMissed = []
        if re.search("vtp mode off",running_config,re.MULTILINE)==None:
            if re.search("vtp mode transparent",running_config,re.MULTILINE)==None:
                    commandsMissed.append("vtp mode")
        if "The VTP password is not configured" in output:
            commandsMissed.append("vtp password")
        return commandsMissed

    def solveByTelnet(self,telnet,command):
        telnet.execute("conf t")
        if command == 'vtp mode':
            telnet.execute("vtp mode transparent")
        elif command == "vtp password":
            telnet.execute("vtp password cisco")
        telnet.execute("end")


    def solveBySSH(self,ssh,command):
        print()

    def solve(self,accessMethod,command):
        if isinstance(accessMethod,Telnet):
            self.solveByTelnet(accessMethod,command)
        elif isinstance(accessMethod,SshVersionII):
            self.solveBySSH(accessMethod,command)
