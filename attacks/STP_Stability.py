import os
import re
from tools.telnet import Telnet
from tools.ssh_v2 import SshVersionII

class STP_Stability:
    def __init__(self,server_ip,host,configDirectory):
        self.exist = True
        self.server_ip = server_ip
        self.host = host
        self.configDirectory = configDirectory

    def checkInterfaceByTelnet(self,telnet,interface_config):
        if re.search("spanning-tree guard loop\n",interface_config,re.MULTILINE)==None:
            return False
        else:
            return True

    def checkInterface(self,accessMethod,interface_config):
        if isinstance(accessMethod,Telnet):
            return self.checkInterfaceByTelnet(accessMethod,interface_config)
        elif isinstance(accessMethod,SshVersionII):
            return self.checkInterfaceBySSH(accessMethod,interface_config)

    def solveByTelnet(self,telnet,interface):
        telnet.execute("conf t")
        telnet.execute("interface "+interface.split('\n')[0].strip())
        telnet.execute("spanning-tree guard loop")
        telnet.execute("end")

    def solveBySSH(self,ssh,interface):
        ssh.conf(["interface "+interface.split('\n')[0].strip(),"spanning-tree guard loop","exit"])

    def solve(self,accessMethod,interface):
        if isinstance(accessMethod,Telnet):
            self.solveByTelnet(accessMethod,interface)
        elif isinstance(accessMethod,SshVersionII):
            self.solveBySSH(accessMethod,interface)

