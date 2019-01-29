import os
import re
from tools.telnet import Telnet
from tools.ssh_v2 import SshVersionII


class Identification:
    def __init__(self, server_ip, host, configDirectory):
        self.exist = True
        self.server_ip = server_ip
        self.host = host
        self.configDirectory = configDirectory

    def checkByTelnet(self, telnet):
        running_config = open(self.configDirectory + "/" + self.host + "_running_config").read().strip()
        vulnerability = self.checkVulnerability(running_config)
        if (vulnerability == True):
            print("device " + self.host + " is vulnerable to  Identification service attack")
            ##solution
            telnet.execute("conf t")
            telnet.execute("no ip identd")
            telnet.execute("end")
        else:
            print("device " + self.host + " is not vulnerable to  Identification service attack")

    def checkBySSH(self, ssh):
        running_config = open(self.configDirectory + "/" + self.host + "_running_config").read().strip()
        vulnerability = self.checkVulnerability(running_config)
        if (vulnerability == True):
            print("device " + self.host + " is vulnerable to  Identification service attack")
            ##solution
            ssh.conf("no ip identd")
        else:
            print("device " + self.host + " is not vulnerable to  Identification service attack")

    def check(self, accessMethod):

        if isinstance(accessMethod, Telnet):
            self.checkByTelnet(accessMethod)
        elif isinstance(accessMethod, SshVersionII):
            self.checkBySSH(accessMethod)

    def checkVulnerability(self, running_config):

        if re.search("ip identd", running_config, re.MULTILINE) is None:
            return False
        else:
            return True
