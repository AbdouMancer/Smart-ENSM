from tools.telnet import Telnet
from tools.ssh_v2 import SshVersionII
import os
import re

class Characteristics:
    def __init__(self,server_ip,host,configDirectory,accessMode):
        self.exist = True
        self.server_ip = server_ip
        self.host = host
        self.configDirectory = configDirectory
        self.accessMode = accessMode

    def getRunningConfig(self):
        self.execute("show running | redirect tftp://"+self.server_ip+"/"+self.host+"_running_config")

    def getCDP(self):
        self.execute("show cdp neigh | redirect tftp://"+self.server_ip+"/"+self.host+"_cdp_config")

    def getLLDP(self):
        self.execute("show lldp neigh | redirect tftp://"+self.server_ip+"/"+self.host+"_lldp_config")

    def getVTP(self):
        self.execute("show vtp status | redirect tftp://"+self.server_ip+"/"+self.host+"_vtp_config")

    def getSTPBPDU(self):
        self.execute("")

    def getInterfaces(self,running_config):
        interfaces = re.findall("interface([^!]*)",running_config,re.MULTILINE)
        return interfaces


    def execute(self,cmd):
        if isinstance(self.accessMode,Telnet):
            self.accessMode.execute(cmd)
            self.accessMode.readUntil(b"!")
            self.accessMode.readUntil(b"#")
        elif isinstance(self.accessMode,SshVersionII):
            self.accessMode.exec(cmd)

    def remove(self):
        os.remove(self.configDirectory+"/"+self.host+"_running_config")
