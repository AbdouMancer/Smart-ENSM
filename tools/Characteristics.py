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
        self.vlans = []
        self.missedVlans = []

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
        interfaces = re.findall("\ninterface([^!]*)",running_config,re.MULTILINE)
        return interfaces


    def execute(self,cmd):
        if isinstance(self.accessMode,Telnet):
            self.accessMode.execute(cmd)
            self.accessMode.readUntil(b"!")
            self.accessMode.readUntil(b"#")
        elif isinstance(self.accessMode,SshVersionII):
            self.accessMode.exec(cmd)

    def getVlans(self,running_config):
        vlans = re.findall("\nvlan ((?:[0-9]|,|-)+)",running_config)
        vlanList = "1"
        for x in range(len(vlans)):
            vlanList = vlanList+","+vlans[x]
        self.vlans = []
        for vlan in vlanList.split(","):
            if "-" not in vlan:
                self.vlans.append(vlan)
            else:
                limits = vlan.split("-")
                for i in range(int(limits[0]),int(limits[1])+1):
                    self.vlans.append(str(i))

    def getMissedVlans(self,interfaces):
        self.missedVlans = []
        for interface in interfaces:
            if re.search("switchport access vlan ",interface,re.MULTILINE):
                vlan = re.findall("switchport access vlan ([0-9]+)",interface)[0]
                if vlan not in self.vlans:
                    self.missedVlans.append(vlan)
    def getVlansList(self):
        vlanList = ''
        for vlan in self.vlans:
            vlanList = vlan + ',' + vlanList
        for vlan in self.missedVlans:
            vlanList = vlan + ',' + vlanList
        return vlanList[0:len(vlanList)-1]
    def remove(self):
        os.remove(self.configDirectory+"/"+self.host+"_running_config")
