import os
import re
from tools.telnet import Telnet
from tools.ssh_v2 import SshVersionII

class STP_ROOT:
    def __init__(self,server_ip,host,configDirectory):
        self.exist = True
        self.server_ip = server_ip
        self.host = host
        self.configDirectory = configDirectory

    def checkByTelnet(self,telnet):
        telnet.execute("show spanning-tree root port | redirect tftp://"+self.server_ip+"/"+self.host+"_stp_root_config")
        telnet.readUntil(b"!")
        telnet.readUntil(b"#")
        output = open(self.configDirectory+"/"+self.host+"_stp_root_config").read().strip()
        running_config = open(self.configDirectory+"/"+self.host+"_running_config").read().strip()
        interfaces = self.getVulnerableTrunkInterfaces(output,running_config)
        if len(interfaces)==0:
            print("device "+self.host+" is not vulnerable to STP Root attack")
        else:
            print("device "+self.host+" is vulnerable to STP Root attack")
            telnet.execute("conf t")
            for interface in interfaces:
                telnet.execute("interface "+interface)
                telnet.execute("spanning-tree guard root")
                telnet.execute("exit")
            telnet.execute("end")
        os.remove(self.configDirectory+"/"+self.host+"_stp_root_config")

    def checkInterfaceByTelnet(self,telnet,interface_config):
        if re.search("spanning-tree guard root\n",interface_config,re.MULTILINE)==None:
            return False
        else:
            return True

    def checkBySSH(self,ssh):
        output = ssh.exec("show spanning-tree root port | redirect tftp://"+self.server_ip+"/"+self.host+"_stp_root_config")
        output = open(self.configDirectory+"/"+self.host+"_stp_root_config").read().strip()
        running_config = open(self.configDirectory+"/"+self.host+"_running_config").read().strip()
        interfaces = self.getVulnerableTrunkInterfaces(output,running_config)
        if len(interfaces)==0:
            print("device "+self.host+" is not vulnerable to STP Root attack")
        else:
            print("device "+self.host+" is vulnerable to STP Root attack")
            for interface in interfaces:
                ssh.conf(["interface "+interface,"spanning-tree guard root","exit"])
        os.remove(self.configDirectory+"/"+self.host+"_stp_root_config")

    def check(self,accessMethod):
        if isinstance(accessMethod,Telnet):
            self.checkByTelnet(accessMethod)
        elif isinstance(accessMethod,SshVersionII):
            self.checkBySSH(accessMethod)

    def checkInterface(self,accessMethod,interface_config):
        if isinstance(accessMethod,Telnet):
            return self.checkInterfaceByTelnet(accessMethod,interface_config)
        elif isinstance(accessMethod,SshVersionII):
            return self.checkInterfaceBySSH(accessMethod,interface_config)

    def solveByTelnet(self,telnet,interface):
        telnet.execute("conf t")
        telnet.execute("interface "+interface.split('\n')[0].strip())
        telnet.execute("spanning-tree guard root")
        telnet.execute("end")

    def solveBySSH(self,ssh,interface):
        ssh.conf(["interface "+interface.split('\n')[0].strip(),"spanning-tree guard root","exit"])

    def solve(self,accessMethod,interface):
        if isinstance(accessMethod,Telnet):
            self.solveByTelnet(accessMethod,interface)
        elif isinstance(accessMethod,SshVersionII):
            self.solveBySSH(accessMethod,interface)

    def getVulnerableTrunkInterfaces(self,stp_output,running_config):
        root_ports = []
        for line in stp_output.split('\n'):
            parts = line.split()
            if parts[1]!="This":
                if parts[1] not in root_ports:
                    root_ports.append(parts[1])
        trunkInterfaces = []
        interfaces = re.findall("interface([^!]*)",running_config,re.MULTILINE)
        for interface in interfaces:
            if interface.split('\n')[0].strip() not in root_ports:
                if re.search("switchport mode trunk",interface,re.MULTILINE):
                    if re.search("spanning-tree guard root\n",interface,re.MULTILINE)==None:
                        trunkInterfaces.append(interface.split('\n')[0].strip())
        return trunkInterfaces

