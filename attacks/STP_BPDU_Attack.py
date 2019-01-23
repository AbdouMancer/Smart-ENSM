import os
import re
from tools.telnet import Telnet
from tools.ssh_v2 import SshVersionII

class STP_BPDU:
    def __init__(self,server_ip,host,configDirectory):
        self.exist = True
        self.server_ip = server_ip
        self.host = host
        self.configDirectory = configDirectory

    def checkByTelnet(self,telnet):
        #telnet.execute("show interfaces switchport | redirect tftp://"+self.server_ip+"/"+self.host+"_stp_bpdu_config")
        #telnet.readUntil(b"!")
        #telnet.readUntil(b"#")
        #output = open(self.configDirectory+"/"+self.host+"_stp_bpdu_config").read().strip()
        #accessInterfaces = self.getAccessInterfaces(output)
        running_config = open(self.configDirectory+"/"+self.host+"_running_config").read().strip()
        vulnerableInterfaces = self.getVulnerableInterfaces(running_config)
        print(vulnerableInterfaces)
        if len(vulnerableInterfaces)==0:
            print("device "+self.host+" is not vulnerable to STP BPDU attack")
        else:
            print("device "+self.host+" is vulnerable to STP BPDU attack")
            telnet.execute("conf t")
            for interface in vulnerableInterfaces:
                telnet.execute("interface "+interface)
                telnet.execute("spanning-tree portfast")
                telnet.execute("spanning-tree bpduguard enable")
                telnet.execute("exit")
            telnet.execute("end")
        #os.remove(self.configDirectory+"/"+self.host+"_stp_bpdu_config")

    def checkBySSH(self,ssh):
        #output = ssh.exec("show interfaces switchport | redirect tftp://"+self.server_ip+"/"+self.host+"_stp_bpdu_config")
        #output = open(self.configDirectory+"/"+self.host+"_stp_bpdu_config").read().strip()
        #accessInterfaces = self.getAccessInterfaces(output)
        running_config = open(self.configDirectory+"/"+self.host+"_running_config").read().strip()
        vulnerableInterfaces = self.getVulnerableInterfaces(running_config)
        print(vulnerableInterfaces)
        if len(vulnerableInterfaces)==0:
            print("device "+self.host+" is not vulnerable to STP BPDU attack")
        else:
            print("device "+self.host+" is vulnerable to STP BPDU attack")
            for interface in vulnerableInterfaces:
                ssh.conf(["interface "+interface,"spanning-tree portfast","spanning-tree bpduguard enable"])
        #os.remove(self.configDirectory+"/"+self.host+"_stp_bpdu_config")

    def check(self,accessMethod):
        if isinstance(accessMethod,Telnet):
            self.checkByTelnet(accessMethod)
        elif isinstance(accessMethod,SshVersionII):
            self.checkBySSH(accessMethod)

    '''
    def getAccessInterfaces(self,show):
        accessInterfaces = []
        interfaces = show.split("Name:")
        for interface in interfaces:
            if interfaces.index(interface)!= 0:
                lines = interface.split('\n')
                for line in lines:
                    if "Operational Mode:" in line and "static access" in line:
                        accessInterfaces.append(lines[0].strip())

        return accessInterfaces
    '''

    def getVulnerableInterfaces(self,running_config):
        vulnerableInterfaces = []
        interfaces = re.findall("interface([^!]*)",running_config,re.MULTILINE)
        for interface in interfaces:
            if re.search("switchport access",interface,re.MULTILINE):
                if re.search("spanning-tree bpduguard enable",interface,re.MULTILINE)==None:
                    vulnerableInterfaces.append(interface.split('\n')[0].strip())
        return vulnerableInterfaces


