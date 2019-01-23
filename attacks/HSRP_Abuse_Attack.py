import os
import re
from tools.telnet import Telnet
from tools.ssh_v2 import SshVersionII

class HSRP_Abuse:
    def __init__(self,server_ip,host,configDirectory):
        self.exist = True
        self.server_ip = server_ip
        self.host = host
        self.configDirectory = configDirectory
        self.vulnerableInterfaces = []

    def checkByTelnet(self,telnet):
        #telnet.execute("show interfaces switchport | redirect tftp://"+self.server_ip+"/"+self.host+"_stp_bpdu_config")
        #telnet.readUntil(b"!")
        #telnet.readUntil(b"#")
        #output = open(self.configDirectory+"/"+self.host+"_stp_bpdu_config").read().strip()
        #accessInterfaces = self.getAccessInterfaces(output)
        running_config = open(self.configDirectory+"/"+self.host+"_running_config").read().strip()
        self.getVulnerableInterfaces(running_config)
        if len(self.vulnerableInterfaces)==0:
            print("device "+self.host+" is not vulnerable to HSRP Abuse attack")
        else:
            print("device "+self.host+" is vulnerable to HSRP Abuse attack")
            print("interfaces "+str(self.vulnerableInterfaces)+" are vulnerable to HSRP Abuse Attack")
            telnet.execute("conf t")
            for interface in self.vulnerableInterfaces:
                telnet.execute("interface "+interface[0])
                telnet.execute("standby "+interface[1]+" authentication md5 key-string cisco")
                telnet.execute("exit")
            telnet.execute("end")
        #os.remove(self.configDirectory+"/"+self.host+"_stp_bpdu_config")

    def checkBySSH(self,ssh):
        #output = ssh.exec("show interfaces switchport | redirect tftp://"+self.server_ip+"/"+self.host+"_stp_bpdu_config")
        #output = open(self.configDirectory+"/"+self.host+"_stp_bpdu_config").read().strip()
        #accessInterfaces = self.getAccessInterfaces(output)
        running_config = open(self.configDirectory+"/"+self.host+"_running_config").read().strip()
        self.getVulnerableInterfaces(running_config)
        if len(self.vulnerableInterfaces)==0:
            print("device "+self.host+" is not vulnerable to HSRP Abuse attack")
        else:
            print("device "+self.host+" is vulnerable to HSRP Abuse attack")
            print("interfaces "+str(self.vulnerableInterfaces)+" are vulnerable to HSRP Abuse Attack")
            for interface in self.vulnerableInterfaces:
                    ssh.conf(["interface "+interface[0],"standby "+interface[1]+" authentication md5 key-string cisco","exit"])
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
        interfaces = re.findall("interface([^!]*)",running_config,re.MULTILINE)
        for interface in interfaces:
            if re.search("standby",interface,re.MULTILINE):
                output = re.findall("standby ([0-9]+)",interface,re.MULTILINE)
                self.vulnerableInterfaces.append([interface.split('\n')[0].strip(),output[0]])



