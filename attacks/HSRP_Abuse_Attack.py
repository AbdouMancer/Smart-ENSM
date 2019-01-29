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

    def checkInterfaceByTelnet(self,telnet,interface_config):
        if re.search("standby",interface_config,re.MULTILINE):
            output = re.findall("standby ([0-9]+)",interface_config,re.MULTILINE)
            if re.search("standby "+output[0]+" authentication md5 ",interface_config,re.MULTILINE)==None:
                print("the interface is vulnerable to hsrp abuse attack")
                telnet.execute("conf t")
                telnet.execute("interface "+interface_config.split('\n')[0].strip())
                telnet.execute("standby "+output[0]+" authentication md5 key-string cisco")
                telnet.execute("end")
            else:
                print("the interface is not vulnerable to hsrp abuse attack")
        else:
            print("HSRP is not enabled on this interface")


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

    def checkInterface(self,accessMethod,interface_config):
        if isinstance(accessMethod,Telnet):
            self.checkInterfaceByTelnet(accessMethod,interface_config)
        elif isinstance(accessMethod,SshVersionII):
            self.checkInterfaceBySSH(accessMethod,interface_config)
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
                if re.search("standby "+output[0]+" authentication md5 ",interface,re.MULTILINE)==None:
                    self.vulnerableInterfaces.append([interface.split('\n')[0].strip(),output[0]])



