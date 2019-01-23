import os
import re
from tools.telnet import Telnet
from tools.ssh_v2 import SshVersionII

class DHCP_Starvation:
    def __init__(self,server_ip,host,configDirectory):
        self.exist = True
        self.server_ip = server_ip
        self.host = host
        self.configDirectory = configDirectory
        self.vulnerableInterfaces = []
        self.incompletedInterfaces = []

    def checkByTelnet(self,telnet):
        #telnet.execute("show interfaces switchport | redirect tftp://"+self.server_ip+"/"+self.host+"_stp_bpdu_config")
        #telnet.readUntil(b"!")
        #telnet.readUntil(b"#")
        #output = open(self.configDirectory+"/"+self.host+"_stp_bpdu_config").read().strip()
        #accessInterfaces = self.getAccessInterfaces(output)
        running_config = open(self.configDirectory+"/"+self.host+"_running_config").read().strip()
        self.getVulnerableInterfaces(running_config)
        print(self.vulnerableInterfaces)
        print(self.incompletedInterfaces)
        if len(self.vulnerableInterfaces)==0:
            print("device "+self.host+" is not vulnerable to DHCP Starvation attack")
            if len(self.incompletedInterfaces)!=0:
                print("interfaces "+str(self.incompletedInterfaces)+" are not configured properly")
                telnet.execute("conf t")
                for interface in self.incompletedInterfaces:
                    telnet.execute("interface "+interface)
                    telnet.execute("switchport port-security")
                    telnet.execute("switchport port-security maximum 3")
                    telnet.execute("switchport port-security maximum 2 vlan access")
                    telnet.execute("switchport port-security maximum 1 vlan voice")
                    telnet.execute("switchport port-security violation shutdown vlan")
                    telnet.execute("switchport port-security aging type inactivity")
                    telnet.execute("switchport port-security aging time 2")
                    telnet.execute("exit")
                telnet.execute("end")
        else:
            print("device "+self.host+" is vulnerable to  DHCP Starvation attack")
            print("interfaces "+str(self.vulnerableInterfaces)+" are vulnerable to DHCP Starvation Attack")
            telnet.execute("conf t")
            for interface in self.vulnerableInterfaces:
                telnet.execute("interface "+interface)
                telnet.execute("switchport port-security")
                telnet.execute("switchport port-security maximum 3")
                telnet.execute("switchport port-security maximum 2 vlan access")
                telnet.execute("switchport port-security maximum 1 vlan voice")
                telnet.execute("switchport port-security violation shutdown vlan")
                telnet.execute("switchport port-security aging type inactivity")
                telnet.execute("switchport port-security aging time 2")
                telnet.execute("exit")
            telnet.execute("end")
            if len(self.incompletedInterfaces)!=0:
                print("interfaces "+str(self.incompletedInterfaces)+" are not configured properly")
                telnet.execute("conf t")
                for interface in self.incompletedInterfaces:
                    telnet.execute("interface "+interface)
                    telnet.execute("switchport port-security")
                    telnet.execute("switchport port-security maximum 3")
                    telnet.execute("switchport port-security maximum 2 vlan access")
                    telnet.execute("switchport port-security maximum 1 vlan voice")
                    telnet.execute("switchport port-security violation shutdown vlan")
                    telnet.execute("switchport port-security aging type inactivity")
                    telnet.execute("switchport port-security aging time 2")
                    telnet.execute("exit")
                telnet.execute("end")
        #os.remove(self.configDirectory+"/"+self.host+"_stp_bpdu_config")

    def checkBySSH(self,ssh):
        #output = ssh.exec("show interfaces switchport | redirect tftp://"+self.server_ip+"/"+self.host+"_stp_bpdu_config")
        #output = open(self.configDirectory+"/"+self.host+"_stp_bpdu_config").read().strip()
        #accessInterfaces = self.getAccessInterfaces(output)
        running_config = open(self.configDirectory+"/"+self.host+"_running_config").read().strip()
        self.getVulnerableInterfaces(running_config)
        print(self.vulnerableInterfaces)
        print(self.incompletedInterfaces)

        if len(self.vulnerableInterfaces)==0:
            print("device "+self.host+" is not vulnerable to  DHCP Starvation attack")
            if len(self.incompletedInterfaces)!=0:
                print("interfaces "+str(self.incompletedInterfaces)+" are not configured properly")
                for interface in self.incompletedInterfaces:
                    ssh.conf(["interface "+interface,"switchport port-security","switchport port-security maximum 3","switchport port-security maximum 2 vlan access","switchport port-security maximum 1 vlan voice","switchport port-security violation shutdown vlan","switchport port-security aging type inactivity","switchport port-security aging time 2"])
        else:
            print("device "+self.host+" is vulnerable to  DHCP Starvation attack")
            print("interfaces "+str(self.vulnerableInterfaces)+" are vulnerable to DHCP Starvation Attack")
            for interface in self.vulnerableInterfaces:
                    ssh.conf(["interface "+interface,"switchport port-security","switchport port-security maximum 3","switchport port-security maximum 2 vlan voice","switchport port-security maximum 1 vlan voice","switchport port-security violation shutdown vlan","switchport port-security aging type inactivity","switchport port-security aging time 2"])
            if len(self.incompletedInterfaces)!=0:
                print("interfaces "+str(self.incompletedInterfaces)+" are not configured properly")
                for interface in self.incompletedInterfaces:
                    ssh.conf(["interface "+interface,"switchport port-security","switchport port-security maximum 3","switchport port-security maximum 2 vlan access","switchport port-security maximum 1 vlan voice","switchport port-security violation shutdown vlan","switchport port-security aging type inactivity","switchport port-security aging time 2"])

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
            if re.search("switchport access",interface,re.MULTILINE):
                if re.search("switchport port-security\n",interface,re.MULTILINE)==None:
                    self.vulnerableInterfaces.append(interface.split('\n')[0].strip())
                elif re.search("switchport port-security maximum 3",interface,re.MULTILINE)==None or re.search("switchport port-security maximum 2 vlan access",interface,re.MULTILINE)==None or re.search("switchport port-security violation shutdown vlan",interface,re.MULTILINE)==None or re.search("switchport port-security aging type inactivity",interface,re.MULTILINE)==None or re.search("switchport port-security aging time",interface,re.MULTILINE)==None:
                    self.incompletedInterfaces.append(interface.split('\n')[0].strip())
            if re.search("switchport voice vlan",interface,re.MULTILINE):
                if re.search("switchport port-security maximum 1 vlan voice",interface,re.MULTILINE)==None:
                    self.incompletedInterfaces.append(interface.split('\n')[0].strip())



