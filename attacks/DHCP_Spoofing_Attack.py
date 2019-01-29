import os
import re
from tools.telnet import Telnet
from tools.ssh_v2 import SshVersionII

class DHCP_Spoofing:
    def __init__(self,server_ip,host,configDirectory):
        self.exist = True
        self.server_ip = server_ip
        self.host = host
        self.configDirectory = configDirectory


    def checkDeviceByTelnet(self,telnet):
        #telnet.execute("show interfaces switchport | redirect tftp://"+self.server_ip+"/"+self.host+"_stp_bpdu_config")
        #telnet.readUntil(b"!")
        #telnet.readUntil(b"#")
        #output = open(self.configDirectory+"/"+self.host+"_stp_bpdu_config").read().strip()
        #accessInterfaces = self.getAccessInterfaces(output)
        running_config = open(self.configDirectory+"/"+self.host+"_running_config").read().strip()
        vlans = self.getVlans(running_config)
        vulnerability = self.checkVulnerability(running_config,vlans)
        if (vulnerability==True):
            print("device "+self.host+" is vulnerable to  DHCP Spoofing attack")
            ##solution
            telnet.execute("conf t")
            telnet.execute("ip dhcp snooping")
            if vlans != "":
                telnet.execute("ip dhcp snooping vlan "+vlans)
            telnet.execute("no ip dhcp snooping information option")
            telnet.execute("ip dhcp snooping database flash:dhcp-snooping-database.txt")
            telnet.execute("ip dhcp snooping database write-delay 60")
            '''
            accessInterfaces = self.getVulnerableAccessInterfaces(running_config)
            for interface in accessInterfaces:
                telnet.execute("interface "+interface)
                telnet.execute("ip dhcp snooping limit rate 10")
                telnet.execute("exit")
            trunkInterfaces = self.getVulnerableTrunkInterfaces(running_config)
            for interface in trunkInterfaces:
                telnet.execute("interface "+interface)
                telnet.execute("ip dhcp snooping trust")
                telnet.execute("exit")
            '''
            telnet.execute("end")
        '''
        else:
            accessInterfaces = self.getVulnerableAccessInterfaces(running_config)
            trunkInterfaces = self.getVulnerableTrunkInterfaces(running_config)
            if self.commandsMissed(running_config,vlans)==False and len(accessInterfaces)==0 and len(trunkInterfaces)==0:
                print("device "+self.host+" is not vulnerable to  DHCP Spoofing attack")
            else:
                print("device "+self.host+" is not configured properly")
                telnet.execute("conf t")
                telnet.execute("ip dhcp snooping")
                if vlans != "":
                    telnet.execute("ip dhcp snooping vlan "+vlans)
                telnet.execute("no ip dhcp snooping information option")
                telnet.execute("ip dhcp snooping database flash:dhcp-snooping-database.txt")
                telnet.execute("ip dhcp snooping database write-delay 60")
                if len(accessInterfaces)!=0:
                    for interface in accessInterfaces:
                        telnet.execute("interface "+interface)
                        telnet.execute("ip dhcp snooping limit rate 10")
                        telnet.execute("exit")

                for interface in trunkInterfaces:
                    telnet.execute("interface "+interface)
                    telnet.execute("ip dhcp snooping trust")
                    telnet.execute("exit")
                telnet.execute("end")
        '''


        #os.remove(self.configDirectory+"/"+self.host+"_stp_bpdu_config")
    def checkInterfaceByTelnet(self,telnet,interface_config,type):
        if type == 'H':
            if re.search("ip dhcp snooping limit rate",interface_config,re.MULTILINE)==None:
                print("the interface is vulnerable to dhcp spoofing attack")
                telnet.execute("conf t")
                telnet.execute("interface "+interface_config.split('\n')[0].strip())
                telnet.execute("ip dhcp snooping limit rate 10")
                telnet.execute("end")
            else:
                print("the interface is not vulnerable to dhcp spoofing attack")
        elif type == 'AD':
            if re.search("ip dhcp snooping trust\n",interface_config,re.MULTILINE)==None:
                print("the interface is not configured properly to mitigate dhcp spoofing")
                telnet.execute("conf t")
                telnet.execute("interface "+interface_config.split('\n')[0].strip())
                telnet.execute("ip dhcp snooping trust")
                telnet.execute("end")
            else:
                print("the interface is configured properly")

    def checkDeviceBySSH(self,ssh):
        #output = ssh.exec("show interfaces switchport | redirect tftp://"+self.server_ip+"/"+self.host+"_stp_bpdu_config")
        #output = open(self.configDirectory+"/"+self.host+"_stp_bpdu_config").read().strip()
        #accessInterfaces = self.getAccessInterfaces(output)
        running_config = open(self.configDirectory+"/"+self.host+"_running_config").read().strip()
        vlans = self.getVlans(running_config)
        vulnerability = self.checkVulnerability(running_config,vlans)
        if (vulnerability==True):
            print("device "+self.host+" is vulnerable to  DHCP Spoofing attack")
            ##solution
            ssh.conf(["ip dhcp snooping","ip dhcp snooping vlan "+vlans,"no ip dhcp snooping information option","ip dhcp snooping database flash:dhcp-snooping-database.txt","ip dhcp snooping database write-delay 60"])
            accessInterfaces = self.getVulnerableAccessInterfaces(running_config)
            for interface in accessInterfaces:
                ssh.conf(["interface "+interface,"ip dhcp snooping limit rate 10","exit"])
            trunkInterfaces = self.getVulnerableTrunkInterfaces(running_config)
            for interface in trunkInterfaces:
                ssh.conf(["interface "+interface,"ip dhcp snooping trust","exit"])
        else:
            accessInterfaces = self.getVulnerableAccessInterfaces(running_config)
            trunkInterfaces = self.getVulnerableTrunkInterfaces(running_config)
            if self.commandsMissed(running_config,vlans)==False and len(accessInterfaces)==0 and len(trunkInterfaces)==0:
                print("device "+self.host+" is not vulnerable to  DHCP Spoofing attack")
            else:
                print("device "+self.host+" is not configured properly")
                ssh.conf(["ip dhcp snooping","ip dhcp snooping vlan "+vlans,"no ip dhcp snooping information option","ip dhcp snooping database flash:dhcp-snooping-database.txt","ip dhcp snooping database write-delay 60"])
                if len(accessInterfaces)!=0:
                    for interface in accessInterfaces:
                        ssh.conf(["interface "+interface,"ip dhcp snooping limit rate 10","exit"])

                for interface in trunkInterfaces:
                    ssh.conf(["interface "+interface,"ip dhcp snooping trust","exit"])



        #os.remove(self.configDirectory+"/"+self.host+"_stp_bpdu_config")
    def checkInterfaceBySSH(self,ssh,interface_config,type):
        if type == 'H':
            if re.search("ip dhcp snooping limit rate",interface_config,re.MULTILINE)==None:
                print("the interface is vulnerable to dhcp spoofing attack")
                ssh.conf(["interface "+interface_config.split('\n')[0].strip(),"ip dhcp snooping limit rate 10","exit"])
            else:
                print("the interface is not vulnerable to dhcp spoofing attack")
        elif type == 'AD':
            if re.search("ip dhcp snooping trust\n",interface_config,re.MULTILINE)==None:
                print("the interface is not configured properly to mitigate dhcp spoofing")
                ssh.conf(["interface "+interface_config.split('\n')[0].strip(),"ip dhcp snooping trust","exit"])
            else:
                print("the interface is configured properly")
    def checkDevice(self,accessMethod):
        if isinstance(accessMethod,Telnet):
            self.checkDeviceByTelnet(accessMethod)
        elif isinstance(accessMethod,SshVersionII):
            self.checkDeviceBySSH(accessMethod)
    def checkInterface(self,accessMethod,interface_config,type):
        if isinstance(accessMethod,Telnet):
            self.checkInterfaceByTelnet(accessMethod,interface_config,type)
        elif isinstance(accessMethod,SshVersionII):
            self.checkInterfaceBySSH(accessMethod,interface_config,type)
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

    def checkVulnerability(self,running_config,vlans):
        if re.search("ip dhcp snooping\n",running_config,re.MULTILINE)==None or re.search("ip dhcp snooping vlan "+vlans,running_config,re.MULTILINE)==None:
            return True
        else:
            return False

    def commandsMissed(self,running_config,vlans):
        if re.search("ip dhcp snooping vlan "+vlans,running_config,re.MULTILINE)==None or re.search("no ip dhcp snooping information option",running_config,re.MULTILINE)==None or re.search("ip dhcp snooping database",running_config,re.MULTILINE)==None:
            return True
        else:
            return False

    def getVulnerableAccessInterfaces(self,running_config):
        accessInterfaces = []
        interfaces = re.findall("interface([^!]*)",running_config,re.MULTILINE)
        for interface in interfaces:
            if re.search("switchport access",interface,re.MULTILINE):
                if re.search("ip dhcp snooping limit rate",interface,re.MULTILINE)==None:
                    accessInterfaces.append(interface.split('\n')[0].strip())
        return accessInterfaces

    def getVulnerableTrunkInterfaces(self,running_config):
        trunkInterfaces = []
        interfaces = re.findall("interface([^!]*)",running_config,re.MULTILINE)
        for interface in interfaces:
            if re.search("switchport mode trunk",interface,re.MULTILINE):
                if re.search("ip dhcp snooping trust\n",interface,re.MULTILINE)==None:
                    trunkInterfaces.append(interface.split('\n')[0].strip())
        return trunkInterfaces

    def getVlans(self,running_config):
        vlans = re.findall("\nvlan ((?:[0-9]|,|-)+)",running_config)
        vlanList = "1"
        for x in range(len(vlans)):
            vlanList = vlanList+","+vlans[x]
        return vlanList
