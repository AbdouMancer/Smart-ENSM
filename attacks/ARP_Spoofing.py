import os
import re
from tools.telnet import Telnet
from tools.ssh_v2 import SshVersionII

class ARP_Spoofing:
    def __init__(self,server_ip,host,configDirectory):
        self.exist = True
        self.server_ip = server_ip
        self.host = host
        self.configDirectory = configDirectory
        self.vlanList = ''


    def checkDeviceByTelnet(self,telnet,running_config,vlanList):
        #telnet.execute("show interfaces switchport | redirect tftp://"+self.server_ip+"/"+self.host+"_stp_bpdu_config")
        #telnet.readUntil(b"!")
        #telnet.readUntil(b"#")
        #output = open(self.configDirectory+"/"+self.host+"_stp_bpdu_config").read().strip()
        #accessInterfaces = self.getAccessInterfaces(output)
        self.vlanList = vlanList
        return self.commandsMissed(running_config)
        if (vulnerability==True):
            print("device "+self.host+" is vulnerable to  ARP Spoofing attack")
            ##solution
            telnet.execute("conf t")
            telnet.execute("ip arp inspection vlan "+vlans)
            telnet.execute("ip arp inspection validate dst-mac ip")
            '''
            accessInterfaces = self.getVulnerableAccessInterfaces(running_config)
            for interface in accessInterfaces:
                telnet.execute("interface "+interface)
                telnet.execute("ip arp inspection limit rate 10")
                telnet.execute("exit")
            trunkInterfaces = self.getVulnerableTrunkInterfaces(running_config)
            for interface in trunkInterfaces:
                telnet.execute("interface "+interface)
                telnet.execute("ip arp inspection trust")
                telnet.execute("exit")
            '''
            telnet.execute("end")
        '''
        else:
            accessInterfaces = self.getVulnerableAccessInterfaces(running_config)
            trunkInterfaces = self.getVulnerableTrunkInterfaces(running_config)
            if self.commandsMissed(running_config,vlans)==False and len(accessInterfaces)==0 and len(trunkInterfaces)==0:
                print("device "+self.host+" is not vulnerable to  ARP Spoofing attack")
            else:
                print("device "+self.host+" is not configured properly")
                telnet.execute("conf t")
                telnet.execute("ip arp inspection vlan "+vlans)
                telnet.execute("ip arp inspection validate dst-mac ip")
                if len(accessInterfaces)!=0:
                    for interface in accessInterfaces:
                        telnet.execute("interface "+interface)
                        telnet.execute("ip arp inspection limit rate 10")
                        telnet.execute("exit")

                for interface in trunkInterfaces:
                    telnet.execute("interface "+interface)
                    telnet.execute("ip arp inspection trust")
                    telnet.execute("exit")
                telnet.execute("end")

        '''
        #os.remove(self.configDirectory+"/"+self.host+"_stp_bpdu_config")

    def checkDeviceBySSH(self,ssh):
        #output = ssh.exec("show interfaces switchport | redirect tftp://"+self.server_ip+"/"+self.host+"_stp_bpdu_config")
        #output = open(self.configDirectory+"/"+self.host+"_stp_bpdu_config").read().strip()
        #accessInterfaces = self.getAccessInterfaces(output)
        running_config = open(self.configDirectory+"/"+self.host+"_running_config").read().strip()
        vlans = self.getVlans(running_config)
        vulnerability = self.checkVulnerability(running_config,vlans)
        if (vulnerability==True):
            print("device "+self.host+" is vulnerable to  ARP Spoofing attack")
            ##solution
            ssh.conf(["ip arp inspection vlan "+vlans,"ip arp inspection validate dst-mac ip"])
            accessInterfaces = self.getVulnerableAccessInterfaces(running_config)
            for interface in accessInterfaces:
                ssh.conf(["interface "+interface,"ip arp inspection limit rate 10","exit"])
            trunkInterfaces = self.getVulnerableTrunkInterfaces(running_config)
            for interface in trunkInterfaces:
                ssh.conf(["interface "+interface,"ip arp inspection trust","exit"])
        else:
            accessInterfaces = self.getVulnerableAccessInterfaces(running_config)
            trunkInterfaces = self.getVulnerableTrunkInterfaces(running_config)
            if self.commandsMissed(running_config,vlans)==False and len(accessInterfaces)==0 and len(trunkInterfaces)==0:
                print("device "+self.host+" is not vulnerable to  ARP Spoofing attack")
            else:
                print("device "+self.host+" is not configured properly")
                ssh.conf(["ip arp inspection vlan "+vlans,"ip arp inspection validate dst-mac ip"])
                if len(accessInterfaces)!=0:
                    for interface in accessInterfaces:
                        ssh.conf(["interface "+interface,"ip arp inspection limit rate 10","exit"])

                for interface in trunkInterfaces:
                    ssh.conf(["interface "+interface,"ip arp inspection trust","exit"])



        #os.remove(self.configDirectory+"/"+self.host+"_stp_bpdu_config")
    def checkInterfaceByTelnet(self,telnet,interface_config,type):
        if type == 'H':
            if re.search("ip arp inspection limit rate",interface_config,re.MULTILINE)==None:
                return False
            else:
                return True
        elif type == 'AD':
            if re.search("ip arp inspection trust\n",interface_config,re.MULTILINE)==None:
                return False
            else:
                return True

    def checkDevice(self,accessMethod,running_config,vlanList):
        if isinstance(accessMethod,Telnet):
            return self.checkDeviceByTelnet(accessMethod,running_config,vlanList)
        elif isinstance(accessMethod,SshVersionII):
            return self.checkDeviceBySSH(accessMethod,running_config,vlanList)

    def checkInterface(self,accessMethod,interface_config,type):
        if isinstance(accessMethod,Telnet):
            return self.checkInterfaceByTelnet(accessMethod,interface_config,type)
        elif isinstance(accessMethod,SshVersionII):
            return self.checkInterfaceBySSH(accessMethod,interface_config,type)

    def solveByTelnet(self,telnet,command):
        telnet.execute("conf t")
        if command == 'ip arp inspection vlan':
            telnet.execute("no ip arp inspection vlan")
            telnet.execute("ip arp inspection vlan "+self.vlanList)
        elif command == "ip arp inspection validate":
            telnet.execute("ip arp inspection validate dst-mac ip")

        telnet.execute("end")


    def solveBySSH(self,ssh,command):
        print()

    def solve(self,accessMethod,command):
        if isinstance(accessMethod,Telnet):
            self.solveByTelnet(accessMethod,command)
        elif isinstance(accessMethod,SshVersionII):
            self.solveBySSH(accessMethod,command)

    def solveInterfaceByTelnet(self,telnet,interface,command):
        telnet.execute("conf t")
        telnet.execute("interface "+interface.split('\n')[0].strip())
        telnet.execute(command)
        telnet.execute("end")


    def solveInterfaceBySSH(self,ssh,interface,command):
        print()

    def solveInterface(self,accessMethod,interface,command):
        if isinstance(accessMethod,Telnet):
            self.solveInterfaceByTelnet(accessMethod,interface,command)
        elif isinstance(accessMethod,SshVersionII):
            self.solveInterfaceBySSH(accessMethod,interface,command)
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



    def commandsMissed(self,running_config):
        vlanListItems = self.vlanList.split(',')
        commandsMissed = []
        if re.search("ip arp inspection vlan ",running_config,re.MULTILINE)==None:
            commandsMissed.append("ip arp inspection vlan")
        else:
            items = re.findall("ip arp inspection vlan ((?:[0-9]|,|-)+)",running_config)[0]
            VLANs = []
            for vlan in items.split(","):
                if "-" not in vlan:
                    VLANs.append(vlan)
                else:
                    limits = vlan.split("-")
                    for i in range(int(limits[0]),int(limits[1])+1):
                        VLANs.append(str(i))

            for vlan in vlanListItems:
                if vlan not in VLANs:
                    commandsMissed.append("ip arp inspection vlan")
                    break

        if re.search("ip arp inspection validate ",running_config,re.MULTILINE)==None:
            commandsMissed.append("ip arp inspection validate")

        return commandsMissed

    def getVulnerableAccessInterfaces(self,running_config):
        accessInterfaces = []
        interfaces = re.findall("interface([^!]*)",running_config,re.MULTILINE)
        for interface in interfaces:
            if re.search("switchport access",interface,re.MULTILINE):
                if re.search("ip arp inspection limit rate",interface,re.MULTILINE)==None:
                    accessInterfaces.append(interface.split('\n')[0].strip())
        return accessInterfaces

    def getVulnerableTrunkInterfaces(self,running_config):
        trunkInterfaces = []
        interfaces = re.findall("interface([^!]*)",running_config,re.MULTILINE)
        for interface in interfaces:
            if re.search("switchport mode trunk",interface,re.MULTILINE):
                if re.search("ip arp inspection trust\n",interface,re.MULTILINE)==None:
                    trunkInterfaces.append(interface.split('\n')[0].strip())
        return trunkInterfaces

    def getVlans(self,running_config):
        vlans = re.findall("\nvlan ((?:[0-9]|,|-)+)",running_config)
        vlanList = "1"
        for x in range(len(vlans)):
            vlanList = vlanList+","+vlans[x]
        return vlanList
