import os
import re
from tools.telnet import Telnet
from tools.ssh_v2 import SshVersionII

class EIGRP:
    def __init__(self,server_ip,host,configDirectory):
        self.exist = True
        self.server_ip = server_ip
        self.host = host
        self.configDirectory = configDirectory
        self.passiveInterfaces = []
        self.interfaces = []
        self.accesslist = False
        self.acl_changed = []

    def checkByTelnet(self,telnet):
        telnet.execute("show ip eigrp interfaces | redirect tftp://"+self.server_ip+"/"+self.host+"_eigrp_interfaces_config")
        telnet.readUntil(b"!")
        telnet.readUntil(b"#")
        telnet.execute("show ip protocols | redirect tftp://"+self.server_ip+"/"+self.host+"_protocols_config")
        telnet.readUntil(b"!")
        telnet.readUntil(b"#")
        eigrpInterfaces = open(self.configDirectory+"/"+self.host+"_eigrp_interfaces_config").read().strip()
        protocols = open(self.configDirectory+"/"+self.host+"_protocols_config").read().strip()
        running_config = open(self.configDirectory+"/"+self.host+"_running_config").read().strip()
        self.getInterfaces(eigrpInterfaces,running_config)
        self.getPassiveInterfaces(protocols)
        '''
        for interface in passiveInterfaces:
            interfaces.append(interface)

        accesslist = False
        acl_changed = []
        telnet.execute("conf t")
        telnet.execute("key chain authentication_chain")
        telnet.execute("key 1")
        telnet.execute("key-string cisco")
        telnet.execute("end")
        for interface in interfaces:
            telnet.execute("show run interface "+interface[0]+" | redirect tftp://"+self.server_ip+"/"+self.host+"_eigrp_interface_config")
            telnet.readUntil(b"!")
            telnet.readUntil(b"#")
            interfaceConfig = open(self.configDirectory+"/"+self.host+"_eigrp_interface_config").read().strip()
            print("Do you confirm that "+interface[0]+" interface within the process "+interface[1]+" is not connected to a router, and no EIGRP adjacency can be formed from it ?")
            answer = input("answer by yes or no ?")
            telnet.execute("conf t")
            if answer  == 'yes':
                telnet.execute("router eigrp "+interface[1])
                telnet.execute("passive-interface "+interface[0])
                telnet.execute("exit")
                if re.search("ip access-group ([^in]*)",interfaceConfig,re.MULTILINE)==None:
                    if accesslist==False:
                        telnet.execute("ip access-list extended deny_eigrp")
                        telnet.execute("deny eigrp any any")
                        telnet.execute("permit ip any any")
                        telnet.execute("exit")
                        accesslist = True
                    telnet.execute("interface "+interface[0])
                    telnet.execute("ip access-group deny_eigrp in")
                    telnet.execute("exit")
                else:
                    accesslistName = re.findall("ip access-group .* in",interfaceConfig,re.MULTILINE)[0].replace('ip access-group','').replace('in','').strip()
                    if re.match("[0-9]+",accesslistName):
                        entries = []
                        entries.append("deny eigrp any any")
                        accesslistEntries = re.findall("access-list "+accesslistName+" .*",running_config,re.MULTILINE)
                        if "access-list "+accesslistName+" deny eigrp any any" not in accesslistEntries:
                                if "acl_"+accesslistName not in acl_changed:
                                    for line in accesslistEntries:
                                        entries.append(line.replace("access-list "+accesslistName,'').strip())
                                    telnet.execute("ip access-list extended acl_"+accesslistName)
                                    for entry in entries:
                                        telnet.execute(entry)
                                    telnet.execute("exit")
                                    acl_changed.append("acl_"+accesslistName)
                                telnet.execute("interface "+interface[0])
                                telnet.execute("ip access-group acl_"+accesslistName+" in")
                                telnet.execute("exit")
                    else:
                        if accesslistName not in acl_changed:
                            telnet.execute("do show access-lists "+accesslistName+" | redirect tftp://"+self.server_ip+"/"+self.host+"_acl_config")
                            telnet.readUntil(b"!")
                            telnet.readUntil(b"#")
                            acl = open(self.configDirectory+"/"+self.host+"_acl_config").read().strip()
                            if "deny eigrp any any" not in acl:
                                entryNumber = re.findall("[0-9]+",acl.split('\n')[1],re.MULTILINE)[0]
                                newEntry = int(entryNumber)-1
                                telnet.execute("ip access-list extended "+accesslistName)
                                telnet.execute(str(newEntry)+" deny eigrp any any")
                                telnet.execute("exit")
                            os.remove(self.configDirectory+"/"+self.host+"_acl_config")
                            acl_changed.append(accesslistName)
            if re.search("ip authentication mode eigrp "+interface[1]+" md5\n",interfaceConfig,re.MULTILINE)==None:
                print("you don't use any authentication method on "+interface[0]+" interface, would you like to enable md5 authentication?")
                auth = input("answer by yes or no ?")
                if auth == 'yes':
                    telnet.execute("interface "+interface[0])
                    telnet.execute("ip authentication mode eigrp "+interface[1]+" md5")
                    telnet.execute("exit")
            telnet.execute("end")
            os.remove(self.configDirectory+"/"+self.host+"_eigrp_interface_config")
        '''
        os.remove(self.configDirectory+"/"+self.host+"_eigrp_interfaces_config")
        os.remove(self.configDirectory+"/"+self.host+"_protocols_config")


    def checkPassiveInterfaceByTelnet(self,telnet,interface_config,running_config):
        interface = interface_config.split('\n')[0].strip()
        for entry in self.passiveInterfaces:
            if interface == entry[0]:
                print("eigrp passive interface is configured properly")
                break
        for entry in self.interfaces:
            begin = re.findall("[a-zA-Z]+",entry[0])[0]
            end = entry[0].replace(begin,'')
            if interface.startswith(begin) and interface.endswith(end):
                print("eigrp passive interface is not configured properly")
                telnet.execute("conf t")
                telnet.execute("router eigrp "+entry[1])
                telnet.execute("passive-interface "+interface)
                telnet.execute("end")
                break
        if re.search("ip access-group ([^in]*)",interface_config,re.MULTILINE)==None:
            telnet.execute("conf t")
            if self.accesslist==False:

                telnet.execute("ip access-list extended deny_eigrp")
                telnet.execute("deny eigrp any any")
                telnet.execute("permit ip any any")
                telnet.execute("exit")
                self.accesslist = True
            telnet.execute("interface "+interface[0])
            telnet.execute("ip access-group deny_eigrp in")
            telnet.execute("end")
        else:
            accesslistName = re.findall("ip access-group .* in",interface_config,re.MULTILINE)[0].replace('ip access-group','').replace('in','').strip()
            telnet.execute("conf t")
            if re.match("[0-9]+",accesslistName):
                entries = []
                entries.append("deny eigrp any any")
                accesslistEntries = re.findall("access-list "+accesslistName+" .*",running_config,re.MULTILINE)
                if "access-list "+accesslistName+" deny eigrp any any" not in accesslistEntries:
                        if "acl_"+accesslistName not in self.acl_changed:
                            for line in accesslistEntries:
                                entries.append(line.replace("access-list "+accesslistName,'').strip())
                            telnet.execute("ip access-list extended acl_"+accesslistName)
                            for entry in entries:
                                telnet.execute(entry)
                            telnet.execute("exit")
                            self.acl_changed.append("acl_"+accesslistName)
                        telnet.execute("interface "+interface[0])
                        telnet.execute("ip access-group acl_"+accesslistName+" in")
                        telnet.execute("exit")
            else:
                if accesslistName not in self.acl_changed:
                    telnet.execute("do show access-lists "+accesslistName+" | redirect tftp://"+self.server_ip+"/"+self.host+"_acl_config")
                    telnet.readUntil(b"!")
                    telnet.readUntil(b"#")
                    acl = open(self.configDirectory+"/"+self.host+"_acl_config").read().strip()
                    if "deny eigrp any any" not in acl:
                        entryNumber = re.findall("[0-9]+",acl.split('\n')[1],re.MULTILINE)[0]
                        newEntry = int(entryNumber)-1
                        telnet.execute("ip access-list extended "+accesslistName)
                        telnet.execute(str(newEntry)+" deny eigrp any any")
                        telnet.execute("exit")
                    os.remove(self.configDirectory+"/"+self.host+"_acl_config")
                    self.acl_changed.append(accesslistName)
            telnet.execute("end")

    def checkOperatingInterfaceByTelnet(self,telnet,interface_config):
        interface = interface_config.split('\n')[0].strip()
        for entry in self.interfaces:
            begin = re.findall("[a-zA-Z]+",entry[0])[0]
            end = entry[0].replace(begin,'')
            if interface.startswith(begin) and interface.endswith(end):
                if re.search("ip authentication mode eigrp "+entry[1]+" md5\n",interface_config,re.MULTILINE)==None:
                    print("you don't use any authentication method on "+interface+" interface")
                    telnet.execute("conf t")
                    telnet.execute("interface "+interface)
                    telnet.execute("ip authentication mode eigrp "+entry[1]+" md5")
                    telnet.execute("end")

    def checkBySSH(self,ssh):
        ssh.exec("show ip eigrp interfaces | redirect tftp://"+self.server_ip+"/"+self.host+"_eigrp_interfaces_config")
        eigrpInterfaces = open(self.configDirectory+"/"+self.host+"_eigrp_interfaces_config").read().strip()
        running_config = open(self.configDirectory+"/"+self.host+"_running_config").read().strip()
        interfaces = self.getInterfaces(eigrpInterfaces,running_config)
        accesslist = False
        acl_changed = []
        ssh.conf(["key chain authentication_chain","key 1","key-string cisco","exit","exit"])
        for interface in interfaces:
            ssh.exec("show run interface "+interface[0]+" | redirect tftp://"+self.server_ip+"/"+self.host+"_eigrp_interface_config")
            interfaceConfig = open(self.configDirectory+"/"+self.host+"_eigrp_interface_config").read().strip()
            print("Do you confirm that "+interface[0]+" interface within the process "+interface[1]+" is not connected to a router, and no EIGRP adjacency can be formed from it ?")
            answer = input("answer by yes or no ?")
            if answer  == 'yes':
                ssh.conf(["router eigrp "+interface[1],"passive-interface "+interface[0],"exit"])
                if re.search("ip access-group ([^in]*)",interfaceConfig,re.MULTILINE)==None:
                    if accesslist==False:
                        ssh.conf(["ip access-list extended deny_eigrp","deny eigrp any any","permit ip any any","exit"])
                        accesslist = True
                    ssh.conf(["interface "+interface[0],"ip access-group deny_eigrp in","exit"])
                else:
                    accesslistName = re.findall("ip access-group .* in",interfaceConfig,re.MULTILINE)[0].replace('ip access-group','').replace('in','').strip()
                    print(accesslistName)
                    if re.match("[0-9]+",accesslistName):
                        entries = []
                        entries.append("deny eigrp any any")
                        accesslistEntries = re.findall("access-list "+accesslistName+" .*",running_config,re.MULTILINE)
                        if "acl_"+accesslistName not in acl_changed:
                            for line in accesslistEntries:
                                entries.append(line.replace("access-list "+accesslistName,'').strip())
                            entries.insert(0,"ip access-list extended acl_"+accesslistName)
                            entries.append("exit")
                            print(entries)
                            ssh.conf(entries)
                            acl_changed.append("acl_"+accesslistName)
                        ssh.conf(["interface "+interface[0],"ip access-group acl_"+accesslistName+" in","exit"])
                    else:
                        if accesslistName not in acl_changed:
                            ssh.exec("show access-lists "+accesslistName+" | redirect tftp://"+self.server_ip+"/"+self.host+"_acl_config")
                            acl = open(self.configDirectory+"/"+self.host+"_acl_config").read().strip()
                            entryNumber = re.findall("[0-9]+",acl.split('\n')[1],re.MULTILINE)[0]
                            newEntry = int(entryNumber)-1
                            ssh.conf(["ip access-list extended "+accesslistName,str(newEntry)+" deny eigrp any any","exit"])
                            os.remove(self.configDirectory+"/"+self.host+"_acl_config")
                            acl_changed.append(accesslistName)
            if re.search("ip authentication mode eigrp "+interface[1]+" md5\n",interfaceConfig,re.MULTILINE)==None:
                print("you don't use any authentication method on "+interface[0]+" interface, would you like to enable md5 authentication?")
                auth = input("answer by yes or no ?")
                if auth == 'yes':
                    ssh.conf(["interface "+interface[0],"ip authentication mode eigrp "+interface[1]+" md5","exit"])
            os.remove(self.configDirectory+"/"+self.host+"_eigrp_interface_config")
        os.remove(self.configDirectory+"/"+self.host+"_eigrp_interfaces_config")

    def check(self,accessMethod):
        if isinstance(accessMethod,Telnet):
            self.checkByTelnet(accessMethod)
        elif isinstance(accessMethod,SshVersionII):
            self.checkBySSH(accessMethod)

    def checkPassiveInterface(self,accessMethod,interface_config,running_config):
        if isinstance(accessMethod,Telnet):
            self.checkPassiveInterfaceByTelnet(accessMethod,interface_config,running_config)
        elif isinstance(accessMethod,SshVersionII):
            self.checkPassiveInterfaceBySSH(accessMethod,interface_config,running_config)

    def checkOperatingInterface(self,accessMethod,interface_config):
        if isinstance(accessMethod,Telnet):
            self.checkOperatingInterfaceByTelnet(accessMethod,interface_config)
        elif isinstance(accessMethod,SshVersionII):
            self.checkOperatingInterfaceBySSH(accessMethod,interface_config)

    def getInterfaces(self,eigrp_interfaces,running_config):
        instances = eigrp_interfaces.split("EIGRP-IPv4 Interfaces for AS")
        for instance in instances:
            if instance!='':
                instanceID = instance.split('\n')[0].replace('(','').replace(')','')
                lines = instance.split('\n')
                for line in lines[3:]:
                    if line != '':
                        self.interfaces.append([line.split()[0],instanceID])

    def getPassiveInterfaces(self,protocols):
        instances = protocols.split("Routing Protocol is ")[1:]
        for instance in instances:
            if "eigrp" in instance.split('\n')[0]:
                instanceID = instance.split('\n')[0].replace('"','').replace('eigrp','').strip()
                if "Passive Interface(s):" in instance:
                    for line in instance.split("Passive Interface(s):")[1].split('\n'):
                        if line != '':
                            if "Routing" not in line:
                                self.passiveInterfaces.append([line.strip(),instanceID])
                            else:
                                break
