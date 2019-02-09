import os
import re
from tools.telnet import Telnet
from tools.ssh_v2 import SshVersionII

class OSPF:
    def __init__(self,server_ip,host,configDirectory):
        self.exist = True
        self.server_ip = server_ip
        self.host = host
        self.configDirectory = configDirectory
        self.passiveInterfaces = []
        self.passiveInterfaces = []
        self.interfaces = []
        self.accesslist = False
        self.acl_changed = []

    def checkByTelnet(self,telnet):
        telnet.execute("show ip ospf interface brief | redirect tftp://"+self.server_ip+"/"+self.host+"_ospf_interfaces_config")
        telnet.readUntil(b"!")
        telnet.readUntil(b"#")
        telnet.execute("show ip protocols | redirect tftp://"+self.server_ip+"/"+self.host+"_protocols_config")
        telnet.readUntil(b"!")
        telnet.readUntil(b"#")
        ospfInterfaces = open(self.configDirectory+"/"+self.host+"_ospf_interfaces_config").read().strip()
        protocols = open(self.configDirectory+"/"+self.host+"_protocols_config").read().strip()
        self.getInterfaces(ospfInterfaces)
        self.getPassiveInterfaces(protocols)
        '''
        interfaces = self.getInterfaces(ospfInterfaces,running_config)
        accesslist = False
        acl_changed = []
        for interface in interfaces:
            telnet.execute("show run interface "+interface[0]+" | redirect tftp://"+self.server_ip+"/"+self.host+"_ospf_interface_config")
            telnet.readUntil(b"!")
            telnet.readUntil(b"#")
            interfaceConfig = open(self.configDirectory+"/"+self.host+"_ospf_interface_config").read().strip()
            print("Do you confirm that "+interface[0]+" interface within the process "+interface[1]+" is not connected to a router, and no OSPF adjacency can be formed from it ?")
            answer = input("answer by yes or no ?")
            telnet.execute("conf t")
            if answer  == 'yes':
                telnet.execute("router ospf "+interface[1])
                telnet.execute("passive-interface "+interface[0])
                telnet.execute("exit")
                if re.search("ip access-group ([^in]*)",interfaceConfig,re.MULTILINE)==None:
                    if accesslist==False:
                        telnet.execute("ip access-list extended deny_ospf")
                        telnet.execute("deny ospf any any")
                        telnet.execute("permit ip any any")
                        telnet.execute("exit")
                        accesslist = True
                    telnet.execute("interface "+interface[0])
                    telnet.execute("ip access-group deny_ospf in")
                    telnet.execute("exit")
                else:
                    accesslistName = re.findall("ip access-group .* in",interfaceConfig,re.MULTILINE)[0].replace('ip access-group','').replace('in','').strip()
                    if re.match("[0-9]+",accesslistName):
                        entries = []
                        entries.append("deny ospf any any")
                        accesslistEntries = re.findall("access-list "+accesslistName+" .*",running_config,re.MULTILINE)
                        if "access-list "+accesslistName+" deny ospf any any" not in accesslistEntries:
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
                            if "deny ospf any any" not in acl:
                                entryNumber = re.findall("[0-9]+",acl.split('\n')[1],re.MULTILINE)[0]
                                newEntry = int(entryNumber)-1
                                telnet.execute("ip access-list extended "+accesslistName)
                                telnet.execute(str(newEntry)+" deny ospf any any")
                                telnet.execute("exit")
                            os.remove(self.configDirectory+"/"+self.host+"_acl_config")
                            acl_changed.append(accesslistName)

            if re.search("ip ospf authentication message-digest\n",interfaceConfig,re.MULTILINE)==None:
                if re.search("ip ospf authentication\n",interfaceConfig,re.MULTILINE):
                    print("you are using plain-text authentication on "+interface[0]+" interface, would you like to enable md5 authentication?")
                    auth = input("answer by yes or no ?")
                    if auth == 'yes':
                        telnet.execute("interface "+interface[0])
                        telnet.execute("no ip ospf authentication")
                        telnet.execute("ip ospf authentication message-digest")
                        telnet.execute("exit")
                    else:
                        print("you don't use any authentication method on "+interface[0]+" interface, would you like to enable md5 authentication?")
                        auth = input("answer by yes or no ?")
                        if auth == 'yes':
                            telnet.execute("interface "+interface[0])
                            telnet.execute("ip ospf authentication message-digest")
                            telnet.execute("exit")
            telnet.execute("end")
            os.remove(self.configDirectory+"/"+self.host+"_ospf_interface_config")
        '''
        os.remove(self.configDirectory+"/"+self.host+"_ospf_interfaces_config")
        os.remove(self.configDirectory+"/"+self.host+"_protocols_config")

    def checkPassiveInterfaceByTelnet(self,telnet,interface_config,running_config):
        interface = interface_config.split('\n')[0].strip()
        missedCommands = []
        found = False
        for entry in self.passiveInterfaces:
            if interface == entry[0]:
                found = True
                break
        if found==False:
            missedCommands.append("passive-interface")
        if re.search("ip access-group ([^in]*)",interface_config,re.MULTILINE)==None:
            missedCommands.append("ip access-group in")
        else:
            accesslistName = re.findall("ip access-group .* in",interface_config,re.MULTILINE)[0].replace('ip access-group','').replace('in','').strip()
            if re.match("[0-9]+",accesslistName):
                accesslistEntries = re.findall("access-list "+accesslistName+" .*",running_config,re.MULTILINE)
                if "access-list "+accesslistName+" deny ospf any any" not in accesslistEntries:
                    if "acl_"+accesslistName not in self.acl_changed:
                        missedCommands.append("deny ospf any any")
            else:
                if accesslistName not in self.acl_changed:
                    telnet.execute("show access-lists "+accesslistName+" | redirect tftp://"+self.server_ip+"/"+self.host+"_acl_config")
                    telnet.readUntil(b"!")
                    telnet.readUntil(b"#")
                    acl = open(self.configDirectory+"/"+self.host+"_acl_config").read().strip()
                    if "deny ospf any any" not in acl:
                        missedCommands.append("deny ospf any any")
                    os.remove(self.configDirectory+"/"+self.host+"_acl_config")
        return missedCommands

    def checkOperatingInterfaceByTelnet(self,telnet,interface_config):
        missedCommands = []
        interface = interface_config.split('\n')[0].strip()
        for entry in self.interfaces:
            begin = re.findall("[a-zA-Z]+",entry[0])[0]
            end = entry[0].replace(begin,'')
            if interface.startswith(begin) and interface.endswith(end):
                if re.search("ip ospf authentication message-digest\n",interface_config,re.MULTILINE)==None:
                    missedCommands.append("ip ospf authentication message-digest")
                if re.search("ip ospf message-digest-key ([0-9]+) md5 ",interface_config,re.MULTILINE)==None:
                    missedCommands.append("ip ospf message-digest-key md5")
                break
        return missedCommands

    def checkPassiveInterface(self,accessMethod,interface_config,running_config):
        if isinstance(accessMethod,Telnet):
            return self.checkPassiveInterfaceByTelnet(accessMethod,interface_config,running_config)
        elif isinstance(accessMethod,SshVersionII):
            return self.checkPassiveInterfaceBySSH(accessMethod,interface_config,running_config)

    def checkOperatingInterface(self,accessMethod,interface_config):
        if isinstance(accessMethod,Telnet):
            return self.checkOperatingInterfaceByTelnet(accessMethod,interface_config)
        elif isinstance(accessMethod,SshVersionII):
            return self.checkOperatingInterfaceBySSH(accessMethod,interface_config)


    def checkBySSH(self,ssh):
        ssh.exec("show ip ospf interface brief | redirect tftp://"+self.server_ip+"/"+self.host+"_ospf_interfaces_config")
        ospfInterfaces = open(self.configDirectory+"/"+self.host+"_ospf_interfaces_config").read().strip()
        running_config = open(self.configDirectory+"/"+self.host+"_running_config").read().strip()
        interfaces = self.getInterfaces(ospfInterfaces,running_config)
        accesslist = False
        acl_changed = []
        for interface in interfaces:
            ssh.exec("show run interface "+interface[0]+" | redirect tftp://"+self.server_ip+"/"+self.host+"_ospf_interface_config")
            interfaceConfig = open(self.configDirectory+"/"+self.host+"_ospf_interface_config").read().strip()
            print("Do you confirm that "+interface[0]+" interface within the process "+interface[1]+" is not connected to a router, and no OSPF adjacency can be formed from it ?")
            answer = input("answer by yes or no ?")
            if answer  == 'yes':
                ssh.conf(["router ospf "+interface[1],"passive-interface "+interface[0],"exit"])
                if re.search("ip access-group ([^in]*)",interfaceConfig,re.MULTILINE)==None:
                    if accesslist==False:
                        ssh.conf(["ip access-list extended deny_ospf","deny ospf any any","permit ip any any","exit"])
                        accesslist = True
                    ssh.conf(["interface "+interface[0],"ip access-group deny_ospf in","exit"])
                else:
                    accesslistName = re.findall("ip access-group .* in",interfaceConfig,re.MULTILINE)[0].replace('ip access-group','').replace('in','').strip()
                    if re.match("[0-9]+",accesslistName):
                        entries = []
                        entries.append("deny ospf any any")
                        accesslistEntries = re.findall("access-list "+accesslistName+" .*",running_config,re.MULTILINE)
                        if "acl_"+accesslistName not in acl_changed:
                            for line in accesslistEntries:
                                entries.append(line.replace("access-list "+accesslistName,'').strip())
                            entries.insert(0,"ip access-list extended acl_"+accesslistName)
                            entries.append("exit")
                            ssh.conf(entries)
                            acl_changed.append("acl_"+accesslistName)
                        ssh.conf(["interface "+interface[0],"ip access-group acl_"+accesslistName+" in","exit"])
                    else:
                        if accesslistName not in acl_changed:
                            ssh.exec("show access-lists "+accesslistName+" | redirect tftp://"+self.server_ip+"/"+self.host+"_acl_config")
                            acl = open(self.configDirectory+"/"+self.host+"_acl_config").read().strip()
                            entryNumber = re.findall("[0-9]+",acl.split('\n')[1],re.MULTILINE)[0]
                            newEntry = int(entryNumber)-1
                            ssh.conf(["ip access-list extended "+accesslistName,str(newEntry)+" deny ospf any any","exit"])
                            os.remove(self.configDirectory+"/"+self.host+"_acl_config")
                            acl_changed.append(accesslistName)

            if re.search("ip ospf authentication message-digest\n",interfaceConfig,re.MULTILINE)==None:
                if re.search("ip ospf authentication\n",interfaceConfig,re.MULTILINE):
                    print("you are using plain-text authentication on "+interface[0]+" interface, would you like to enable md5 authentication?")
                    auth = input("answer by yes or no ?")
                    if auth == 'yes':
                        ssh.conf(["interface "+interface[0],"no ip ospf authentication","ip ospf authentication message-digest","exit"])
                    else:
                        print("you don't use any authentication method on "+interface[0]+" interface, would you like to enable md5 authentication?")
                        auth = input("answer by yes or no ?")
                        if auth == 'yes':
                            ssh.conf(["interface "+interface[0],"ip ospf authentication message-digest","exit"])
            os.remove(self.configDirectory+"/"+self.host+"_ospf_interface_config")
        os.remove(self.configDirectory+"/"+self.host+"_ospf_interfaces_config")

    def check(self,accessMethod):
        if isinstance(accessMethod,Telnet):
            self.checkByTelnet(accessMethod)
        elif isinstance(accessMethod,SshVersionII):
            self.checkBySSH(accessMethod)

    def solveInterfaceByTelnet(self,telnet,running_config,interface,command):
        telnet.execute("conf t")
        if command == 'deny ospf any any':
            accesslistName = re.findall("ip access-group .* in",interface,re.MULTILINE)[0].replace('ip access-group','').replace('in','').strip()
            if re.match("[0-9]+",accesslistName):
                entries = []
                entries.append("deny ospf any any")
                accesslistEntries = re.findall("access-list "+accesslistName+" .*",running_config,re.MULTILINE)
                for line in accesslistEntries:
                    entries.append(line.replace("access-list "+accesslistName,'').strip())
                telnet.execute("ip access-list extended acl_"+accesslistName)
                for entry in entries:
                    telnet.execute(entry)
                telnet.execute("exit")
                self.acl_changed.append("acl_"+accesslistName)
                telnet.execute("interface "+interface.split('\n')[0].strip())
                telnet.execute("ip access-group acl_"+accesslistName+" in")
                telnet.execute("exit")
            else:
                telnet.execute("do show access-lists "+accesslistName+" | redirect tftp://"+self.server_ip+"/"+self.host+"_acl_config")
                telnet.readUntil(b"!")
                telnet.readUntil(b"#")
                acl = open(self.configDirectory+"/"+self.host+"_acl_config").read().strip()
                entryNumber = re.findall("[0-9]+",acl.split('\n')[1],re.MULTILINE)[0]
                newEntry = int(entryNumber)-1
                telnet.execute("ip access-list extended "+accesslistName)
                telnet.execute(str(newEntry)+" deny ospf any any")
                telnet.execute("exit")
                os.remove(self.configDirectory+"/"+self.host+"_acl_config")
                self.acl_changed.append(accesslistName)
        elif command ==  'ip access-group in':
            if self.accesslist==False:
                telnet.execute("ip access-list extended deny_ospf")
                telnet.execute("deny ospf any any")
                telnet.execute("permit ip any any")
                telnet.execute("exit")
                self.accesslist = True
            telnet.execute("interface "+interface.split('\n')[0].strip())
            telnet.execute("ip access-group deny_ospf in")
            telnet.execute("exit")
        elif command == 'passive-interface':
            for entry in self.interfaces:
                begin = re.findall("[a-zA-Z]+",entry[0])[0]
                end = entry[0].replace(begin,'')
                if interface.split('\n')[0].strip().startswith(begin) and interface.split('\n')[0].strip().endswith(end):
                    telnet.execute("router ospf "+entry[1])
                    telnet.execute("passive-interface "+interface.split('\n')[0].strip())
                    telnet.execute("exit")
                    break
        else:
            telnet.execute("interface "+interface.split('\n')[0].strip())
            if command == 'ip ospf authentication message-digest':
                telnet.execute(command)
            elif command == 'ip ospf message-digest-key md5':
                telnet.execute("ip ospf message-digest-key 1 md5 cisco")
        telnet.execute("end")


    def solveInterfaceBySSH(self,ssh,running_config,interface,command):
        print()

    def solveInterface(self,accessMethod,running_config,interface,command):
        if isinstance(accessMethod,Telnet):
            self.solveInterfaceByTelnet(accessMethod,running_config,interface,command)
        elif isinstance(accessMethod,SshVersionII):
            self.solveInterfaceBySSH(accessMethod,running_config,interface,command)

    def getInterfaces(self,ospf_interfaces):
        for line in ospf_interfaces.split('\n')[1:]:
            parts = line.split()
            self.interfaces.append([parts[0],parts[1]])

    def getPassiveInterfaces(self,protocols):
        instances = protocols.split("Routing Protocol is ")[1:]
        for instance in instances:
            if "ospf" in instance.split('\n')[0]:
                instanceID = instance.split('\n')[0].replace('"','').replace('ospf','').strip()
                if "Passive Interface(s):" in instance:
                    for line in instance.split("Passive Interface(s):")[1].split('\n'):
                        if line != '':
                            if "Routing" not in line:
                                self.passiveInterfaces.append([line.strip(),instanceID])
                            else:
                                break

