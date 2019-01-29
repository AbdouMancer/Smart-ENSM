import os
import re
from tools.telnet import Telnet
from tools.ssh_v2 import SshVersionII

class DNS:
    def __init__(self):
        self.acl = []
        self.accesslist=False
        self.acl_changed = []

    def start(self):
        print("Do you have an Internal DNS Server ?")
        answer = input("answer by yes or no ?")
        if answer == 'yes':
            IPAddress = input("give its IP Address :")
            self.acl.append("permit udp any host "+IPAddress+" eq 53")
            self.acl.append("permit tcp any host "+IPAddress+" eq 53")
            self.acl.append("deny udp any any eq 53")
            self.acl.append("deny tcp any any eq 53")
        elif answer == 'no':
            self.acl.append("deny udp any 10.0.0.0 0.255.255.255 eq 53")
            self.acl.append("deny tcp any 10.0.0.0 0.255.255.255 eq 53")
            self.acl.append("deny udp any 172.16.0.0 0.15.255.255 eq 53")
            self.acl.append("deny tcp any 172.16.0.0 0.15.255.255 eq 53")
            self.acl.append("deny udp any 192.168.0.0 0.0.255.255 eq 53")
            self.acl.append("deny tcp any 192.168.0.0 0.0.255.255 eq 53")
            self.acl.append("permit udp any any eq 53")
            self.acl.append("permit tcp any any eq 53")

    def applyByTelnet(self,telnet):
        running_config = open(self.configDirectory+"/"+self.host+"_running_config").read().strip()
        interfaces = self.getInterfaces(running_config)
        accesslist = False
        acl_changed = []
        for interface in interfaces:
            telnet.execute("conf t")
            if re.search("ip access-group ([^in]*)",interface,re.MULTILINE)==None:
                if accesslist==False:
                    telnet.execute("ip access-list extended filter_dns")
                    for entry in self.acl:
                        telnet.execute(entry)
                    telnet.execute("permit ip any any")
                    telnet.execute("exit")
                    accesslist = True
                telnet.execute("interface "+interface.split('\n')[0].strip())
                telnet.execute("ip access-group filter_dns in")
                telnet.execute("exit")
            else:
                accesslistName = re.findall("ip access-group .* in",interface,re.MULTILINE)[0].replace('ip access-group','').replace('in','').strip()
                if re.match("[0-9]+",accesslistName):
                    entries = []
                    index = 10
                    for entry in self.acl:
                        entries.append(str(index)+" "+entry)
                        index = index + 10
                    accesslistEntries = re.findall("access-list "+accesslistName+" .*",running_config,re.MULTILINE)
                    if "acl_"+accesslistName not in acl_changed:
                        if len(accesslistEntries)==0:
                            entries.insert(0,"100 permit ip any any")
                        for line in accesslistEntries:
                            entries.append(str(index)+" "+line.replace("access-list "+accesslistName,'').strip())
                            index = index + 10
                        telnet.execute("ip access-list extended acl_"+accesslistName)
                        for entry in entries:
                            telnet.execute(entry)
                        telnet.execute("exit")
                        acl_changed.append("acl_"+accesslistName)
                    telnet.execute("interface "+interface.split('\n')[0].strip())
                    telnet.execute("ip access-group acl_"+accesslistName+" in")
                    telnet.execute("exit")
                else:
                    if accesslistName not in acl_changed:
                        telnet.execute("do show access-lists "+accesslistName+" | redirect tftp://"+self.server_ip+"/"+self.host+"_acl_config")
                        telnet.readUntil(b"!")
                        telnet.readUntil(b"#")
                        acl = open(self.configDirectory+"/"+self.host+"_acl_config").read().strip()
                        telnet.execute("ip access-list extended "+accesslistName)
                        if acl.strip()!='':
                            entryNumber = re.findall("[0-9]+",acl.split('\n')[1],re.MULTILINE)[0]
                            newEntry = int(entryNumber)-len(self.acl)
                            for entry in self.acl:
                                telnet.execute(str(newEntry)+" "+entry)
                                newEntry = newEntry+1
                        else:
                            telnet.execute("100 permit ip any any")
                            index = 10
                            for entry in self.acl:
                                telnet.execute(str(index)+" "+entry)
                                index = index + 10
                        telnet.execute("exit")
                        os.remove(self.configDirectory+"/"+self.host+"_acl_config")
                        acl_changed.append(accesslistName)

            telnet.execute("end")
    def checkInterfaceByTelnet(self,telnet,interface_config,running_config):
        if re.search("ip access-group ([^in]*)",interface_config,re.MULTILINE)==None:
            print("the interface is vulnerable to DNS Poisoning Attack")
            telnet.execute("conf t")
            if self.accesslist==False:
                telnet.execute("ip access-list extended filter_dns")
                for entry in self.acl:
                    telnet.execute(entry)
                telnet.execute("permit ip any any")
                telnet.execute("exit")
                self.accesslist = True
            telnet.execute("interface "+interface_config.split('\n')[0].strip())
            telnet.execute("ip access-group filter_dns in")
            telnet.execute("end")
        else:
            accesslistName = re.findall("ip access-group .* in",interface_config,re.MULTILINE)[0].replace('ip access-group','').replace('in','').strip()
            telnet.execute("conf t")
            if re.match("[0-9]+",accesslistName):
                entries = []
                index = 10
                for entry in self.acl:
                    entries.append(str(index)+" "+entry)
                    index = index + 10
                accesslistEntries = re.findall("access-list "+accesslistName+" .*",running_config,re.MULTILINE)
                if "acl_"+accesslistName not in self.acl_changed:
                    if len(accesslistEntries)==0:
                        entries.insert(0,"100 permit ip any any")
                    for line in accesslistEntries:
                        entries.append(str(index)+" "+line.replace("access-list "+accesslistName,'').strip())
                        index = index + 10
                    telnet.execute("ip access-list extended acl_"+accesslistName)
                    for entry in entries:
                        telnet.execute(entry)
                    telnet.execute("exit")
                    self.acl_changed.append("acl_"+accesslistName)
                telnet.execute("interface "+interface_config.split('\n')[0].strip())
                telnet.execute("ip access-group acl_"+accesslistName+" in")
                telnet.execute("exit")
            else:
                if accesslistName not in self.acl_changed:
                    telnet.execute("do show access-lists "+accesslistName+" | redirect tftp://"+self.server_ip+"/"+self.host+"_acl_config")
                    telnet.readUntil(b"!")
                    telnet.readUntil(b"#")
                    acl = open(self.configDirectory+"/"+self.host+"_acl_config").read().strip()
                    telnet.execute("ip access-list extended "+accesslistName)
                    if acl.strip()!='':
                        entryNumber = re.findall("[0-9]+",acl.split('\n')[1],re.MULTILINE)[0]
                        newEntry = int(entryNumber)-len(self.acl)
                        for entry in self.acl:
                            telnet.execute(str(newEntry)+" "+entry)
                            newEntry = newEntry+1
                    else:
                        telnet.execute("100 permit ip any any")
                        index = 10
                        for entry in self.acl:
                            telnet.execute(str(index)+" "+entry)
                            index = index + 10
                    telnet.execute("exit")
                    os.remove(self.configDirectory+"/"+self.host+"_acl_config")
                    self.acl_changed.append(accesslistName)



    def applyBySSH(self,ssh):
        running_config = open(self.configDirectory+"/"+self.host+"_running_config").read().strip()
        interfaces = self.getInterfaces(running_config)
        accesslist = False
        acl_changed = []
        for interface in interfaces:
            if re.search("ip access-group ([^in]*)",interface,re.MULTILINE)==None:
                if accesslist==False:
                    aclentries = []
                    aclentries.append("ip access-list extended filter_dns")
                    for entry in self.acl:
                        aclentries.append(entry)
                    aclentries.append("permit ip any any")
                    aclentries.append("exit")
                    ssh.conf(aclentries)
                    accesslist = True
                ssh.conf(["interface "+interface.split('\n')[0].strip(),"ip access-group filter_dns in","exit"])
            else:
                accesslistName = re.findall("ip access-group .* in",interface,re.MULTILINE)[0].replace('ip access-group','').replace('in','').strip()
                if re.match("[0-9]+",accesslistName):
                    entries = []
                    index = 10
                    for entry in self.acl:
                        entries.append(str(index)+" "+entry)
                        index = index+10
                    accesslistEntries = re.findall("access-list "+accesslistName+" .*",running_config,re.MULTILINE)
                    if "acl_"+accesslistName not in acl_changed:
                        if len(accesslistEntries)==0:
                            entries.insert(0,"100 permit ip any any")
                        for line in accesslistEntries:
                            entries.append(str(index)+" "+line.replace("access-list "+accesslistName,'').strip())
                            index = index+10
                        entries.insert(0,"ip access-list extended acl_"+accesslistName)
                        entries.append("exit")
                        ssh.conf(entries)
                        acl_changed.append("acl_"+accesslistName)
                    ssh.conf(["interface "+interface.split('\n')[0].strip(),"ip access-group acl_"+accesslistName+" in","exit"])
                else:
                    if accesslistName not in acl_changed:
                        ssh.exec("show access-lists "+accesslistName+" | redirect tftp://"+self.server_ip+"/"+self.host+"_acl_config")
                        acl = open(self.configDirectory+"/"+self.host+"_acl_config").read().strip()
                        aclentries = []
                        aclentries.append("ip access-list extended "+accesslistName)
                        if acl.strip()!='':
                            entryNumber = re.findall("[0-9]+",acl.split('\n')[1],re.MULTILINE)[0]
                            newEntry = int(entryNumber)-len(self.acl)
                            for entry in self.acl:
                                aclentries.append(str(newEntry)+" "+entry)
                                newEntry = newEntry+1
                        else:
                            aclentries.append("100 permit ip any any")
                            index = 10
                            for entry in self.acl:
                                aclentries.append(str(index)+" "+entry)
                                index = index + 10
                        aclentries.append("exit")
                        ssh.conf(aclentries)
                        os.remove(self.configDirectory+"/"+self.host+"_acl_config")
                        acl_changed.append(accesslistName)


    def apply(self,accessMethod,server_ip,host,configDirectory):
        self.server_ip = server_ip
        self.host = host
        self.configDirectory = configDirectory
        if isinstance(accessMethod,Telnet):
            self.applyByTelnet(accessMethod)
        elif isinstance(accessMethod,SshVersionII):
            self.applyBySSH(accessMethod)

    def checkInterface(self,accessMethod,server_ip,host,configDirectory,interface_config,running_config):
        self.server_ip = server_ip
        self.host = host
        self.configDirectory = configDirectory
        if isinstance(accessMethod,Telnet):
            self.checkInterfaceByTelnet(accessMethod,interface_config,running_config)
        elif isinstance(accessMethod,SshVersionII):
            self.checkInterfaceBySSH(accessMethod,interface_config,running_config)


    def getInterfaces(self,running_config):
        interfaces = re.findall("\ninterface ([^!]*)",running_config,re.MULTILINE)
        return interfaces

