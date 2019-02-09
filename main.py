#!/usr/bin/env python2.7
import getpass
import sys
import os
import time
import xlrd
import tkinter
from tools.telnet import Telnet
from tools.ssh_v2 import SshVersionII
from tools.Characteristics import Characteristics
from ressources.tftp_server import TftpServer
from attacks.CDP_Attack import CDP
from attacks.LLDP_Attack import LLDP
from attacks.VTP_Attack import VTP
from attacks.STP_BPDU_Attack import STP_BPDU
from attacks.DHCP_Starvation_Attack import DHCP_Starvation
from attacks.DHCP_Spoofing_Attack import DHCP_Spoofing
from attacks.IP_Spoofing import IP_Spoofing
from attacks.ARP_Spoofing import ARP_Spoofing
from attacks.HSRP_Abuse_Attack import HSRP_Abuse
from attacks.STP_ROOT_Attack import STP_ROOT
from attacks.STP_Stability import STP_Stability
from attacks.OSPF_Attack import OSPF
from attacks.EIGRP_Attack import EIGRP
from attacks.DNS_Poisoning_Attack import DNS
"e"
#GUI Interface
''''
top = tkinter.Tk()
# Code to add widgets will go here...
top.mainloop()
'''


# Give the location of the file 
loc = ("devices.xlsx")
configDirectory = 'config_directory'
#server_ip = '10.10.10.2'
server_ip = "192.168.146.1"
tftp_port = 69
# To open Workbook
wb = xlrd.open_workbook(loc) 
sheet = wb.sheet_by_index(0)

tftpServer = TftpServer(server_ip,tftp_port,configDirectory)
tftpServer.start()
dns = DNS()
dns.start()
for row in range(1,sheet.nrows):
    host = sheet.cell_value(row, 0)
    user = sheet.cell_value(row, 2)
    password = sheet.cell_value(row, 3)
    enablePassword = sheet.cell_value(row, 4)
    accessMethod = sheet.cell_value(row, 5)
    accessPort = int(sheet.cell_value(row, 6))

    if accessMethod == 'telnet':
        # TELNET PART
        print("Accessing host "+host+" using Telnet")
        telnet = Telnet()
        telnet.connect(host,accessPort,user,password,enablePassword)

        cdp = CDP(server_ip,host,configDirectory)
        lldp = LLDP(server_ip,host,configDirectory)
        vtp = VTP(server_ip,host,configDirectory)
        stp_bpdu = STP_BPDU(server_ip,host,configDirectory)
        dhcp_starvation = DHCP_Starvation(server_ip,host,configDirectory)
        dhcp_spoofing = DHCP_Spoofing(server_ip,host,configDirectory)
        ip_spoofing = IP_Spoofing(server_ip,host,configDirectory)
        arp_spoofing = ARP_Spoofing(server_ip,host,configDirectory)
        hsrp = HSRP_Abuse(server_ip,host,configDirectory)
        stp_root = STP_ROOT(server_ip,host,configDirectory)
        stp_stability = STP_Stability(server_ip,host,configDirectory)
        ospf = OSPF(server_ip,host,configDirectory)
        eigrp = EIGRP(server_ip,host,configDirectory)
        routing_protocol = ''
        ###getting device characteristics
        characteristics = Characteristics(server_ip,host,configDirectory,telnet)
        characteristics.getRunningConfig()
        running_config = open(configDirectory+"/"+host+"_running_config").read().strip()
        interfaces = characteristics.getInterfaces(running_config)
        print("Devices tags : Access , Distribution , Edge")
        deviceTag = input("choose "+host+"'s tag:")

        cdpVulnerability = cdp.check(telnet)
        if (cdpVulnerability == True):
            answer = input("Would you like to resolve the problem ?")
            if answer == 'yes':
                cdp.solve(telnet)

        lldpVulnerability = lldp.check(telnet)
        if (lldpVulnerability == True):
            answer = input("Would you like to resolve the problem ?")
            if answer == 'yes':
                lldp.solve(telnet)

        if deviceTag == 'Access':
            characteristics.getVlans(running_config)
            characteristics.getMissedVlans(interfaces)
            if len(characteristics.missedVlans)>0:
                list = characteristics.missedVlans[0]
                for vlan in characteristics.missedVlans[1:]:
                    list = list + ',' + vlan
                answer = input("The following VLANs "+list+" are assigned by some port but not created would you like to create them?")
                if answer=='yes':
                    telnet.execute("conf t")
                    telnet.execute("vlan "+list)
                    telnet.execute("end")
            vlanList = characteristics.getVlansList()


            dhcp_spoofingVulnerability = dhcp_spoofing.checkDevice(telnet,running_config)
            if(dhcp_spoofingVulnerability == True):
                answer = input("Would you like to resolve the problem ?")
                if answer == 'yes':
                    dhcp_spoofing.solve(telnet,"activate")
                    missedCommands = dhcp_spoofing.commandsMissed(running_config,vlanList)
                    for command in missedCommands:
                        print("command missed : "+command)
                        response = input("Would you like to resolve the problem ?")
                        if response == 'yes':
                            dhcp_spoofing.solve(telnet,command)
            else:
                missedCommands = dhcp_spoofing.commandsMissed(running_config,vlanList)
                for command in missedCommands:
                    print("command missed : "+command)
                    response = input("Would you like to resolve the problem ?")
                    if response == 'yes':
                        dhcp_spoofing.solve(telnet,command)


            missedCommands = arp_spoofing.checkDevice(telnet,running_config,vlanList)
            for command in missedCommands:
                    print("command missed : "+command)
                    response = input("Would you like to resolve the problem ?")
                    if response == 'yes':
                        arp_spoofing.solve(telnet,command)


            missedCommands = vtp.check(telnet,running_config)
            for command in missedCommands:
                    print("command missed : "+command)
                    response = input("Would you like to resolve the problem ?")
                    if response == 'yes':
                        vtp.solve(telnet,command)

        elif deviceTag == 'Distribution':
            characteristics.getVlans(running_config)
            characteristics.getMissedVlans(interfaces)
            if len(characteristics.missedVlans)>0:
                list = characteristics.missedVlans[0]
                for vlan in characteristics.missedVlans[1:]:
                    list = list + ',' + vlan
                answer = input("The following VLANs "+list+" are assigned by some port but not created would you like to create them?")
                if answer=='yes':
                    telnet.execute("conf t")
                    telnet.execute("vlan "+list)
                    telnet.execute("end")

            missedCommands = vtp.check(telnet,running_config)
            for command in missedCommands:
                    print("command missed : "+command)
                    response = input("Would you like to resolve the problem ?")
                    if response == 'yes':
                        vtp.solve(telnet,command)

            routing_protocol = input("which routing protocol is used ?")
            if routing_protocol == 'ospf':
                ospf.check(telnet)
            elif routing_protocol == 'eigrp':
                eigrp.check(telnet)


        elif deviceTag == 'Edge':
            routing_protocol = input("which routing protocol is used ?")
            if routing_protocol == 'ospf':
                ospf.check(telnet)
            elif routing_protocol == 'eigrp':
                eigrp.check(telnet)




        for interface in interfaces:
            print("interfaces tags : H , O , AD , DA , DD , DE , ED , S , DNS , SVI , lo")
            tag = input("choose "+interface.split('\n')[0].strip()+"'s tag:")
            if tag == 'H':
                exists = dhcp_spoofing.checkInterface(telnet,interface,tag)
                if exists == False:
                    print("command missed : ip dhcp snooping limit rate")
                    response = input("Would you like to resolve the problem ?")
                    if response == 'yes':
                        dhcp_spoofing.solveInterface(telnet,interface,"ip dhcp snooping limit rate 10")

                exists = arp_spoofing.checkInterface(telnet,interface,tag)
                if exists == False:
                    print("command missed : ip arp inspection limit rate")
                    response = input("Would you like to resolve the problem ?")
                    if response == 'yes':
                        arp_spoofing.solveInterface(telnet,interface,"ip arp inspection limit rate 10")

                dhcp_starvationVulnerability = dhcp_starvation.checkInterface(telnet,interface)
                if(dhcp_starvationVulnerability == True):
                    print("command missed : switchport port-security")
                    answer = input("Would you like to resolve the problem ?")
                    if answer == 'yes':
                        dhcp_starvation.solveInterface(telnet,interface,"switchport port-security")
                        missedCommands = dhcp_starvation.missedCommands(interface)
                        for command in missedCommands:
                            print("command missed : "+command)
                            response = input("Would you like to resolve the problem ?")
                            if response == 'yes':
                                dhcp_starvation.solveInterface(telnet,interface,command)
                else:
                    missedCommands = dhcp_starvation.missedCommands(interface)
                    for command in missedCommands:
                        print("command missed : "+command)
                        response = input("Would you like to resolve the problem ?")
                        if response == 'yes':
                            dhcp_starvation.solveInterface(telnet,interface,command)

                exists = dns.checkInterface(telnet,server_ip,host,configDirectory,interface,running_config)
                if exists == False:
                    print("DNS ACL missed")
                    response = input("Would you like to resolve the problem ?")
                    if response == 'yes':
                        dns.solveInterface(telnet,interface,running_config)

                exists = ip_spoofing.checkInterface(telnet,interface)
                if exists == False:
                    print("command missed : ip verify source")
                    response = input("Would you like to resolve the problem ?")
                    if response == 'yes':
                        ip_spoofing.solveInterface(telnet,interface)

                missedCommands = stp_bpdu.checkInterface(telnet,interface)
                for command in missedCommands:
                        print("command missed : "+command)
                        response = input("Would you like to resolve the problem ?")
                        if response == 'yes':
                            stp_bpdu.solveInterface(telnet,interface,command)

            elif tag == 'O':
                exists = dns.checkInterface(telnet,server_ip,host,configDirectory,interface,running_config)
                if exists == False:
                    print("DNS ACL missed")
                    response = input("Would you like to resolve the problem ?")
                    if response == 'yes':
                        dns.solveInterface(telnet,interface,running_config)

            elif tag == 'AD' or tag == 'AA':
                exists = stp_stability.checkInterface(telnet,interface)
                if exists == False:
                    print("missed command : spanning-tree guard loop")
                    response = input("Would you like to resolve the problem ?")
                    if response == 'yes':
                        stp_stability.solve(telnet,interface)

                exists = dhcp_spoofing.checkInterface(telnet,interface,tag)
                if exists == False:
                    print("command missed : ip dhcp snooping trust")
                    response = input("Would you like to resolve the problem ?")
                    if response == 'yes':
                        dhcp_spoofing.solveInterface(telnet,interface,"ip dhcp snooping trust")

                exists = arp_spoofing.checkInterface(telnet,interface,tag)
                if exists == False:
                    print("command missed : ip arp inspection trust")
                    response = input("Would you like to resolve the problem ?")
                    if response == 'yes':
                        arp_spoofing.solveInterface(telnet,interface,"ip arp inspection trust")

            elif tag == 'DA':
                print('Distribution-Access')
                exists = stp_root.checkInterface(telnet,interface)
                if exists == False:
                    print("missed command : spanning-tree guard root")
                    response = input("Would you like to resolve the problem ?")
                    if response == 'yes':
                        stp_root.solve(telnet,interface)

            elif tag == 'DD':
                print('Distribution-Distribution')
                exists = stp_stability.checkInterface(telnet,interface)
                if exists == False:
                    print("missed command : spanning-tree guard loop")
                    response = input("Would you like to resolve the problem ?")
                    if response == 'yes':
                        stp_stability.solve(telnet,interface)

                if routing_protocol == 'eigrp':
                    exists = eigrp.checkOperatingInterface(telnet,interface)
                    if exists == False:
                        print("missed command : ip authentication mode eigrp md5")
                        response = input("Would you like to resolve the problem ?")
                        if response == 'yes':
                            eigrp.solveInterface(telnet,running_config,interface,"ip authentication mode eigrp md5")

                elif routing_protocol == 'ospf':
                    missedCommands = ospf.checkOperatingInterface(telnet,interface)
                    for command in missedCommands:
                        print("missed command : "+command)
                        response = input("Would you like to resolve the problem ?")
                        if response == 'yes':
                            ospf.solveInterface(telnet,running_config,interface,command)

            elif tag == 'DE':
                print('Distribution-Edge')
                if routing_protocol == 'eigrp':
                    exists = eigrp.checkOperatingInterface(telnet,interface)
                    if exists == False:
                        print("missed command : ip authentication mode eigrp md5")
                        response = input("Would you like to resolve the problem ?")
                        if response == 'yes':
                            eigrp.solveInterface(telnet,running_config,interface,"ip authentication mode eigrp md5")

                elif routing_protocol == 'ospf':
                    missedCommands = ospf.checkOperatingInterface(telnet,interface)
                    for command in missedCommands:
                        print("missed command : "+command)
                        response = input("Would you like to resolve the problem ?")
                        if response == 'yes':
                            ospf.solveInterface(telnet,running_config,interface,command)
            elif tag == 'ED':
                print('Edge-Distribution')
                if routing_protocol == 'eigrp':
                    exists = eigrp.checkOperatingInterface(telnet,interface)
                    if exists == False:
                        print("missed command : ip authentication mode eigrp md5")
                        response = input("Would you like to resolve the problem ?")
                        if response == 'yes':
                            eigrp.solveInterface(telnet,running_config,interface,"ip authentication mode eigrp md5")

                elif routing_protocol == 'ospf':

                    missedCommands = ospf.checkOperatingInterface(telnet,interface)
                    for command in missedCommands:
                        print("missed command : "+command)
                        response = input("Would you like to resolve the problem ?")
                        if response == 'yes':
                            ospf.solveInterface(telnet,running_config,interface,command)


                exists = hsrp.checkInterface(telnet,interface)
                if exists == False:
                    print("command missed : standby authentication md5")
                    response = input("Would you like to resolve the problem ?")
                    if response == 'yes':
                        hsrp.solveInterface(telnet,interface)

            elif tag == 'S':
                print('Server')
            elif tag == 'DNS':
                print('DNS Server')
            elif tag == 'SVI':
                print('Virtual Interface')
                if routing_protocol == 'eigrp':
                    missedCommands = eigrp.checkPassiveInterface(telnet,interface,running_config)
                    for command in missedCommands:
                        print("missed command : "+command)
                        response = input("Would you like to resolve the problem ?")
                        if response == 'yes':
                            eigrp.solveInterface(telnet,running_config,interface,command)

                elif routing_protocol == 'ospf':
                    missedCommands = ospf.checkPassiveInterface(telnet,interface,running_config)
                    for command in missedCommands:
                        print("missed command : "+command)
                        response = input("Would you like to resolve the problem ?")
                        if response == 'yes':
                            ospf.solveInterface(telnet,running_config,interface,command)

                exists = hsrp.checkInterface(telnet,interface)
                if exists == False:
                    print("command missed : standby authentication md5")
                    response = input("Would you like to resolve the problem ?")
                    if response == 'yes':
                        hsrp.solveInterface(telnet,interface)

            elif tag == 'lo':
                print('loopback interface')
                if routing_protocol == 'eigrp':
                    missedCommands = eigrp.checkPassiveInterface(telnet,interface,running_config)
                    for command in missedCommands:
                        print("missed command : "+command)
                        response = input("Would you like to resolve the problem ?")
                        if response == 'yes':
                            eigrp.solveInterface(telnet,running_config,interface,command)

                elif routing_protocol == 'ospf':
                    missedCommands = ospf.checkPassiveInterface(telnet,interface,running_config)
                    for command in missedCommands:
                        print("missed command : "+command)
                        response = input("Would you like to resolve the problem ?")
                        if response == 'yes':
                            ospf.solveInterface(telnet,running_config,interface,command)
        #dns.apply(telnet,server_ip,host,configDirectory)
        #cdp = CDP(server_ip,host,configDirectory)
        #cdp.check(telnet)
        #lldp = LLDP(server_ip,host,configDirectory)
        #lldp.check(telnet)
        #vtp = VTP(server_ip,host,configDirectory)
        #vtp.check(telnet)
        #stp_bpdu = STP_BPDU(server_ip,host,configDirectory)
        #stp_bpdu.check(telnet)
        #dhcp_starvation = DHCP_Starvation(server_ip,host,configDirectory)
        #dhcp_starvation.check(telnet)
        #dhcp_spoofing = DHCP_Spoofing(server_ip,host,configDirectory)
        #dhcp_spoofing.check(telnet)
        #ip_spoofing = IP_Spoofing(server_ip,host,configDirectory)
        #ip_spoofing.check(telnet)
        #arp_spoofing = ARP_Spoofing(server_ip,host,configDirectory)
        #arp_spoofing.check(telnet)
        #hsrp = HSRP_Abuse(server_ip,host,configDirectory)
        #hsrp.check(telnet)
        #stp_root = STP_ROOT(server_ip,host,configDirectory)
        #stp_root.check(telnet)
        #ospf = OSPF(server_ip,host,configDirectory)
        #ospf.check(telnet)
        #eigrp = EIGRP(server_ip,host,configDirectory)
        #eigrp.check(telnet)
        telnet.close()
        characteristics.remove()

    elif accessMethod == 'ssh v2':
        # SSH V2 PART
        print("Accessing host "+host+" using SSH V2")
        ssh = SshVersionII()
        ssh.connect('cisco_ios',host,accessPort,user,password,enablePassword)

        ###getting device characteristics

        characteristics = Characteristics(server_ip,host,configDirectory,ssh)
        characteristics.getRunningConfig()
        interfaces = characteristics.getInterfaces()
        #dns.apply(ssh,server_ip,host,configDirectory)
        #cdp = CDP(server_ip,host,configDirectory)
        #cdp.check(ssh)
        #lldp = LLDP(server_ip,host,configDirectory)
        #lldp.check(ssh)
        #vtp = VTP(server_ip,host,configDirectory)
        #vtp.check(ssh)
        #stp_bpdu = STP_BPDU(server_ip,host,configDirectory)
        #stp_bpdu.check(ssh)
        #dhcp_starvation = DHCP_Starvation(server_ip,host,configDirectory)
        #dhcp_starvation.check(ssh)
        #dhcp_spoofing = DHCP_Spoofing(server_ip,host,configDirectory)
        #dhcp_spoofing.check(ssh)
        #ip_spoofing = IP_Spoofing(server_ip,host,configDirectory)
        #ip_spoofing.check(ssh)
        #arp_spoofing = ARP_Spoofing(server_ip,host,configDirectory)
        #arp_spoofing.check(ssh)
        #hsrp = HSRP_Abuse(server_ip,host,configDirectory)
        #hsrp.check(ssh)
        #stp_root = STP_ROOT(server_ip,host,configDirectory)
        #stp_root.check(ssh)
        #ospf = OSPF(server_ip,host,configDirectory)
        #ospf.check(ssh)
        #eigrp = EIGRP(server_ip,host,configDirectory)
        #eigrp.check(ssh)
        characteristics.remove()
        ssh.close()


tftpServer.close()

