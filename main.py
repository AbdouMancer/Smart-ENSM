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
server_ip = '192.168.146.1'
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
        ospf = OSPF(server_ip,host,configDirectory)
        eigrp = EIGRP(server_ip,host,configDirectory)
        routing_protocol = ''
        ###getting device characteristics
        characteristics = Characteristics(server_ip,host,configDirectory,telnet)
        characteristics.getRunningConfig()
        running_config = open(configDirectory+"/"+host+"_running_config").read().strip()
        print("Devices tags : Access , Distribution , Edge")
        deviceTag = input("choose "+host+"'s tag:")
        cdp.check(telnet)
        #lldp.check(telnet)
        if deviceTag == 'Access':
            dhcp_spoofing.checkDevice(telnet)
            arp_spoofing.checkDevice(telnet)
            vtp.check(telnet)
        elif deviceTag == 'Distribution':
            routing_protocol = input("which routing protocol is used ?")
            if routing_protocol == 'ospf':
                ospf.check(telnet)
            elif routing_protocol == 'eigrp':
                eigrp.check(telnet)
            vtp.check(telnet)
        elif deviceTag == 'Edge':
            routing_protocol = input("which routing protocol is used ?")
            if routing_protocol == 'ospf':
                ospf.check(telnet)
            elif routing_protocol == 'eigrp':
                eigrp.check(telnet)
        interfaces = characteristics.getInterfaces(running_config)
        for interface in interfaces:
            print("interfaces tags : H , O , AD , DA , DD , DE , ED , S , DNS , SVI , lo")
            tag = input("choose "+interface.split('\n')[0].strip()+"'s tag:")
            if tag == 'H':
                print('host')
                dhcp_spoofing.checkInterface(telnet,interface,tag)
                arp_spoofing.checkInterface(telnet,interface,tag)
                dhcp_starvation.checkInterface(telnet,interface)
                dns.checkInterface(telnet,server_ip,host,configDirectory,interface,running_config)
                ip_spoofing.checkInterface(telnet,interface)
                stp_bpdu.checkInterface(telnet,interface)
            elif tag == 'O':
                print('Outside')
                dns.checkInterface(telnet,server_ip,host,configDirectory,interface,running_config)
            elif tag == 'AD':
                print('Access-Distribution')
                dhcp_spoofing.checkInterface(telnet,interface,tag)
                arp_spoofing.checkInterface(telnet,interface,tag)
            elif tag == 'DA':
                print('Distribution-Access')
                stp_root.checkInterface(telnet,interface)
            elif tag == 'DD':
                print('Distribution-Distribution')
                if routing_protocol == 'eigrp':
                    eigrp.checkOperatingInterface(telnet,interface)
                elif routing_protocol == 'ospf':
                    ospf.checkOperatingInterface(telnet,interface)
            elif tag == 'DE':
                print('Distribution-Edge')
                if routing_protocol == 'eigrp':
                    eigrp.checkOperatingInterface(telnet,interface)
                elif routing_protocol == 'ospf':
                    ospf.checkOperatingInterface(telnet,interface)
            elif tag == 'ED':
                print('Edge-Distribution')
                if routing_protocol == 'eigrp':
                    eigrp.checkOperatingInterface(telnet,interface)
                elif routing_protocol == 'ospf':
                    ospf.checkOperatingInterface(telnet,interface)
                hsrp.checkInterface(telnet,interface)
            elif tag == 'S':
                print('Server')
            elif tag == 'DNS':
                print('DNS Server')
            elif tag == 'SVI':
                print('Virtual Interface')
                if routing_protocol == 'eigrp':
                    eigrp.checkPassiveInterfaceByTelnet(telnet,interface,running_config)
                elif routing_protocol == 'ospf':
                    ospf.checkPassiveInterfaceByTelnet(telnet,interface,running_config)
                hsrp.checkInterface(telnet,interface)
            elif tag == 'lo':
                print('loopback interface')
                if routing_protocol == 'eigrp':
                    eigrp.checkPassiveInterfaceByTelnet(telnet,interface,running_config)
                elif routing_protocol == 'ospf':
                    ospf.checkPassiveInterfaceByTelnet(telnet,interface,running_config)
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

