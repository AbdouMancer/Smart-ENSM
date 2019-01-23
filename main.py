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

        ###getting device characteristics

        characteristics = Characteristics(server_ip,host,configDirectory,telnet)
        characteristics.getRunningConfig()
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
        hsrp = HSRP_Abuse(server_ip,host,configDirectory)
        hsrp.check(telnet)
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
        characteristics.remove()
        ssh.close()


tftpServer.close()

