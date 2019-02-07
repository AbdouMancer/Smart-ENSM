from netmiko import ConnectHandler

class SshVersionII:
    def __init__(self):
        net_connect = None
    def connect(self,device_type,host,port,username,password,secret):
        self.net_connect = ConnectHandler(device_type=device_type, host=host,port=port, username=username, password=password,secret =secret)

    def exec(self,cmd):
        self.net_connect.enable()
        output = self.net_connect.send_command(cmd)
        return output
    def conf(self,cmd):
        self.net_connect.enable()
        output = self.net_connect.send_config_set(cmd)
        return output
    def close(self):
        self.net_connect.disconnect()
