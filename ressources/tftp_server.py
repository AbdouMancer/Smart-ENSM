import sys
import tftpy
import threading

#setting up the tftp server
class TftpServer(threading.Thread):
        def __init__(self,IP,Port,directory):
                threading.Thread.__init__(self)
                self.IP = IP
                self.Port = Port
                self.directory = directory
                self.server = ''

        def run(self):
                print("Starting TFTP Server")
                self.server = tftpy.TftpServer(self.directory)
                try:
                        self.server.listen(self.IP, self.Port)
                except tftpy.TftpException as err:
                        sys.stderr.write("%s\n" % str(err))
                        sys.exit(1)
                except KeyboardInterrupt:
                        pass
        def close(self):
                self.server.stop()
                print("TFTP Server Stopped")
