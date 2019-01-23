from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

class FtpServer:
    def run(self,IP,Port,user,password,directory):
        authorizer = DummyAuthorizer()
        authorizer.add_user(user, password, directory)

        handler = FTPHandler
        handler.authorizer = authorizer

        address = (IP, Port)
        server = FTPServer(address, handler)
        server.serve_forever()
