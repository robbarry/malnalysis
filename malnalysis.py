import re
import json
import socket
import requests

FILE_EXTENSIONS = [".doc", ".exe", ".docx", ".xlsx", ".xls", ".pdf", ".dll", ".dmg"]
try:
    API_KEYS = json.load(open("api_keys.json", "r"))
except Exception as e:
    print("Encountered error loading API keys: {}".format(e))

class IOC:
    def __init__(self, ioc_str, type = None):
        if type is None:
            self.type = self._get_type(ioc_str)
        else:
            self.type = type

        if self.type == "ip":
            self.obj = ip(ioc_str)

    def _get_type(self, ioc_str):

        # Is it an IP address?
        try:
            socket.inet_aton(ioc_str)
            return "ip"
        except socket.error:
            pass
        
        # If it has a slash in it, let's treat it as a URL
        if "/" in ioc_str:
            return "url"

        # If it ends in common file extensions, we'll call it a file
        for ext in FILE_EXTENSIONS:            
            if ioc_str.lower()[-len(ext):] == ext:
                return "filename"

        # Otherwise, if there are periods, call it a domain (ambiguity here)
        if "." in ioc_str:
            return "domain"

        # If it is only the characters 0-9 and a-f, it's a hash
        if re.match(r"[0-9a-f]+\Z", ioc_str, re.IGNORECASE):
            return "hash"

        # We don't know what this is
        return "unknown"

class base_type:
    pass

class ip(base_type):
    def __init__(self, ip):
        self.ip = ip
        print(self.ip)


class urlscan:
    def __init__(self, api_key):
        self.api_key = api_key

    def search(self, ioc):
        


def main():
    ioc = IOC("192.168.1.1")    

if __name__ == '__main__':
       main() 