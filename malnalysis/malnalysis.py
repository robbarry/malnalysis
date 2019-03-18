import os
import re
import json
import socket
import datetime
import argparse
from pymongo import MongoClient
from bson.objectid import ObjectId

FILE_EXTENSIONS = [".doc", ".exe", ".docx", ".xlsx", ".xls", ".pdf", ".dll", ".dmg"]
MONGO_HOST = 'mongodb://10.2.173.9/twitterdb'

class IOC:
    def __init__(self, ioc_str, type = None):        
        self.ioc_str = ioc_str.strip()
        if type is None:
            self.type = self._get_type()
        else:
            self.type = type

    def dict(self):
        return {"ioc": self.ioc_str, "type": self.type}

    def _get_type(self):

        if len(self.ioc_str) == 0:
            return None

        # Is it an IP address?
        try:
            socket.inet_aton(self.ioc_str)
            return "ip"
        except socket.error:
            pass
        
        # If it has a slash in it, let's treat it as a URL
        if "/" in self.ioc_str:
            return "url"

        # An email address?
        if "@" in self.ioc_str:
            return "email"

        # If it ends in common file extensions, we'll call it a file
        for ext in FILE_EXTENSIONS:            
            if self.ioc_str.lower()[-len(ext):] == ext:
                return "filename"

        # Otherwise, if there are periods, call it a domain (ambiguity here)
        if "." in self.ioc_str:
            return "domain"

        if self.ioc_str[0:4].upper() == "CVE-":
            return "cve"

        if self.ioc_str[0:2].upper() == "AS":
            return "as"

        # If it is only the characters 0-9 and a-f, it's a hash
        if re.match(r"[0-9a-f]+\Z", self.ioc_str, re.IGNORECASE):
            return "hash"

        # We don't know what this is
        return "unknown"

def import_iocs(args):
    filename = args.filename
    client = MongoClient(MONGO_HOST)
    db = client.malware
    iocs_db = db.iocs

    if os.path.exists(filename):
        with open(filename, "r") as f:
            for line in f:
                ioc = IOC(line).dict()
                ioc["stamp"] = datetime.datetime.utcnow()
                ioc["source"] = args.source
                ioc["campaign"] = args.campaign
                ioc["analysis"] = {}
                try:
                    iocs_db.insert_one(ioc)         
                except:
                    pass

def main():    
    parser = argparse.ArgumentParser()
    parser.add_argument("--filename", "-f", help="read IOCs from file")
    parser.add_argument("--campaign", "-c", help="campaign tag")
    parser.add_argument("--source", "-s", help="data source")
    args = parser.parse_args()

    if args.filename:
        import_iocs(args)

if __name__ == '__main__':
    main() 