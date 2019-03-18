import csv
import json
import config
import pprint
import argparse
from pymongo import MongoClient

MONGO_HOST = config.mongo_host

def main():    
	with open("/media/data1/data/network.csv", "w") as f:
		f.write("source\ttarget\n")
		client = MongoClient(MONGO_HOST)
		db = client.malware
		iocs_db = db.iocs

		parser = argparse.ArgumentParser()
		parser.add_argument("--campaign", "-c", help="campaign tag")    
		args = parser.parse_args()

		writer = Writer(f)

		if args.campaign:
			for row in iocs_db.find({"campaign": args.campaign}):
				writer.virustotal(row.get("ioc"), row.get("type"), row.get("analysis", {}).get("virustotal", {}))				
				writer.farsight(row.get("ioc"), row.get("type"), row.get("analysis", {}).get("farsight", {}))
				writer.domaintools(row.get("ioc"), row.get("type"), row.get("analysis", {}).get("domaintools", {}))
				writer.urlscan(row.get("ioc"), row.get("type"), row.get("analysis", {}).get("urlscan", {}))
			writer.write_queue()

class Writer:

	def __init__(self, f):
		self.f = f
		self.queue = []

	def urlscan(self, ioc, type, raw_data):
		data = raw_data.get("data", {}).get("results", [])
		for row in data:
			self.queue.append([ioc, row.get("task", {}).get("url", "")])
			self.queue.append([ioc, row.get("page", {}).get("domain", "")])
			self.queue.append([ioc, row.get("page", {}).get("asn", "")])

	def domaintools(self, ioc, type, raw_data):
		data = raw_data.get("data", {}).get("response", {})
		if type == "email":
			for row in data.get("domains", []):
				self.queue.append([ioc, row])
		elif type == "domain":
			for row in data.get("history", []):				
				if row.get("is_private", 1) == 0:					
					registrant = row.get("whois", {}).get("registrant", "")
					self.queue.append([ioc, registrant])

	def farsight(self, ioc, type, raw_data):
		data = raw_data.get("data", [])
		for row in data:
			if type == "ip" and row["rrtype"] == "A":				
				self.queue.append([row["rrname"], row["rdata"]])
			if type == "domain":
				if row["rrtype"] in ["NS", "A"]:					
					for rdata in row.get("rdata", []):						
						self.queue.append([row["rrname"], rdata])

	def virustotal(self, ioc, type, raw_data):
		data = raw_data.get("data", {})		
		if type == "hash":
			self.queue.append([ioc, data.get("sha1", "")])
			self.queue.append([ioc, data.get("sha256", "")])
			self.queue.append([ioc, data.get("md5", "")])
		elif type == "domain":		
			for detected_url in data.get("detected_urls", []):
				self.queue.append([ioc, detected_url.get("url", "")])			
			for resolutions in data.get("resolutions", []):
				self.queue.append([ioc, resolutions.get("ip_address", "")])
			for subdomain in data.get("subdomains", []):
				self.queue.append([ioc, subdomain])			
		elif type == "ip":
			self.queue.append([ioc, "AS{}".format(data.get("asn", ""))])		
			for resolutions in data.get("resolutions", []):
				self.queue.append([ioc, resolutions.get("hostname", "")])			
			for detected_url in data.get("detected_urls", []):		
				self.queue.append([ioc, detected_url.get("url", "")])


	def write_queue(self):
		output = set()
		if len(self.queue) > 0:
			for row in self.queue:
				if str(row[0]).lower() != str(row[1]).lower():
					if len(str(row[1])) > 0:
						row[0] = str(row[0]).lower()
						row[1] = str(row[1]).lower()
						if row[0][-1] == ".":
							row[0] = row[0][0:-1]
						if row[1][-1] == ".":
							row[1] = row[1][0:-1]	
						if row[1] != "as":					
							output.add("{}\t{}".format(row[0], row[1]))
		self.f.write("\n".join(output))


# def fs_write(f, ioc, type, farsight):
# 	data = farsight.get("data", [])
# 	for row in data:
# 		if rrtype




if __name__ == '__main__':
    main() 