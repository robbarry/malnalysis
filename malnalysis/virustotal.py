import sys
import json
import time
import config
import argparse
import datetime
import requests
from pymongo import MongoClient

REQUEST_URL = "https://www.virustotal.com/vtapi/v2/"
MONGO_HOST = config.mongo_host

def main():	

	parser = argparse.ArgumentParser()
	parser.add_argument("--limit", "-l", help="limit records to lookup", default=1000000)
	parser.add_argument("--verbose", "-v", help="verbose output", action="count")
	parser.add_argument("--delay", "-d", help="delay between requests", default=15)
	args = parser.parse_args()

	client = MongoClient(MONGO_HOST)
	db = client.malware
	iocs_db = db.iocs
	items = []

	for item in iocs_db.find({"$and": [{"type": {"$in": ["hash", "url", "ip", "domain", "host"]}}, {"analysis.virustotal": {"$exists": False}}]}).limit(int(args.limit)):
		items.append(item)

	for i, item in enumerate(items):
		id = item["_id"]
		ioc = item["ioc"]		
		if args.verbose:
			config.log("({} / {}) {} [{}]".format(i + 1, len(items), ioc, item["type"]))		
		if item["type"] == "hash":			
			url = "{}file/report".format(REQUEST_URL)
			params = {'apikey': config.api_keys["virustotal"], 'resource': ioc}
		elif item["type"] == "url":			
			url = "{}url/report".format(REQUEST_URL)
			params = {'apikey': config.api_keys["virustotal"], 'resource': ioc}
		elif item["type"] == "ip":
			url = "{}ip-address/report".format(REQUEST_URL)
			params = {'apikey': config.api_keys["virustotal"], 'ip': ioc}
		elif item["type"] in ["domain", "host"]:
			url = "{}domain/report".format(REQUEST_URL)
			params = {'apikey': config.api_keys["virustotal"], 'domain': ioc}
		headers = {"Accept-Encoding": "gzip, deflate", "User-Agent" : "gzip, WSJ analysis"}
		response = requests.get(url, params=params, headers=headers)
		if args.verbose > 1:
			print(response.json())
		iocs_db.update_one({"_id": id}, {"$set": {"analysis.virustotal": {"stamp": datetime.datetime.utcnow(), "data": response.json()}}})
		time.sleep(args.delay)
		

if __name__ == '__main__':
	main()

