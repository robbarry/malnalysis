import sys
import json
import time
import config
import datetime
import requests
from pymongo import MongoClient

REQUEST_URL = "https://www.virustotal.com/vtapi/v2/"
MONGO_HOST = config.mongo_host

def main():	
	client = MongoClient(MONGO_HOST)
	db = client.malware
	iocs_db = db.iocs

	for item in iocs_db.find({"$and": [{"type": {"$in": ["hash", "url", "ip", "domain"]}}, {"analysis.virustotal": {"$exists": False}}]}):
		id = item["_id"]
		ioc = item["ioc"]		
		if item["type"] == "hash":			
			url = "{}file/report".format(REQUEST_URL)
			params = {'apikey': config.api_keys["virustotal"], 'resource': ioc}
		elif item["type"] == "url":			
			url = "{}url/report".format(REQUEST_URL)
			params = {'apikey': config.api_keys["virustotal"], 'resource': ioc}
		elif item["type"] == "ip":
			url = "{}ip-address/report".format(REQUEST_URL)
			params = {'apikey': config.api_keys["virustotal"], 'ip': ioc}
		elif item["type"] == "domain":
			url = "{}domain/report".format(REQUEST_URL)
			params = {'apikey': config.api_keys["virustotal"], 'domain': ioc}
		headers = {"Accept-Encoding": "gzip, deflate", "User-Agent" : "gzip, WSJ analysis"}
		response = requests.get(url, params=params, headers=headers)
		iocs_db.update_one({"_id": id}, {"$set": {"analysis.virustotal": {"stamp": datetime.datetime.utcnow(), "data": response.json()}}})
		time.sleep(15)
		

if __name__ == '__main__':
	main()

