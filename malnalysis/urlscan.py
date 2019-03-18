import sys
import json
import config
import datetime
import requests
from pymongo import MongoClient

API_KEY = config.api_keys.get("urlscan")
MONGO_HOST = config.mongo_host

def main():	
	client = MongoClient(MONGO_HOST)
	db = client.malware
	iocs_db = db.iocs
	for item in iocs_db.find({"analysis.urlscan": {"$exists": False}}):		
		id = item["_id"]
		url = "https://urlscan.io/api/v1/search/?q={}".format(item["ioc"])
		iocs_db.update_one({"_id": id}, {"$set": {"analysis.urlscan": {"stamp": datetime.datetime.utcnow(), "data": requests.get(url).json()}}})

if __name__ == '__main__':
	main()
