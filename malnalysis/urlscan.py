import sys
import json
import config
import argparse
import datetime
import requests
from pymongo import MongoClient

API_KEY = config.api_keys.get("urlscan")
MONGO_HOST = config.mongo_host

def main():	

    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", "-l", help="limit records to lookup", default=1000000)
    parser.add_argument("--verbose", "-v", help="verbose output", action="count")
    args = parser.parse_args()

	client = MongoClient(MONGO_HOST)
	db = client.malware
	iocs_db = db.iocs
    items = []

	for item in iocs_db.find({"analysis.urlscan": {"$exists": False}}).limit(int(args.limit)):		
        if item["type"] != "cve":
            items.append(item)

    for i, item in enumerate(items):
		id = item["_id"]
		url = "https://urlscan.io/api/v1/search/?q={}".format(item["ioc"])
        if args.verbose:
            config.log("({} / {}) {} [{}]".format(i + 1, len(items), item["ioc"], item["type"]))
		iocs_db.update_one({"_id": id}, {"$set": {"analysis.urlscan": {"stamp": datetime.datetime.utcnow(), "data": requests.get(url).json()}}})

if __name__ == '__main__':
	main()
