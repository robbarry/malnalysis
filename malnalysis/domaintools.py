import sys
import json
import time
import config
import argparse
import datetime
import requests
from pymongo import MongoClient

REQUEST_URL = "https://api.domaintools.com/v1/"
MONGO_HOST = config.mongo_host

def main():	

	parser = argparse.ArgumentParser()
	parser.add_argument("--limit", "-l", help="limit records to lookup", default=10000)
	parser.add_argument("--verbose", "-v", help="verbose output", action="count")
	parser.add_argument("--delay", "-d", help="delay between requests", default=1)
	args = parser.parse_args()

	client = MongoClient(MONGO_HOST)
	db = client.malware
	iocs_db = db.iocs
	items = []

	for item in iocs_db.find({"$and": [{"type": {"$in": ["domain", "email"]}}, {"analysis.domaintools": {"$exists": False}}]}).limit(int(args.limit)):
		items.append(item)

	for i, item in enumerate(items):
		try:
			id = item["_id"]
			ioc = item["ioc"]

			if args.verbose:
				config.log("({} / {}) {} [{}]".format(i + 1, len(items), item["ioc"], item["type"]))		
			
			parameters = []		
			parameters.append("api_username={}".format(config.api_keys["domaintools"]["api_username"]))
			parameters.append("api_key={}".format(config.api_keys["domaintools"]["api_key"]))

			if item["type"] == "domain":
				query = "{}/whois/history/".format(ioc)
			elif item["type"] == "email":
				query = "/reverse-whois/"
				parameters.append("terms={}".format(ioc))
				parameters.append("mode=purchase")
				parameters.append("scope=historic")
			
			full_query = "{}{}?{}".format(REQUEST_URL, query, "&".join(parameters))				
			r = requests.get(full_query, timeout = 5)		
			try:
				data = json.loads(r.content)
			except:
				data = {}
				pass

			if args.verbose > 1:
				print(data)
				
			iocs_db.update_one({"_id": id}, {"$set": {"analysis.domaintools": {"stamp": datetime.datetime.utcnow(), "data": data}}})
			time.sleep(args.delay)
		except:
			pass
		
if __name__ == '__main__':
	main()

