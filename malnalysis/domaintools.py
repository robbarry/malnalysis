import sys
import json
import time
import config
import datetime
import requests
from pymongo import MongoClient

REQUEST_URL = "https://api.domaintools.com/v1/"
MONGO_HOST = config.mongo_host

def main():	
	client = MongoClient(MONGO_HOST)
	db = client.malware
	iocs_db = db.iocs

	for item in iocs_db.find({"$and": [{"type": {"$in": ["domain", "email"]}}, {"analysis.domaintools": {"$exists": False}}]}):
		try:
			id = item["_id"]
			ioc = item["ioc"]
			
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
			iocs_db.update_one({"_id": id}, {"$set": {"analysis.domaintools": {"stamp": datetime.datetime.utcnow(), "data": data}}})

			time.sleep(5)
		except:
			pass
		
if __name__ == '__main__':
	main()

