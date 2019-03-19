import json
import config
import datetime
import requests
from pymongo import MongoClient

FILE_EXTENSIONS = [".doc", ".exe", ".docx", ".xlsx", ".xls", ".pdf", ".dll", ".dmg"]
PDNS_URL = "https://api.dnsdb.info/"
API_KEY = config.api_keys.get("farsight")
MONGO_HOST = config.mongo_host

def main():	
	client = MongoClient(MONGO_HOST)
	db = client.malware
	iocs_db = db.iocs
	updates = {}

	for item in iocs_db.find({"$and": [{"type": {"$in": ["domain", "ip"]}}, {"analysis.farsight": {"$exists": False}}]}):
		id = item["_id"]
		ioc = item["ioc"]
		if item["type"] == "domain":
			query = "lookup/rrset/name/{}?limit=1000".format(ioc)
		else:
			query = "lookup/rdata/ip/{}?limit=1000".format(ioc)	

		full_query = "{}{}".format(PDNS_URL, query)
		headers = {
		    "X-API-Key": API_KEY,
		    "Accept": "application/json"
		}
		r = requests.get(full_query, headers = headers, timeout = 5)
		parts = r.content.split(b'\n')		
		data = []
		for part in parts:
			try:
				data.append(json.loads(part.decode("utf-8")))
			except:
				pass
		iocs_db.update_one({"_id": id}, {"$set": {"analysis.farsight": {"stamp": datetime.datetime.utcnow(), "data": data}}})
		
		
if __name__ == '__main__':
	main()

