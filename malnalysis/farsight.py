import json
import config
import argparse
import datetime
import requests
from pymongo import MongoClient

FILE_EXTENSIONS = [".doc", ".exe", ".docx", ".xlsx", ".xls", ".pdf", ".dll", ".dmg"]
PDNS_URL = "https://api.dnsdb.info/"
API_KEY = config.api_keys.get("farsight")
MONGO_HOST = config.mongo_host

def main():	

	parser = argparse.ArgumentParser()
	parser.add_argument("--limit", "-l", help="limit records to lookup", default=1000)
	parser.add_argument("--verbose", "-v", help="verbose output", action="store_true")
	args = parser.parse_args()

	client = MongoClient(MONGO_HOST)
	db = client.malware
	iocs_db = db.iocs
	items = []

	for item in iocs_db.find({"$and": [{"type": {"$in": ["domain", "ip", "host"]}}, {"analysis.farsight": {"$exists": False}}]}).limit(int(args.limit)):
		items.append(item)

	for i, item in enumerate(items):
		id = item["_id"]
		ioc = item["ioc"]
		if args.verbose:
			config.log("({} / {}) {} [{}]".format(i + 1, len(items), ioc, item["type"]))
		if item["type"] in ["host", "domain"]:
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

