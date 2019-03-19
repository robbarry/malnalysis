import json
import config
import argparse
from bson import json_util
from pymongo import MongoClient
from bson.objectid import ObjectId

MONGO_HOST = config.mongo_host

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--keyword", "-k", help="search keyword")    
	parser.add_argument("--buffer", "-b", help="buffer in search results", default = 40)    
	parser.add_argument("--all", "-a", help="show all results", action="store_true")
	args = parser.parse_args()

	client = MongoClient(MONGO_HOST)
	db = client.malware
	iocs_db = db.iocs
	matches = 0
	records = 0
	keyword = args.keyword.lower()
	buff = int(args.buffer)

	for item in iocs_db.find():
		id = item["_id"]
		del item["_id"]
		records += 1		
		text = json.dumps(item, default=json_util.default).lower()
		if keyword in text:			
			matches += 1
			print("Match {}: {} - ObjectId('{}')".format(matches, item["ioc"], id))
			while text.find(keyword) >= 0:
				pos = text.find(keyword)
				print("... {} ...".format(text[(pos - buff):(pos + buff + len(keyword))]))
				text = text[(pos + 1):]
				if not args.all:
					break

			



if __name__ == '__main__':
	main()

