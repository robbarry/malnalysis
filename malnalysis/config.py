import json

api_keys = {}
settings = {}

try:
	api_keys = json.load(open("../api_keys.json", "r"))
except Exception as e:
	print("Error loading API keys: {}".format(e))

try:
    settings = json.load(open("../config.json", "r"))
except Exception as e:
    print("Error loading settings: {}".format(e))

mongo_host = settings.get("mongo_host", "")
