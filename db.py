from pymongo import MongoClient
from os import getenv

host = getenv('MONGO_HOST', 'localhost')
port = getenv('MONGO_PORT', '27017')
dbname = getenv('MONGO_DBNAME', '')
username = getenv('MONGO_USERNAME', 'root')
password = getenv('MONGO_PASSWORD', 'password')
authSource = getenv('MONGO_AUTH_SOURCE', 'admin')

def get_client():
  client = MongoClient(host=host, port=int(port), username=username, password=password, authSource=authSource)
  return client

def get_database():
  client = get_client()
  return client.get_database(dbname)
