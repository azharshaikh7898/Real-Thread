from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from pydantic import BaseModel
from pymongo import MongoClient

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# SINGLE global Mongo connection and collection used by both APIs.
client = MongoClient("mongodb://mongo:27017/")
db = client["threat_db"]
collection = db["threats"]


class Threat(BaseModel):
    ip: str
    threat_type: str
    severity: str


@app.post("/threat")
def create_threat(threat: Threat):
    data = threat.dict()
    data["timestamp"] = datetime.utcnow().isoformat()
    collection.insert_one(data)
    return {"message": "Threat stored successfully"}


@app.get("/threats")
def get_threats():
    threats = list(collection.find({}, {"_id": 0}))
    return threats
