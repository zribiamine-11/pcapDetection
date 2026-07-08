from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os
import shutil

from pcap_parser import parse_pcap

app = FastAPI(title="PCAP Anomaly Analyzer")

# allow the frontend (served on a different port) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # for dev only; restrict this in production
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_FOLDER = "../uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.post("/upload")
async def upload_pcap(file: UploadFile = File(...)):
    if not file.filename.endswith((".pcap", ".pcapng",".cap")):
        raise HTTPException(status_code=400, detail="File must be a .pcap or .pcapng")

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)

    # save uploaded file to disk
    with open(filepath, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # parse it
    result = parse_pcap(filepath)

    return result


@app.get("/")
def root():
    return {"message": "PCAP Anomaly Analyzer API is running"}