import os
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from scanner.hash_scanner import scan_file



app = FastAPI(
    title="PyGuard AV Engine",
    description="Hash-based malware detection engine",
    version="1.0.0"
)


# CORS MIDDLEWARE

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # Allow all origins (for development)
    allow_methods=["*"],      # Allow all HTTP methods (GET, POST, etc.)
    allow_headers=["*"],      # Allow all headers
)


# PATHS

BASE_DIR        = os.path.dirname(__file__)
SIGNATURES_PATH = os.path.join(BASE_DIR, "signatures", "hashes.txt")



# ROUTES

@app.get("/health")
def health_check():
    """
    Simple health check endpoint.
    Visit http://localhost:8000/health to confirm backend is running.
    Returns: { "status": "ok" }
    """
    return {"status": "ok", "message": "antiVirus Engine is running"}


@app.post("/scan")
async def scan_endpoint(file: UploadFile = File(...)):

    file_bytes = await file.read()
    
    # if file contians no data in it
    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    result = scan_file(file_bytes, SIGNATURES_PATH)

    result["filename"] = file.filename

    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)