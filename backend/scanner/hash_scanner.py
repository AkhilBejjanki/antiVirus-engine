import hashlib
import os


# COMPUTE HASHES

def compute_hashes(file_bytes: bytes) -> dict:
    """
    It takes bytes as input and returns a hex string (the hash).

    Example:
        hashlib.md5(b"hello").hexdigest() → "5d41402abc4b2a76b9719d911017c592"
    """

    md5    = hashlib.md5(file_bytes).hexdigest()
    sha1   = hashlib.sha1(file_bytes).hexdigest()
    sha256 = hashlib.sha256(file_bytes).hexdigest()

    return {
        "md5":    md5,
        "sha1":   sha1,
        "sha256": sha256,
    }



# LOAD SIGNATURE DATABASE

def load_signatures(signatures_path: str) -> list[dict]:

    signatures = []

    # If the file doesn't exist, return empty list (no signatures loaded)
    if not os.path.exists(signatures_path):
        return signatures

    with open(signatures_path, "r") as f:
        for line in f:
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # Splitting the line by "|"
            parts = line.split("|")

            # We need exactly 3 parts: type, hash, name
            if len(parts) != 3:
                continue

            hash_type  = parts[0].strip().upper()   # Ex : "SHA256"
            hash_value = parts[1].strip().lower()    # lowercase the hash for comparison
            threat_name = parts[2].strip()           # Ex : "WannaCry Ransomware"

            signatures.append({
                "type":  hash_type,
                "hash":  hash_value,
                "name":  threat_name,
            })

    return signatures



# COMPARE HASHES

def check_against_signatures(file_hashes: dict, signatures: list[dict]) -> dict:
    
    for sig in signatures:
        hash_type  = sig["type"]   # "SHA256"
        hash_value = sig["hash"]   # "abc123..."
        threat_name = sig["name"]  # "WannaCry Ransomware"

        # Get the corresponding hash from the file
        # hash_type is "SHA256", we need file_hashes["sha256"]
        # So we lowercase the type to match our dict keys
        file_hash = file_hashes.get(hash_type.lower())

        # Compare — both are lowercased so case doesn't matter
        if file_hash and file_hash == hash_value:
            return {
                "matched": True,
                "matched_type": hash_type,
                "matched_hash": hash_value,
                "threat_name":  threat_name,
            }

    # No match found
    return {"matched": False}



# MAIN SCAN FUNCTION

def scan_file(file_bytes: bytes, signatures_path: str) -> dict:
    
    # compute hashes
    file_hashes = compute_hashes(file_bytes)

    # load signatures
    signatures = load_signatures(signatures_path)

    # compare
    match_result = check_against_signatures(file_hashes, signatures)

    # final result
    if match_result["matched"]:
        return {
            "verdict":      "MALICIOUS",
            "md5":          file_hashes["md5"],
            "sha1":         file_hashes["sha1"],
            "sha256":       file_hashes["sha256"],
            "matched_type": match_result["matched_type"],
            "matched_hash": match_result["matched_hash"],
            "threat_name":  match_result["threat_name"],
        }
    else:
        return {
            "verdict":      "CLEAN",
            "md5":          file_hashes["md5"],
            "sha1":         file_hashes["sha1"],
            "sha256":       file_hashes["sha256"],
            "matched_type": None,
            "matched_hash": None,
            "threat_name":  None,
        }