import hashlib
import requests

import cv2

def decode_qr(image_path):
    img = cv2.imread(image_path)

    if img is None:
        return None

    detector = cv2.QRCodeDetector()
    data, bbox, _ = detector.detectAndDecode(img)

    if data:
        return data

    return None


def check_pwned_password(password: str):
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url, timeout=15)
    response.raise_for_status()

    for line in response.text.splitlines():
        hash_suffix, count = line.split(':')
        if hash_suffix == suffix:
            return {
                "pwned": True,
                "count": int(count),
                "sha1_prefix": prefix
            }

    return {
        "pwned": False,
        "count": 0,
        "sha1_prefix": prefix
    }