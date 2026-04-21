from pyzbar.pyzbar import decode
from PIL import Image
import hashlib
import requests

def decode_qr(image_path):
    img = Image.open(image_path)
    decoded = decode(img)

    if not decoded:
        return None

    return decoded[0].data.decode('utf-8')

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