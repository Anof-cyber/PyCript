from base64 import b64decode

def decode_base64(data):
    return b64decode(data.encode('utf-8'))
