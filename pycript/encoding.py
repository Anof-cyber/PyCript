from base64 import b64encode

def encode_base64(data):
    return b64encode(data).decode('utf-8')
