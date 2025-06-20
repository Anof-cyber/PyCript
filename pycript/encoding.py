from base64 import b64encode

def encode_base64(data):
    if isinstance(data, unicode):
        data = data.encode('utf-8')
    return b64encode(data).decode('utf-8')
