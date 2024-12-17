import os
import tempfile
import random
import string

user_home = os.path.expanduser("~")
pycript_dir = os.path.join(user_home, ".pycript")

def parse_temp_file_output(original_data, original_header, temp_file_path):
    with open(temp_file_path, 'rb') as temp_file:
        file_content = temp_file.read()
    body_end_marker = b'\n--BODY_END--\n'

    # Split the file content using the marker
    parts = file_content.split(body_end_marker, 1)

    # Extract body data
    body_data = parts[0]

    # Extract header data if present, otherwise use the original header
    if len(parts) > 1 and parts[1].strip():  # Check if header exists and is not empty
        header_data = parts[1].strip()
    else:
        header_data = original_header
    return body_data, header_data


def create_temp_file(data, headervalue=None):
    # Get the temp directory path
    random_file_name = ''.join([random.choice(string.ascii_letters + string.digits) for _ in range(12)])
    file_path = os.path.join(pycript_dir, random_file_name)
    
    # Write data to the file
    with open(file_path, "wb") as file:
        file.write(bytes(data))  # Write the byte array directly to the file
        file.write(b'\n--BODY_END--\n')  # Write the binary body end marker
        if headervalue is not None:
            file.write(headervalue.encode('utf-8'))
    
    return file_path


def create_temp_dir():
    
    if not os.path.exists(pycript_dir):
        os.makedirs(pycript_dir)
    temp_dir = tempfile.mkdtemp(dir=pycript_dir)
    