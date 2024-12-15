
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
