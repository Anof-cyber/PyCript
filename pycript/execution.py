import subprocess
from .gui import logerrors
import tempfile
from os import remove
from .temp_file import parse_temp_file_output

def execute_command(selectedlang, path, data, headervalue=None):

    try:
        temp_file_path = tempfile.NamedTemporaryFile(delete=False).name
        with open(temp_file_path, "wb") as file:
            file.write(bytes(data))  # Write the byte array directly to the file
            file.write(b'\n--BODY_END--\n')  # Write the binary body end marker
            if headervalue is not None:
                file.write(headervalue.encode('utf-8'))
            #temp_file_path = temp_file.name
        
        command = []
        if selectedlang:
            command.append('"' + selectedlang + '"')

        if path.endswith(".jar"):
            command.extend(["-jar"])

        command.extend(['"' + path + '"',"-d", temp_file_path])
        command_str = ' '.join(command)
        logerrors("$ " + command_str)

        process = subprocess.Popen(
            command_str,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        output, error = process.communicate()
        
        if process.returncode != 0:
            logerrors(error.strip())
            remove(temp_file_path)
            return False
        else:
            logerrors(output.strip())
            body, header = parse_temp_file_output(data,headervalue,temp_file_path)
            remove(temp_file_path)
            if body:
                return body, header  
            else:
                return False
    except Exception as e:
        logerrors(str(e))
        remove(temp_file_path)
        return False
