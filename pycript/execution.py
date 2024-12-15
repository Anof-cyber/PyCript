import subprocess
from .gui import logerrors
import tempfile
from os import remove
import json
from .temp_file import parse_temp_file_output

def execute_command(selectedlang, path, data, headervalue=None):
    try:
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_file:
            temp_file.write(data)
            temp_file.write(b'\n--BODY_END--\n')
            if headervalue is not None:
                temp_file.write(headervalue)
            temp_file_path = temp_file.name
            

        
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
        #remove(temp_file_path)

        if process.returncode != 0:
            logerrors(error.strip())
            return False
        else:
            logerrors(output.strip())
            body, header = parse_temp_file_output(data,headervalue,temp_file_path)
            if body:
                return body, header  
            else:
                return False
    except Exception as e:
        logerrors(str(e))
        return False
