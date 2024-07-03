import subprocess
from .gui import logerrors
import tempfile
from os import remove
import json

def execute_command(selectedlang, path, data, headervalue=None):
    try:

        content = {
            "data": data
        }
        if headervalue is not None:
            content["header"] = headervalue

        with tempfile.NamedTemporaryFile(delete=False, mode='w') as temp_file:
            json.dump(content, temp_file)
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
        remove(temp_file_path)

        if process.returncode != 0:
            logerrors(error.strip())
            return False
        else:
            logerrors(output.strip())
            output = output.strip()
            return output if output else False
    except Exception as e:
        logerrors(str(e))
        return False
