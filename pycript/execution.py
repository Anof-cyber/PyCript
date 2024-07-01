import subprocess
from .gui import logerrors
import os 
def execute_command(selectedlang, path, data, headervalue=None):
    try:
        command = []
        if selectedlang:
            command.append('"' + selectedlang + '"')

        command.extend(['"' + path + '"',"-d", data])

        if headervalue is not None:
            command.extend(["-h", headervalue])

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
            return False
        else:
            logerrors(output.strip())
            output = output.strip()
            return output if output else False
    except Exception as e:
        logerrors(str(e))
        return False
