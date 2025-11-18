import subprocess
from .gui import logerrors
import tempfile
from os import remove
from .temp_file import parse_temp_file_output, create_temp_file

def execute_command(selectedlang, path, data, headervalue=None):

    try:
        temp_file_path = create_temp_file(data,headervalue)
            #temp_file_path = temp_file.name
        command = []
        if selectedlang:
            command.append(selectedlang)  # Add the selected language executable directly

        if path.endswith(".jar"):
            command.extend(["-jar"])

        command.extend([path, "-d", temp_file_path])

        # Log the command for debugging
        command_str = ' '.join('"{0}"'.format(arg) if ' ' in arg else arg for arg in command)
        logerrors("$ " + command_str)

        try:
            output = subprocess.check_output(command, stderr=subprocess.PIPE)
            logerrors(output.strip())
            body, header = parse_temp_file_output(data, headervalue, temp_file_path)
            remove(temp_file_path)
            if body:
                return body, header  
            else:
                return False
        except subprocess.CalledProcessError as e:
            logerrors("Command failed with return code: {}, Error: {}".format(e.returncode, e.output))
            remove(temp_file_path)

        
    except Exception as e:
        logerrors(str(e))
        #remove(temp_file_path)
        return False
