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
            body = "g"
            header = 'h'
            if body:
                return body, header  
            else:
                return False
    except Exception as e:
        logerrors(str(e))
        #remove(temp_file_path)
        return False
