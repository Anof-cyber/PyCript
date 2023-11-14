import os
import sys
from .gui import logerrors

def execute_command(selectedlang, path, data, headervalue=None):
    try:
        command = []
        if selectedlang == "JavaScript":
            command.extend(["node", '"' + path + '"'])  # Surround path with double quotes
        elif selectedlang == "Python":
            command.extend(["python", '"' + path + '"'])  # Surround path with double quotes
        elif selectedlang == "Java Jar":
            command.extend(["java", "-jar", '"' + path + '"'])  # Surround path with double quotes

        command.extend(["-d", data])

        if headervalue is not None:
            command.extend(["-h", headervalue])

        command_str = ' '.join(command)
        logerrors("$ " + command_str)
        output = os.popen(command_str).read().rstrip()
        logerrors(output)
    except Exception as e:
        logerrors(e)
        output = data  # Return data if an exception occurs
    return output
