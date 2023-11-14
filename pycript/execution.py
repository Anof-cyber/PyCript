import subprocess
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
        else:
            logerrors(output.strip())
        output = output.strip()
    except Exception as e:
        logerrors(str(e))
        output = data  # Return data if an exception occurs
    return output
