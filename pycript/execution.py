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

        if headervalue is not None:
            command.extend(["-h", headervalue])

        command_str = ' '.join(command)
        logerrors("$ " + command_str)

        process = subprocess.Popen(
            command_str,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        stdin_output = process.stdin.write(data.encode())
        process.stdin.close()
        output, error = process.communicate()

        if process.returncode != 0:
            logerrors(error.strip())
            return False
        else:
            logerrors(output.strip())
            output = output.strip()
            return output.decode('GBK').encode('utf-8') if output else False
    except Exception as e:
        logerrors(str(e))
        return False
