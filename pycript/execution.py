import subprocess
from .gui import logerrors
import os
def get_login_shell_env():
    # Determine the user's login shell
    shell = os.environ.get('SHELL', '/bin/sh')

    # Run the login shell and echo the environment
    cmd = [shell, '-l', '-c', 'env']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)

    # Parse the output into a dictionary
    env = {}
    for line in proc.stdout:
        line = line.decode('utf-8').strip()
        if '=' in line:
            key, value = line.split('=', 1)
            env[key] = value

    proc.wait()
    return env

login_env = get_login_shell_env()

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
            env=login_env,
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
