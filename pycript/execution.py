'''
import subprocess

def execute_command(selectedlang, path, *args):
    try:
        command = []
        if selectedlang == "JavaScript":
            command.extend(["node", path])
        elif selectedlang == "Python":
            command.extend(["python", path])
        elif selectedlang == "Java Jar":
            command.extend(["java", "-jar", path])
        command.extend(args)
        print(command)
        output = subprocess.check_output(command, shell=True).rstrip()
    except subprocess.CalledProcessError as e:
        print(e)
        output = args[0]
    return output

'''
import os

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
        print(command_str)
        output = os.popen(command_str).read().rstrip()
        print(output)
    except Exception as e:
        print(e)
        output = data  # Return data if an exception occurs
    return output
