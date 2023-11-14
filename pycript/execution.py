
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
        output = subprocess.check_output(command, shell=True).rstrip()
    except subprocess.CalledProcessError:
        output = args[0]
    return output

