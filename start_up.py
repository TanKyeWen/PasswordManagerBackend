import subprocess

def run_command(command):
    subprocess.run(["bash", "-lc", command], check=True)

def main():
    # Run the command to start the server
    commands = [
        "pip install -r requirements.txt",
        "python ./flask-app/app.py"
    ]

    for command in commands:
        try:
            run_command(command)
        except subprocess.CalledProcessError as e:
            print(f"An error occurred while executing '{command}': {e}")
            return
    
    print("Server started successfully.")

if __name__ == "__main__":
    main()