import yaml
import os
import sys

# Path to where the repo is cloned
ART_PATH = "/opt/atomic-red-team/atomics"

def get_atomic_command(t_code):

    # Step 1 — Technique folder
    folder_path = os.path.join(ART_PATH, t_code)

    if not os.path.exists(folder_path):
        return None, f"Technique folder not found: {folder_path}"

    # Step 2 — Find YAML file automatically
    yaml_files = [f for f in os.listdir(folder_path) if f.endswith(".yaml")]

    if not yaml_files:
        return None, "No YAML file found inside technique folder"

    yaml_path = os.path.join(folder_path, yaml_files[0])

    try:
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)

        # Step 3 — Extract Linux supported test
        for test in data.get('atomic_tests', []):
            if 'linux' in test.get('supported_platforms', []):
                command = test['executor']['command']
                command = command.replace("#{output_file}", "/tmp/process_list.txt")
                command = command.replace("#{username}", "root")

                name = test['name']
                return command, name

        return None, "No Linux test found for this technique"

    except Exception as e:
        return None, str(e)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 payload_loader.py <T_CODE>")
        sys.exit(1)

    t_code = sys.argv[1]
    cmd, name = get_atomic_command(t_code)

    if cmd:
        print(f"---FOUND: {name}---")
        print(cmd)
    else:
        print(f"ERROR: {name}")
        sys.exit(1)
