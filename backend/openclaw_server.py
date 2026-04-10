from fastapi import FastAPI
import subprocess
import json

app = FastAPI()

@app.post("/chat")
async def chat(data: dict):
    try:
        messages = data.get("messages", [])
        user_msg = messages[-1]["content"] if messages else ""

        # Call OpenClaw CLI
        result = subprocess.run(
            ["openclaw", "agent", "--agent", "main", "--message", user_msg],
            capture_output=True,
            text=True
        )

        output = result.stdout.strip()

        return {
            "choices": [
                {
                    "message": {
                        "content": output
                    }
                }
            ]
        }

    except Exception as e:
        return {"error": str(e)}
