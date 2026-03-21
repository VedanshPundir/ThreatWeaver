#!/bin/bash
export C2_BASE_URL=http://localhost:8000
export C2_USERNAME=admin
export C2_PASSWORD=YOUR_C2_PASSWORD
export OPENAI_API_KEY="YOUR_OPENAI_API_KEY"
node /home/ocuser/.openclaw/skills/c2-operator/dynamic-attack.js "$@"
