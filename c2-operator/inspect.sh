#!/bin/bash
SKILL_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SKILL_DIR/dynamic.sh" profile
