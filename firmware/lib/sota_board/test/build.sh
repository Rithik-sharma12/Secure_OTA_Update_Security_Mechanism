#!/bin/sh
# Build the native agent host used by apps/agent/tests/test_uart_agent_e2e.py.
set -e
cd "$(dirname "$0")"
OUT=${1:-/tmp/sota_agent_host}
CORE=../../sota_core/src
OBJ=$(mktemp -d)
for f in sota_core monocypher monocypher-ed25519; do
  cc -std=c99 -O1 -Wall -c "$CORE/$f.c" -o "$OBJ/$f.o"
done
c++ -std=c++17 -O1 -Wall -Wextra -Imock -I../src -I$CORE -o "$OUT" \
  host_main.cpp ../src/sota_board.cpp ../src/sota_uart_agent.cpp "$OBJ"/*.o -lpthread
rm -rf "$OBJ"
echo "$OUT"
