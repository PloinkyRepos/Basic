#!/bin/sh
set -eu

HOST="127.0.0.1:11434"
READY_TIMEOUT_SECONDS="${OLLAMA_BOOTSTRAP_READY_TIMEOUT_SECONDS:-120}"
DESIRED_FILE="$(mktemp)"
INSTALLED_FILE="$(mktemp)"

cleanup() {
    rm -f "$DESIRED_FILE" "$INSTALLED_FILE"
}

trap cleanup EXIT HUP INT TERM

wait_for_ollama() {
    i=0
    while [ "$i" -lt "$READY_TIMEOUT_SECONDS" ]; do
        if OLLAMA_HOST="$HOST" ollama list >/dev/null 2>&1; then
            return 0
        fi
        i=$((i + 1))
        sleep 1
    done
    echo "[bootstrap] Ollama did not become ready within ${READY_TIMEOUT_SECONDS}s."
    return 1
}

refresh_installed_models() {
    OLLAMA_HOST="$HOST" ollama list 2>/dev/null | awk 'NR > 1 {print $1}' > "$INSTALLED_FILE"
}

case "${OLLAMA_BOOTSTRAP_ENABLED:-true}" in
    false|FALSE|0|no|NO)
        echo "[bootstrap] Automatic bootstrap disabled."
        exit 0
        ;;
esac

printf '%s\n' "${OLLAMA_DEFAULT_MODEL:-}" > "$DESIRED_FILE"
printf '%s' "${OLLAMA_BOOTSTRAP_MODELS:-}" | tr ',' '\n' >> "$DESIRED_FILE"

awk 'NF {gsub(/^[ \t]+|[ \t]+$/, ""); if (!seen[$0]++) print $0}' "$DESIRED_FILE" > "${DESIRED_FILE}.normalized"
mv "${DESIRED_FILE}.normalized" "$DESIRED_FILE"

if [ ! -s "$DESIRED_FILE" ]; then
    echo "[bootstrap] No models requested."
    exit 0
fi

wait_for_ollama
refresh_installed_models

failures=0
while IFS= read -r model; do
    [ -n "$model" ] || continue

    if grep -Fxq "$model" "$INSTALLED_FILE"; then
        echo "[bootstrap] Present: $model"
        continue
    fi

    echo "[bootstrap] Pulling missing model: $model"
    if ! OLLAMA_HOST="$HOST" ollama pull "$model"; then
        echo "[bootstrap] ERROR: failed to pull $model"
        failures=$((failures + 1))
        continue
    fi

    refresh_installed_models
    if grep -Fxq "$model" "$INSTALLED_FILE"; then
        echo "[bootstrap] Pulled: $model"
    else
        echo "[bootstrap] ERROR: $model was pulled but is not listed as installed"
        failures=$((failures + 1))
    fi
done < "$DESIRED_FILE"

if [ "$failures" -ne 0 ]; then
    echo "[bootstrap] Reconciliation failed for $failures model(s)."
    exit 1
fi

echo "[bootstrap] Reconciliation complete."
