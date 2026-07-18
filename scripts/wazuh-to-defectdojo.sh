#!/usr/bin/env bash
set -Eeuo pipefail

ENV_FILE="${ENV_FILE:-/etc/wazuh-defectdojo.env}"

log() {
    printf '%s\n' "$*"
}

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

[[ -r "$ENV_FILE" ]] || fail "No puedo leer $ENV_FILE"

# shellcheck disable=SC1090
source "$ENV_FILE"

: "${WAZUH_INDEXER_URL:=https://localhost:9200}"
: "${WAZUH_NETRC:=/root/.netrc}"
: "${DEFECTDOJO_URL:?Falta DEFECTDOJO_URL}"
: "${DEFECTDOJO_API_KEY:?Falta DEFECTDOJO_API_KEY}"
: "${DEFECTDOJO_PRODUCT_TYPE_NAME:?Falta DEFECTDOJO_PRODUCT_TYPE_NAME}"
: "${DEFECTDOJO_PRODUCT_NAME:?Falta DEFECTDOJO_PRODUCT_NAME}"
: "${DEFECTDOJO_ENGAGEMENT_NAME:?Falta DEFECTDOJO_ENGAGEMENT_NAME}"
: "${MINIMUM_SEVERITY:=Info}"
: "${TEST_TITLE:=Wazuh Vulnerabilities}"
: "${AGENT_ID:=}"
: "${WAZUH_INDEX_PATTERN:=wazuh-states-vulnerabilities*}"
: "${PAGE_SIZE:=1000}"

for required_command in curl jq mktemp; do
    command -v "$required_command" >/dev/null 2>&1 \
        || fail "Falta el comando: $required_command"
done

[[ -r "$WAZUH_NETRC" ]] || fail "No puedo leer $WAZUH_NETRC"

WORKDIR="$(mktemp -d /tmp/wazuh-defectdojo.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

BATCH_FILE="$WORKDIR/batch.json"
REPORT_FILE="$WORKDIR/wazuh-vulnerabilities.json"
NEXT_REPORT="$WORKDIR/report-next.json"
DD_RESPONSE="$WORKDIR/defectdojo-response.json"

if [[ -n "$AGENT_ID" ]]; then
    QUERY="$(
        jq -cn \
            --arg agent_id "$AGENT_ID" \
            '{term:{"agent.id":$agent_id}}'
    )"
    CURRENT_TEST_TITLE="${TEST_TITLE} - agent ${AGENT_ID}"
else
    QUERY='{"match_all":{}}'
    CURRENT_TEST_TITLE="$TEST_TITLE"
fi

PAYLOAD="$(
    jq -cn \
        --argjson query "$QUERY" \
        --argjson page_size "$PAGE_SIZE" \
        '{
            size: $page_size,
            sort: ["_doc"],
            _source: ["agent", "package", "vulnerability"],
            query: $query
        }'
)"

log "[1/3] Leyendo vulnerabilidades de Wazuh..."

curl -fsSk \
    --netrc-file "$WAZUH_NETRC" \
    -H 'Content-Type: application/json' \
    -X POST \
    "${WAZUH_INDEXER_URL%/}/${WAZUH_INDEX_PATTERN}/_search?scroll=2m" \
    -d "$PAYLOAD" > "$BATCH_FILE"

if jq -e '.error' "$BATCH_FILE" >/dev/null 2>&1; then
    jq '.error' "$BATCH_FILE" >&2
    fail "Wazuh devolvió un error"
fi

jq '{hits:{hits:(.hits.hits // [])}}' "$BATCH_FILE" > "$REPORT_FILE"
SCROLL_ID="$(jq -r '._scroll_id // empty' "$BATCH_FILE")"

while [[ -n "$SCROLL_ID" ]]; do
    SCROLL_PAYLOAD="$(
        jq -cn \
            --arg scroll_id "$SCROLL_ID" \
            '{scroll:"2m",scroll_id:$scroll_id}'
    )"

    curl -fsSk \
        --netrc-file "$WAZUH_NETRC" \
        -H 'Content-Type: application/json' \
        -X POST \
        "${WAZUH_INDEXER_URL%/}/_search/scroll" \
        -d "$SCROLL_PAYLOAD" > "$BATCH_FILE"

    if jq -e '.error' "$BATCH_FILE" >/dev/null 2>&1; then
        jq '.error' "$BATCH_FILE" >&2
        fail "Wazuh devolvió un error durante la paginación"
    fi

    BATCH_COUNT="$(jq '.hits.hits | length' "$BATCH_FILE")"
    [[ "$BATCH_COUNT" -eq 0 ]] && break

    jq -s \
        '{hits:{hits:(.[0].hits.hits + .[1].hits.hits)}}' \
        "$REPORT_FILE" "$BATCH_FILE" > "$NEXT_REPORT"

    mv "$NEXT_REPORT" "$REPORT_FILE"
    SCROLL_ID="$(jq -r '._scroll_id // empty' "$BATCH_FILE")"
done

if [[ -n "$SCROLL_ID" ]]; then
    curl -sSk \
        --netrc-file "$WAZUH_NETRC" \
        -H 'Content-Type: application/json' \
        -X DELETE \
        "${WAZUH_INDEXER_URL%/}/_search/scroll" \
        -d "$(jq -cn --arg scroll_id "$SCROLL_ID" '{scroll_id:[$scroll_id]}')" \
        >/dev/null || true
fi

FINDING_COUNT="$(jq '.hits.hits | length' "$REPORT_FILE")"
log "[2/3] Vulnerabilidades exportadas: $FINDING_COUNT"
log "[3/3] Enviando reporte a DefectDojo..."

HTTP_CODE="$(
    curl -sS \
        -o "$DD_RESPONSE" \
        -w '%{http_code}' \
        -X POST \
        "${DEFECTDOJO_URL%/}/api/v2/reimport-scan/" \
        -H "Authorization: Token ${DEFECTDOJO_API_KEY}" \
        -F 'scan_type=Wazuh' \
        -F "product_type_name=${DEFECTDOJO_PRODUCT_TYPE_NAME}" \
        -F "product_name=${DEFECTDOJO_PRODUCT_NAME}" \
        -F "engagement_name=${DEFECTDOJO_ENGAGEMENT_NAME}" \
        -F 'auto_create_context=true' \
        -F "test_title=${CURRENT_TEST_TITLE}" \
        -F "minimum_severity=${MINIMUM_SEVERITY}" \
        -F 'active=true' \
        -F 'verified=false' \
        -F 'close_old_findings=true' \
        -F 'do_not_reactivate=false' \
        -F "file=@${REPORT_FILE};type=application/json"
)"

if [[ "$HTTP_CODE" =~ ^2 ]]; then
    log "OK: DefectDojo aceptó el reporte. HTTP $HTTP_CODE"
    jq . "$DD_RESPONSE" 2>/dev/null || cat "$DD_RESPONSE"
else
    printf 'ERROR: DefectDojo respondió HTTP %s\n' "$HTTP_CODE" >&2
    jq . "$DD_RESPONSE" 2>/dev/null || cat "$DD_RESPONSE" >&2
    exit 1
fi
