#!/usr/bin/env bash
set -Eeuo pipefail

ENV_FILE="/etc/wazuh-defectdojo.env"

[[ -r "$ENV_FILE" ]] || {
    echo "No puedo leer $ENV_FILE" >&2
    exit 1
}

# shellcheck disable=SC1090
source "$ENV_FILE"

: "${WAZUH_INDEXER_URL:=https://localhost:9200}"
: "${WAZUH_NETRC:=/root/.netrc}"
: "${DEFECTDOJO_URL:?Falta DEFECTDOJO_URL}"
: "${DEFECTDOJO_API_KEY:?Falta DEFECTDOJO_API_KEY}"
: "${DEFECTDOJO_ENGAGEMENT_ID:?Falta DEFECTDOJO_ENGAGEMENT_ID}"
: "${MINIMUM_SEVERITY:=Info}"
: "${TEST_TITLE:=Wazuh Vulnerabilities}"
: "${AGENT_ID:=}"

for required_command in curl jq mktemp; do
    command -v "$required_command" >/dev/null 2>&1 || {
        echo "Falta el comando: $required_command" >&2
        exit 1
    }
done

[[ -r "$WAZUH_NETRC" ]] || {
    echo "No puedo leer $WAZUH_NETRC" >&2
    exit 1
}

WORKDIR="$(mktemp -d /tmp/wazuh-defectdojo.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

BATCH_FILE="$WORKDIR/batch.json"
REPORT_FILE="$WORKDIR/wazuh-vulnerabilities.json"
NEXT_REPORT="$WORKDIR/report-next.json"
DD_RESPONSE="$WORKDIR/defectdojo-response.json"

# Permite importar todos los agentes o solamente uno.
if [[ -n "$AGENT_ID" ]]; then
    QUERY="$(
        jq -cn \
            --arg agent_id "$AGENT_ID" \
            '{term:{"agent.id":$agent_id}}'
    )"

    TEST_TITLE="${TEST_TITLE} - agent ${AGENT_ID}"
else
    QUERY='{"match_all":{}}'
fi

# Solamente pedimos los campos que utiliza el parser de DefectDojo.
PAYLOAD="$(
    jq -cn \
        --argjson query "$QUERY" \
        '{
            size: 1000,
            sort: ["_doc"],
            _source: [
                "agent",
                "package",
                "vulnerability"
            ],
            query: $query
        }'
)"

echo "[1/3] Leyendo vulnerabilidades de Wazuh..."

curl -fsSk \
    --netrc-file "$WAZUH_NETRC" \
    -H 'Content-Type: application/json' \
    -X POST \
    "${WAZUH_INDEXER_URL}/wazuh-states-vulnerabilities*/_search?scroll=2m" \
    -d "$PAYLOAD" > "$BATCH_FILE"

if jq -e '.error' "$BATCH_FILE" >/dev/null 2>&1; then
    echo "Wazuh devolvió un error:" >&2
    jq '.error' "$BATCH_FILE" >&2
    exit 1
fi

# DefectDojo espera un documento con hits.hits.
jq '{hits:{hits:(.hits.hits // [])}}' \
    "$BATCH_FILE" > "$REPORT_FILE"

SCROLL_ID="$(jq -r '._scroll_id // empty' "$BATCH_FILE")"

# Recorremos más páginas si existen más de 1000 vulnerabilidades.
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
        "${WAZUH_INDEXER_URL}/_search/scroll" \
        -d "$SCROLL_PAYLOAD" > "$BATCH_FILE"

    if jq -e '.error' "$BATCH_FILE" >/dev/null 2>&1; then
        echo "Wazuh devolvió un error durante la paginación:" >&2
        jq '.error' "$BATCH_FILE" >&2
        exit 1
    fi

    BATCH_COUNT="$(jq '.hits.hits | length' "$BATCH_FILE")"

    [[ "$BATCH_COUNT" -eq 0 ]] && break

    jq -s \
        '{hits:{hits:(.[0].hits.hits + .[1].hits.hits)}}' \
        "$REPORT_FILE" \
        "$BATCH_FILE" > "$NEXT_REPORT"

    mv "$NEXT_REPORT" "$REPORT_FILE"

    SCROLL_ID="$(jq -r '._scroll_id // empty' "$BATCH_FILE")"
done

# Liberamos la búsqueda del Indexer.
if [[ -n "$SCROLL_ID" ]]; then
    curl -sSk \
        --netrc-file "$WAZUH_NETRC" \
        -H 'Content-Type: application/json' \
        -X DELETE \
        "${WAZUH_INDEXER_URL}/_search/scroll" \
        -d "$(
            jq -cn \
                --arg scroll_id "$SCROLL_ID" \
                '{scroll_id:[$scroll_id]}'
        )" >/dev/null || true
fi

FINDING_COUNT="$(jq '.hits.hits | length' "$REPORT_FILE")"

echo "[2/3] Vulnerabilidades exportadas: $FINDING_COUNT"
echo "[3/3] Enviando reporte a DefectDojo..."

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
        -F "test_title=${TEST_TITLE}" \
        -F "minimum_severity=${MINIMUM_SEVERITY}" \
        -F 'active=true' \
        -F 'verified=false' \
        -F 'close_old_findings=true' \
        -F 'do_not_reactivate=false' \
        -F "file=@${REPORT_FILE};type=application/json"
)"

if [[ "$HTTP_CODE" =~ ^2 ]]; then
    echo "OK: DefectDojo aceptó el reporte. HTTP $HTTP_CODE"
    jq . "$DD_RESPONSE" 2>/dev/null || cat "$DD_RESPONSE"
else
    echo "ERROR: DefectDojo respondió HTTP $HTTP_CODE" >&2
    jq . "$DD_RESPONSE" 2>/dev/null || cat "$DD_RESPONSE" >&2
    exit 1
fi
