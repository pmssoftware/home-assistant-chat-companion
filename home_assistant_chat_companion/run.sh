#!/usr/bin/with-contenv bashio
set -euo pipefail

database="/data/companion.sqlite3"
admin_name="$(bashio::config 'bootstrap_admin_name')"
admin_password="$(bashio::config 'bootstrap_admin_password')"
log_level="$(bashio::config 'log_level')"

if [[ ${#admin_password} -lt 12 ]]; then
    bashio::log.fatal "bootstrap_admin_password must contain at least 12 characters"
    exit 1
fi

bashio::log.info "Preparing persistent companion-server storage"
printf '%s\n' "${admin_password}" | python3 -m hachat_companion \
    --database "${database}" bootstrap-account \
    --name "${admin_name}" --password-stdin
unset admin_password

server_id="$(python3 -m hachat_companion --database "${database}" info | awk '/^Server ID:/ {print $3}')"
bashio::log.info "Federation server ID: ${server_id}"
bashio::log.info "Client listener: 8210/tcp; federation listener: 8211/tcp"

python3 -m hachat_companion --database "${database}" disable-peers

while IFS=$'\t' read -r peer_id address port shared_secret insecure_http tls_server_name; do
    [[ -n "${peer_id}" ]] || continue
    peer_args=(
        python3 -m hachat_companion
        --database "${database}"
        configure-peer
        --peer-id "${peer_id}"
        --address "${address}"
        --port "${port}"
        --secret-stdin
    )
    if [[ "${insecure_http}" == "true" ]]; then
        peer_args+=(--insecure-http)
    elif [[ -n "${tls_server_name}" ]]; then
        peer_args+=(--tls-server-name "${tls_server_name}")
    fi
    printf '%s\n' "${shared_secret}" | "${peer_args[@]}"
done < <(
    bashio::config 'federation_peers' | jq -r \
        '.[] | [.peer_id, .address, (.port | tostring), .shared_secret, (.insecure_http | tostring), (.tls_server_name // "")] | @tsv'
)

args=(
    python3 -m hachat_companion
    --database "${database}"
    serve
    --client-listen 0.0.0.0:8210
    --federation-listen 0.0.0.0:8211
    --log-level "${log_level}"
)

if bashio::config.true 'ssl'; then
    certfile="/ssl/$(bashio::config 'certfile')"
    keyfile="/ssl/$(bashio::config 'keyfile')"
    if ! bashio::fs.file_exists "${certfile}" || ! bashio::fs.file_exists "${keyfile}"; then
        bashio::log.fatal "SSL is enabled but the configured certificate or key is missing"
        exit 1
    fi
    args+=(
        --client-tls-cert "${certfile}"
        --client-tls-key "${keyfile}"
        --federation-tls-cert "${certfile}"
        --federation-tls-key "${keyfile}"
    )
else
    if ! bashio::config.true 'allow_insecure_test_http'; then
        bashio::log.fatal "TLS is disabled; enable allow_insecure_test_http only for an isolated test LAN"
        exit 1
    fi
    bashio::log.warning "TLS is disabled; expose both ports only on a trusted test network"
    args+=(--allow-insecure-client-http --allow-insecure-federation-http)
fi

exec "${args[@]}"
