# DNS Profile Manager network backend. Source with Bash; no network changes on load.
# Machine-specific settings live in the project .local directory (excluded from Git).
_dns_load_network_settings() {
    local project_root settings assignments
    project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)" || return 1
    local config="${DNS_MANAGER_CONFIG:-$HOME/.config/dns-manager/providers.json}"
    if [[ -z "${DNS_MANAGER_CONFIG:-}" && -r "$project_root/.local/config/providers.json" ]]; then
        config="$project_root/.local/config/providers.json"
    fi
    local config_dir="${config%/*}"
    settings="${DNS_MANAGER_NETWORK_CONFIG:-$config_dir/network.json}"
    [[ -n "${DNS_MANAGER_NETWORK_CONFIG:-}" || -r "$settings" ]] || settings="$config_dir/network.bash"
    if [[ ! -r "$settings" ]]; then
        printf 'DNS Manager: нет настроек %s. Выполните ./install.\n' "$settings" >&2
        return 1
    fi
    unset DNS_CONNECTIONS DNS_INSTALLATION_ID DNS_ETH_UUID DNS_WIFI_UUID DNS_INTERFACES DNS_PROFILE_CONF DNS_LEGACY_CONFS
    if [[ "$settings" == *.json ]]; then
        assignments="$(/usr/bin/python3 "$project_root/dns_network.py" shell "$settings")" || return 1
        eval "$assignments" || return 1
    else
        source "$settings" || return 1
    fi
    if [[ -z "${DNS_PROFILE_CONF:-}" ]] || ! declare -p DNS_LEGACY_CONFS >/dev/null 2>&1; then
        printf 'DNS Manager: неполные настройки %s\n' "$settings" >&2; return 1
    fi
    if ! declare -p DNS_CONNECTIONS >/dev/null 2>&1 &&
       [[ -z "${DNS_ETH_UUID:-}" || -z "${DNS_WIFI_UUID:-}" || -z "${DNS_INTERFACES[1]:-}" ]]; then
        printf 'DNS Manager: отсутствуют подключения в %s\n' "$settings" >&2; return 1
    fi
}
_dns_load_network_settings || return 1

# Only known active UUID/interface pairs; never VPN or inactive connections.
_dns_active_connections() {
    if declare -p DNS_CONNECTIONS >/dev/null 2>&1; then
        local ident kind device spec allowed interface expected
        while IFS=: read -r ident kind device; do
            [[ "$kind" == 802-3-ethernet || "$kind" == 802-11-wireless ]] || continue
            [[ -n "$device" && "$device" != -- ]] || continue
            for spec in "${DNS_CONNECTIONS[@]}"; do
                IFS='|' read -r allowed interface expected <<< "$spec"
                if [[ "$ident" == "$allowed" && "$kind" == "$expected" && ( -z "$interface" || "$device" == "$interface" ) ]]; then
                    printf '%s|%s\n' "$ident" "$device"; break
                fi
            done
        done < <(nmcli -t --escape no -f UUID,TYPE,DEVICE connection show --active 2>/dev/null)
        return
    fi
    local uuid iface
    while IFS='|' read -r uuid iface; do
        case "$uuid:$iface" in
            "$DNS_ETH_UUID:${DNS_INTERFACES[0]}"|"$DNS_WIFI_UUID:${DNS_INTERFACES[1]}")
                printf '%s|%s\n' "$uuid" "$iface" ;;
        esac
    done < <(nmcli -t -f UUID,DEVICE connection show --active 2>/dev/null | tr ':' '|')
}

# Меняем DNS только на подключениях, активных на момент команды.
# Не выполняем connection down/up и не трогаем отключённый профиль.
_dns_nm_configure() {
    local ignore_auto="$1" custom_dns="${2:-}"
    local entries uuid iface changed=0 failed=0
    entries="$(_dns_active_connections)"
    if [[ -z "$entries" ]]; then
        echo 'Ошибка: нет активного Ethernet или Wi-Fi подключения из известных профилей.' >&2
        return 1
    fi
    while IFS='|' read -r uuid iface; do
        [[ -n "$uuid" ]] || continue
        echo "Настраиваю активный интерфейс $iface ($uuid)"
        if ! nmcli connection modify "$uuid" \
            ipv4.ignore-auto-dns "$ignore_auto" ipv4.dns "$custom_dns" \
            ipv6.ignore-auto-dns "$ignore_auto" ipv6.dns ''; then
            failed=1
            continue
        fi
        changed=1
        if ! nmcli device reapply "$iface"; then
            echo "Внимание: не удалось применить настройки к $iface без переподключения." >&2
            failed=1
        fi
    done <<< "$entries"
    (( changed )) && (( ! failed ))
}

# Connection state capture/restore run only inside the authorized root process.
# Values unreadable by nmcli are restored empty; devices are reapplied by the
# rollback in _dns_apply_as_root. Never executes outside _dns_apply_as_root.
_dns_capture_connection_state() {
    local uuid fields index value
    local -a values
    while IFS= read -r uuid; do
        [[ -n "$uuid" ]] || continue
        fields="$(nmcli -t --escape no -g \
            ipv4.ignore-auto-dns,ipv4.dns,ipv6.ignore-auto-dns,ipv6.dns connection show "$uuid")" || return 1
        mapfile -t values <<< "$fields"
        printf '%s' "$uuid"
        for index in 0 1 2 3; do
            value="${values[index]:-}"
            [[ "$value" == '--' ]] && value=''
            printf '|%s' "$value"
        done
        printf '\n'
    done
}

_dns_restore_connection_state() {
    local rest
    local uuid ignore4 dns4 ignore6 dns6
    while IFS='|' read -r uuid ignore4 dns4 ignore6 dns6 rest; do
        [[ -n "$uuid" ]] || continue
        nmcli connection modify "$uuid" \
            ipv4.ignore-auto-dns "${ignore4:-no}" ipv4.dns "${dns4:-}" \
            ipv6.ignore-auto-dns "${ignore6:-no}" ipv6.dns "${dns6:-}" \
            || echo "Не удалось восстановить прежние настройки $uuid." >&2
    done
}

# Runs only inside the one explicitly authorized root process below.
_dns_apply_as_root() (
    local mode="$1" name="$2" servers="$3" dot="$4"
    local lock_fd entries config staged_conf previous_conf previous_connections
    local lock_file=/run/lock/nm-dns-primary-route.lock
    umask 022
    if [[ -L "$lock_file" ]]; then
        echo 'Небезопасный файл блокировки Dispatcher (симлинк). Операция прервана.' >&2
        return 1
    fi
    # Read-write open also creates the file when it is absent (fresh installations).
    # The Dispatcher applies the same ownership/mode checks to the same file.
    exec {lock_fd}<>"$lock_file" || return 1
    chmod 644 -- "$lock_file" 2>/dev/null || true
    flock -x -w 15 "$lock_fd" || { echo 'Dispatcher DNS занят. Повторите операцию.' >&2; return 1; }
    # Recheck after authorization and lock acquisition: the connection may have changed.
    entries="$(_dns_active_connections)"
    if [[ -z "$entries" ]]; then
        echo 'Нет активного известного подключения: DNS не изменён.' >&2
        return 1
    fi
    # Best-effort rollback state: previous resolved profile text and per-connection
    # DNS fields. Legacy confs removed on this run are not restored; they are ours.
    previous_conf=''
    [[ -f "$DNS_PROFILE_CONF" && -r "$DNS_PROFILE_CONF" ]] && previous_conf="$(<"$DNS_PROFILE_CONF")"
    previous_connections="$(_dns_capture_connection_state <<<"$entries")" || {
        echo 'Не удалось сохранить текущие параметры NetworkManager; переключение отменено.' >&2
        return 1
    }

    _dns_apply_rollback() {
        echo 'Внимание: применить настройки NetworkManager не удалось, восстанавливаю прежние параметры DNS...' >&2
        if [[ -n "$previous_conf" ]]; then
            local restore_conf
            restore_conf="$(mktemp "${DNS_PROFILE_CONF}.XXXXXX")" || return 1
            printf '%s\n' "$previous_conf" > "$restore_conf" || { rm -f -- "$restore_conf"; return 1; }
            chmod 644 "$restore_conf" || { rm -f -- "$restore_conf"; return 1; }
            mv -f -- "$restore_conf" "$DNS_PROFILE_CONF" || return 1
        else
            rm -f -- "$DNS_PROFILE_CONF"
        fi
        _dns_restore_connection_state <<<"$previous_connections"
        while IFS='|' read -r uuid iface; do
            [[ -n "$iface" ]] && nmcli device reapply "$iface" 2>/dev/null \
                || echo "Не удалось применить восстановленные настройки к $iface." >&2
        done <<<"$entries"
        systemctl restart systemd-resolved
        echo 'Прежняя конфигурация DNS восстановлена. Проверьте фактический статус.' >&2
    }

    if [[ "$mode" == dhcp ]]; then
        echo 'Возвращаю DNS от DHCP только на активных подключениях...'
        rm -f -- "$DNS_PROFILE_CONF" "${DNS_LEGACY_CONFS[@]}" || return 1
        _dns_nm_configure no || { _dns_apply_rollback; return 1; }
    else
        echo "Переключаю DNS: $name"
        printf -v config '[Resolve]\nDNS=%s\nDNSOverTLS=%s\nDomains=~.\n' "$servers" "$dot"
        if [[ -n "${DNS_INSTALLATION_ID:-}" ]]; then
            config="# DNS Profile Manager: $DNS_INSTALLATION_ID"$'\n'"$config"
        fi
        mkdir -p -- "${DNS_PROFILE_CONF%/*}" || return 1
        staged_conf="$(mktemp "${DNS_PROFILE_CONF}.XXXXXX")" || return 1
        trap '[[ -z "${staged_conf:-}" ]] || rm -f -- "$staged_conf"' EXIT
        printf '%s' "$config" > "$staged_conf" || return 1
        chmod 644 "$staged_conf" || return 1
        mv -f -- "$staged_conf" "$DNS_PROFILE_CONF" || return 1
        staged_conf=''
        rm -f -- "${DNS_LEGACY_CONFS[@]}" || { _dns_apply_rollback; return 1; }
        _dns_nm_configure yes || { _dns_apply_rollback; return 1; }
    fi
    systemctl restart systemd-resolved || { _dns_apply_rollback; return 1; }
    echo "Профиль $name выбран. Маршрут выбирает NetworkManager."
    resolvectl status | sed -n '1,35p'
)

_dns_privileged_apply() (
    if [[ -n "${DNS_INSTALLATION_ID:-}" ]]; then
        /usr/bin/python3 "$(dirname -- "${BASH_SOURCE[0]}")/../dns_setup.py" status || return 1
    fi
    if [[ -z "$(_dns_active_connections)" ]]; then
        echo 'Нет активного известного подключения: DNS не изменён.' >&2
        return 1
    fi
    local script variable
    # Serialize only known data and project functions. No aliases or settings files
    # are sourced by root; declare -p quotes all values as literal Bash data.
    script=$'set -o pipefail\n'
    for variable in DNS_CONNECTIONS DNS_ETH_UUID DNS_WIFI_UUID DNS_INTERFACES DNS_PROFILE_CONF DNS_LEGACY_CONFS DNS_INSTALLATION_ID; do
        if declare -p "$variable" >/dev/null 2>&1; then
            script+="$(declare -p "$variable")"$'\n'
        fi
    done
    script+="$(declare -f _dns_active_connections _dns_nm_configure _dns_apply_as_root _dns_capture_connection_state _dns_restore_connection_state)"$'\n'
    script+='_dns_apply_as_root "$@"'
    # One authorization covers writing resolved config, nmcli and service reload.
    # GUI substitutes sudo -A here; there are no nested sudo/Polkit requests.
    sudo /usr/bin/bash -c "$script" dns-profile-manager "$@"
)

# Shared entry points used by CLI, GUI and legacy shell commands.
_dns_switch() {
    _dns_privileged_apply manual "$1" "$2" "$3"
}

_dns_provider_apply() {
    _dns_privileged_apply dhcp 'DNS провайдера' '' no
}
