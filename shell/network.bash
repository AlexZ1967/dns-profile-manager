# DNS Profile Manager network backend. Source with Bash; no network changes on load.
# Machine-specific settings are kept outside the repository.
_dns_load_network_settings() {
    local config_dir="${DNS_MANAGER_CONFIG:-$HOME/.config/dns-manager/providers.json}"
    config_dir="${config_dir%/*}"
    local settings="${DNS_MANAGER_NETWORK_CONFIG:-$config_dir/network.bash}"
    if [[ ! -r "$settings" ]]; then
        printf 'DNS Manager: нет локальных настроек %s. Выполните integrate.py.\n' "$settings" >&2
        return 1
    fi
    source "$settings" || return 1
    if [[ -z "${DNS_ETH_UUID:-}" || -z "${DNS_WIFI_UUID:-}" ||
          -z "${DNS_INTERFACES[0]:-}" || -z "${DNS_INTERFACES[1]:-}" ||
          -z "${DNS_PROFILE_CONF:-}" ]] || ! declare -p DNS_LEGACY_CONFS >/dev/null 2>&1; then
        printf 'DNS Manager: неполные локальные настройки в %s\n' "$settings" >&2
        return 1
    fi
}
_dns_load_network_settings || return 1

# Only known active UUID/interface pairs; never VPN or inactive connections.
_dns_active_connections() {
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

_dns_clear_profiles() {
    sudo rm -f "$DNS_PROFILE_CONF" "${DNS_LEGACY_CONFS[@]}"
}

# Общая функция: 1=название, 2=DNS-серверы, 3=DoT yes/no.
_dns_switch() (
    local name="$1" servers="$2" dot="$3"
    local config
    printf -v config '[Resolve]\nDNS=%s\nDNSOverTLS=%s\nDomains=~.\n' "$servers" "$dot"

    if [[ -z "$(_dns_active_connections)" ]]; then
        echo 'Нет активного известного подключения: DNS не изменён.' >&2
        return 1
    fi
    # Same lock as Dispatcher v2; authorization happens before taking it.
    sudo -v || return 1
    local lock_fd
    if [[ -e /run/lock/nm-dns-primary-route.lock ]]; then
        exec {lock_fd}</run/lock/nm-dns-primary-route.lock || return 1
        flock -x -w 15 "$lock_fd" || { echo 'Dispatcher DNS занят. Повторите операцию.' >&2; return 1; }
    fi
    echo "Переключаю DNS: $name"
    # Сначала записываем настройки в один управляемый файл.
    sudo mkdir -p /etc/systemd/resolved.conf.d || return 1
    local staged_conf="${DNS_PROFILE_CONF}.new"
    printf '%s' "$config" | sudo tee "$staged_conf" >/dev/null || return 1
    sudo chmod 644 "$staged_conf" || return 1
    sudo mv -f -- "$staged_conf" "$DNS_PROFILE_CONF" || return 1
    sudo rm -f "${DNS_LEGACY_CONFS[@]}" || return 1
    _dns_nm_configure yes || return 1
    sudo systemctl restart systemd-resolved || return 1
    sudo resolvectl flush-caches
    echo "Профиль $name выбран. Маршрут выбирает NetworkManager."
    resolvectl status | sed -n '1,21p'
)

_dns_provider_apply() (
    if [[ -z "$(_dns_active_connections)" ]]; then
        echo 'Нет активного известного подключения: DNS не изменён.' >&2
        return 1
    fi
    # Same lock as Dispatcher v2; authorization happens before taking it.
    sudo -v || return 1
    local lock_fd
    if [[ -e /run/lock/nm-dns-primary-route.lock ]]; then
        exec {lock_fd}</run/lock/nm-dns-primary-route.lock || return 1
        flock -x -w 15 "$lock_fd" || { echo 'Dispatcher DNS занят. Повторите операцию.' >&2; return 1; }
    fi
    echo 'Возвращаю DNS от DHCP только на активных подключениях...'
    _dns_clear_profiles || return 1
    _dns_nm_configure no || return 1
    sudo systemctl restart systemd-resolved || return 1
    sudo resolvectl flush-caches
    echo 'Готово. DNS должен появиться на активных сетевых интерфейсах.'
    resolvectl status | sed -n '1,35p'
)
