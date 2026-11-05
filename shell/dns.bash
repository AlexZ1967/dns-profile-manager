# DNS Profile Manager shell entry point. Add only a guarded source of this file to ~/.bash_aliases.
_dns_manager_load_shell() {
    local project_root
    project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)" || return 1
    source "$project_root/shell/network.bash" || return 1
    local config="${DNS_MANAGER_CONFIG:-$HOME/.config/dns-manager/providers.json}"
    local commands="${config%/*}/commands.bash"
    if [[ -r "$commands" ]]; then
        source "$commands" || return 1
    fi
}
if _dns_manager_load_shell; then
    unset -f _dns_manager_load_shell
else
    unset -f _dns_manager_load_shell
    return 1
fi

# Сохраняем отдельную возможность скачать и проверить новый DNS-AI setup.sh,
# но НЕ запускаем сторонний установщик при переключении DNS-профиля.
DNS_AI_DIR="$HOME/.local/share/dns-ai"
DNS_AI_SCRIPT="$DNS_AI_DIR/setup.sh"
DNS_AI_URL='https://raw.githubusercontent.com/confeden/DNS-AI/main/setup.sh'

dns-ai-update() {
    mkdir -p "$DNS_AI_DIR" || return 1
    local tmp answer
    tmp="$(mktemp)" || return 1
    if ! curl --noproxy '*' -fsSL --connect-timeout 10 --max-time 30 \
        "$DNS_AI_URL" -o "$tmp"; then
        echo 'Не удалось скачать DNS-AI setup.sh'
        rm -f "$tmp"
        return 1
    fi
    if [[ -f "$DNS_AI_SCRIPT" ]] && cmp -s "$tmp" "$DNS_AI_SCRIPT"; then
        rm -f "$tmp"
        echo 'DNS-AI setup.sh не изменился.'
        return 0
    fi
    if [[ -f "$DNS_AI_SCRIPT" ]]; then
        diff -u "$DNS_AI_SCRIPT" "$tmp" || true
    else
        echo 'Получен новый DNS-AI setup.sh:'
        sed -n '1,80p' "$tmp"
    fi
    read -r -p 'Сохранить новый setup.sh (без запуска)? [y/N] ' answer
    case "$answer" in
        y|Y|yes|YES)
            mv "$tmp" "$DNS_AI_SCRIPT" && chmod 700 "$DNS_AI_SCRIPT"
            ;;
        *) rm -f "$tmp"; echo 'Изменения не приняты.' ;;
    esac
}
