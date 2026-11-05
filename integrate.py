#!/usr/bin/python3
"""Install only user files; retain the established network functions and dispatcher."""
import datetime
import re
import shlex
from pathlib import Path
import dns_manager as manager


def integrate():
    original=manager.ALIASES.read_text()
    marker='# DNS Manager: shared provider configuration and generated CLI commands.'
    if marker in original:
        manager.install_commands(manager.load_config())
        print('CLI integration already installed.')
        return
    # Refuse unexpected versions rather than replacing unrelated shell definitions.
    required=['_dns_active_connections() {','_dns_nm_configure() {','_dns_switch() {','dns-provider() {',"# Информативный статус без изменений сети."]
    if any(value not in original for value in required):
        raise manager.ManagerError('Версия ~/.bash_aliases отличается от проверенной. Автоматическая интеграция остановлена.')
    stamp=datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    backup=manager.CONFIG.parent/'backups'/('bash_aliases.'+stamp)
    manager.atomic_write(backup,original)
    if not manager.CONFIG.exists():
        import json
        manager.save_config(json.loads((manager.ROOT/'providers.default.json').read_text()))
    else:
        manager.install_commands(manager.load_config())
    text=original[:original.index('# Информативный статус без изменений сети.')]
    text=re.sub(r'^DNS_(?:XBOX|AI|DAGAMI|MAGIC)_SERVERS=.*\n','',text,flags=re.M)
    start=text.index('xbox-dns-on()')
    text=text[:start]
    switch_start=text.index('_dns_switch() {')
    provider_start=text.index('dns-provider() {',switch_start)
    switch=text[switch_start:provider_start]
    provider=text[provider_start:]
    auth='''    # Same lock as Dispatcher v2; authorization happens before taking it.
    sudo -v || return 1
    local lock_fd
    if [[ -e /run/lock/nm-dns-primary-route.lock ]]; then
        exec {lock_fd}</run/lock/nm-dns-primary-route.lock || return 1
        flock -x -w 15 "$lock_fd" || { echo 'Dispatcher DNS занят. Повторите операцию.' >&2; return 1; }
    fi
'''
    switch=switch.replace('_dns_switch() {','_dns_switch() (',1)
    switch=switch.replace('    echo "Переключаю DNS: $name"',auth+'    echo "Переключаю DNS: $name"',1)
    switch=switch.replace('    printf \'%s\' "$config" | sudo tee "$DNS_PROFILE_CONF" >/dev/null || return 1', '''    local staged_conf="${DNS_PROFILE_CONF}.new"
    printf '%s' "$config" | sudo tee "$staged_conf" >/dev/null || return 1
    sudo chmod 644 "$staged_conf" || return 1
    sudo mv -f -- "$staged_conf" "$DNS_PROFILE_CONF" || return 1''')
    before,after=switch.rsplit('\n}',1); switch=before+'\n)'+after
    provider=provider.replace('dns-provider() {','_dns_provider_apply() (',1)
    provider=provider.replace("    echo 'Возвращаю DNS от DHCP только на активных подключениях...'",auth+"    echo 'Возвращаю DNS от DHCP только на активных подключениях...'",1)
    before,after=provider.rsplit('\n}',1); provider=before+'\n)'+after
    text=text[:switch_start]+switch+provider
    text+='\n'+marker+'\nsource '+shlex.quote(str(manager.CONFIG.parent/'commands.bash'))+'\n'
    # Check Bash grammar before touching the live aliases file.
    import subprocess
    check=subprocess.run(['bash','-n'],input=text,text=True,capture_output=True)
    if check.returncode: raise manager.ManagerError(check.stderr)
    manager.atomic_write(manager.ALIASES,text,original_mode(manager.ALIASES))
    print('Общий конфиг:',manager.CONFIG)
    print('Резервная копия aliases:',backup)
    print('Системные DNS-файлы и Dispatcher не изменены. Сеть не переключалась.')


def original_mode(path): return path.stat().st_mode & 0o777


if __name__=='__main__': integrate()
