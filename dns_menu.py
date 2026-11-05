#!/usr/bin/python3
"""Terminal frontend using the same configuration and engine as GTK."""
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
import dns_manager as manager

DIALOG_ENV = None


def terminal_environment(directory):
    # The application owns the alternate screen for its entire lifetime.
    # Prevent each new dialog process from switching back to the main buffer.
    term = os.environ.get('TERM', 'xterm-256color')
    description = subprocess.run(['/usr/bin/infocmp', '-x', '-1', term], capture_output=True, text=True)
    if description.returncode:
        raise manager.ManagerError('Не удалось прочитать описание терминала: ' + description.stderr)
    source = re.sub(r'(?m)^\s*(smcup|rmcup)=.*,$', r'\t\1@,', description.stdout)
    source_file = Path(directory) / 'dns-manager.src'
    source_file.write_text(source)
    compiled = subprocess.run(['/usr/bin/tic', '-x', '-o', directory, str(source_file)], capture_output=True, text=True)
    if compiled.returncode:
        raise manager.ManagerError('Не удалось подготовить терминал: ' + compiled.stderr)
    return {**os.environ, 'TERMINFO': directory}


def dialog(*args):
    result=subprocess.run(['dialog','--stdout',*args],stdout=subprocess.PIPE,text=True,env=DIALOG_ENV)
    return result.returncode,result.stdout


def report(title,text):
    with tempfile.NamedTemporaryFile(mode='w',suffix='.txt') as f:
        f.write(text); f.flush()
        dialog('--no-mouse','--no-ok','--no-cancel','--title',title+' · Esc — закрыть','--textbox',f.name,'0','0')


def task(title,worker):
    lines=[]; error=[]; message=[title]
    def emit(text): lines.append(text); message[0]=text.replace('\n',' ')[:170]
    def work():
        try: worker(emit)
        except Exception as exc: error.append(str(exc)); emit('Ошибка: '+str(exc))
    thread=threading.Thread(target=work,daemon=True)
    process=subprocess.Popen(['dialog','--title',title,'--gauge','Выполняется…','9','76','0'],stdin=subprocess.PIPE,text=True,env=DIALOG_ENV)
    thread.start(); index=0
    while thread.is_alive():
        try:
            process.stdin.write(f'XXX\n{min(index,95)}\n{message[0]}\nXXX\n'); process.stdin.flush()
        except (BrokenPipeError,OSError): pass
        index+=1; thread.join(0.3)
    try: process.stdin.close()
    except (BrokenPipeError,OSError): pass
    process.wait()
    report(title,'\n'.join(lines))


def main():
    global DIALOG_ENV
    if sys.argv[1:] == ['--version']:
        print('DNS Profile Manager ' + manager.__version__)
        return
    if not sys.stdout.isatty(): raise SystemExit('Запустите dns-menu в терминале.')
    terminal = tempfile.TemporaryDirectory(prefix='dns-manager-terminfo-')
    DIALOG_ENV = terminal_environment(terminal.name)
    subprocess.run(['tput','smcup'])
    try:
        while True:
            data=manager.load_config(); state=manager.current_state(data); health=manager.health_results(data,state['network'])
            icons={'green':'✓','yellow':'⚠','red':'✕','unknown':'○'}
            choices=[]
            for p in data['providers']:
                choices.extend(['apply:'+p['id'],icons[health.get(p['id'],{}).get('state','unknown')]+' '+p['name']])
            choices+=['check','Проверить один DNS БЕЗ переключения','check-all','Проверить все БЕЗ переключения','status','Диагностика текущего DNS и HTTPS','details','Сетевая конфигурация','config','Общий конфиг CLI / GUI','quit','Выход']
            rc,choice=dialog('--clear','--keep-window','--title','DNS Profile Manager', '--menu',f'Текущий DNS: {state["name"]}\nМаршрут: {state["route"]["interface"]} · Esc — выход','0','0','12',*choices)
            if rc or choice=='quit': break
            if choice.startswith('apply:'):
                ident=choice.partition(':')[2]; p=manager.provider(data,ident)
                rc,_=dialog('--title','Подтверждение','--yesno','Применить '+p['name']+'? Только активные Ethernet/Wi-Fi.','8','70')
                if rc: continue
                # Authenticate on the terminal before drawing a progress window.
                if subprocess.run(['sudo','-v']).returncode: continue
                task('Переключение DNS',lambda emit:manager.apply_profile(ident,emit))
            elif choice=='check':
                entries=[]
                for p in data['providers']: entries += [p['id'],p['name']]
                rc,ident=dialog('--title','Без переключения DNS','--menu','Какой DNS проверить?','0','0','10',*entries)
                if not rc:
                    task('Проверка без переключения',lambda emit:emit(manager.format_health(manager.check_provider(ident,emit))))
            elif choice=='check-all':
                def check_all(emit):
                    for p in data['providers']: emit(manager.format_health(manager.check_provider(p['id'],emit)))
                task('Все DNS · без переключения',check_all)
            elif choice in ('status','details'):
                task('Диагностика DNS',lambda emit:manager.diagnostic(choice=='details',emit))
            elif choice=='config':
                report('Общий конфиг',str(manager.CONFIG)+'\n\n'+json.dumps(data,ensure_ascii=False,indent=2))
    except (manager.ManagerError,OSError) as exc:
        report('Ошибка',str(exc))
    finally:
        subprocess.run(['tput','rmcup'])
        terminal.cleanup()


if __name__=='__main__': main()
