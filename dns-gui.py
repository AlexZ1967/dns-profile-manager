#!/usr/bin/python3
"""GTK frontend; CLI and GUI use the same provider store and network engine."""
import copy
import json
import threading
import sys
import gi
gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
from gi.repository import Gdk, Gio, GLib, Gtk, Pango
import dns_manager as manager
from dns_checker import GatewayChecker

CSS = b"""
window.app-window { background: #f5f7fb; color: #1b2b43; }
* { font-family: 'Noto Sans', sans-serif; font-size: 14px; }
headerbar { background: #ffffff; border-bottom: 1px solid #e2e7ee; box-shadow: none; }
headerbar .title { font-size: 15px; font-weight: 600; }
.sidebar { background: #ffffff; border-right: 1px solid #e2e7ee; }
.section-caption { color: #758299; font-size: 11px; font-weight: 700; letter-spacing: 1px; }
.profile-list { background: transparent; }
.profile-row { padding: 13px 14px; margin: 3px 12px; border-radius: 9px; color: #25364d; }
.profile-row:hover { background: #f1f5fc; }
.profile-row:selected { background: #eaf0ff; color: #234fc2; }
.profile-name { font-size: 14px; font-weight: 600; }
.profile-row:selected label.profile-name { color: #234fc2; }
.profile-kind { font-size: 12px; color: #7a879a; }
.profile-row:selected .profile-kind { color: #5975b5; }
.muted { color: #758299; font-size: 12px; }
.current-card { background: #ffffff; border: 1px solid #e0e7f0; border-radius: 12px; }
.current-name { font-size: 17px; font-weight: 600; color: #243f72; }
.current-dot { color: #5178ce; font-size: 20px; }
.profile-title { font-size: 27px; font-weight: 700; color: #172a44; }
.description { color: #65748b; font-size: 14px; }
button { background: #ffffff; background-image: none; color: #334862; border: 1px solid #dce3ee; border-radius: 7px; padding: 8px 13px; box-shadow: none; text-shadow: none; }
button:hover { background: #edf2fa; border-color: #c2d0e5; }
button:disabled { color: #9aa5b5; background: #f4f6f9; border-color: #e6eaf0; }
button.primary { background: #315fce; color: #ffffff; border-color: #315fce; font-weight: 600; padding: 10px 20px; }
button.primary:hover { background: #244eb7; }
button.primary:disabled { background: #c7d4f1; color: #f8faff; border-color: #c7d4f1; }
button.flat { background: transparent; border-color: transparent; padding: 5px 8px; }
button.flat:hover { background: #eaf0fa; }
.report-card { background: #ffffff; border: 1px solid #e0e7f0; border-radius: 10px; }
.report-title { font-size: 14px; font-weight: 600; }
textview, textview text { background: #ffffff; color: #334862; font-family: 'Noto Sans Mono', monospace; font-size: 12px; }
.status { font-size: 12px; color: #718096; }
.status.error { color: #bc3f42; }
.status.success { color: #277459; }
.progress-title { font-size: 17px; font-weight: 600; }
spinner { color: #315fce; }
"""

HEALTH = {'green': ('✓', '#15803d', 'Работает'), 'yellow': ('⚠', '#ad7100', 'Частично работает'),
          'red': ('✕', '#c3353d', 'Не работает'), 'unknown': ('○', '#8894a5', 'Не проверен')}


def label(text, css=None):
    widget = Gtk.Label(label=text, xalign=0)
    if css:
        widget.get_style_context().add_class(css)
    return widget


def box(orientation=Gtk.Orientation.VERTICAL, spacing=0, css=None):
    widget = Gtk.Box(orientation=orientation, spacing=spacing)
    if css:
        widget.get_style_context().add_class(css)
    return widget


def margins(widget, amount):
    for side in ('top', 'bottom', 'start', 'end'):
        getattr(widget, 'set_margin_' + side)(amount)


class ProviderEditor(Gtk.Dialog):
    def __init__(self, parent, item=None):
        super().__init__(title='Настройки провайдера' if item else 'Новый DNS-провайдер', transient_for=parent, modal=True)
        self.set_default_size(610, 620)
        self.original = copy.deepcopy(item)
        self.base_config = copy.deepcopy(parent.data)
        self.expected_hash = manager.fingerprint(self.base_config)
        self.add_button('Отмена', Gtk.ResponseType.CANCEL)
        self.add_button('Сохранить', Gtk.ResponseType.OK)
        grid = Gtk.Grid(column_spacing=16, row_spacing=12)
        margins(grid, 22)
        content = self.get_content_area()
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.add(grid)
        content.pack_start(scroll, True, True, 0)
        p = item or {'id': '', 'name': '', 'mode': 'dot', 'servers': [], 'tls_hostname': '', 'port': 853, 'command': '', 'off_commands': [], 'description': '', 'website': ''}
        self.fields = {}
        fields = [('name','Название'), ('id','ID (латиница)'), ('command','Команда CLI'), ('off_commands','Команды отключения'),
                  ('mode','Протокол'), ('servers','IP-серверы'), ('tls_hostname','TLS-имя'), ('port','Порт'),
                  ('website','Сайт провайдера'), ('description','Описание')]
        for row, (key,title) in enumerate(fields):
            caption = label(title)
            caption.set_valign(Gtk.Align.CENTER)
            grid.attach(caption,0,row,1,1)
            if key == 'mode':
                widget = Gtk.ComboBoxText()
                for mode, text in manager.MODE_NAMES.items():
                    if mode != 'dhcp' or p['mode'] == 'dhcp': widget.append(mode,text)
                widget.set_active_id(p['mode'])
                widget.connect('changed', self._mode_changed)
            else:
                widget = Gtk.Entry()
                value = p.get(key,'')
                if isinstance(value,list): value = ', '.join(value)
                widget.set_text(str(value))
                if key == 'servers': widget.set_placeholder_text('45.88.163.92, 109.120.177.170')
                if key == 'tls_hostname': widget.set_placeholder_text('dns.example.org — без https://')
                if key == 'command': widget.set_placeholder_text('dns-my-provider-on')
                if key == 'id': widget.set_placeholder_text('my-provider')
            widget.set_hexpand(True)
            self.fields[key] = widget
            grid.attach(widget,1,row,1,1)
        if item:
            self.fields['id'].set_sensitive(False)
        if p['mode'] == 'dhcp':
            self.fields['mode'].set_sensitive(False)
            self.fields['command'].set_sensitive(False)
        note = label('Сохранение меняет общий конфиг CLI и GUI. Текущий DNS изменится только после «Применить». Новые CLI-команды создаются автоматически.', 'muted')
        note.set_line_wrap(True); note.set_max_width_chars(65)
        grid.attach(note,0,len(fields),2,1)
        self.error = label('')
        self.error.set_line_wrap(True); self.error.set_max_width_chars(65)
        grid.attach(self.error,0,len(fields)+1,2,1)
        self._mode_changed(self.fields['mode'])
        self.show_all()

    def _mode_changed(self, combo):
        if 'servers' not in self.fields: return
        mode = combo.get_active_id()
        for key in ('servers','port'):
            self.fields[key].set_sensitive(mode != 'dhcp')
        self.fields['tls_hostname'].set_sensitive(mode == 'dot')
        port = self.fields['port'].get_text()
        if mode == 'dot' and port == '53': self.fields['port'].set_text('853')
        if mode == 'plain' and port == '853': self.fields['port'].set_text('53')

    def value(self):
        p = copy.deepcopy(self.original) if self.original else {}
        for key, widget in self.fields.items():
            if key == 'mode': p[key] = widget.get_active_id()
            else: p[key] = widget.get_text().strip()
        p['servers'] = [s.strip() for s in p['servers'].replace('\n',',').split(',') if s.strip()]
        p['off_commands'] = [s.strip() for s in p['off_commands'].split(',') if s.strip()]
        try: p['port'] = int(p['port'])
        except ValueError: raise manager.ManagerError('Порт должен быть числом.')
        if not p['command']: p['command'] = 'dns-' + p['id'] + '-on'
        if not self.original and not p['off_commands']: p['off_commands'] = ['dns-' + p['id'] + '-off']
        if p['mode'] != 'dot': p['tls_hostname'] = ''
        if p['mode'] == 'dhcp': p['servers'] = []
        data = copy.deepcopy(self.base_config)
        if self.original:
            data['providers'] = [p if v['id'] == p['id'] else v for v in data['providers']]
        else: data['providers'].append(p)
        manager.validate_config(data)
        return data, p['id']


class DnsGui(Gtk.Window):
    def __init__(self):
        super().__init__(title='DNS Profile Manager')
        self.data = manager.load_config()
        self.set_default_size(1100, 820)
        self.set_size_request(920, 710)
        self.set_position(Gtk.WindowPosition.CENTER)
        self.get_style_context().add_class('app-window')
        self.busy = False
        self.progress = None
        self.checker = None
        self.operation = None
        self.operation_results = []
        self.cancel_event = threading.Event()
        self._pending_report = []
        self._flush_scheduled = None
        self.current = {}
        self.selected_id = self.data['providers'][0]['id']
        self.initial_selection = True
        self.refresh_generation = 0
        self.refresh_in_progress = False
        self.controls = []
        self.health = {}
        self.badges = {}
        self._health_signature = None
        self._style(); self._build()
        self.connect('delete-event', self._close)
        self.refresh_profile()
        self._setup_config_watch()
        # Slow periodic refresh: network changes (DHCP DNS, primary route) are not file changes.
        GLib.timeout_add_seconds(20, self._watch_state)

    def _style(self):
        settings = Gtk.Settings.get_default()
        settings.set_property('gtk-font-name','Noto Sans 10')
        settings.set_property('gtk-xft-antialias',1)
        settings.set_property('gtk-xft-hinting',1)
        settings.set_property('gtk-xft-hintstyle','hintslight')
        provider = Gtk.CssProvider(); provider.load_from_data(CSS)
        Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(),provider,Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    def _button(self,text,callback,css=None):
        button = Gtk.Button(label=text); button.connect('clicked',callback)
        if css: button.get_style_context().add_class(css)
        self.controls.append(button)
        return button

    def _build(self):
        header = Gtk.HeaderBar(title='DNS Profile Manager', show_close_button=True)
        header.set_subtitle(f'v{manager.__version__} · Общие настройки CLI и GUI')
        self.set_titlebar(header)
        self.refresh_button = self._button('Обновить',lambda _:self.refresh_profile(),'flat')
        header.pack_end(self.refresh_button)
        layout = box(Gtk.Orientation.HORIZONTAL); self.add(layout)
        sidebar = box(css='sidebar'); sidebar.set_size_request(260,-1)
        layout.pack_start(sidebar,False,False,0)
        caption = label('DNS-ПРОВАЙДЕРЫ','section-caption'); margins(caption,24)
        caption.set_margin_bottom(12); sidebar.pack_start(caption,False,False,0)
        self.profile_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.profile_list.get_style_context().add_class('profile-list')
        side_scroll = Gtk.ScrolledWindow(); side_scroll.set_policy(Gtk.PolicyType.NEVER,Gtk.PolicyType.AUTOMATIC)
        side_scroll.add(self.profile_list); sidebar.pack_start(side_scroll,True,True,0)
        self.profile_list.connect('row-selected',self._select_profile)
        add = self._button('+ Добавить провайдера',lambda _:self.edit_provider(new=True),'flat')
        margins(add,12); sidebar.pack_start(add,False,False,0)
        foot = label('○ Не проверен  ·  ✓ Работает\n⚠ Частично  ·  ✕ Не работает','muted')
        margins(foot,18); sidebar.pack_end(foot,False,False,0)

        main = box(spacing=16); margins(main,24)
        layout.pack_start(main,True,True,0)
        current = box(spacing=6,css='current-card'); inner = box(spacing=5); margins(inner,16); current.add(inner)
        inner.add(label('ТЕКУЩИЙ DNS / ОСНОВНОЙ МАРШРУТ','section-caption'))
        self.current_label = label('Определяю профиль…','current-name')
        self.current_label.set_ellipsize(Pango.EllipsizeMode.END)
        self.current_label.set_max_width_chars(50)
        inner.add(self.current_label)
        self.route_label = label('','muted'); self.route_label.set_line_wrap(True); inner.add(self.route_label)
        main.pack_start(current,False,False,0)

        detail = box(spacing=8)
        heading = box(Gtk.Orientation.HORIZONTAL,8)
        self.profile_title = label('','profile-title'); heading.pack_start(self.profile_title,True,True,0)
        self.edit_button = self._button('Настроить',lambda _:self.edit_provider(),'flat'); heading.pack_end(self.edit_button,False,False,0)
        results_button = Gtk.Button(label='Результаты')
        results_button.get_style_context().add_class('flat')
        results_button.connect('clicked', lambda _: self.open_checker())
        heading.pack_end(results_button, False, False, 0)
        detail.add(heading)
        self.description = label('','description'); self.description.set_line_wrap(True); self.description.set_max_width_chars(70); detail.add(self.description)
        self.addresses = label('','muted'); self.addresses.set_selectable(True); self.addresses.set_line_wrap(True); detail.add(self.addresses)
        self.health_label = label(''); self.health_label.set_line_wrap(True); self.health_label.set_max_width_chars(75); detail.add(self.health_label)
        apply_row = box(Gtk.Orientation.HORIZONTAL,8)
        self.apply_button = self._button('Применить',self.switch_profile,'primary')
        apply_row.pack_start(self.apply_button,False,False,0)
        apply_row.pack_start(self._button('Проверить без переключения',self.check_selected),False,False,0)
        detail.add(apply_row); main.pack_start(detail,False,False,0)

        diagnostics = box(Gtk.Orientation.HORIZONTAL,8)
        diagnostics.add(self._button('Проверить все',self.check_all))
        diagnostics.add(self._button('Статус DNS',lambda _:self._start_task('Получаю статус DNS…','status')))
        main.pack_start(diagnostics,False,False,0)

        report_card = box(css='report-card')
        report_header = box(Gtk.Orientation.HORIZONTAL,8); margins(report_header,10)
        report_header.pack_start(label('Отчёт','report-title'),True,True,0)
        copy_button = Gtk.Button(label='Скопировать'); copy_button.get_style_context().add_class('flat'); copy_button.connect('clicked',self.copy_report)
        report_header.pack_end(copy_button,False,False,0)
        report_header.pack_end(self._button('Подробности сети',lambda _:self._start_task('Собираю конфигурацию…','details'),'flat'),False,False,0)
        report_card.add(report_header); report_card.add(Gtk.Separator())
        self.report = Gtk.TextView(editable=False,cursor_visible=False,wrap_mode=Gtk.WrapMode.WORD_CHAR)
        for side in ('left','right','top','bottom'): getattr(self.report,'set_'+side+'_margin')(14)
        self.report.set_pixels_above_lines(2); self.report.set_pixels_below_lines(2)
        self.buffer = self.report.get_buffer()
        self.buffer.set_text('Проверки обращаются напрямую к серверам выбранного провайдера.\nСистемный DNS и подключения при этом не изменяются.\n\nЦвет показывает результат DNS + HTTPS из текущей сети.\nРезультат устаревает через 15 минут, после смены сети или редактирования провайдера.')
        scroll = Gtk.ScrolledWindow(); scroll.set_policy(Gtk.PolicyType.AUTOMATIC,Gtk.PolicyType.AUTOMATIC); scroll.set_min_content_height(150)
        scroll.add(self.report); report_card.pack_start(scroll,True,True,0)
        main.pack_start(report_card,True,True,0)
        self.status = label('Готово к работе','status'); main.pack_start(self.status,False,False,0)
        self._rebuild_profiles()

    def _rebuild_profiles(self):
        for child in self.profile_list.get_children(): self.profile_list.remove(child)
        self.badges = {}
        for p in self.data['providers']:
            row = Gtk.ListBoxRow(); row.provider_id = p['id']; row.get_style_context().add_class('profile-row')
            content = box(Gtk.Orientation.HORIZONTAL,10)
            texts = box(spacing=4)
            name = label(p['name'],'profile-name'); name.set_ellipsize(Pango.EllipsizeMode.END); name.set_max_width_chars(23)
            texts.add(name); texts.add(label(manager.MODE_NAMES[p['mode']],'profile-kind'))
            content.pack_start(texts,True,True,0)
            badge = label('○'); content.pack_end(badge,False,False,0); self.badges[p['id']] = badge
            row.add(content); self.profile_list.add(row)
        self.profile_list.show_all()
        for row in self.profile_list.get_children():
            if row.provider_id == self.selected_id: self.profile_list.select_row(row); break
        self._update_badges()

    def _select_profile(self,_list,row):
        if row is None: return
        self.selected_id = row.provider_id
        self._update_detail()

    def _update_detail(self):
        p = manager.provider(self.data,self.selected_id)
        self.profile_title.set_text(p['name'])
        self.description.set_text(p.get('description',''))
        servers = ', '.join(p['servers']) if p['servers'] else 'DHCP активных подключений'
        self.addresses.set_text(f'{manager.MODE_NAMES[p["mode"]]} · {servers}\n' + (f'TLS: {p["tls_hostname"]} · ' if p['mode']=='dot' else '') + f'CLI: {p["command"]}')
        active = self.current.get('id') == p['id'] and self.current.get('config_matches') and self.current.get('effective_matches')
        apply_label = 'Уже подключён' if active else 'Получать DNS по DHCP' if p['mode'] == 'dhcp' else 'Применить'
        self.apply_button.set_label(apply_label)
        self.apply_button.set_sensitive(not self.busy and not active)
        item = self.health.get(p['id'])
        state = item['state'] if item else 'unknown'
        icon,color,text = HEALTH[state]
        issue = ('; '.join(item['issues'][:3]) if item and item['issues'] else 'DNS и HTTPS отвечают' if state=='green' else 'Запустите проверку: системный DNS не изменится.')
        self.health_label.set_tooltip_text(issue)
        visible_issue = issue if len(issue) <= 180 else issue[:177] + '…'
        markup = f'<span foreground="{color}"><b>{GLib.markup_escape_text(icon)} {GLib.markup_escape_text(text)}</b>'
        if item:
            markup += '\n' + GLib.markup_escape_text(visible_issue)
        markup += '</span>'
        self.health_label.set_markup(markup)

    def _update_badges(self):
        for ident,badge in self.badges.items():
            item = self.health.get(ident)
            icon,color,text = HEALTH[item['state'] if item else 'unknown']
            badge.set_markup(f'<span foreground="{color}" size="large"><b>{icon}</b></span>')
            badge.set_tooltip_text(text + ('\n'+ '\n'.join(item['issues']) + '\n' + item['checked_at'] if item else '\nПроверка ещё не выполнена или устарела.'))
        # The detail card rerenders only when checked results or the active profile changed;
        # selection changes call _update_detail directly.
        signature = ([(ident, item.get('state'), item.get('checked_at')) for ident, item in sorted(self.health.items())],
                     (self.current.get('id'), self.current.get('config_matches'), self.current.get('effective_matches')))
        if signature != self._health_signature:
            self._health_signature = signature
            if hasattr(self,'health_label'): self._update_detail()

    def _set_status(self,text,state=None):
        self.status.set_text(text)
        context = self.status.get_style_context()
        for name in ('error','success'): context.remove_class(name)
        if state: context.add_class(state)

    def refresh_profile(self):
        if self.busy or self.refresh_in_progress: return
        self.refresh_generation += 1; generation = self.refresh_generation
        self.refresh_in_progress = True
        self.refresh_button.set_sensitive(False)
        def worker():
            try:
                data = manager.load_config(); state = manager.current_state(data)
                health = manager.health_results(data,state['network'])
                GLib.idle_add(self._loaded,generation,data,state,health,None)
            except Exception as exc:
                GLib.idle_add(self._loaded,generation,None,None,None,str(exc))
        threading.Thread(target=worker,daemon=True).start()

    def _loaded(self,generation,data,state,health,error):
        if generation != self.refresh_generation: return False
        self.refresh_in_progress = False
        if self.busy: return False
        self.refresh_button.set_sensitive(True)
        if error:
            self.current_label.set_text('Ошибка чтения состояния'); self._set_status(error,'error'); return False
        changed = data != self.data
        self.data,self.current,self.health = data,state,health
        self.current_label.set_text(state['name'] + (' · настройки изменены' if state['id'] and not state['config_matches'] else ''))
        route = state['route']; interfaces=', '.join(c['interface'] for c in state['connections']) or 'нет активных известных подключений'
        self.route_label.set_text(f'Маршрут: {route["interface"] or "нет"} через {route["gateway"] or "—"} · Активны: {interfaces}')
        if not state['effective_matches']: self.route_label.set_text(self.route_label.get_text()+'\nКонфиг resolved и фактический DNS различаются.')
        if self.initial_selection:
            self.initial_selection=False
            if state['id']: self.selected_id=state['id']
            changed=True
        if self.selected_id not in [p['id'] for p in data['providers']]: self.selected_id='provider'
        if changed: self._rebuild_profiles()
        else: self._update_badges()
        if self.checker and not self.checker.busy:
            checker_changed = self.checker.data != data or self.checker.results != health or self.checker.current.get('network') != state.get('network')
            if checker_changed:
                view = self.checker.selector.get_active_id()
                if view not in [p['id'] for p in data['providers']]:
                    view = self.selected_id
                self.checker.configure(data, health, view, state)
        return False

    def _setup_config_watch(self):
        """Providers/network file changes replace the previous 5-second polling."""
        self._config_pending = False
        monitor = None
        try:
            directory = Gio.File.new_for_path(str(manager.CONFIG.parent))
            monitor = directory.monitor_directory(Gio.FileMonitorFlags.NONE)
            monitor.connect('changed', self._on_config_activity)
        except (OSError, GLib.Error):
            monitor = None
        self._config_monitor = monitor

    def _on_config_activity(self,*_):
        if self.busy or self._config_pending: return None
        self._config_pending = True
        GLib.timeout_add(800,self._config_refresh_timeout,priority=GLib.PRIORITY_DEFAULT_IDLE)
        return None

    def _config_refresh_timeout(self):
        self._config_pending = False
        if not self.busy: self.refresh_profile()
        return False

    def _watch_state(self):
        if not self.busy: self.refresh_profile()
        return True

    def _confirm(self,title,text):
        d=Gtk.MessageDialog(transient_for=self,modal=True,message_type=Gtk.MessageType.QUESTION,buttons=Gtk.ButtonsType.NONE,text=title)
        d.format_secondary_text(text); d.add_button('Отмена',Gtk.ResponseType.CANCEL); d.add_button('Продолжить',Gtk.ResponseType.OK)
        response=d.run(); d.destroy(); return response==Gtk.ResponseType.OK

    def switch_profile(self,_button): self._apply(self.selected_id)

    def _apply(self,ident):
        p=manager.provider(self.data,ident)
        title = 'Получать DNS от провайдера по DHCP?' if ident == 'provider' else 'Подключить '+p['name']+'?'
        if self._confirm(title, 'Будут изменены DNS только активных Ethernet/Wi-Fi подключений. Маршрут выбирает NetworkManager. Потребуется авторизация администратора.'):
            self._start_task('Подключаю '+p['name']+'…','apply',ident)

    def check_selected(self,_button):
        self._start_task('Проверяю без переключения…','check',self.selected_id)

    def check_all(self,_button):
        self._start_task('Проверяю все DNS без переключения…','check-all')

    def edit_provider(self,new=False):
        if self.busy: return
        d=ProviderEditor(self,None if new else manager.provider(self.data,self.selected_id))
        while d.run()==Gtk.ResponseType.OK:
            try:
                data,ident=d.value()
                manager.save_config(data,expected_hash=d.expected_hash)
                self.selected_id=ident
                self.data=data
                self.health.pop(ident, None)
                if self.current.get('id') == ident:
                    self.current = {**self.current, 'config_matches': False}
                self._rebuild_profiles()
                d.destroy(); self.refresh_profile()
                self._set_status('Конфиг и CLI-команды сохранены. Текущий DNS не изменён.','success')
                return
            except (manager.ManagerError,ValueError,OSError) as exc:
                d.error.set_markup('<span foreground="#bc3f42">'+GLib.markup_escape_text(str(exc))+'</span>')
        d.destroy()

    def _show_progress(self,title,cancellable=False):
        self.progress=Gtk.Dialog(title='Выполняется операция',transient_for=self,modal=True,destroy_with_parent=True)
        self.progress.set_resizable(False); self.progress.set_default_size(440,-1)
        self.progress.set_position(Gtk.WindowPosition.CENTER_ON_PARENT)
        self.progress.connect('delete-event',lambda *_:True); self.progress.connect('response',lambda *_:None)
        content=self.progress.get_content_area(); margins(content,28); content.set_spacing(16)
        spinner=Gtk.Spinner(); spinner.set_size_request(32,32); spinner.set_halign(Gtk.Align.CENTER); spinner.start(); content.add(spinner)
        self.progress_label=label(title,'progress-title'); self.progress_label.set_line_wrap(True); self.progress_label.set_max_width_chars(40); content.add(self.progress_label)
        content.add(label('Результат появится в отчёте','muted'))
        if cancellable:
            cancel=Gtk.Button(label='Отмена')
            cancel.set_halign(Gtk.Align.CENTER)
            cancel.connect('clicked',self._cancel_clicked)
            content.add(cancel)
            self.progress_cancel=cancel
        self.progress.show_all()

    def open_checker(self, selected=None):
        if self.checker is None:
            self.checker = GatewayChecker(self, lambda ident: self._start_task('Проверяю без переключения…', 'check', ident))
        if not self.busy:
            self.checker.configure(self.data, self.health, selected or self.selected_id, self.current)
        self.checker.show_all()
        self.checker.present()
        return self.checker

    def _checker_event(self, event):
        if self.checker:
            self.checker.receive(event)
        return False

    def _start_task(self,title,operation,ident=None):
        if self.busy: return
        checking = operation in ('check', 'check-all')
        if checking:
            self.open_checker(ident or self.selected_id)
        self.operation = operation
        self.operation_results = []
        self.cancel_event.clear()
        self.busy=True; self.refresh_generation+=1; self.refresh_in_progress=False; self.buffer.set_text(''); self._set_status(title)
        for c in self.controls: c.set_sensitive(False)
        self.profile_list.set_sensitive(False)
        if checking:
            self.checker.start()
        else:
            # Switching DNS is one short privileged operation; it must not be interrupted.
            self._show_progress(title,operation in ('status','details'))
        def emit(text): GLib.idle_add(self._receive_line,text,priority=GLib.PRIORITY_DEFAULT_IDLE)
        def worker():
            code=0
            try:
                if operation=='apply': manager.apply_profile(ident,emit,gui=True)
                elif operation in ('status','details'): manager.diagnostic(operation=='details',emit,self.cancel_event.is_set)
                else:
                    ids=[p['id'] for p in manager.load_config()['providers']] if operation=='check-all' else [ident]
                    for index, item in enumerate(ids):
                        if self.cancel_event.is_set():
                            emit('Операция отменена: следующие профили не проверялись.')
                            break
                        def event(packet, index=index):
                            packet = dict(packet, overall_progress=(index + packet.get('progress', 0)) / len(ids), batch_index=index+1, batch_total=len(ids))
                            GLib.idle_add(self._checker_event,packet,priority=GLib.PRIORITY_DEFAULT_IDLE)
                        try:
                            result=manager.check_provider(item,emit,on_event=event,should_stop=self.cancel_event.is_set)
                        except Exception as exc:
                            if self.cancel_event.is_set():
                                emit('Проверка '+item+' отменена.')
                            else:
                                code=1; emit('Ошибка: '+str(exc))
                            continue
                        GLib.idle_add(self._receive_health,result,priority=GLib.PRIORITY_DEFAULT_IDLE)
            except Exception as exc:
                if self.cancel_event.is_set():
                    emit('Операция отменена.')
                else:
                    code=1; emit('Ошибка: '+str(exc))
            GLib.idle_add(self._finish,code,priority=GLib.PRIORITY_DEFAULT_IDLE)
        threading.Thread(target=worker,daemon=True).start()

    def _cancel_clicked(self,_button):
        if not self.can_cancel(): return
        self.cancel_event.set()
        if self.progress:
            self.progress_label.set_text('Отмена запрошена: текущий этап завершится, новые не начнутся.')
        if getattr(self,'progress_cancel',None):
            self.progress_cancel.set_sensitive(False)

    def cancel_check(self):
        """Cancel hook for the GatewayChecker panel (check / check-all)."""
        if not self.can_cancel(): return
        self.cancel_event.set()

    def can_cancel(self):
        return self.busy and self.operation in ('status','details','check','check-all')

    def _receive_line(self,text):
        if self.progress and self.progress_label:
            self.progress_label.set_text(text[-250:])
        self._pending_report.append(text)
        if not self._flush_scheduled:
            self._flush_scheduled=GLib.timeout_add(150,self._flush_report,priority=GLib.PRIORITY_DEFAULT_IDLE)
        return False

    def _flush_report(self):
        self._flush_scheduled=None
        if self._pending_report:
            text='\n'.join(self._pending_report)
            self._pending_report=[]
            self.buffer.insert(self.buffer.get_end_iter(),text+'\n')
        return False

    def _receive_health(self,result):
        self.health[result['id']]=result
        self.operation_results.append(result)
        self.buffer.insert(self.buffer.get_end_iter(),'\n'+manager.format_health(result)+'\n')
        self._update_badges(); return False

    def _finish(self,code):
        if self._flush_scheduled:
            GLib.source_remove(self._flush_scheduled); self._flush_scheduled=None
        self._flush_report()
        cancelled=self.cancel_event.is_set()
        if self.progress: self.progress.destroy(); self.progress=None
        self.busy=False
        if self.operation in ('check', 'check-all') and self.checker:
            self.checker.finish(error=code != 0 and not cancelled,cancelled=cancelled)
        for c in self.controls: c.set_sensitive(True)
        self.profile_list.set_sensitive(True); self._update_detail()
        if cancelled:
            self._set_status('Операция отменена. Частичные результаты — в отчёте.')
        elif code:
            self._set_status('Ошибка — подробности в отчёте', 'error')
        elif self.operation_results and any(r['state'] != 'green' for r in self.operation_results):
            self._set_status('Проверка завершена: есть ограничения — см. карточки сервисов')
        else:
            self._set_status('Операция завершена', 'success')
        self.refresh_profile(); return False

    def copy_report(self,_button):
        text=self.buffer.get_text(self.buffer.get_start_iter(),self.buffer.get_end_iter(),True)
        Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text(text,-1)

    def _close(self,*_):
        if self.busy:
            if self.progress: self.progress.present()
            elif self.checker: self.checker.present()
            return True
        Gtk.main_quit(); return False


def main():
    if sys.argv[1:] == ['--version']:
        print('DNS Profile Manager ' + manager.__version__)
        return
    try: window=DnsGui()
    except (manager.ManagerError,OSError) as exc:
        d=Gtk.MessageDialog(message_type=Gtk.MessageType.ERROR,buttons=Gtk.ButtonsType.CLOSE,text='Не удалось открыть DNS Manager')
        d.format_secondary_text(str(exc)); d.run(); d.destroy(); return
    window.show_all(); Gtk.main()


if __name__=='__main__': main()
