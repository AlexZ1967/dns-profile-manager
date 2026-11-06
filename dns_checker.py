"""GTK service diagnostics dashboard. Network work stays in dns_manager."""
import gi

gi.require_version('Gtk', '3.0')
gi.require_version('Gdk', '3.0')
from gi.repository import Gdk, GLib, Gtk, Pango
import dns_manager as manager

ms = manager.ms

CSS = b'''
window.gateway-checker { background: #0a1221; color: #ecf3ff; }
.gateway-checker label { color: #e7effd; }
.gateway-checker .check-title { font-size: 23px; font-weight: 700; }
.gateway-checker .check-muted { color: #9daec9; font-size: 12px; }
.gateway-checker .check-caption { color: #8da2c3; font-size: 11px; font-weight: 600; }
.gateway-checker .check-banner { background: #112238; border: 1px solid #233c56; border-radius: 12px; padding: 18px; }
.gateway-checker .check-result { font-size: 18px; font-weight: 600; }
.gateway-checker .service-probe { background: #101e33; border: 1px solid #25384f; border-radius: 11px; padding: 14px; }
.gateway-checker .service-name { font-size: 15px; font-weight: 600; }
.gateway-checker .service-host { color: #8ea4c4; font-size: 11px; }
.gateway-checker .service-status { font-size: 13px; font-weight: 600; }
.gateway-checker .service-stages { color: #b9c9df; font-size: 11px; }
.gateway-checker .service-detail { color: #9daec9; font-size: 11px; }
.gateway-checker .check-metric { background: #0e1c2e; border: 1px solid #22344a; border-radius: 9px; padding: 14px; }
.gateway-checker .metric-value { color: #64dec5; font-size: 17px; font-weight: 600; }
.gateway-checker button { background: #14253b; background-image: none; color: #d9e7fd; border: 1px solid #2a415d; border-radius: 8px; padding: 9px 17px; text-shadow: none; box-shadow: none; }
.gateway-checker button:hover { background: #1a3150; }
.gateway-checker button:disabled { background: #192b3f; color: #7288a3; }
.gateway-checker button.check-again { border-radius: 22px; background: #51ddb1; color: #081923; border-color: #51ddb1; font-weight: 700; }
.gateway-checker button.check-again:hover { background: #73edc7; }
.gateway-checker button.check-again:disabled { background: #23524b; color: #81aaa0; border-color: #23524b; }
.gateway-checker combobox button { background: #14253b; color: #d9e7fd; }
.gateway-checker progressbar trough { background: #182b41; min-height: 6px; border: none; border-radius: 4px; }
.gateway-checker progressbar progress { background: #56dbca; min-height: 6px; border: none; border-radius: 4px; }
.gateway-checker textview, .gateway-checker textview text { background: #0d1b2c; color: #becde1; font-family: 'Noto Sans Mono', monospace; font-size: 12px; }
.gateway-checker expander { color: #c3d3e9; }
'''
COLORS = {'green': '#62dfb5', 'yellow': '#f2c16d', 'red': '#fb899b', 'unknown': '#96a9c7', 'checking': '#65d2ed'}
STATES = {'green': '✓ Доступен', 'yellow': '⚠ Ограничен / частично', 'red': '✕ Недоступен', 'unknown': '○ Не проверен', 'checking': '… Проверяется'}


def text(value='', css=None):
    widget = Gtk.Label(label=value, xalign=0)
    if css:
        widget.get_style_context().add_class(css)
    return widget


def column(spacing=0, css=None):
    widget = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=spacing)
    if css:
        widget.get_style_context().add_class(css)
    return widget


class GatewayChecker(Gtk.Window):
    def __init__(self, parent, repeat):
        super().__init__(title='Проверка DNS-профиля и ИИ-сервисов', transient_for=parent)
        self.set_destroy_with_parent(True)
        self.set_default_size(1080, 800)
        self.set_size_request(720, 540)
        self.set_position(Gtk.WindowPosition.CENTER_ON_PARENT)
        self.get_style_context().add_class('gateway-checker')
        provider = Gtk.CssProvider()
        provider.load_from_data(CSS)
        Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        self.repeat = repeat
        self.owner = parent
        self.busy = False
        self.failed = False
        self.results = {}
        self.partials = {}
        self.cards = {}
        self.data = None
        self.current = {}
        self.connect('delete-event', self._hide)
        self.connect('key-press-event', self._key)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.add(scroll)
        content = column(18)
        for side in ('top','bottom','start','end'):
            getattr(content, 'set_margin_' + side)(24)
        scroll.add(content)
        content.add(text('Проверка доступа к ИИ-сервисам', 'check-title'))
        intro = text('DNS выбранного профиля → TCP → TLS → HTTPS. Без переключения системного DNS.', 'check-muted')
        intro.set_line_wrap(True)
        content.add(intro)
        toolbar = Gtk.Box(spacing=12)
        self.selector = Gtk.ComboBoxText()
        self.selector.connect('changed', lambda _: self.render())
        toolbar.pack_start(self.selector, True, True, 0)
        self.stop = Gtk.Button(label='Отмена')
        self.stop.set_sensitive(False)
        self.stop.connect('clicked', lambda _: self.owner.cancel_check() if self.owner else None)
        toolbar.pack_start(self.stop, False, False, 0)
        self.retry = Gtk.Button(label='Проверить профиль')
        self.retry.get_style_context().add_class('check-again')
        self.retry.connect('clicked', lambda _: self.repeat(self.selector.get_active_id()))
        toolbar.pack_start(self.retry, False, False, 0)
        close = Gtk.Button(label='Закрыть')
        close.connect('clicked', self._hide)
        toolbar.pack_end(close, False, False, 0)
        content.add(toolbar)
        progress = column(7)
        self.bar = Gtk.ProgressBar(show_text=False)
        progress.add(self.bar)
        self.phase = text('Готово к проверке', 'check-muted')
        self.phase.set_line_wrap(True)
        progress.add(self.phase)
        content.add(progress)
        banner = column(7, 'check-banner')
        self.result_title = text('Выберите профиль и запустите проверку', 'check-result')
        self.result_title.set_line_wrap(True)
        banner.add(self.result_title)
        self.context = text('', 'check-muted')
        self.context.set_line_wrap(True)
        banner.add(self.context)
        content.add(banner)
        self.flow = Gtk.FlowBox()
        self.flow.set_selection_mode(Gtk.SelectionMode.NONE)
        self.flow.set_homogeneous(True)
        self.flow.set_min_children_per_line(2)
        self.flow.set_max_children_per_line(4)
        self.flow.set_column_spacing(12)
        self.flow.set_row_spacing(12)
        content.add(self.flow)
        self.metrics = {}
        metric_grid = Gtk.Grid(column_spacing=12, row_spacing=12, column_homogeneous=True)
        for index, (key, caption) in enumerate([
            ('ai', 'ИИ-СЕРВИСЫ'), ('servers', 'DNS-СЕРВЕРЫ'), ('https', 'ОТВЕТ HTTPS · МЕДИАНА'),
            ('tcp', 'TCP · МЕДИАНА'), ('protocol', 'ПРОТОКОЛ DNS'), ('route', 'ОСНОВНОЙ ИНТЕРФЕЙС')]):
            tile = column(7, 'check-metric')
            tile.add(text(caption, 'check-caption'))
            value = text('—', 'metric-value')
            value.set_ellipsize(Pango.EllipsizeMode.END)
            value.set_max_width_chars(25)
            tile.add(value)
            self.metrics[key] = value
            metric_grid.attach(tile, index % 3, index // 3, 1, 1)
        content.add(metric_grid)
        note = text('Время измеряется по фактическим запросам, это не оценка RTT. Проверяется сетевой доступ без входа в аккаунт; зелёный статус не гарантирует работу генерации или отсутствие CAPTCHA после авторизации.', 'check-muted')
        note.set_line_wrap(True)
        note.set_max_width_chars(110)
        content.add(note)
        expander = Gtk.Expander(label='Технические подробности и причины ошибок')
        self.report = Gtk.TextView(editable=False, cursor_visible=False, wrap_mode=Gtk.WrapMode.WORD_CHAR)
        for side in ('left','right','top','bottom'):
            getattr(self.report, 'set_' + side + '_margin')(12)
        self.buffer = self.report.get_buffer()
        detail_scroll = Gtk.ScrolledWindow()
        detail_scroll.set_min_content_height(230)
        detail_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        detail_scroll.add(self.report)
        expander.add(detail_scroll)
        content.add(expander)
        copy = Gtk.Button(label='Скопировать технический отчёт')
        copy.set_halign(Gtk.Align.START)
        copy.connect('clicked', self._copy)
        content.add(copy)

    def configure(self, data, results, selected, current):
        self.data = data
        self.failed = False
        self.partials = {}
        self.results = dict(results)
        self.current = current
        self.selector.remove_all()
        for provider in data['providers']:
            self.selector.append(provider['id'], provider['name'])
        self._build_cards(manager.diagnostic_services(data))
        self.selector.set_active_id(selected)
        self.render()

    def _build_cards(self, services):
        signature = [(s['id'], s['name'], s['host']) for s in services]
        if getattr(self, '_catalog', None) == signature:
            return
        self._catalog = signature
        for child in self.flow.get_children():
            self.flow.remove(child)
        self.cards = {}
        for service in services:
            card = column(8, 'service-probe')
            card.set_size_request(200, -1)
            heading = Gtk.Box(spacing=8)
            glyphs = {'claude': ('✦','#f2bd7b'), 'gemini': ('✧','#7fc8f3'), 'chatgpt': ('◎','#74ddbb'), 'perplexity': ('P','#6bd7e2'), 'aistudio': ('AI','#bca4f2'), 'antigravity': ('△','#a8c3f3'), 'github': ('GH','#bdcce2')}
            glyph, color = glyphs.get(service['id'], (service['name'][0].upper(), '#a8c3f3'))
            icon = text()
            icon.set_size_request(28, 28)
            icon.set_markup(f'<span foreground="{color}" size="large"><b>{GLib.markup_escape_text(glyph)}</b></span>')
            heading.pack_start(icon, False, False, 0)
            name = text(service['name'], 'service-name')
            name.set_ellipsize(Pango.EllipsizeMode.END)
            heading.pack_start(name, True, True, 0)
            card.add(heading)
            host = text(service['host'], 'service-host')
            host.set_ellipsize(Pango.EllipsizeMode.END)
            host.set_max_width_chars(28)
            card.add(host)
            status = text('', 'service-status')
            status.set_line_wrap(True)
            card.add(status)
            stages = text('', 'service-stages')
            stages.set_line_wrap(True)
            card.add(stages)
            response = text('', 'service-stages')
            card.add(response)
            detail = text('', 'service-detail')
            detail.set_line_wrap(True)
            detail.set_max_width_chars(30)
            detail.set_ellipsize(Pango.EllipsizeMode.END)
            detail.set_lines(2)
            card.add(detail)
            self.cards[service['id']] = (card, status, stages, response, detail)
            self.flow.add(card)
        self.flow.show_all()

    def start(self):
        self.busy = True
        self.failed = False
        self.partials = {}
        self.stop.set_sensitive(True)
        self.retry.set_sensitive(False)
        self.bar.set_fraction(0)
        self.phase.set_text('Подготовка DNS-запросов…')
        self.render()
        self.show_all()
        self.present()

    def receive(self, event):
        ident = event['id']
        if event['kind'] == 'start':
            self.partials[ident] = {'services': {}, 'profile': event['profile'], 'route': event['route']}
        elif event['kind'] == 'service':
            self.partials.setdefault(ident, {'services': {}})['services'][event['service']['id']] = event['service']
        elif event['kind'] == 'finished':
            self.add_result(event['result'])
        self.bar.set_fraction(max(self.bar.get_fraction(), min(1, event.get('overall_progress', 0))))
        phase = event.get('phase', 'Готово' if event['kind'] == 'finished' else 'DNS')
        count = f' {event["completed"]}/{event["total"]}' if 'completed' in event else ''
        batch = f' · профиль {event["batch_index"]}/{event["batch_total"]}' if event.get('batch_total', 1) > 1 else ''
        self.phase.set_text(f'{event["name"]}{batch} · {phase}{count}')
        self.render()
        return False

    def add_result(self, result):
        self.results[result['id']] = result
        self.partials.pop(result['id'], None)
        self.render()

    def finish(self, error=False, cancelled=False):
        self.busy = False
        self.failed = error
        if error or cancelled:
            self.partials = {}
        self.retry.set_sensitive(True)
        self.stop.set_sensitive(False)
        self.retry.set_label('Проверить снова')
        if cancelled:
            self.bar.set_fraction(0)
            self.phase.set_text('Проверка отменена')
        else:
            if not error:
                self.bar.set_fraction(1)
            self.phase.set_text('Проверка завершена' if not error else 'Проверка прервана ошибкой — см. отчёт основного окна')
        self.render()

    def render(self):
        ident = self.selector.get_active_id()
        if not self.data or not ident or not self.cards:
            return
        provider = manager.provider(self.data, ident)
        result = self.results.get(ident)
        partial = self.partials.get(ident)
        services = {s['id']: s for s in result.get('services', [])} if result else {}
        if partial is not None:
            services = partial['services']
        for service in manager.diagnostic_services(self.data):
            _, status, stages, response, detail = self.cards[service['id']]
            item = services.get(service['id'], {})
            state = item.get('state', 'checking' if partial is not None else 'unknown')
            status.set_markup(f'<span foreground="{COLORS[state]}">{STATES[state]}</span>')
            pending = '…' if state == 'checking' else '—'
            dns_mark = '✓' if item.get('dns_ok') else pending
            tcp_mark = '✓' if item.get('tcp_ok') else pending
            tls_mark = '✓' if item.get('tls_ok') else pending
            stages.set_text(f'DNS {dns_mark} {ms(item.get("dns_ms"))} · TCP {tcp_mark} {ms(item.get("tcp_ms"))}\nTLS {tls_mark} {ms(item.get("tls_ms"))}')
            codes = ', '.join(map(str, item.get('http_codes', [])))
            response.set_text(('HTTP ' + codes if codes else 'HTTP —') + ' · ' + ms(item.get('https_ms')))
            explanation = item.get('detail', 'Ожидается результат')
            detail.set_text(explanation)
            self.cards[service['id']][0].set_tooltip_text('\n'.join([service['host'], *item.get('issues', []), 'IP: ' + ', '.join(item.get('addresses', []))]))
        snapshot = partial.get('route', {}) if partial is not None else (result.get('route', {}) if result else self.current.get('route', {}))
        self.context.set_text(f'Проверяемый профиль: {provider["name"]} · системный DNS при запуске: {self.current.get("name", "—")}\nIPv4: {snapshot.get("interface") or "нет маршрута"} через {snapshot.get("gateway") or "—"} · без прокси и без переключения профиля')
        if result and partial is None:
            self.context.set_text(self.context.get_text() + '\nПоследняя проверка: ' + result['checked_at'])
        if self.failed:
            self.result_title.set_text('Проверка не завершена — ниже могут быть предыдущие данные')
        elif partial is not None:
            self.result_title.set_text('Проверка профиля выполняется…')
        elif result:
            state = result['state']
            title = {'green': 'Профиль отвечает: DNS и HTTPS доступны', 'yellow': 'Профиль работает частично — есть ограничения', 'red': 'Нет корректных ответов DNS', 'unknown': 'Недостаточно данных для вывода'}[state]
            self.result_title.set_markup(f'<span foreground="{COLORS[state]}">{title}</span>')
        else:
            self.result_title.set_text('Запустите проверку выбранного профиля')
        summary = result.get('summary', {}) if result and partial is None else {}
        self.metrics['ai'].set_text(f'{summary["ai_ok"]} / {summary["ai_total"]}' if summary else '—')
        self.metrics['servers'].set_text(f'{summary["dns_servers_ok"]} / {summary["dns_servers_total"]}' if summary else '—')
        self.metrics['https'].set_text(ms(summary.get('https_ms')))
        self.metrics['tcp'].set_text(ms(summary.get('tcp_ms')))
        self.metrics['protocol'].set_text(manager.MODE_NAMES[provider['mode']])
        self.metrics['protocol'].set_tooltip_text(f'Порт {provider["port"]}' + (' · сертификат проверяется для ' + provider['tls_hostname'] if provider['mode'] == 'dot' else ''))
        self.metrics['route'].set_text(snapshot.get('interface') or '—')
        self.buffer.set_text('Проверка выполняется. Подробный отчёт обновится после её завершения.' if partial is not None else manager.format_health(result) if result else 'После проверки здесь появятся DNS-ответы, измеренные этапы HTTPS и цепочки перенаправлений.')
        if not self.busy:
            self.retry.set_label('Проверить снова' if result else 'Проверить профиль')

    def _copy(self, _button):
        body = self.buffer.get_text(self.buffer.get_start_iter(), self.buffer.get_end_iter(), True)
        Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text(body, -1)

    def _hide(self, *_):
        self.hide()
        return True

    def _key(self, _window, event):
        if event.keyval == Gdk.KEY_Escape:
            self.hide()
            return True
        return False
