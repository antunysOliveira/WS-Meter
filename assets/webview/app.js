'use strict';

// ---------- Class colors ----------
var CLASS_COLORS = (window.CLASS_COLORS || {});
var REDUCE_MOTION = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

// ---------- IPC ----------
function sendCmd(cmd, args) {
    if (window.chrome && window.chrome.webview) {
        window.chrome.webview.postMessage({ cmd: cmd, args: args || {} });
    } else {
        console.log('[dev-mode] would send', cmd, args);
    }
}

if (window.chrome && window.chrome.webview) {
    window.chrome.webview.addEventListener('message', function (e) {
        var msg = e.data;
        if (!msg || !msg.type) return;
        switch (msg.type) {
            case 'leaderboard': renderLeaderboard(msg.rows); break;
            case 'timer':       updateTimer(msg.boutSec); break;
            case 'status':      setStatus(msg.text); break;
            case 'capture':     setCaptureState(msg.state); break;
            case 'area':        setAreaCount(msg); break;
            case 'players':     renderPlayers(msg.roster); break;
        }
    });
}

// ---------- Formatting ----------
function fmtNumber(n) {
    if (n === null || n === undefined) return '--';
    n = Math.round(n);
    if (n < 1000) return String(n);
    if (n < 10000) return (n / 1000).toFixed(2) + 'K';
    if (n < 1000000) return (n / 1000).toFixed(1) + 'K';
    return (n / 1000000).toFixed(2) + 'M';
}
function fmtDps(n) {
    if (!n || n <= 0) return '--';
    return n.toFixed(2);
}

// ---------- Color helpers ----------
function hexToRgba(hex, a) {
    if (!hex || hex.length < 7) return 'rgba(120,120,120,' + a + ')';
    var r = parseInt(hex.substr(1, 2), 16);
    var g = parseInt(hex.substr(3, 2), 16);
    var b = parseInt(hex.substr(5, 2), 16);
    return 'rgba(' + r + ',' + g + ',' + b + ',' + a + ')';
}
function classColor(classId) {
    if (!classId) return null;
    return CLASS_COLORS[String(classId)] || null;
}

// ---------- Row state ----------
// Map<id, { tr, cells, values, isHealOnly }>
var rowMap = new Map();
var dividerRow = null;
var lastParticipants = [];
var currentRank = 'all';   // 'all' | 'raid' | 'chefe' | 'forte' | 'comum'
function damageFor(r) {
    if (!r) return 0;
    switch (currentRank) {
        case 'raid':  return r.damageRaid  || 0;
        case 'chefe': return r.damageChefe || 0;
        case 'forte': return r.damageForte || 0;
        case 'comum': return r.damageComum || 0;
        default:      return r.damage      || 0;
    }
}

// Persisted setting: show aggregated "Mobs (N)" row. Off by default.
var showMobs = false;
try { showMobs = localStorage.getItem('ws:showMobs') === '1'; } catch (e) {}
function isMobRowId(id) { return id === 'mobs' || id === 'unresolved'; }

// ---------- Row DOM factory ----------
var NUM_COLS = [
    { key: 'damage',       cls: 'col-num col-damage sorted' },
    { key: 'received',     cls: 'col-num col-received' },
    { key: 'healingDone',  cls: 'col-num col-heal-done' },
    { key: 'dps',          cls: 'col-num col-dps' },
    { key: 'max',          cls: 'col-num col-max' }
];

function createRow() {
    var tr = document.createElement('tr');

    var tdName = document.createElement('td');
    tdName.className = 'col-name';
    var bar = document.createElement('div');
    bar.className = 'dmg-bar';
    var inner = document.createElement('div');
    inner.className = 'name-inner';
    var icon = document.createElement('span');
    icon.className = 'class-icon';
    var nameText = document.createElement('span');
    nameText.className = 'name-text';
    inner.appendChild(icon);
    inner.appendChild(nameText);
    tdName.appendChild(bar);
    tdName.appendChild(inner);
    tr.appendChild(tdName);

    var buffStrip = document.createElement('span');
    buffStrip.className = 'lb-buffs';
    inner.appendChild(buffStrip);

    var cells = { bar: bar, icon: icon, nameText: nameText, buffStrip: buffStrip };
    for (var i = 0; i < NUM_COLS.length; i++) {
        var td = document.createElement('td');
        td.className = NUM_COLS[i].cls;
        td.textContent = '--';
        tr.appendChild(td);
        cells[NUM_COLS[i].key] = td;
    }

    return { tr: tr, cells: cells, values: {}, isHealOnly: false };
}

// ---------- Animated numeric updates ----------
function animateNumber(td, from, to, fmt) {
    if (to === null || to === undefined) {
        td.textContent = '--';
        return;
    }
    if (REDUCE_MOTION || from === undefined || from === null || from === to) {
        td.textContent = fmt(to);
        return;
    }
    if (td._raf) cancelAnimationFrame(td._raf);
    var start = performance.now();
    var duration = 450;
    function step(now) {
        var t = Math.min(1, (now - start) / duration);
        var e = 1 - Math.pow(1 - t, 3); // ease-out cubic
        var v = from + (to - from) * e;
        td.textContent = fmt(v);
        if (t < 1) td._raf = requestAnimationFrame(step);
        else td._raf = null;
    }
    td._raf = requestAnimationFrame(step);
}

// ---------- Row update ----------
function updateRow(entry, r, maxDmg, isHealOnly) {
    var tr = entry.tr;
    var cells = entry.cells;
    var values = entry.values;

    // Row classes
    var cls = [];
    if (r.unresolved) cls.push('row-unresolved');
    if (isHealOnly) cls.push('row-outoffight');
    tr.className = cls.join(' ');
    entry.isHealOnly = isHealOnly;

    // Icon (only replace when file actually changed)
    var iconFile = r.classIconFile || '';
    if (r.classId && iconFile) {
        if (values.iconFile !== iconFile) {
            cells.icon.innerHTML = '';
            var img = document.createElement('img');
            img.src = '../class-icons/individual/' + iconFile;
            img.alt = '';
            cells.icon.appendChild(img);
            values.iconFile = iconFile;
        }
    } else if (values.iconFile !== '?') {
        cells.icon.innerHTML = '';
        cells.icon.textContent = '?';
        values.iconFile = '?';
    }

    // Class color -> icon border + bar tint
    var color = classColor(r.classId);
    var barGrad;
    if (color) {
        cells.icon.style.borderColor = color;
        barGrad = 'linear-gradient(90deg, ' + hexToRgba(color, 0.42) + ' 0%, ' + hexToRgba(color, 0.10) + ' 100%)';
    } else {
        cells.icon.style.borderColor = '#3a3d47';
        barGrad = 'linear-gradient(90deg, rgba(140,140,140,0.32) 0%, rgba(140,140,140,0.05) 100%)';
    }
    if (values.barGrad !== barGrad) {
        cells.bar.style.background = barGrad;
        values.barGrad = barGrad;
    }

    // Name
    if (values.name !== r.name) {
        cells.nameText.textContent = r.name;
        values.name = r.name;
    }

    // Buffs strip (small discreet icons next to the name)
    var newBuffKey = JSON.stringify((r.buffs || []).map(function (b) { return b.cat + '|' + Math.floor(b.remainSec); }));
    if (values.buffKey !== newBuffKey) {
        cells.buffStrip.innerHTML = '';
        if (Array.isArray(r.buffs)) {
            for (var bi = 0; bi < r.buffs.length; bi++) {
                var b = r.buffs[bi];
                var im = document.createElement('img');
                im.className = 'lb-buff-icon buff-' + (b.cat || 'outro');
                im.src = buffIconPath(b.cat);
                im.alt = b.cat || '';
                im.dataset.name = b.name;
                im.dataset.remain = b.remainSec < 0 ? 'permanente' : formatDurationShort(b.remainSec);
                attachInstantTooltip(im);
                cells.buffStrip.appendChild(im);
            }
        }
        values.buffKey = newBuffKey;
    }

    // Bar width (participants only; hidden on healers via CSS)
    var dmgDisplay = damageFor(r);
    var pct = 0;
    if (!isHealOnly && maxDmg > 0 && dmgDisplay > 0) {
        pct = Math.max(0, (dmgDisplay / maxDmg) * 100);
    }
    if (values.pct !== pct) {
        cells.bar.style.width = pct.toFixed(2) + '%';
        values.pct = pct;
    }

    // Numeric cells
    animateNumber(cells.damage,      values.damage,      dmgDisplay,    fmtNumber);
    animateNumber(cells.received,    values.received,    r.received,    fmtNumber);
    animateNumber(cells.healingDone, values.healingDone, r.healingDone, fmtNumber);
    animateNumber(cells.dps,         values.dps,         r.dps,         fmtDps);
    animateNumber(cells.max,         values.max,         r.max,         fmtNumber);
    values.damage      = dmgDisplay;
    values.received    = r.received;
    values.healingDone = r.healingDone;
    values.dps         = r.dps;
    values.max         = r.max;
}

// ---------- FLIP reorder ----------
function measurePositions() {
    var map = new Map();
    rowMap.forEach(function (entry, id) {
        map.set(id, entry.tr.getBoundingClientRect().top);
    });
    return map;
}
function animateReorder(oldPos) {
    if (REDUCE_MOTION) return;
    rowMap.forEach(function (entry, id) {
        var oldTop = oldPos.get(id);
        if (oldTop === undefined) return;
        var newTop = entry.tr.getBoundingClientRect().top;
        var delta = oldTop - newTop;
        if (Math.abs(delta) < 1) return;
        var tr = entry.tr;
        tr.style.transition = 'none';
        tr.style.transform = 'translateY(' + delta + 'px)';
        // Force reflow, then let transition run.
        // eslint-disable-next-line no-unused-expressions
        tr.offsetHeight;
        requestAnimationFrame(function () {
            tr.style.transition = 'transform 450ms cubic-bezier(0.2, 0.7, 0.3, 1)';
            tr.style.transform = '';
        });
    });
}

// ---------- Render leaderboard (diff-based) ----------
var _lastLbRows = [];
function renderLeaderboard(rows) {
    _lastLbRows = rows || [];
    var tbody = document.getElementById('lb-body');

    // Partition into participants + healers-only. Filter mob aggregate rows
    // client-side when the user has toggled them off (default).
    var participants = [];
    var healOnly = [];
    for (var i = 0; i < rows.length; i++) {
        var r = rows[i];
        if (!showMobs && isMobRowId(r.id)) continue;
        if (r.participant === false) healOnly.push(r); else participants.push(r);
    }
    // Backend sorts by 'damage' (total). When rank filter ativo, re-sort local
    // por damageFor(rank), assim leaderboard reflete "top X em raid/chefe/etc".
    if (currentRank !== 'all') {
        participants.sort(function (a, b) { return damageFor(b) - damageFor(a); });
    }
    healOnly.sort(function (a, b) { return (b.healingDone || 0) - (a.healingDone || 0); });
    lastParticipants = participants.slice();

    // Max damage for bar scaling (participants only) — usa valor filtrado
    var maxDmg = 0;
    for (var j = 0; j < participants.length; j++) {
        var v = damageFor(participants[j]);
        if (v > maxDmg) maxDmg = v;
    }


    // FLIP: measure before mutation
    var oldPos = measurePositions();

    // Collect new ids and remove stale
    var nextIds = {};
    for (var a = 0; a < participants.length; a++) nextIds[participants[a].id] = true;
    for (var b = 0; b < healOnly.length; b++) nextIds[healOnly[b].id] = true;
    rowMap.forEach(function (entry, id) {
        if (!nextIds[id]) {
            entry.tr.remove();
            rowMap.delete(id);
        }
    });

    // Divider row (create/remove as needed)
    var needsDivider = healOnly.length > 0;
    if (needsDivider && !dividerRow) {
        dividerRow = document.createElement('tr');
        dividerRow.className = 'section-divider';
        var dtd = document.createElement('td');
        dtd.colSpan = 6;   // Nome + Dano + Recebido + Cura + DPS + Máx
        dtd.textContent = 'Fora da luta — só cura';
        dividerRow.appendChild(dtd);
    } else if (!needsDivider && dividerRow) {
        dividerRow.remove();
        dividerRow = null;
    }

    // Build desired order and apply
    var desired = [];
    var newlyCreated = [];

    function ensureRow(r, isHealOnly) {
        var entry = rowMap.get(r.id);
        var isNew = false;
        if (!entry) {
            entry = createRow();
            rowMap.set(r.id, entry);
            isNew = true;
        }
        updateRow(entry, r, maxDmg, isHealOnly);
        desired.push(entry.tr);
        if (isNew) newlyCreated.push(entry.tr);
    }

    for (var p = 0; p < participants.length; p++) ensureRow(participants[p], false);
    if (needsDivider) desired.push(dividerRow);
    for (var h = 0; h < healOnly.length; h++) ensureRow(healOnly[h], true);

    // Reorder DOM to match desired sequence with minimal churn.
    // appendChild on an existing child just moves it — safe and cheap.
    for (var d = 0; d < desired.length; d++) tbody.appendChild(desired[d]);

    // FLIP animate reordered rows
    animateReorder(oldPos);

    // Row-enter animation on new rows
    if (!REDUCE_MOTION) {
        for (var n = 0; n < newlyCreated.length; n++) {
            var tr = newlyCreated[n];
            tr.classList.add('row-enter');
            (function (el) {
                setTimeout(function () { el.classList.remove('row-enter'); }, 500);
            })(tr);
        }
    }
}

// ---------- Timer / status / capture ----------
function updateTimer(sec) {
    var s = Math.max(0, Math.floor(sec));
    var m = Math.floor(s / 60);
    var r = s - m * 60;
    document.getElementById('bout-timer').textContent = m + ':' + (r < 10 ? '0' + r : r);
}
function setStatus(text) {
    document.getElementById('status-text').textContent = text;
}
function setAreaCount(msg) {
    // Toolbar pill (compact players / mobs+pets breakdown for the Luta tab)
    var players = msg.players || 0;
    var pets = msg.pets || 0;
    var mobs = msg.mobs || 0;
    var other = msg.other || 0;
    var total = msg.total || (players + pets + mobs + other);
    // Area counter pill foi removida da toolbar — null-check antes de atualizar
    var _ap = document.getElementById('area-players-n');
    if (_ap) _ap.textContent = players;
    var _am = document.getElementById('area-mobs-n');
    if (_am) _am.textContent = (mobs + pets);

    // Jogadores tab foi removida — setNum já era null-safe
    var setNum = function (id, n) { var el = document.getElementById(id); if (el) el.textContent = n; };
    setNum('area-total', total);
    setNum('area-players', players);
    setNum('area-pets', pets);
    setNum('area-mobs', mobs);
    setNum('area-other', other);
    // Hide the "outros" card when zero — reduces visual noise
    var oc = document.getElementById('card-other');
    if (oc) oc.style.display = other > 0 ? '' : 'none';
}
function setCaptureState(state) {
    console.log('[setCaptureState] ' + state);
    var btnCap  = document.getElementById('btn-capture');
    var btnReset = document.getElementById('btn-reset');
    var indicator = document.getElementById('capture-indicator');
    var label = document.getElementById('capture-label');

    if (btnReset) btnReset.disabled = false;

    if (state === 'running') {
        indicator.classList.add('capturing');
        indicator.classList.remove('stopped');
        label.textContent = 'capturando';
        btnCap.innerHTML = ICON_PAUSE;
        btnCap.classList.remove('stopped');
        btnCap.title = 'Parar captura — pets e classes podem ficar incompletos para quem entrar na área enquanto estiver parado.';
        btnCap.dataset.mode = 'stop';
    } else {
        // 'stopped' OR 'idle' — anything not actively capturing shows the play button.
        indicator.classList.remove('capturing');
        indicator.classList.add('stopped');
        label.textContent = 'parado';
        btnCap.innerHTML = ICON_START;
        btnCap.classList.add('stopped');
        btnCap.title = 'Iniciar captura';
        btnCap.dataset.mode = 'start';
    }
}

// Icon SVGs used by btn-capture toggle. Keep inline (no HTTP round-trip;
// fill=currentColor lets CSS control theming).
var ICON_START = '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M20.494,7.968l-9.54-7A5,5,0,0,0,3,5V19a5,5,0,0,0,7.957,4.031l9.54-7a5,5,0,0,0,0-8.064Zm-1.184,6.45-9.54,7A3,3,0,0,1,5,19V5A2.948,2.948,0,0,1,6.641,2.328,3.018,3.018,0,0,1,8.006,2a2.97,2.97,0,0,1,1.764.589l9.54,7a3,3,0,0,1,0,4.836Z"/></svg>';
var ICON_PAUSE = '<img src="icons/pause.png" alt="pause" aria-hidden="true" />';

// ---------- Clipboard ----------
function fmtDmgShort(n) {
    if (!n || n <= 0) return '0';
    n = Math.round(n);
    if (n < 1000) return String(n);
    if (n < 1000000) return Math.round(n / 1000) + 'k';
    return (n / 1000000).toFixed(1).replace(/\.0$/, '') + 'M';
}
// mode: 'all' (dano geral) | 'raid' (dano só em boss raid)
function copyTopToClipboard(mode) {
    mode = mode || 'all';
    if (!lastParticipants || lastParticipants.length === 0) {
        setStatus('Nada para copiar.');
        return;
    }
    var valueOf = function (r) {
        return mode === 'raid' ? (r.damageRaid || 0) : (r.damage || 0);
    };
    var header = mode === 'raid' ? 'TOP DANO EM BOSS RAID' : 'TOP DANO GERAL';
    // Re-sort by mode value (backend sorts por damage total)
    var sorted = lastParticipants.slice().sort(function (a, b) { return valueOf(b) - valueOf(a); });
    var parts = [];
    for (var i = 0; i < sorted.length; i++) {
        var r = sorted[i];
        var v = valueOf(r);
        if (v <= 0) continue;
        parts.push((parts.length + 1) + '- ' + r.name + ' ' + fmtDmgShort(v));
    }
    if (parts.length === 0) { setStatus('Nada para copiar (' + mode + ').'); return; }
    var text = header + '\n' + parts.join('\n');
    var done = function () { setStatus('Top copiado — ' + mode + ' (' + parts.length + ' jogadores).'); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
    } else {
        fallbackCopy(text);
        done();
    }
}
function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta);
}

// ---------- Buttons ----------
// Buttons:
//   btn-capture:     single toggle start/stop (▶/■). Default mode = 'start'.
//   btn-reset:       restart capture (kill dumpcap + fresh pcap).
//   btn-copy-geral:  copia top do dano geral (todos os alvos).
//   btn-copy-raid:   copia top do dano em boss raid (HP > 800k).
document.getElementById('btn-reset').addEventListener('click', function () {
    if (this.disabled) return;
    sendCmd('reset');
});
var _btnCopyGeral = document.getElementById('btn-copy-geral');
if (_btnCopyGeral) _btnCopyGeral.addEventListener('click', function () { copyTopToClipboard('all'); });
var _btnCopyRaid = document.getElementById('btn-copy-raid');
if (_btnCopyRaid) _btnCopyRaid.addEventListener('click', function () { copyTopToClipboard('raid'); });
// Retro-compat: btn-copy antigo (fallback caso HTML velho fique em cache)
var _btnCopyLegacy = document.getElementById('btn-copy');
if (_btnCopyLegacy) _btnCopyLegacy.addEventListener('click', function () { copyTopToClipboard('all'); });
document.getElementById('btn-capture').addEventListener('click', function () {
    var mode = this.dataset.mode || 'start';
    console.log('[btn-capture] click mode=' + mode);
    if (mode === 'start') {
        sendCmd('start-capture');
        setCaptureState('running');
    } else {
        sendCmd('stop-capture');
        setCaptureState('stopped');
    }
});

// Toggle mobs row visibility. Persisted so the choice sticks across runs.
// UI do botão foi removida (área simplificada). Wire só liga se elemento existir.
function applyMobsToggleUi() {
    var btn = document.getElementById('btn-toggle-mobs');
    if (!btn) return;
    if (showMobs) btn.classList.add('active'); else btn.classList.remove('active');
    btn.title = showMobs
        ? 'Ocultar dano de mobs no leaderboard'
        : 'Mostrar dano de mobs no leaderboard';
}
var _btnToggleMobs = document.getElementById('btn-toggle-mobs');
if (_btnToggleMobs) _btnToggleMobs.addEventListener('click', function () {
    showMobs = !showMobs;
    try { localStorage.setItem('ws:showMobs', showMobs ? '1' : '0'); } catch (e) {}
    applyMobsToggleUi();
    // Drop or re-add mob rows on next render — trigger a redraw with the
    // last known participants so we do not wait 1.5s for a fresh push.
    // Cheapest path: remove existing "mobs"/"unresolved" rows now if hiding.
    if (!showMobs) {
        rowMap.forEach(function (entry, id) {
            if (isMobRowId(id)) { entry.tr.remove(); rowMap.delete(id); }
        });
    }
});
applyMobsToggleUi();

document.getElementById('filter-input').addEventListener('input', function (e) {
    var q = e.target.value.toLowerCase();
    var rows = document.querySelectorAll('#lb-body tr');
    for (var i = 0; i < rows.length; i++) {
        var text = rows[i].textContent.toLowerCase();
        rows[i].style.display = text.indexOf(q) >= 0 ? '' : 'none';
    }
});

// ---------- Tabs ----------
var tabButtons = document.querySelectorAll('.tab-btn');
for (var t = 0; t < tabButtons.length; t++) {
    tabButtons[t].addEventListener('click', function (e) {
        var target = e.target.dataset.tab;
        for (var i = 0; i < tabButtons.length; i++) tabButtons[i].classList.remove('active');
        e.target.classList.add('active');
        var panels = document.querySelectorAll('.tab-panel');
        for (var j = 0; j < panels.length; j++) {
            panels[j].classList.toggle('active', panels[j].id === target);
        }
    });
}

// ---------- Players roster ----------
var lastRoster = [];
var playersFilterText = '';
var expandedGuilds = {};

function renderPlayers(roster) {
    lastRoster = Array.isArray(roster) ? roster : [];

    // Group by guild.
    var byGuild = {};
    for (var i = 0; i < lastRoster.length; i++) {
        var p = lastRoster[i];
        var g = (p.guild && p.guild.trim()) ? p.guild.trim() : '';
        if (!byGuild[g]) byGuild[g] = [];
        byGuild[g].push(p);
    }
    var guildNames = Object.keys(byGuild);
    // Named guilds first, sorted by count desc.
    guildNames.sort(function (a, b) {
        if (a === '' && b !== '') return 1;
        if (b === '' && a !== '') return -1;
        return byGuild[b].length - byGuild[a].length;
    });

    // Guilds panel removido — null-safe
    var _gt = document.getElementById('guilds-total');
    if (_gt) _gt.textContent = guildNames.filter(function (g) { return g !== ''; }).length;

    var q = playersFilterText.toLowerCase();
    var list = document.getElementById('guilds-list');
    if (!list) return;   // painel removido, sem renderização
    list.innerHTML = '';
    for (var gi = 0; gi < guildNames.length; gi++) {
        var gname = guildNames[gi];
        // Sort priority (per user request):
        //   1. Known players first (real name + class icon resolved).
        //   2. Then by active-buff count desc.
        //   3. Then alphabetical.
        var members = byGuild[gname].slice().sort(function (a, b) {
            var ak = (a.classId > 0 && !/^0x[0-9a-f]{8}$/i.test(a.name)) ? 1 : 0;
            var bk = (b.classId > 0 && !/^0x[0-9a-f]{8}$/i.test(b.name)) ? 1 : 0;
            if (ak !== bk) return bk - ak;
            var ab = (a.buffs && a.buffs.length) || 0;
            var bb = (b.buffs && b.buffs.length) || 0;
            if (ab !== bb) return bb - ab;
            return a.name.localeCompare(b.name);
        });
        if (q) {
            members = members.filter(function (p) {
                return p.name.toLowerCase().indexOf(q) >= 0 || gname.toLowerCase().indexOf(q) >= 0;
            });
            if (members.length === 0) continue;
        }

        // Expand by default; user can collapse individually.
        var isOpen = expandedGuilds[gname] !== false;
        if (q && members.length > 0) isOpen = true;

        var block = document.createElement('div');
        block.className = 'guild-block' + (isOpen ? ' open' : '');

        var hdr = document.createElement('div');
        hdr.className = 'guild-header';
        hdr.appendChild(elem('span', 'chevron'));
        var gnEl = elem('span', 'guild-name' + (gname === '' ? ' none' : ''));
        gnEl.textContent = gname === '' ? 'Sem guilda / desconhecida' : gname;
        hdr.appendChild(gnEl);
        var gc = elem('span', 'guild-count');
        gc.textContent = members.length;
        hdr.appendChild(gc);
        (function (name) {
            hdr.addEventListener('click', function () {
                // Default state is OPEN; toggle inverts.
                var currentlyOpen = expandedGuilds[name] !== false;
                expandedGuilds[name] = !currentlyOpen;
                renderPlayers(lastRoster);
            });
        })(gname);
        block.appendChild(hdr);

        var mDiv = document.createElement('div');
        mDiv.className = 'guild-members';
        for (var mi = 0; mi < members.length; mi++) {
            mDiv.appendChild(buildPlayerRow(members[mi]));
        }
        block.appendChild(mDiv);
        list.appendChild(block);
    }
}

function buildPlayerRow(p) {
    var row = document.createElement('div');
    row.className = 'player-row';

    var icon = document.createElement('span');
    icon.className = 'class-icon';
    if (p.classId && p.classIconFile) {
        var img = document.createElement('img');
        img.src = '../class-icons/individual/' + p.classIconFile;
        icon.appendChild(img);
        var c = classColor(p.classId);
        if (c) icon.style.borderColor = c;
    } else {
        icon.textContent = '?';
    }
    row.appendChild(icon);

    var name = elem('span', 'p-name');
    name.textContent = p.name;
    row.appendChild(name);

    // Buffs — decoded from tag=429 (consumable apply) [MEDIDO].
    var buffs = elem('span', 'p-buffs');
    if (Array.isArray(p.buffs)) {
        for (var bi = 0; bi < p.buffs.length; bi++) {
            var b = p.buffs[bi];
            var img = document.createElement('img');
            img.className = 'buff-icon buff-' + (b.cat || 'outro');
            img.src = buffIconPath(b.cat);
            img.alt = b.cat || '';
            img.dataset.name = b.name;
            img.dataset.remain = b.remainSec < 0 ? 'permanente' : formatDurationShort(b.remainSec);
            // Custom instant-tooltip (native title has ~500ms delay).
            attachInstantTooltip(img);
            buffs.appendChild(img);
        }
    }
    row.appendChild(buffs);

    return row;
}
function buffIconPath(cat) {
    switch (cat) {
        case 'poção':      return '../buff-icons/pocao.png';
        case 'pergaminho': return '../buff-icons/pergaminho.png';
        case 'comida':     return '../buff-icons/comida.png';
        case 'pot cura':   return '../buff-icons/potcura.png';
        default:           return '../buff-icons/pocao.png';
    }
}
// Single reusable tooltip node — no delay, follows cursor lightly.
var _tt = null;
function tooltipNode() {
    if (_tt) return _tt;
    _tt = document.createElement('div');
    _tt.className = 'instant-tooltip';
    _tt.style.display = 'none';
    document.body.appendChild(_tt);
    return _tt;
}
function attachInstantTooltip(el) {
    el.addEventListener('mouseenter', function (e) {
        var t = tooltipNode();
        t.textContent = (el.dataset.name || '') + ' — ' + (el.dataset.remain || '');
        t.style.display = 'block';
        positionTooltip(t, e);
    });
    el.addEventListener('mousemove', function (e) { if (_tt) positionTooltip(_tt, e); });
    el.addEventListener('mouseleave', function () { if (_tt) _tt.style.display = 'none'; });
}
function positionTooltip(t, e) {
    var pad = 12;
    var x = e.clientX + pad;
    var y = e.clientY + pad;
    // Keep on-screen
    var r = t.getBoundingClientRect();
    var vw = window.innerWidth, vh = window.innerHeight;
    if (x + r.width > vw - 4) x = e.clientX - r.width - pad;
    if (y + r.height > vh - 4) y = e.clientY - r.height - pad;
    t.style.left = x + 'px';
    t.style.top  = y + 'px';
}
function formatDurationShort(sec) {
    if (sec < 60) return Math.round(sec) + 's';
    if (sec < 3600) return Math.round(sec / 60) + 'min';
    return (sec / 3600).toFixed(1) + 'h';
}

function elem(tag, cls) { var e = document.createElement(tag); if (cls) e.className = cls; return e; }

var pf = document.getElementById('players-filter');
if (pf) {
    pf.addEventListener('input', function (e) {
        playersFilterText = e.target.value || '';
        renderPlayers(lastRoster);
    });
}

// ---------- Local clock ----------
function tickClock() {
    var d = new Date();
    var hh = d.getHours(); var mm = d.getMinutes();
    document.getElementById('clock').textContent =
        (hh < 10 ? '0' + hh : hh) + ':' + (mm < 10 ? '0' + mm : mm);
}
tickClock();
setInterval(tickClock, 30000);

// Rank tabs — filtra dano exibido no leaderboard por rank do target
(function wireRankTabs() {
    var tabs = document.querySelectorAll('.rank-tab');
    for (var i = 0; i < tabs.length; i++) {
        tabs[i].addEventListener('click', function (ev) {
            var rank = ev.currentTarget.getAttribute('data-rank') || 'all';
            if (rank === currentRank) return;
            currentRank = rank;
            for (var k = 0; k < tabs.length; k++) tabs[k].classList.remove('active');
            ev.currentTarget.classList.add('active');
            // Re-render com rows atuais
            if (_lastLbRows && _lastLbRows.length) renderLeaderboard(_lastLbRows);
        });
    }
})();

// Signal ready
sendCmd('ready');
