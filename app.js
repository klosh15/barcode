'use strict';
/* Inventario v5-B · un usuario y una clave por celular · base en IndexedDB */

const APP_VER = '5B-2.1.0';
const USUARIOS = ['PAOLO', 'EYMHI', 'JHIMY', 'CARLOS', 'INVITADO'];
const ITER = 600000;            // iteraciones PBKDF2-SHA256
const MIN_CLAVE = 10;
const DB_NAME = 'inventario_v5B';
const NUEVAS = [['MARCA', 'Marca'], ['MODELO', 'Modelo'], ['TIPO', 'Tipo'], ['COLOR', 'Color'], ['SERIE', 'Serie'], ['DIMENSIONES', 'Dimensiones'], ['OTROS', 'Otros']];   // columnas opcionales de Vista2
const COLS = ['IDCodigoAntiguo', 'Descripcion', 'Nombre', 'Ubicacion', 'Ambiente', 'Baja'];
const ESTADOS = ['Bueno', 'Regular', 'Malo', 'Chatarra', 'RAEE'];
const SITUACIONES = ['Propuesto baja', 'Mantenimiento', 'Sobrantes', 'Disponibles para asignar'];
const FORMATOS = [
  ['F1 · NN.NNN.NNNN', /^\d{2}\.\d{3}\.\d{4}$/],
  ['F2 · NN.NNN.NNNN.XXX', /^\d{2}\.\d{3}\.\d{4}\.[A-Z]{1,3}$/],
  ['F3 · NN.NN.NNNN', /^\d{2}\.\d{2}\.\d{4}$/],
  ['F4 · XXNNN', /^[A-Z]{2}\d{3}$/],
];

/* ---------- utilidades ---------- */
const $ = (s, r = document) => r.querySelector(s);
const te = new TextEncoder(), td = new TextDecoder();
const p2 = n => String(n).padStart(2, '0');
const limpiar = t => String(t == null ? '' : t).trim().toUpperCase().replace(/\s+/g, '');
const normInterno = c => limpiar(c).replace(/^0+(?=\d)/, '');   // 000013401 == 13401
const sinTilde = s => String(s).normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]/g, '');
const fmt = ms => { const d = new Date(ms); return `${p2(d.getDate())}/${p2(d.getMonth() + 1)}/${d.getFullYear()} ${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`; };
const serial = ms => (ms - new Date(ms).getTimezoneOffset() * 60000) / 86400000 + 25569;   // serie de Excel en hora local
const formatoDe = c => { for (const [n, r] of FORMATOS) if (r.test(c)) return n; return null; };

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'class') e.className = v; else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v);
  }
  for (const c of kids) if (c != null) e.append(c);
  return e;
}
let toastT;
function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('on'); clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('on'), 2200); }
function busy(txt) { $('#busy-txt').textContent = txt || 'Procesando…'; $('#busy').hidden = false; }
function unbusy() { $('#busy').hidden = true; }
const tick = () => new Promise(r => setTimeout(r, 30));
function mensaje(cont, tipo, txt) { cont.replaceChildren(txt ? el('div', { class: 'msg ' + tipo, text: txt }) : ''); }

function dialogo(titulo, cuerpo, botones) {
  return new Promise(res => {
    const box = $('#modal-box'); box.replaceChildren(el('h2', { text: titulo, style: 'margin-top:0' }), ...[].concat(cuerpo));
    const fila = el('div', { class: 'row', style: 'margin-top:14px' });
    botones.forEach(b => fila.append(el('button', { class: 'btn ' + (b.cls || ''), text: b.t, onclick: () => { $('#modal').hidden = true; res(b.v); } })));
    box.append(fila); $('#modal').hidden = false;
  });
}

/* ---------- IndexedDB ---------- */
let _db;
function abrirDB() {
  if (_db) return Promise.resolve(_db);
  return new Promise((ok, ko) => {
    const rq = indexedDB.open(DB_NAME, 1);
    rq.onupgradeneeded = () => {
      const d = rq.result;
      d.createObjectStore('meta', { keyPath: 'k' });
      d.createObjectStore('maestro', { keyPath: 'k' });
      d.createObjectStore('diario', { autoIncrement: true });
    };
    rq.onsuccess = () => { _db = rq.result; ok(_db); };
    rq.onerror = () => ko(rq.error);
  });
}
async function tx(store, modo, fn) {
  const d = await abrirDB();
  return new Promise((ok, ko) => {
    const t = d.transaction(store, modo); const s = t.objectStore(store);
    const r = fn(s);
    t.oncomplete = () => ok(r && 'result' in r ? r.result : undefined);
    t.onerror = () => ko(t.error); t.onabort = () => ko(t.error);
  });
}
const idbGet = (s, k) => tx(s, 'readonly', st => st.get(k));
const idbPut = (s, v) => tx(s, 'readwrite', st => st.put(v));
const idbAdd = (s, v) => tx(s, 'readwrite', st => st.add(v));
const idbAll = s => tx(s, 'readonly', st => st.getAll());
function borrarDB() {
  return new Promise(res => { if (_db) { _db.close(); _db = null; } const r = indexedDB.deleteDatabase(DB_NAME); r.onsuccess = r.onerror = r.onblocked = () => res(); });
}

/* ---------- criptografía ---------- */
async function derivarKEK(frase, sal, iter) {
  const base = await crypto.subtle.importKey('raw', te.encode(frase.normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: sal, iterations: iter, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function aesEnc(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));        // IV nuevo en cada cifrado
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
  return { iv, ct };
}
const aesDec = async (key, { iv, ct }) => new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
const encJSON = (key, obj) => aesEnc(key, te.encode(JSON.stringify(obj)));
const decJSON = async (key, rec) => JSON.parse(td.decode(await aesDec(key, rec)));
const importarK = raw => crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);   // no extraíble

async function desenvolver(usuario, frase, meta) {            // devuelve la clave maestra en bruto
  const u = meta.usuarios[usuario];
  const kek = await derivarKEK(frase, u.sal, meta.iter);
  return aesDec(kek, u);                                        // GCM falla si la clave es incorrecta
}

/* ---------- estado ---------- */
let sesion = null;     // { usuario, key }
let S = null;          // datos descifrados en memoria
let ctx = null;        // ficha / alta en curso
let metaCache = null;

function nuevoEstado(maestro) {
  const bienes = new Map();
  const porInterno = new Map();
  maestro.bienes.forEach(b => { if (b.CodigoInterno) porInterno.set(normInterno(b.CodigoInterno), b.IDCodigoAntiguo); });
  maestro.bienes.forEach(b => bienes.set(b.IDCodigoAntiguo, { ...b, Resultado: '', Nombre1: '', Ubicacion1: '', Ambiente1: '', CodigoBarras: '', Condicion: '', Estado: '', Situacion: '', Observaciones: '', FechaCaptura: 0, FechaGuardado: 0, Usuario: '', AvisoReloj: '' }));
  const nombres = new Set(maestro.catalogo.nombres), ubic = new Set(maestro.catalogo.ubicaciones), amb = new Set(maestro.catalogo.ambientes);
  const porUbic = new Map();
  const par = (u, a) => { if (!u || !a) return; if (!porUbic.has(u)) porUbic.set(u, new Set()); porUbic.get(u).add(a); };
  const est = maestro.catalogo.estricto || {};          // con hojas Personal / UbicacionAmbiente las listas salen SOLO de ellas
  maestro.bienes.forEach(b => { if (!est.nombres) nombres.add(b.Nombre); if (!est.pares) { ubic.add(b.Ubicacion); amb.add(b.Ambiente); par(b.Ubicacion, b.Ambiente); } });
  maestro.catalogo.pares.forEach(([u, a]) => par(u, a));
  const ord = s => [...s].filter(Boolean).sort((a, b) => a.localeCompare(b, 'es'));
  return {
    bienes, porInterno, porBarra: new Map(), idxOCR: null, uso: new Map((maestro.catalogo.usos || []).map(([u, a, c]) => [sinTilde(u) + '|' + sinTilde(a), c])), info: maestro.info, historial: [], altas: [], ultimaCaptura: 0, relojDudoso: false,
    cat: { estricto: !!est.pares, nombres: ord(nombres), ubicaciones: ord(ubic), ambientes: ord(amb), porUbic: new Map([...porUbic].map(([u, s]) => [u, ord(s)])) },
  };
}
const usoDe = (u, a) => (S && S.uso.get(sinTilde(u || '') + '|' + sinTilde(a || ''))) || '';     // CONDICION por defecto según UbicacionAmbiente
function aplicar(reg) {
  if (reg.t === 'dec') {
    const b = S.bienes.get(reg.codigo);
    if (reg.CodigoBarras && reg.CodigoBarras !== reg.codigo) S.porBarra.set(normInterno(reg.CodigoBarras), reg.codigo);
    if (b) Object.assign(b, { Resultado: reg.Resultado, Nombre1: reg.Nombre1, Ubicacion1: reg.Ubicacion1, Ambiente1: reg.Ambiente1, CodigoBarras: reg.CodigoBarras || b.CodigoBarras, Condicion: reg.Condicion || '', Estado: reg.Estado || '', Situacion: reg.Situacion || '', Observaciones: reg.Observaciones || '', FechaCaptura: reg.FechaCaptura, FechaGuardado: reg.FechaGuardado, Usuario: reg.Usuario, AvisoReloj: reg.AvisoReloj || '' });
  } else if (reg.t === 'alta') S.altas.push(reg);
  S.historial.push(reg);
  if (reg.FechaCaptura > S.ultimaCaptura && reg.Usuario === (sesion && sesion.usuario)) S.ultimaCaptura = reg.FechaCaptura;
}

/* ---------- páginas ---------- */
const PAGINAS = ['setup', 'login', 'main'], OVERLAYS = ['ficha', 'corr', 'alta', 'menu'];
function pagina(p) { PAGINAS.forEach(x => $('#p-' + x).hidden = x !== p); cerrarOverlays(); }
function overlay(o) { OVERLAYS.forEach(x => $('#o-' + x).hidden = x !== o); if (o) { $('#o-' + o).scrollTop = 0; pausarLector(); } else { reanudarLector(); programarOCR(2500); } }
function cerrarOverlays() { OVERLAYS.forEach(x => $('#o-' + x).hidden = true); reanudarLector(); programarOCR(2500); }
const overlayAbierto = () => OVERLAYS.some(x => !$('#o-' + x).hidden) || !$('#modal').hidden || !$('#busy').hidden;

/* ============================================================
   CONFIGURACIÓN INICIAL
   ============================================================ */
let maestroCargado = null, setupUser = null, usuarioFijo = null;

function leerMaestro(buf, nombreArchivo) {
  const wb = /.csv$/i.test(nombreArchivo) ? XLSX.read(td.decode(buf), { type: 'string' }) : XLSX.read(buf, { type: 'array' });
  const nombreCat = wb.SheetNames.find(n => /^catalog/i.test(n.trim()));
  const nombrePers = wb.SheetNames.find(n => sinTilde(n) === 'personal');
  const nombreUA = wb.SheetNames.find(n => sinTilde(n) === 'ubicacionambiente');
  const nombreBienes = wb.SheetNames.find(n => n !== nombreCat && n !== nombrePers && n !== nombreUA);
  if (!nombreBienes) throw new Error('El archivo no tiene hojas con datos.');
  const filas = XLSX.utils.sheet_to_json(wb.Sheets[nombreBienes], { defval: '', raw: false });
  if (!filas.length) throw new Error('La hoja «' + nombreBienes + '» está vacía.');
  const mapa = {}; Object.keys(filas[0]).forEach(h => { mapa[sinTilde(h)] = h; });
  const colInt = ['codigointerno', 'idcodigointerno', 'codinterno'].map(k => mapa[k]).find(Boolean);
  const faltan = COLS.filter(c => !mapa[sinTilde(c)]);
  if (faltan.length) throw new Error('Faltan columnas: ' + faltan.join(', ') + '.');
  const bienes = [], vistos = new Set(), duplicados = [], formatos = {}, otros = [], internos = new Set(), internosRep = [];
  let vacios = 0, bajaRara = 0;
  for (const f of filas) {
    const g = c => String(f[mapa[sinTilde(c)]] == null ? '' : f[mapa[sinTilde(c)]]).trim();
    const codigo = limpiar(g('IDCodigoAntiguo'));
    if (!codigo) { vacios++; continue; }
    if (vistos.has(codigo)) { duplicados.push(codigo); continue; }
    vistos.add(codigo);
    let baja = g('Baja'); if (baja !== '0' && baja !== '1') { if (baja !== '') bajaRara++; baja = baja === '1' ? '1' : '0'; }
    const fm = formatoDe(codigo); if (fm) formatos[fm] = (formatos[fm] || 0) + 1; else otros.push(codigo);
    let interno = colInt ? String(f[colInt] == null ? '' : f[colInt]).trim() : '';
    if (interno) { const k = normInterno(interno); if (internos.has(k)) { internosRep.push(interno); interno = ''; } else internos.add(k); }
    bienes.push({ IDCodigoAntiguo: codigo, CodigoInterno: interno, Descripcion: g('Descripcion'), ...Object.fromEntries(NUEVAS.map(([c]) => [c, g(c)])), Nombre: g('Nombre'), Ubicacion: g('Ubicacion'), Ambiente: g('Ambiente'), Baja: baja });
  }
  const catalogo = { nombres: [], ubicaciones: [], ambientes: [], pares: [] };
  if (nombreCat) {
    const cf = XLSX.utils.sheet_to_json(wb.Sheets[nombreCat], { defval: '', raw: false });
    cf.forEach(r => {
      const m = {}; Object.keys(r).forEach(h => { m[sinTilde(h)] = String(r[h]).trim(); });
      if (m.nombre) catalogo.nombres.push(m.nombre);
      if (m.ubicacion) catalogo.ubicaciones.push(m.ubicacion);
      if (m.ambiente) catalogo.ambientes.push(m.ambiente);
      if (m.ubicacion && m.ambiente) catalogo.pares.push([m.ubicacion, m.ambiente]);
    });
  }
  // Hoja Personal → lista de Nombre. Hoja UbicacionAmbiente → pares Ubicación/Ambiente y la CONDICION (USO/DESUSO) por defecto.
  const hojaFilas = nom => XLSX.utils.sheet_to_json(wb.Sheets[nom], { defval: '', raw: false }).map(r => { const m = {}; Object.keys(r).forEach(h => { m[sinTilde(h)] = String(r[h]).trim(); }); return m; });
  const usos = [], parUA = new Set(), personal = new Set();
  let usoRaro = 0;
  if (nombrePers) hojaFilas(nombrePers).forEach(m => { if (m.nombre) { catalogo.nombres.push(m.nombre); personal.add(m.nombre); } });
  if (nombreUA) hojaFilas(nombreUA).forEach(m => {
    if (!m.ubicacion || !m.ambiente) return;
    catalogo.ubicaciones.push(m.ubicacion); catalogo.ambientes.push(m.ambiente); catalogo.pares.push([m.ubicacion, m.ambiente]); parUA.add(m.ubicacion + '|' + m.ambiente);
    const c = sinTilde(m.condicion || m.uso || '');
    if (c === 'uso' || c === 'desuso') usos.push([m.ubicacion, m.ambiente, c.toUpperCase()]); else if (c) usoRaro++;
  });
  catalogo.usos = usos; catalogo.estricto = { nombres: personal.size > 0, pares: parUA.size > 0 };
  const fueraPersonal = personal.size ? bienes.filter(b => b.Nombre && !personal.has(b.Nombre)).length : 0;
  const fueraUA = parUA.size ? bienes.filter(b => !parUA.has(b.Ubicacion + '|' + b.Ambiente)).length : 0;
  return { bienes, catalogo, info: { archivo: nombreArchivo, filas: bienes.length, cargadoEn: Date.now() }, resumen: { conInterno: internos.size, internosRep, total: filas.length, vacios, duplicados, formatos, otros, bajaRara, bajas: bienes.filter(b => b.Baja === '1').length, catalogo: !!nombreCat, personal: personal.size, pares: parUA.size, conUso: usos.length, usoRaro, fueraPersonal, fueraUA } };
}

function pintarResumen(r) {
  const c = $('#setup-resumen'); c.replaceChildren();
  const filas = [['Filas leídas', r.total], ['Bienes cargados', r.bienes.length], ['Con Baja = 1', r.resumen.bajas],
    ['Duplicados descartados', r.resumen.duplicados.length], ['Filas sin código', r.resumen.vacios], ['Con código interno', r.resumen.conInterno], ['Con Marca/Modelo/Serie…', r.bienes.filter(b => NUEVAS.some(([c]) => b[c])).length], ['Hoja Catálogo', r.resumen.catalogo ? 'sí' : 'no'],
    ['Hoja Personal', r.resumen.personal ? r.resumen.personal + ' nombres' : 'no'], ['Hoja UbicacionAmbiente', r.resumen.pares ? r.resumen.pares + ' pares · ' + r.resumen.conUso + ' con CONDICION' : 'no']];
  const t = el('table'); filas.forEach(([k, v]) => t.append(el('tr', {}, el('td', { text: k }), el('td', { text: String(v) }))));
  c.append(el('h2', { text: r.info.archivo }), t, el('h2', { text: 'Formatos de código' }));
  const tf = el('table'); Object.entries(r.resumen.formatos).forEach(([k, v]) => tf.append(el('tr', {}, el('td', { text: k }), el('td', { text: String(v) }))));
  if (r.resumen.otros.length) tf.append(el('tr', {}, el('td', { text: 'Otros (se aceptan igual)' }), el('td', { text: r.resumen.otros.length + ': ' + r.resumen.otros.slice(0, 8).join(', ') + (r.resumen.otros.length > 8 ? '…' : '') })));
  c.append(tf);
  if (r.resumen.duplicados.length) c.append(el('div', { class: 'msg warn', text: 'Códigos duplicados (se conservó el primero): ' + r.resumen.duplicados.slice(0, 8).join(', ') }));
  if (r.resumen.internosRep.length) c.append(el('div', { class: 'msg warn', text: 'Códigos internos repetidos (se conservó el primero): ' + r.resumen.internosRep.slice(0, 8).join(', ') }));
  if (r.resumen.pares && !r.resumen.conUso) c.append(el('div', { class: 'msg warn', text: 'La hoja UbicacionAmbiente no trae la columna CONDICION (USO o DESUSO): no se sugerirá la Condición.' }));
  if (r.resumen.usoRaro) c.append(el('div', { class: 'msg warn', text: r.resumen.usoRaro + ' filas de UbicacionAmbiente tienen una CONDICION distinta de USO o DESUSO; se ignoraron.' }));
  if (r.resumen.fueraPersonal) c.append(el('div', { class: 'msg warn', text: r.resumen.fueraPersonal + ' bienes tienen un Nombre que no está en la hoja Personal.' }));
  if (r.resumen.fueraUA) c.append(el('div', { class: 'msg warn', text: r.resumen.fueraUA + ' bienes tienen una Ubicación/Ambiente que no está en la hoja UbicacionAmbiente.' }));
  if (r.resumen.bajaRara) c.append(el('div', { class: 'msg warn', text: r.resumen.bajaRara + ' filas con Baja distinta de 0 o 1; se trataron como 0.' }));
}

function iniciarSetup() {
  maestroCargado = null;
  usuarioFijo = null; setupUser = null;
  const us = $('#setup-users'); us.replaceChildren();
  USUARIOS.forEach(u => us.append(el('button', { class: 'chip', type: 'button', 'aria-pressed': 'false', text: u, onclick: ev => { setupUser = u; us.querySelectorAll('.chip').forEach(x => x.setAttribute('aria-pressed', String(x === ev.currentTarget))); $('#pw-1').focus(); } })));
  const cont = $('#setup-claves'); cont.replaceChildren();
  cont.append(el('label', { for: 'pw-1', text: 'Clave' }),
    el('input', { id: 'pw-1', type: 'password', autocomplete: 'new-password', placeholder: 'Clave' }),
    el('input', { id: 'pw-2', type: 'password', autocomplete: 'new-password', placeholder: 'Repetir clave', style: 'margin-top:6px' }));
  $('#setup-resumen').replaceChildren(); mensaje($('#setup-msg'), 'err', '');
  $('#btn-setup').disabled = true;
  pagina('setup');
}

async function crearBase() {
  const msg = $('#setup-msg'); mensaje(msg, 'err', '');
  if (!maestroCargado) return mensaje(msg, 'err', 'Cargue primero el archivo del maestro.');
  const u = setupUser, a = $('#pw-1').value, b = $('#pw-2').value;
  if (!u) return mensaje(msg, 'err', 'Elija un usuario.');
  if (a.length < MIN_CLAVE) return mensaje(msg, 'err', `La clave debe tener al menos ${MIN_CLAVE} caracteres.`);
  if (/^\d+$/.test(a)) return mensaje(msg, 'err', 'La clave no puede ser solo números.');
  if (a !== b) return mensaje(msg, 'err', 'Las dos claves no coinciden.');
  try {
    busy('Procesando…'); await tick();
    const raw = crypto.getRandomValues(new Uint8Array(32));        // clave maestra de datos
    const sal = crypto.getRandomValues(new Uint8Array(16));
    const kek = await derivarKEK(a, sal, ITER);
    const usuarios = { [u]: { sal, ...(await aesEnc(kek, raw)) } };
    const K = await importarK(raw);
    const { resumen, total, ...maestro } = maestroCargado;
    const control = await encJSON(K, { ok: 'inventario-v5B' });
    await idbPut('maestro', { k: 'main', ...(await encJSON(K, maestro)) });
    await idbPut('meta', { k: 'meta', ver: 1, iter: ITER, usuarios, control, creado: Date.now() });
    raw.fill(0);
    try { if (navigator.storage && navigator.storage.persist) await navigator.storage.persist(); } catch (e) { /* opcional */ }
    unbusy(); maestroCargado = null; usuarioFijo = u;
    iniciarLogin('Base creada. Ingrese con su clave.');
  } catch (e) { unbusy(); console.error(e); mensaje(msg, 'err', 'No se pudo crear la base: ' + (e.message || e)); }
}

/* ============================================================
   INICIO DE SESIÓN
   ============================================================ */
let userSel = null;
function iniciarLogin(info) {
  userSel = usuarioFijo;
  $('#login-user').textContent = usuarioFijo || '';
  $('#login-clave').value = ''; $('#login-ver').checked = false; $('#login-clave').type = 'password';
  mensaje($('#login-msg'), info && /bloque|inactiv|sesión cerrada/i.test(info) ? 'warn' : 'info', info || '');
  $('#login-info').textContent = 'Versión ' + APP_VER;
  pagina('login');
}
function espera(u) { try { const f = JSON.parse(localStorage.getItem('fallos_' + u) || 'null'); if (f && f.hasta > Date.now()) return Math.ceil((f.hasta - Date.now()) / 1000); } catch (e) { /* sin acceso */ } return 0; }
function falla(u) { try { const f = JSON.parse(localStorage.getItem('fallos_' + u) || '{"n":0}'); f.n++; f.hasta = f.n >= 5 ? Date.now() + Math.min(900, 30 * 2 ** (f.n - 5)) * 1000 : 0; localStorage.setItem('fallos_' + u, JSON.stringify(f)); } catch (e) { /* sin acceso */ } }
function exito(u) { try { localStorage.removeItem('fallos_' + u); } catch (e) { /* sin acceso */ } }

async function entrar() {
  const m = $('#login-msg'); mensaje(m, 'err', '');
  if (!userSel) return mensaje(m, 'err', 'No hay usuario configurado.');
  const frase = $('#login-clave').value;
  if (!frase) return mensaje(m, 'err', 'Escriba su clave.');
  const w = espera(userSel); if (w) return mensaje(m, 'err', `Demasiados intentos. Espere ${w} s.`);
  try {
    busy('Procesando…'); await tick();
    const meta = await idbGet('meta', 'meta'); metaCache = meta;
    let raw;
    try { raw = await desenvolver(userSel, frase, meta); }
    catch (e) { falla(userSel); unbusy(); return mensaje(m, 'err', 'Clave incorrecta.'); }
    exito(userSel);
    const key = await importarK(raw); raw.fill(0);
    await decJSON(key, meta.control);
    $('#busy-txt').textContent = 'Procesando…'; await tick();
    sesion = { usuario: userSel, key };
    const maestro = await decJSON(key, await idbGet('maestro', 'main'));
    S = nuevoEstado(maestro);
    const diario = await idbAll('diario');
    for (const rec of diario) aplicar(await decJSON(key, rec));
    $('#login-clave').value = '';
    unbusy(); abrirPrincipal(); verificarReloj();
  } catch (e) { unbusy(); sesion = null; S = null; console.error(e); mensaje(m, 'err', 'No se pudo abrir la base: ' + (e.message || e)); }
}

/* ============================================================
   SESIÓN, BLOQUEO E INACTIVIDAD
   ============================================================ */
let tInact, ocultoDesde = 0, camQuiere = false;
const minBloqueo = () => { try { return Number(localStorage.getItem('bloqueoMin')) || 5; } catch (e) { return 5; } };
function reiniciarInactividad() { clearTimeout(tInact); if (sesion) tInact = setTimeout(() => bloquear('Sesión bloqueada por inactividad.'), minBloqueo() * 60000); }
function bloquear(msg) {
  detenerCamara(); clearTimeout(tInact);
  sesion = null; S = null; ctx = null; metaCache = null;
  $('#ficha-campos').replaceChildren(); $('#corr-form').replaceChildren(); $('#alta-form').replaceChildren(); $('#ficha-estado').replaceChildren(); mensaje($('#ficha-msg'), 'err', ''); $('#alta-estado').replaceChildren(); $('#alta-impreso').value = '';
  $('#modal').hidden = true; unbusy();
  iniciarLogin(msg || 'Sesión cerrada.');
}
['pointerdown', 'keydown', 'touchstart'].forEach(ev => document.addEventListener(ev, reiniciarInactividad, { passive: true }));
document.addEventListener('visibilitychange', () => {
  if (document.hidden) ocultoDesde = Date.now();
  else if (sesion && ocultoDesde && Date.now() - ocultoDesde > 60000) bloquear('Sesión bloqueada: la página estuvo en segundo plano.');
  else if (sesion && !$('#p-main').hidden && camQuiere) { const t = pistaVideo(); if (!t || t.readyState === 'ended') iniciarCamara(); }
});

/* ---------- reloj ---------- */
async function verificarReloj() {
  if (!S || !navigator.onLine) return;
  try {
    const r = await fetch(location.pathname, { method: 'HEAD', cache: 'no-store' });
    const d = r.headers.get('Date'); if (!d) return;
    const dif = Date.now() - new Date(d).getTime();
    S.relojDudoso = Math.abs(dif) > 60000;
    pintarAviso(S.relojDudoso ? `El reloj del celular difiere ${Math.round(dif / 1000)} s de la hora del servidor. Active la hora automática. Los registros quedarán marcados.` : '');
  } catch (e) { /* sin red: se omite */ }
}
function pintarAviso(txt) { mensaje($('#main-aviso'), 'warn', txt); }
function avisoReloj(capturadoEn) {
  if (S.relojDudoso) return 'RELOJ_DUDOSO';
  if (capturadoEn < S.ultimaCaptura) return 'RETROCESO';
  return '';
}

/* ============================================================
   PANTALLA PRINCIPAL
   ============================================================ */
function abrirPrincipal() {
  $('#top-user').textContent = 'Usuario: ' + sesion.usuario;
  $('#top-sub').textContent = `${S.info.archivo} · ${S.bienes.size} bienes`;
  pintarAviso(''); pintarStats(); pagina('main'); reiniciarInactividad();
  $('#sel-bloqueo').value = String(minBloqueo());
  iniciarCamara();
}
function contar() {
  let ok = 0, mal = 0;
  S.bienes.forEach(b => { if (b.Resultado === 'CORRECTO') ok++; else if (b.Resultado === 'INCORRECTO') mal++; });
  return { total: S.bienes.size, ok, mal, altas: S.altas.length, pend: S.bienes.size - ok - mal };
}
function pintarStats() {
  const c = contar(), s = $('#stats'); s.replaceChildren();
  [['Correctos', c.ok], ['Incorrectos', c.mal], ['Pendientes', c.pend], ['Altas', c.altas]].forEach(([k, v]) => s.append(el('div', {}, el('b', { text: String(v) }), el('span', { text: k }))));
}

/* ---------- señales ---------- */
let actx;
function señal(tipo) {
  try {
    if (navigator.vibrate) navigator.vibrate(tipo === 'ok' ? 60 : [120, 60, 120]);
    actx = actx || new (window.AudioContext || window.webkitAudioContext)();
    const o = actx.createOscillator(), g = actx.createGain();
    o.frequency.value = tipo === 'ok' ? 880 : tipo === 'baja' ? 320 : 520; g.gain.value = 0.12;
    o.connect(g); g.connect(actx.destination); o.start(); o.stop(actx.currentTime + (tipo === 'ok' ? 0.1 : 0.3));
  } catch (e) { /* sin audio */ }
}

/* ---------- lectura ---------- */
function buscarBien(c) { return S.bienes.get(c) || S.bienes.get(S.porInterno.get(normInterno(c))) || S.bienes.get(S.porBarra.get(normInterno(c))); }
let ultimo = { codigo: '', t: 0 };
function alLeer(texto, origen, extra) {
  if (!sesion || overlayAbierto()) return;
  const capturadoEn = Date.now();
  const codigo = limpiar(texto); if (!codigo) return;
  if (origen === 'camara' && ultimo.codigo === codigo && capturadoEn - ultimo.t < 2500) return;
  ultimo = { codigo, t: capturadoEn };
  reiniciarInactividad();
  const bien = buscarBien(codigo);
  if (bien) { señal(bien.Baja === '1' ? 'baja' : 'ok'); abrirFicha(bien, capturadoEn, origen, origen === 'camara' ? codigo : ''); }
  else if (origen === 'camara') leerImpresoYAbrir(codigo, capturadoEn, capturarFrame(extra && extra.bbox));
  else { señal('no'); abrirAlta(codigo, capturadoEn, origen); }
}

/* ---------- lectura del código impreso bajo las barras (OCR local, sin internet) ---------- */
const OCR_DIR = 'lib/tesseract/';
let ocrCargando = null;
const cargarScript = src => new Promise((ok, ko) => { const t = el('script', { src }); t.onload = ok; t.onerror = () => ko(new Error('No se pudo cargar ' + src)); document.head.append(t); });
function ocrTrabajador() {
  if (!ocrCargando) ocrCargando = (async () => {
    if (!window.Tesseract) await cargarScript(OCR_DIR + 'tesseract.min.js');
    const abs = p => new URL(p, location.href).href;
    const w = await Tesseract.createWorker('eng', 1, { workerPath: abs(OCR_DIR + 'worker.min.js'), corePath: abs(OCR_DIR), langPath: abs(OCR_DIR), gzip: true, cacheMethod: 'none' });
    await w.setParameters({ tessedit_char_whitelist: '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ.-*', tessedit_pageseg_mode: '11' });
    return w;
  })().catch(e => { ocrCargando = null; throw e; });
  return ocrCargando;
}
function capturarFrame(bbox) {          // lista de lienzos a probar: primero la franja bajo las barras y luego el cuadro completo
  const v = $('#video'); if (!v.videoWidth || v.readyState < 2) return [];
  const full = el('canvas'); full.width = v.videoWidth; full.height = v.videoHeight; full.getContext('2d').drawImage(v, 0, 0);
  const lista = [];
  if (bbox && bbox.width > 20 && bbox.height > 5) {
    const x = Math.max(0, bbox.x - bbox.width * 0.15), y = Math.min(full.height - 2, bbox.y + bbox.height * 0.45);
    const w = Math.min(full.width - x, bbox.width * 1.3), h = Math.min(full.height - y, bbox.height * 1.6 + 40);
    const c = el('canvas'); c.width = Math.round(w); c.height = Math.round(h); c.getContext('2d').drawImage(full, x, y, w, h, 0, 0, c.width, c.height); lista.push(c);
  }
  lista.push(full); return lista;
}
function prepararOCR(origen) {          // gris + estiramiento de contraste (2 %–98 %); amplía las franjas pequeñas
  const esc = Math.max(1, Math.min(3, 1000 / origen.width));
  const c = el('canvas'); c.width = Math.round(origen.width * esc); c.height = Math.round(origen.height * esc);
  const g = c.getContext('2d', { willReadFrequently: true }); g.imageSmoothingQuality = 'high'; g.drawImage(origen, 0, 0, c.width, c.height);
  const im = g.getImageData(0, 0, c.width, c.height), d = im.data, h = new Uint32Array(256), n = d.length / 4;
  for (let i = 0; i < d.length; i += 4) { const y = (d[i] * 299 + d[i + 1] * 587 + d[i + 2] * 114) / 1000 | 0; d[i] = y; h[y]++; }
  let a = 0, lo = 0, hi = 255;
  for (; lo < 255 && (a += h[lo]) < n * 0.02; lo++);
  a = 0; for (; hi > 0 && (a += h[hi]) < n * 0.02; hi--);
  const k = hi > lo ? 255 / (hi - lo) : 1;
  for (let i = 0; i < d.length; i += 4) { const y = Math.max(0, Math.min(255, (d[i] - lo) * k)); d[i] = d[i + 1] = d[i + 2] = y; d[i + 3] = 255; }
  g.putImageData(im, 0, 0); return c;
}
const CONFUSOS = { O: '0', Q: '0', I: '1', L: '1', S: '5', B: '8', Z: '2', G: '6' };       // letras que el OCR confunde con dígitos
const claveOCR = t => limpiar(t).replace(/[^A-Z0-9]/g, '').replace(/[OQILSBZG]/g, c => CONFUSOS[c]);
function indiceOCR() { if (!S.idxOCR) { const m = new Map(); S.bienes.forEach((b, id) => { const k = claveOCR(id); if (!m.has(k)) m.set(k, []); m.get(k).push(id); }); S.idxOCR = m; } return S.idxOCR; }
function buscarEnTexto(texto) {         // devuelve { bien, leido, exacto } o null
  const toks = [...new Set(String(texto).toUpperCase().split(/[\s,;:|]+/).map(t => t.replace(/^[^A-Z0-9*]+|[^A-Z0-9*]+$/g, '')).filter(t => t.length >= 3))];
  for (const t of toks) { const b = buscarBien(t); if (b) return { bien: b, leido: t, exacto: true }; }
  const idx = indiceOCR(), cand = [...toks, ...toks.slice(1).map((t, i) => toks[i] + t)];
  const variantes = cand.flatMap(t => [t, t.slice(1), t.slice(0, -1)]);                   // el OCR a veces pega un carácter sobrante de las barras
  for (const t of variantes) { const k = claveOCR(t); if (k.length < 5) continue; const ids = idx.get(k); if (ids && ids.length === 1) return { bien: S.bienes.get(ids[0]), leido: t, exacto: false }; }
  return null;
}
function franjasTexto(cv) {            // franjas horizontales con tinta que no son barras: candidatas a línea de texto impreso
  const esc = Math.min(1, 800 / cv.width), w = Math.max(1, Math.round(cv.width * esc)), h = Math.max(1, Math.round(cv.height * esc));
  const c = el('canvas'); c.width = w; c.height = h;
  const g = c.getContext('2d', { willReadFrequently: true }); g.drawImage(cv, 0, 0, w, h);
  const d = g.getImageData(0, 0, w, h).data, gris = new Uint8Array(w * h);
  for (let i = 0; i < w * h; i++) gris[i] = (d[i * 4] * 299 + d[i * 4 + 1] * 587 + d[i * 4 + 2] * 114) / 1000 | 0;
  const W = w + 1, ii = new Float64Array(W * (h + 1));                  // imagen integral: media local rápida
  for (let y = 0; y < h; y++) { let acc = 0; for (let x = 0; x < w; x++) { acc += gris[y * w + x]; ii[(y + 1) * W + x + 1] = ii[y * W + x + 1] + acc; } }
  const r = 12, fila = new Float32Array(h), x0 = new Int32Array(h).fill(w), x1 = new Int32Array(h).fill(-1), tinta = new Uint8Array(w * h);
  for (let y = 0; y < h; y++) {
    const ya = Math.max(0, y - r), yb = Math.min(h, y + r + 1); let n = 0;
    for (let x = 0; x < w; x++) {
      const xa = Math.max(0, x - r), xb = Math.min(w, x + r + 1);
      const media = (ii[yb * W + xb] - ii[ya * W + xb] - ii[yb * W + xa] + ii[ya * W + xa]) / ((xb - xa) * (yb - ya));
      const xs = Math.max(0, x - 1), xe = Math.min(w, x + 2), ys = Math.max(0, y - 1), ye = Math.min(h, y + 2);       // media 3×3: el ruido de la cámara no cuenta como tinta
      const suave = (ii[ye * W + xe] - ii[ys * W + xe] - ii[ye * W + xs] + ii[ys * W + xs]) / ((xe - xs) * (ye - ys));
      if (suave < media - 25) { n++; tinta[y * w + x] = 1; if (x < x0[y]) x0[y] = x; x1[y] = x; }      // tinta = más oscuro que su entorno
    }
    fila[y] = n >= 3 ? n / (x1[y] - x0[y] + 1) : 0;                      // densidad de tinta respecto al ancho real de la fila
  }
  for (let y = 6; y < h; y++) {                                          // fila de barras: densa y casi idéntica a la de 6 filas más arriba (las barras son verticales; el texto no)
    if (fila[y] < 0.25) continue;
    let tot = 0, igual = 0;
    for (let x = x0[y]; x <= x1[y]; x++) if (tinta[y * w + x]) { tot++; const o = (y - 6) * w + x; if (tinta[o] || (x > 0 && tinta[o - 1]) || (x < w - 1 && tinta[o + 1])) igual++; }
    if (tot && igual / tot > 0.85) fila[y] = -1;
  }
  const bandas = []; let ini = -1, hueco = 0;
  for (let y = 0; y <= h; y++) {
    const hayTinta = y < h && fila[y] > 0.08;
    if (hayTinta) { if (ini < 0) ini = y; hueco = 0; }
    else if (ini >= 0 && (++hueco > 2 || y === h)) { bandas.push([ini, y - hueco]); ini = -1; hueco = 0; }
  }
  const salida = [];
  for (const [a, b] of bandas) {
    const alto = b - a + 1; if (alto < 8 || alto > h * 0.5) continue;
    let media = 0, xa = w, xb = -1; for (let y = a; y <= b; y++) { media += Math.max(0, fila[y]); xa = Math.min(xa, x0[y]); xb = Math.max(xb, x1[y]); }
    media /= alto; if (media > 0.3 && alto > 30) continue;                 // barras: muy densas y altas
    if ((xb - xa) < w * 0.1) continue;
    const m = Math.round(alto * 0.35), y = Math.max(0, a - m), yh = Math.min(h, b + m + 1), xi = Math.max(0, xa - m * 2), xf = Math.min(w, xb + m * 2 + 1);
    const o = el('canvas'); o.width = Math.round((xf - xi) / esc); o.height = Math.round((yh - y) / esc);
    o.getContext('2d').drawImage(cv, xi / esc, y / esc, o.width, o.height, 0, 0, o.width, o.height); salida.push(o);
    if (salida.length >= 5) break;
  }
  return salida;
}
async function ocrBuscar(lienzos) {
  const w = await ocrTrabajador(), lecturas = [];

  const leer = async (cv, psm) => {
    await w.setParameters({ tessedit_pageseg_mode: psm });
    const { data } = await w.recognize(prepararOCR(cv));
    lecturas.push(data.text.replace(/\s+/g, ' ').trim());
    return buscarEnTexto(data.text);
  };
  for (const cv of lienzos) {                              // 1) cada franja de texto como línea suelta  2) el lienzo completo como texto disperso
    for (const f of franjasTexto(cv)) { const r = await leer(f, '7'); if (r) return { ...r, lecturas }; }
    const r = await leer(cv, '11'); if (r) return { ...r, lecturas };
  }
  return { bien: null, lecturas };
}
async function leerImpresoYAbrir(codigo, capturadoEn, lienzos) {
  if (!lienzos.length) { señal('no'); return abrirAlta(codigo, capturadoEn, 'camara'); }
  busy('Leyendo el código impreso…'); pausarLector();
  let r; try { r = await ocrBuscar(lienzos); } catch (e) { console.warn('OCR:', e); r = { bien: null, lecturas: [] }; }
  unbusy();
  if (!sesion) return;
  if (r.bien) { señal(r.bien.Baja === '1' ? 'baja' : 'ok'); abrirFicha(r.bien, capturadoEn, 'camara', codigo, r); }
  else { señal('no'); abrirAlta(codigo, capturadoEn, 'camara', r.lecturas); }
}
async function leerImpresoManual() {     // botón «Leer texto impreso»: sin código de barras previo
  if (!sesion || overlayAbierto()) return;
  const lienzos = capturarFrame(null); if (!lienzos.length) return toast('Active la cámara y apunte al texto impreso');
  const capturadoEn = Date.now(); busy('Leyendo el código impreso…'); pausarLector();
  let r; try { r = await ocrBuscar(lienzos); } catch (e) { console.warn('OCR:', e); r = { bien: null, lecturas: [] }; }
  unbusy(); if (!sesion) return;
  if (r.bien) { señal(r.bien.Baja === '1' ? 'baja' : 'ok'); mensaje($('#main-aviso'), 'info', ''); abrirFicha(r.bien, capturadoEn, 'ocr', '', r); }
  else { reanudarLector(); señal('no'); toast('No se reconoció un código de la base'); mensaje($('#main-aviso'), 'info', r.lecturas.some(Boolean) ? 'Texto leído: ' + r.lecturas.filter(Boolean).join(' · ').slice(0, 160) : 'No se leyó texto. Acerque la cámara al código impreso y enfoque.'); }
}
async function leerImpresoDesdeAlta() {  // en «No está en la base»: vuelve a leer el texto impreso con el cuadro actual de la cámara
  const m = $('#alta-bmsg'), lienzos = capturarFrame(null);
  if (!lienzos.length) return mensaje(m, 'err', 'La cámara no está activa.');
  busy('Leyendo el código impreso…');
  let r; try { r = await ocrBuscar(lienzos); } catch (e) { console.warn('OCR:', e); r = { bien: null, lecturas: [] }; }
  unbusy();
  if (r.bien) { $('#alta-impreso').value = r.bien.IDCodigoAntiguo; buscarImpreso(); }
  else mensaje(m, 'err', r.lecturas.some(Boolean) ? 'No coincide con la base. Texto leído: ' + r.lecturas.filter(Boolean).join(' · ').slice(0, 160) : 'No se leyó texto. Acerque la cámara al código impreso.');
}

/* ---------- lectura continua del código impreso (modo por defecto) ---------- */
let modoImpreso = true, timerOCR = null, ocrOcupado = false, ultimoOCR = { id: '', t: 0 };
try { modoImpreso = localStorage.getItem('inv5b_modo') !== 'barras'; } catch (e) { /* sin almacenamiento */ }
function vivo(txt, cls) { const d = $('#ocr-vivo'); if (!d) return; d.textContent = txt || ''; d.className = 'ocr-vivo ' + (cls || ''); d.hidden = !txt; }
function pintarModo() {
  $('#btn-modo').textContent = modoImpreso ? 'Modo: leer código impreso' : 'Modo: leer código de barras';
  if (!(stream || reader)) return;
  $('#cam-hint').textContent = modoImpreso ? 'Apunte al código impreso (texto bajo las barras)' : 'Apunte al código de barras';
  if (!modoImpreso) vivo('');
}
function cambiarModo() {
  modoImpreso = !modoImpreso; try { localStorage.setItem('inv5b_modo', modoImpreso ? 'impreso' : 'barras'); } catch (e) { /* sin almacenamiento */ }
  pintarModo(); programarOCR(0);
}
function programarOCR(ms) { clearTimeout(timerOCR); timerOCR = null; if (modoImpreso && (stream || reader)) timerOCR = setTimeout(cicloOCR, ms); }
async function cicloOCR() {
  timerOCR = null;
  if (!modoImpreso || !(stream || reader) || !sesion) return;
  const v = $('#video');
  if (ocrOcupado || overlayAbierto() || v.readyState < 2 || !v.videoWidth || !$('#busy').hidden) return programarOCR(800);
  ocrOcupado = true; vivo('Leyendo…', 'trabajando');
  let r = null; try { r = await ocrBuscar(capturarFrame(null)); } catch (e) { console.warn('OCR:', e); }
  ocrOcupado = false;
  if (!sesion || !modoImpreso || !(stream || reader)) return vivo('');
  if (r && r.bien) {
    const id = r.bien.IDCodigoAntiguo, ahora = Date.now();
    if (ultimoOCR.id === id && ahora - ultimoOCR.t < 6000) { ultimoOCR.t = ahora; vivo('Leído y encontrado: ' + id, 'ok'); return programarOCR(1200); }
    ultimoOCR = { id, t: ahora }; reiniciarInactividad(); señal(r.bien.Baja === '1' ? 'baja' : 'ok');
    vivo('Leído: ' + r.leido + ' → encontrado ' + id, 'ok');
    return abrirFicha(r.bien, ahora, 'ocr', '', r);
  }
  const txt = r && r.lecturas.filter(Boolean).join(' · ').slice(0, 90);
  vivo(txt ? 'Leído: ' + txt + ' → no coincide con la base' : 'Sin texto legible: acerque la cámara y enfoque', 'no');
  programarOCR(700);
}

/* ---------- cámara ---------- */
let stream = null, detector = null, timerDet = null, reader = null, torchOn = false, lectorPausado = false;
const alResultadoZX = res => { if (res && !modoImpreso) alLeer(res.getText(), 'camara'); };
function pausarLector() { if (reader && !lectorPausado) { lectorPausado = true; try { reader.stopContinuousDecode(); } catch (e) { /* sin lector */ } } }     // ZXing decodifica sin parar: se detiene mientras hay una ficha u OCR en pantalla
function reanudarLector() { if (reader && lectorPausado) { lectorPausado = false; try { reader.decodeContinuously($('#video'), alResultadoZX); } catch (e) { /* se reabrirá al activar la cámara */ } } }
const FMT_BD = ['code_128', 'code_39', 'code_93', 'codabar', 'itf', 'ean_13', 'ean_8', 'upc_a', 'qr_code', 'data_matrix'];
function pistaVideo() { const v = $('#video').srcObject; return v && v.getVideoTracks && v.getVideoTracks()[0]; }
function detenerCamara() {
  clearInterval(timerDet); timerDet = null; clearTimeout(timerOCR); timerOCR = null; vivo('');
  if (reader) { try { reader.reset(); } catch (e) { /* ya detenido */ } reader = null; } lectorPausado = false;
  if (stream) { stream.getTracks().forEach(t => t.stop()); stream = null; }
  const v = $('#video'); if (v.srcObject) { v.srcObject.getTracks && v.srcObject.getTracks().forEach(t => t.stop()); v.srcObject = null; }
  torchOn = false; $('#cam-hint').textContent = 'Cámara apagada'; $('#btn-cam').textContent = 'Activar cámara';
}
async function iniciarCamara() {
  detenerCamara();
  const hint = $('#cam-hint');
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) { hint.textContent = 'Sin cámara: se necesita HTTPS. Use la digitación manual.'; return; }
  try {
    hint.textContent = 'Iniciando cámara…';
    const video = $('#video');
    detector = null;
    if ('BarcodeDetector' in window) {
      try { const sop = await BarcodeDetector.getSupportedFormats(); const f = FMT_BD.filter(x => sop.includes(x)); if (f.length) detector = new BarcodeDetector({ formats: f }); } catch (e) { detector = null; }
    }
    if (detector) {
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' }, width: { ideal: 1920 }, height: { ideal: 1080 } }, audio: false });
      video.srcObject = stream; await video.play();
      let ocupado = false;
      timerDet = setInterval(async () => {
        if (ocupado || video.readyState < 2 || overlayAbierto()) return;
        ocupado = true;
        try { const r = modoImpreso ? [] : await detector.detect(video); if (r.length) alLeer(r[0].rawValue, 'camara', { bbox: r[0].boundingBox }); } catch (e) { /* cuadro sin código */ }
        ocupado = false;
      }, 150);
    } else {
      const Z = ZXing, hints = new Map();
      hints.set(Z.DecodeHintType.POSSIBLE_FORMATS, [Z.BarcodeFormat.CODE_128, Z.BarcodeFormat.CODE_39, Z.BarcodeFormat.CODE_93, Z.BarcodeFormat.CODABAR, Z.BarcodeFormat.ITF, Z.BarcodeFormat.EAN_13, Z.BarcodeFormat.EAN_8, Z.BarcodeFormat.UPC_A, Z.BarcodeFormat.QR_CODE, Z.BarcodeFormat.DATA_MATRIX]);
      hints.set(Z.DecodeHintType.TRY_HARDER, true);
      reader = new Z.BrowserMultiFormatReader(hints, 200);
      await reader.decodeFromConstraints({ video: { facingMode: { ideal: 'environment' }, width: { ideal: 1920 }, height: { ideal: 1080 } }, audio: false }, video, alResultadoZX);
    }
    $('#btn-cam').textContent = 'Detener cámara'; camQuiere = true; pintarModo(); programarOCR(1200);
  } catch (e) {
    console.error(e);
    hint.textContent = e && e.name === 'NotAllowedError' ? 'Permiso de cámara denegado. Actívelo en los ajustes del navegador o use la digitación manual.' : 'No se pudo abrir la cámara (' + (e && e.name || 'error') + '). Use la digitación manual.';
    detenerCamaraSilencioso();
  }
}
function detenerCamaraSilencioso() { const h = $('#cam-hint').textContent; detenerCamara(); $('#cam-hint').textContent = h; }
async function linterna() {
  const t = pistaVideo(); const caps = t && t.getCapabilities && t.getCapabilities();
  if (!caps || !caps.torch) return toast('La linterna no está disponible');
  torchOn = !torchOn;
  try { await t.applyConstraints({ advanced: [{ torch: torchOn }] }); } catch (e) { torchOn = false; toast('No se pudo cambiar la linterna'); }
}

/* ============================================================
   FICHA
   ============================================================ */
function campo(k, v, cls) { return el('div', { class: 'field ' + (cls || '') }, el('div', { class: 'k', text: k }), el('div', { class: 'v', text: v || '—' })); }
function abrirFicha(bien, capturadoEn, origen, barra, impreso) {
  ctx = { tipo: 'bien', bien, capturadoEn, origen, barra: barra || '', impreso: impreso && impreso.leido ? impreso : null };
  $('#ficha-codigo').textContent = bien.IDCodigoAntiguo;
  $('#ficha-baja').hidden = bien.Baja !== '1';
  const campos = $('#ficha-campos'); campos.replaceChildren(...(bien.CodigoInterno ? [campo('Código interno', bien.CodigoInterno)] : []), campo('Descripción', bien.Descripcion), ...NUEVAS.filter(([c]) => bien[c]).map(([c, t]) => campo(t, bien[c])), campo('Nombre', bien.Nombre), campo('Ubicación', bien.Ubicacion), campo('Ambiente', bien.Ambiente));
  $('#ficha-cap').textContent = fmt(capturadoEn);
  const br = $('#ficha-barra'); br.replaceChildren();
  if (ctx.barra && ctx.barra !== bien.IDCodigoAntiguo) br.append(campo('Código de barras leído', ctx.barra + ' (se asociará a este bien al guardar)'));
  if (bien.CodigoBarras && ctx.barra && normInterno(bien.CodigoBarras) !== normInterno(ctx.barra)) br.append(el('div', { class: 'msg warn', text: 'Este bien ya tenía asociado otro código de barras: ' + bien.CodigoBarras }));
  if (ctx.impreso) br.append(campo('Código impreso leído por la cámara', ctx.impreso.leido + (ctx.impreso.exacto ? '' : ' (corregido a ' + bien.IDCodigoAntiguo + ')')));
  ctx.estadoApi = armarEstado($('#ficha-estado'), bien, usoDe(bien.Ubicacion, bien.Ambiente)); mensaje($('#ficha-msg'), 'err', '');
  const prev = $('#ficha-previo');
  prev.textContent = bien.Resultado ? `Ya verificado: ${bien.Resultado} por ${bien.Usuario} el ${fmt(bien.FechaGuardado)}. Si decide de nuevo, se reemplaza el resultado (el historial se conserva).` : '';
  overlay('ficha');
}
async function guardarDecision(datos) {
  const { bien, capturadoEn, origen } = ctx;
  const reg = { t: 'dec', codigo: bien.IDCodigoAntiguo, Resultado: datos.Resultado, Nombre1: datos.Nombre1 || '', Ubicacion1: datos.Ubicacion1 || '', Ambiente1: datos.Ambiente1 || '', CodigoBarras: ctx.barra || '', CodigoImpreso: ctx.impreso ? ctx.impreso.leido : '', ...ctx.estadoApi.leer(),
    FechaCaptura: capturadoEn, FechaGuardado: Date.now(), Usuario: sesion.usuario, Origen: origen };
  const av = avisoReloj(capturadoEn); if (av) reg.AvisoReloj = av;
  try { await idbAdd('diario', await encJSON(sesion.key, reg)); }
  catch (e) { console.error(e); toast('No se pudo guardar: ' + (e.message || e)); return false; }
  aplicar(reg); pintarStats(); reiniciarInactividad();
  return true;
}
async function correcto() {
  if (!ctx || ctx.tipo !== 'bien' || !ctx.estadoApi.validar($('#ficha-msg'))) return;
  if (await guardarDecision({ Resultado: 'CORRECTO' })) { toast('✔ Correcto guardado'); cerrarYSeguir(); }
}
function cerrarYSeguir() { ctx = null; cerrarOverlays(); $('#manual').value = ''; }

/* ---------- condición, estado, situación y observaciones ---------- */
let seqEst = 0;
function armarEstado(cont, ini, sugerida) {
  const nom = 'cond' + (++seqEst), id = 'est' + seqEst;
  let tocado = !!ini.Condicion;                         // si el usuario ya eligió (o el bien ya tenía), no se vuelve a sugerir
  const inicial = ini.Condicion || sugerida || '';
  const pista = el('div', { class: 'muted', text: !ini.Condicion && sugerida ? 'Sugerida según el ambiente.' : '' });
  const rd = v => el('label', { class: 'rd' }, el('input', { type: 'radio', name: nom, value: v, onchange: () => { tocado = true; pista.textContent = ''; }, ...(inicial === v ? { checked: '' } : {}) }), v);
  const sel = (idc, lista, val) => el('select', { id: idc }, el('option', { value: '', text: 'Seleccione…' }), ...lista.map(x => el('option', { value: x, text: x, ...(x === val ? { selected: '' } : {}) })));
  const sEst = sel(id + 'e', ESTADOS, ini.Estado || 'Bueno'), sSit = sel(id + 's', SITUACIONES, ini.Situacion);
  const obs = el('textarea', { id: id + 'o', maxlength: '500', rows: '3', placeholder: 'Opcional' }); obs.value = ini.Observaciones || '';
  cont.replaceChildren(
    el('label', { style: 'margin-top:0', text: 'Condición *' }), el('div', { class: 'row', role: 'radiogroup', 'aria-label': 'Condición' }, rd('USO'), rd('DESUSO')), pista,
    el('label', { for: id + 'e', text: 'Estado *' }), sEst,
    el('label', { for: id + 's', text: 'Situación' }), sSit,
    el('label', { for: id + 'o', text: 'Observaciones' }), obs);
  const falta = () => { const v = api.leer(); return !v.Condicion ? 'Elija la Condición: USO o DESUSO.' : !v.Estado ? 'Elija el Estado del bien.' : ''; };
  const api = { validar(msgCont) { const f = falta(); mensaje(msgCont, 'err', f); if (f) (!sEst.value && cont.querySelector('input[type=radio]:checked') ? sEst : cont.querySelector('input[type=radio]')).focus(); return !f; },
    sugerir(c) { if (tocado || !c) return; cont.querySelectorAll('input[type=radio]').forEach(r => { r.checked = r.value === c; }); pista.textContent = 'Sugerida según el ambiente.'; },
    leer() { const c = cont.querySelector('input[type=radio]:checked'); return { Condicion: c ? c.value : '', Estado: sEst.value, Situacion: sSit.value, Observaciones: obs.value.trim() }; } };
  return api;
}

/* ============================================================
   COMBOS (listas con filtro)
   ============================================================ */
let seqCombo = 0;
function crearCombo(etiqueta, valorInicial, lista) {
  const id = 'cb' + (++seqCombo);
  const dl = el('datalist', { id: 'dl-' + id });
  const inp = el('input', { type: 'text', id, list: 'dl-' + id, autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false', placeholder: 'Seleccione…' });
  const api = { id, input: inp, lista: [], wrap: el('div', {}, el('label', { for: id, text: etiqueta }), inp, dl),
    setLista(l) { api.lista = l; dl.replaceChildren(...l.map(x => el('option', { value: x }))); },
    valor() { const v = inp.value.trim().toLowerCase(); return api.lista.find(x => x.toLowerCase() === v) || null; } };
  let previo = '';
  inp.addEventListener('focus', () => { previo = inp.value; inp.value = ''; });
  inp.addEventListener('blur', () => { if (!inp.value.trim()) inp.value = previo; else { const v = api.valor(); if (v) inp.value = v; } });
  api.setLista(lista); inp.value = valorInicial || '';
  return api;
}
function ambientesDe(ubic) { if (ubic && S.cat.porUbic.has(ubic)) return S.cat.porUbic.get(ubic); return S.cat.estricto ? [] : S.cat.ambientes; }   // con UbicacionAmbiente: primero la ubicación, luego solo sus ambientes
const sugerirCond = (u, a) => { const c = u && a && usoDe(u, a); if (c && ctx && ctx.estadoApi) ctx.estadoApi.sugerir(c); };
function armarCombosTres(cont, inicial, alCambiar) {
  const n = crearCombo('Nombre', inicial.Nombre, S.cat.nombres);
  const u = crearCombo('Ubicación', inicial.Ubicacion, S.cat.ubicaciones);
  const a = crearCombo('Ambiente', inicial.Ambiente, ambientesDe(inicial.Ubicacion));
  const alCambiarU = () => { const v = u.valor(); if (v) { const l = ambientesDe(v); a.setLista(l); if (!l.includes(a.valor())) a.input.value = ''; } else if (S.cat.estricto) { a.setLista([]); a.input.value = ''; } };
  u.input.addEventListener('change', alCambiarU); u.input.addEventListener('blur', alCambiarU); u.input.addEventListener('input', alCambiarU);
  if (alCambiar) [u, a].forEach(x => ['change', 'blur'].forEach(ev => x.input.addEventListener(ev, () => alCambiar(u.valor(), a.valor()))));
  cont.replaceChildren(n.wrap, u.wrap, a.wrap);
  return { n, u, a };
}
function leerTres(c, msgCont) {
  const n = c.n.valor(), u = c.u.valor(), a = c.a.valor();
  if (!n) { mensaje(msgCont, 'err', 'Elija un Nombre de la lista.'); return null; }
  if (!u) { mensaje(msgCont, 'err', 'Elija una Ubicación de la lista.'); return null; }
  if (!a) { mensaje(msgCont, 'err', 'Elija un Ambiente de la lista.'); return null; }
  mensaje(msgCont, 'err', ''); return { n, u, a };
}

/* ---------- corrección ---------- */
let combosCorr = null;
function abrirCorreccion() {
  if (!ctx.estadoApi.validar($('#ficha-msg'))) return;
  const b = ctx.bien;
  $('#corr-codigo').textContent = b.IDCodigoAntiguo;
  const f = $('#corr-form'); f.replaceChildren(); mensaje($('#corr-msg'), 'err', '');
  combosCorr = armarCombosTres(f, { Nombre: b.Nombre, Ubicacion: b.Ubicacion, Ambiente: b.Ambiente }, sugerirCond);
  const rel = [['Nombre (actual)', b.Nombre], ['Ubicación (actual)', b.Ubicacion], ['Ambiente (actual)', b.Ambiente]];
  const ref = el('div', { class: 'card' }, ...rel.map(([k, v]) => campo(k, v, 'old')));
  f.prepend(ref);
  [['Nombre', 'Nombre1'], ['Ubicación', 'Ubicacion1'], ['Ambiente', 'Ambiente1']].forEach(([k, n], i) => { const lab = f.querySelectorAll('label')[i]; if (lab) lab.textContent = n; });
  overlay('corr');
}
async function guardarCorreccion() {
  const m = $('#corr-msg'), v = leerTres(combosCorr, m); if (!v) return;
  const b = ctx.bien;
  if (v.n === b.Nombre && v.u === b.Ubicacion && v.a === b.Ambiente) return mensaje(m, 'err', 'No cambió ningún dato. Si todo es igual, use «Correcto».');
  if (await guardarDecision({ Resultado: 'INCORRECTO', Nombre1: v.n, Ubicacion1: v.u, Ambiente1: v.a })) { toast('Corrección guardada'); cerrarYSeguir(); }
}

/* ---------- alta de sobrante ---------- */
let combosAlta = null;
function abrirAlta(codigo, capturadoEn, origen, lecturas) {
  ctx = { tipo: 'alta', codigo, capturadoEn, origen };
  $('#alta-codigo').textContent = codigo;
  $('#alta-buscar').hidden = origen !== 'camara'; $('#alta-impreso').value = ''; mensaje($('#alta-bmsg'), 'info', lecturas && lecturas.some(Boolean) ? 'La cámara leyó: ' + lecturas.filter(Boolean).join(' · ').slice(0, 160) + ' (no coincide con la base).' : '');
  ctx.estadoApi = armarEstado($('#alta-estado'), { Situacion: 'Sobrantes' }, '');
  const fm = formatoDe(codigo);
  $('#alta-aviso').replaceChildren(fm ? '' : el('div', { class: 'msg warn', text: 'El formato no coincide con ninguno conocido. Verifique que la lectura sea correcta.' }));
  combosAlta = armarCombosTres($('#alta-form'), { Nombre: '', Ubicacion: '', Ambiente: '' }, sugerirCond);
  mensaje($('#alta-msg'), 'err', '');
  overlay('alta');
}
async function guardarAlta() {
  const m = $('#alta-msg'), v = leerTres(combosAlta, m); if (!v || !ctx.estadoApi.validar(m)) return;
  const { codigo, capturadoEn, origen } = ctx;
  const reg = { t: 'alta', codigo, Nombre: v.n, Ubicacion: v.u, Ambiente: v.a, FechaCaptura: capturadoEn, FechaGuardado: Date.now(), Usuario: sesion.usuario, Origen: origen, FormatoReconocido: formatoDe(codigo) ? 'SI' : 'NO', CodigoBarras: origen === 'camara' ? codigo : '', CodigoImpreso: limpiar($('#alta-impreso').value), ...ctx.estadoApi.leer() };
  const av = avisoReloj(capturadoEn); if (av) reg.AvisoReloj = av;
  try { await idbAdd('diario', await encJSON(sesion.key, reg)); } catch (e) { console.error(e); return mensaje(m, 'err', 'No se pudo guardar: ' + (e.message || e)); }
  aplicar(reg); pintarStats(); reiniciarInactividad(); toast('Alta guardada'); cerrarYSeguir();
}

function buscarImpreso() {
  const m = $('#alta-bmsg'), v = limpiar($('#alta-impreso').value);
  if (!v) return mensaje(m, 'err', 'Escriba el código impreso en la etiqueta.');
  const bien = buscarBien(v);
  if (!bien) return mensaje(m, 'err', 'El código impreso «' + v + '» no está en la base.');
  const { codigo, capturadoEn, origen } = ctx;
  señal(bien.Baja === '1' ? 'baja' : 'ok'); abrirFicha(bien, capturadoEn, origen, codigo);
}

/* ============================================================
   MENÚ, EXPORTACIÓN Y SEGURIDAD
   ============================================================ */
function abrirMenu() {
  const c = contar(), r = $('#menu-resumen'); r.replaceChildren();
  const t = el('table');
  [['Bienes en el maestro', c.total], ['Correctos', c.ok], ['Incorrectos', c.mal], ['Pendientes (faltantes si termina hoy)', c.pend], ['Altas (sobrantes)', c.altas], ['Registros en el historial', S.historial.length]]
    .forEach(([k, v]) => t.append(el('tr', {}, el('td', { text: k }), el('td', { text: String(v) }))));
  r.append(t);
  const u = $('#menu-ultimos'); u.replaceChildren();
  const ult = S.historial.slice(-15).reverse();
  if (!ult.length) u.append(el('p', { class: 'muted', text: 'Aún no hay registros.' }));
  else {
    const tb = el('table'); tb.append(el('tr', {}, ...['Hora', 'Código', 'Resultado', 'Usuario'].map(h => el('th', { text: h }))));
    ult.forEach(x => tb.append(el('tr', {}, el('td', { text: fmt(x.FechaGuardado).slice(11) }), el('td', { text: x.codigo }), el('td', { text: x.t === 'alta' ? 'ALTA' : x.Resultado }), el('td', { text: x.Usuario }))));
    u.append(tb);
  }
  $('#menu-info').textContent = `Maestro: ${S.info.archivo} (${S.info.filas} filas, cargado ${fmt(S.info.cargadoEn)}) · Versión ${APP_VER}`;
  overlay('menu');
}

function construirLibro() {
  const ws = (aoa, anchos, colsFecha) => {
    const h = XLSX.utils.aoa_to_sheet(aoa);
    h['!cols'] = anchos.map(w => ({ wch: w }));
    const rango = XLSX.utils.decode_range(h['!ref']);
    for (let r = 1; r <= rango.e.r; r++) colsFecha.forEach(c => { const a = h[XLSX.utils.encode_cell({ r, c })]; if (a && a.t === 'n') a.z = 'dd/mm/yyyy hh:mm:ss'; });
    h['!autofilter'] = { ref: h['!ref'] };
    return h;
  };
  const f = ms => ms ? serial(ms) : '';
  const bienes = [...S.bienes.values()];
  const encB = [...COLS, 'CodigoInterno', 'Resultado', 'Nombre1', 'Ubicacion1', 'Ambiente1', 'FechaCaptura', 'FechaGuardado', 'Usuario', 'AvisoReloj', 'CodigoBarras', 'Condicion', 'Estado', 'Situacion', 'Observaciones', ...NUEVAS.map(([c]) => c)];
  const aoaB = [encB, ...bienes.map(b => [b.IDCodigoAntiguo, b.Descripcion, b.Nombre, b.Ubicacion, b.Ambiente, Number(b.Baja), b.CodigoInterno, b.Resultado, b.Nombre1, b.Ubicacion1, b.Ambiente1, f(b.FechaCaptura), f(b.FechaGuardado), b.Usuario, b.AvisoReloj, b.CodigoBarras, b.Condicion, b.Estado, b.Situacion, b.Observaciones, ...NUEVAS.map(([c]) => b[c] || '')])];
  const aoaL = [['Tipo', 'IDCodigoAntiguo', 'Resultado', 'Nombre1', 'Ubicacion1', 'Ambiente1', 'FechaCaptura', 'FechaGuardado', 'Usuario', 'Origen', 'AvisoReloj', 'CodigoBarras', 'Condicion', 'Estado', 'Situacion', 'Observaciones', 'CodigoImpreso'],
    ...S.historial.map(x => [x.t === 'alta' ? 'ALTA' : 'DECISION', x.codigo, x.t === 'alta' ? 'SOBRANTE' : x.Resultado, x.t === 'alta' ? x.Nombre : x.Nombre1, x.t === 'alta' ? x.Ubicacion : x.Ubicacion1, x.t === 'alta' ? x.Ambiente : x.Ambiente1, f(x.FechaCaptura), f(x.FechaGuardado), x.Usuario, x.Origen, x.AvisoReloj || '', x.CodigoBarras || '', x.Condicion || '', x.Estado || '', x.Situacion || '', x.Observaciones || '', x.CodigoImpreso || ''])];
  const aoaA = [['Codigo', 'Nombre', 'Ubicacion', 'Ambiente', 'FechaCaptura', 'FechaGuardado', 'Usuario', 'Origen', 'FormatoReconocido', 'AvisoReloj', 'CodigoBarras', 'CodigoImpreso', 'Condicion', 'Estado', 'Situacion', 'Observaciones'],
    ...S.altas.map(x => [x.codigo, x.Nombre, x.Ubicacion, x.Ambiente, f(x.FechaCaptura), f(x.FechaGuardado), x.Usuario, x.Origen, x.FormatoReconocido, x.AvisoReloj || '', x.CodigoBarras || '', x.CodigoImpreso || '', x.Condicion || '', x.Estado || '', x.Situacion || '', x.Observaciones || ''])];
  const aoaF = [[...COLS, ...NUEVAS.map(([c]) => c)], ...bienes.filter(b => !b.Resultado).map(b => [b.IDCodigoAntiguo, b.Descripcion, b.Nombre, b.Ubicacion, b.Ambiente, Number(b.Baja), ...NUEVAS.map(([c]) => b[c] || '')])];
  const c = contar();
  const aoaI = [['Campo', 'Valor'], ['Exportado por', sesion.usuario], ['Exportado el', fmt(Date.now())], ['Maestro', S.info.archivo], ['Bienes', c.total], ['Correctos', c.ok], ['Incorrectos', c.mal], ['Faltantes (sin resultado)', c.pend], ['Altas', c.altas], ['Versión de la aplicación', APP_VER]];
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws(aoaB, [16, 60, 30, 30, 30, 6, 14, 12, 28, 28, 28, 20, 20, 10, 14, 16, 10, 10, 22, 40, 16, 16, 16, 16, 16, 24, 50], [11, 12]), 'Bienes');
  XLSX.utils.book_append_sheet(wb, ws(aoaL, [10, 16, 12, 28, 28, 28, 20, 20, 10, 10, 14, 16, 10, 10, 22, 40, 18], [6, 7]), 'Lecturas');
  XLSX.utils.book_append_sheet(wb, ws(aoaA, [16, 28, 28, 28, 20, 20, 10, 10, 10, 14, 16, 16, 10, 10, 22, 40], [4, 5]), 'Altas');
  XLSX.utils.book_append_sheet(wb, ws(aoaF, [16, 60, 30, 30, 30, 6, 16, 16, 16, 16, 16, 24, 50], []), 'Faltantes');
  XLSX.utils.book_append_sheet(wb, ws(aoaI, [30, 40], []), 'Info');
  return wb;
}
function nombreArchivo() { const d = new Date(); return `Inventario_${d.getFullYear()}${p2(d.getMonth() + 1)}${p2(d.getDate())}_${p2(d.getHours())}${p2(d.getMinutes())}_${sesion.usuario}.xlsx`; }
async function confirmarClaro() {
  return await dialogo('Exportar a Excel', el('p', { text: 'El Excel contiene los datos y los nombres tal cual. Envíelo solo por un canal acordado y bórrelo del celular cuando ya no se necesite.' }),
    [{ t: 'Cancelar', v: false, cls: 'sec' }, { t: 'Exportar', v: true }]);
}
async function exportar(compartir) {
  if (!(await confirmarClaro())) return;
  try {
    busy('Generando Excel…'); await tick();
    const wb = construirLibro(); const buf = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
    const nombre = nombreArchivo();
    const blob = new Blob([buf], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
    unbusy();
    if (compartir) {
      const file = new File([blob], nombre, { type: blob.type });
      if (navigator.canShare && navigator.canShare({ files: [file] })) { try { await navigator.share({ files: [file], title: nombre }); return; } catch (e) { if (e.name === 'AbortError') return; } }
      toast('Compartir no está disponible; se descargará.');
    }
    const a = el('a', { href: URL.createObjectURL(blob), download: nombre }); document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 30000); toast('Excel generado: ' + nombre);
  } catch (e) { unbusy(); console.error(e); toast('Error al exportar: ' + (e.message || e)); }
}

async function pedirClave(titulo, texto) {
  const inp = el('input', { type: 'password', autocomplete: 'off', id: 'dlg-clave' });
  const ok = await dialogo(titulo, [el('p', { class: 'muted', text: texto }), inp], [{ t: 'Cancelar', v: false, cls: 'sec' }, { t: 'Aceptar', v: true }]);
  return ok ? inp.value : null;
}
async function cambiarClave() {
  const vieja = await pedirClave('Cambiar mi clave', 'Escriba su clave actual.'); if (vieja == null) return;
  const nueva = el('input', { type: 'password', autocomplete: 'new-password' }), rep = el('input', { type: 'password', autocomplete: 'new-password' });
  const ok = await dialogo('Nueva clave', [el('p', { class: 'muted', text: `Mínimo ${MIN_CLAVE} caracteres, no solo números.` }), nueva, el('div', { style: 'height:8px' }), rep], [{ t: 'Cancelar', v: false, cls: 'sec' }, { t: 'Cambiar', v: true }]);
  if (!ok) return;
  if (nueva.value.length < MIN_CLAVE || /^\d+$/.test(nueva.value)) return toast(`La clave debe tener ${MIN_CLAVE}+ caracteres y no ser solo números.`);
  if (nueva.value !== rep.value) return toast('Las claves no coinciden.');
  try {
    busy('Procesando…'); await tick();
    const meta = await idbGet('meta', 'meta');
    let raw; try { raw = await desenvolver(sesion.usuario, vieja, meta); } catch (e) { unbusy(); return toast('La clave actual es incorrecta.'); }
    const sal = crypto.getRandomValues(new Uint8Array(16));
    const kek = await derivarKEK(nueva.value, sal, meta.iter);
    meta.usuarios[sesion.usuario] = { sal, ...(await aesEnc(kek, raw)) }; raw.fill(0);
    await idbPut('meta', meta); unbusy(); toast('Clave cambiada');
  } catch (e) { unbusy(); console.error(e); toast('No se pudo cambiar: ' + (e.message || e)); }
}
async function borrarTodo() {
  const frase = await pedirClave('Borrar toda la base', 'Se eliminarán el maestro y todos los registros de este celular. Escriba su clave para continuar.'); if (frase == null) return;
  try { busy('Procesando…'); await tick(); const meta = await idbGet('meta', 'meta'); (await desenvolver(sesion.usuario, frase, meta)).fill(0); unbusy(); }
  catch (e) { unbusy(); return toast('Clave incorrecta.'); }
  const t = el('input', { type: 'text', autocomplete: 'off', placeholder: 'BORRAR' });
  const ok = await dialogo('Confirmar', [el('p', { text: 'Escriba BORRAR para confirmar. Esta acción no se puede deshacer; exporte antes si necesita los datos.' }), t], [{ t: 'Cancelar', v: false, cls: 'sec' }, { t: 'Borrar todo', v: true, cls: 'no' }]);
  if (!ok || t.value.trim() !== 'BORRAR') return toast('No se borró nada.');
  detenerCamara(); sesion = null; S = null; await borrarDB();
  try { USUARIOS.forEach(u => localStorage.removeItem('fallos_' + u)); } catch (e) { /* sin acceso */ }
  iniciarSetup();
}

/* ============================================================
   ARRANQUE
   ============================================================ */
function conectar() {
  $('#f-maestro').addEventListener('change', async ev => {
    const f = ev.target.files[0]; if (!f) return;
    const msg = $('#setup-msg'); mensaje(msg, 'err', ''); maestroCargado = null; $('#btn-setup').disabled = true;
    try {
      busy('Leyendo el archivo…'); await tick();
      const r = leerMaestro(await f.arrayBuffer(), f.name);
      if (!r.bienes.length) throw new Error('No se encontraron bienes con código.');
      r.total = r.resumen.total; maestroCargado = r; pintarResumen(r); $('#btn-setup').disabled = false; unbusy();
    } catch (e) { unbusy(); console.error(e); $('#setup-resumen').replaceChildren(); mensaje(msg, 'err', 'No se pudo leer el maestro: ' + (e.message || e)); }
  });
  $('#setup-ver').addEventListener('change', e => document.querySelectorAll('#setup-claves input').forEach(i => i.type = e.target.checked ? 'text' : 'password'));
  $('#btn-setup').addEventListener('click', crearBase);
  $('#login-ver').addEventListener('change', e => { $('#login-clave').type = e.target.checked ? 'text' : 'password'; });
  $('#btn-login').addEventListener('click', entrar);
  $('#login-clave').addEventListener('keydown', e => { if (e.key === 'Enter') entrar(); });
  $('#btn-lock').addEventListener('click', () => bloquear('Sesión cerrada.'));
  $('#btn-menu').addEventListener('click', abrirMenu);
  $('#btn-menu-cerrar').addEventListener('click', () => overlay(null));
  $('#btn-cam').addEventListener('click', () => { if (stream || reader) { camQuiere = false; detenerCamara(); } else iniciarCamara(); });
  $('#btn-torch').addEventListener('click', linterna);
  $('#btn-ocr').addEventListener('click', leerImpresoManual);
  $('#btn-modo').addEventListener('click', cambiarModo); pintarModo();
  $('#btn-alta-ocr').addEventListener('click', leerImpresoDesdeAlta);
  const manual = () => { const v = $('#manual').value; if (v.trim()) { $('#manual').value = ''; alLeer(v, 'manual'); } };
  $('#btn-manual').addEventListener('click', manual);
  $('#manual').addEventListener('keydown', e => { if (e.key === 'Enter') manual(); });
  $('#btn-correcto').addEventListener('click', correcto);
  $('#btn-incorrecto').addEventListener('click', abrirCorreccion);
  $('#btn-descartar').addEventListener('click', cerrarYSeguir);
  $('#btn-corr-guardar').addEventListener('click', guardarCorreccion);
  $('#btn-corr-cancelar').addEventListener('click', () => overlay('ficha'));
  $('#btn-alta-buscar').addEventListener('click', buscarImpreso);
  $('#alta-impreso').addEventListener('keydown', e => { if (e.key === 'Enter') buscarImpreso(); });
  $('#btn-alta-guardar').addEventListener('click', guardarAlta);
  $('#btn-alta-cancelar').addEventListener('click', cerrarYSeguir);
  $('#btn-export').addEventListener('click', () => exportar(false));
  $('#btn-share').addEventListener('click', () => exportar(true));
  $('#btn-cambiar').addEventListener('click', cambiarClave);
  $('#btn-borrar').addEventListener('click', borrarTodo);
  $('#sel-bloqueo').addEventListener('change', e => { try { localStorage.setItem('bloqueoMin', e.target.value); } catch (x) { /* sin acceso */ } reiniciarInactividad(); toast('Bloqueo: ' + e.target.value + ' min'); });
}

(async function main() {
  conectar();
  if (!window.crypto || !crypto.subtle) {
    document.body.replaceChildren(el('main', { class: 'page' }, el('h1', { text: 'Contexto no seguro' }), el('p', { text: 'Esta aplicación necesita HTTPS (o localhost) para usar la cámara y guardar los datos. Abra la dirección https:// de la aplicación.' })));
    return;
  }
  if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1')) {
    navigator.serviceWorker.register('sw.js').catch(e => console.warn('SW:', e));
  }
  try {
    const meta = await idbGet('meta', 'meta');
    if (meta) { usuarioFijo = Object.keys(meta.usuarios)[0]; iniciarLogin(''); } else iniciarSetup();
  } catch (e) { console.error(e); document.body.prepend(el('div', { class: 'msg err', text: 'No se pudo abrir el almacenamiento del navegador: ' + (e.message || e) })); }
})();
