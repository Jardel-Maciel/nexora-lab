# -*- coding: utf-8 -*-
"""
Nexora Lab — alvo de treino de pentest (versao single-file).

Aplicacao web DELIBERADAMENTE vulneravel, para treino legal (seu sistema, seu
servidor). Simula o portal interno de uma empresa ficticia. Ha varias falhas
plantadas e flags (flag{...}) para capturar.

O "mundo" (banco + arquivos) se reconstroi sozinho: se passou de
RESET_INTERVAL_MIN minutos desde o ultimo reset, ele reconstroi no proximo
acesso. Tambem da pra forcar em /__maintenance/reset?token=...

NAO use este codigo em producao real. E um alvo de tiro.
"""
import os
import time
import base64
import hashlib
import hmac
import json
import random
import string
import shutil
import subprocess
import urllib.request

import psycopg2
import psycopg2.extras
from flask import (
    Flask, request, redirect, make_response, abort, jsonify,
    render_template, render_template_string, url_for, g,
)
from jinja2 import DictLoader

# ===========================================================================
# Config
# ===========================================================================
DATABASE_URL = os.environ.get("DATABASE_URL", "")
RESET_TOKEN = os.environ.get("RESET_TOKEN", "troque-este-token")
RESET_INTERVAL_MIN = int(os.environ.get("RESET_INTERVAL_MIN", "30"))
DATA_DIR = os.environ.get("DATA_DIR", "/tmp/nexora_data")
APP_SECRET = os.environ.get("APP_SECRET", "nexora")  # fraco de proposito

FLAGS = {
    "login":    "flag{quem_nao_valida_entrada_colhe_injecao}",
    "dump":     "flag{union_select_abriu_o_cofre}",
    "stored":   "flag{script_que_mora_no_banco}",
    "idor":     "flag{id_sequencial_e_um_convite}",
    "authz":    "flag{cookie_nao_e_cracha_de_admin}",
    "template": "flag{chaves_duplas_viram_codigo}",
    "exec":     "flag{o_servidor_obedeceu_o_comando}",
    "fs":       "flag{dois_pontos_dois_pontos_barra}",
    "pickle":   "flag{nao_desserialize_o_que_nao_confia}",
    "privesc":  "flag{campo_escondido_virou_admin}",
    "leak":     "flag{backup_publico_e_mapa_do_tesouro}",
}
ADMIN_PASSWORD = "Nexora@Adm1n2024"


# ===========================================================================
# DB helpers
# ===========================================================================
def get_conn():
    if "db_conn" not in g:
        g.db_conn = psycopg2.connect(DATABASE_URL)
        g.db_conn.autocommit = True
    return g.db_conn


def close_conn(exc=None):
    conn = g.pop("db_conn", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass


def query(sql, params=None, one=False):
    cur = get_conn().cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(sql, params)
    rows = cur.fetchall()
    cur.close()
    if one:
        return rows[0] if rows else None
    return rows


def execute(sql, params=None):
    cur = get_conn().cursor()
    cur.execute(sql, params)
    cur.close()


# ===========================================================================
# Tokens de sessao (tipo-JWT; aceita alg=none e usa segredo fraco de proposito)
# ===========================================================================
def _b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign(signing_input, secret):
    return _b64e(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())


def make_token(payload):
    h = _b64e(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    p = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    s = _sign(f"{h}.{p}".encode(), APP_SECRET)
    return f"{h}.{p}.{s}"


def read_token(token):
    try:
        h_b64, p_b64, s_b64 = token.split(".")
        header = json.loads(_b64d(h_b64))
        payload = json.loads(_b64d(p_b64))
        if header.get("alg") == "none":
            return payload
        expected = _sign(f"{h_b64}.{p_b64}".encode(), APP_SECRET)
        return payload if hmac.compare_digest(expected, s_b64) else None
    except Exception:
        return None


def current_user():
    token = request.cookies.get("nx_session")
    if not token:
        return None
    payload = read_token(token)
    if not payload or payload.get("uid") is None:
        return None
    try:
        user = query("SELECT * FROM users WHERE id = %s", (payload["uid"],), one=True)
    except Exception:
        return None
    if not user:
        return None
    user = dict(user)
    user["role"] = payload.get("role", user.get("role", "user"))
    return user


def get_setting(key, default=""):
    row = query("SELECT value FROM settings WHERE key = %s", (key,), one=True)
    return row["value"] if row else default


# ===========================================================================
# Schema + seed + arquivos
# ===========================================================================
SCHEMA = """
DROP TABLE IF EXISTS reviews, orders, invoices, tickets, settings, secrets, users, products CASCADE;
CREATE TABLE users (
    id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
    email TEXT, full_name TEXT, bio TEXT DEFAULT '', role TEXT DEFAULT 'user',
    balance NUMERIC DEFAULT 0, api_key TEXT);
CREATE TABLE products (
    id SERIAL PRIMARY KEY, name TEXT NOT NULL, description TEXT, price NUMERIC NOT NULL,
    category TEXT, stock INTEGER DEFAULT 0);
CREATE TABLE reviews (
    id SERIAL PRIMARY KEY, product_id INTEGER REFERENCES products(id), author TEXT,
    body TEXT, created_at TIMESTAMP DEFAULT now());
CREATE TABLE orders (
    id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id),
    product_id INTEGER REFERENCES products(id), qty INTEGER, total NUMERIC,
    created_at TIMESTAMP DEFAULT now());
CREATE TABLE invoices (
    id SERIAL PRIMARY KEY, order_id INTEGER, user_id INTEGER, filename TEXT);
CREATE TABLE tickets (
    id SERIAL PRIMARY KEY, user_id INTEGER, subject TEXT, body TEXT,
    status TEXT DEFAULT 'aberto', created_at TIMESTAMP DEFAULT now());
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE secrets (name TEXT PRIMARY KEY, flag TEXT);
"""


def _rand_key(n=24):
    return "nx_" + "".join(random.choices(string.ascii_letters + string.digits, k=n))


def _seed(cur):
    users = [
        ("admin", ADMIN_PASSWORD, "admin@nexora.corp", "Administrador do Sistema", "Conta de administracao.", "admin", 0),
        ("jlima", "senha123", "joao.lima@nexora.corp", "Joao Lima", "Analista de compras.", "user", 1200),
        ("msantos", "mariana2023", "mariana@nexora.corp", "Mariana Santos", "Financeiro.", "user", 350),
        ("pcosta", "qwerty", "pedro.costa@nexora.corp", "Pedro Costa", "Estagiario de TI.", "user", 50),
        ("rfaria", "iloveyou", "renata@nexora.corp", "Renata Faria", "RH.", "user", 800),
        ("suporte", "suporte", "suporte@nexora.corp", "Equipe de Suporte", "Atendimento interno.", "support", 0),
    ]
    for u in users:
        cur.execute(
            "INSERT INTO users (username,password,email,full_name,bio,role,balance,api_key)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (u[0], u[1], u[2], u[3], u[4], u[5], u[6], _rand_key()))
    products = [
        ("Licenca Nexora ERP", "Licenca anual do ERP corporativo.", 4990.00, "software", 25),
        ("Suporte Premium 24x7", "Pacote de suporte dedicado.", 1290.00, "servico", 100),
        ("Notebook Nexora Pro 14", "i7, 32GB, 1TB SSD.", 8790.00, "hardware", 12),
        ("Monitor UltraWide 34", "Monitor curvo para produtividade.", 2490.00, "hardware", 30),
        ("Treinamento DevSecOps", "Trilha de 40h para o time de engenharia.", 3200.00, "servico", 40),
        ("Backup Cloud 1TB", "Armazenamento gerenciado.", 199.00, "servico", 500),
    ]
    for p in products:
        cur.execute("INSERT INTO products (name,description,price,category,stock) VALUES (%s,%s,%s,%s,%s)", p)
    for r in [(1, "jlima", "Otimo ERP, integrou com nosso financeiro rapidinho."),
              (3, "pcosta", "Notebook voando, recomendo."),
              (2, "msantos", "Suporte respondeu em minutos.")]:
        cur.execute("INSERT INTO reviews (product_id,author,body) VALUES (%s,%s,%s)", r)
    orders = [(2, 1, 1, 4990.00), (3, 4, 1, 2490.00), (2, 6, 3, 597.00), (5, 5, 1, 3200.00)]
    for i, o in enumerate(orders, start=1001):
        cur.execute("INSERT INTO orders (user_id,product_id,qty,total) VALUES (%s,%s,%s,%s) RETURNING id", o)
        oid = cur.fetchone()[0]
        cur.execute("INSERT INTO invoices (order_id,user_id,filename) VALUES (%s,%s,%s)",
                    (oid, o[0], f"INV-{i}.txt"))
    for t in [(3, "Nao consigo emitir nota", "Ao clicar em emitir da erro 500."),
              (4, "Reset de senha", "Pode resetar minha senha, por favor?")]:
        cur.execute("INSERT INTO tickets (user_id,subject,body) VALUES (%s,%s,%s)", t)
    for s in [("homepage_banner", "Bem-vindo ao portal interno da Nexora Corp."),
              ("company_name", "Nexora Corp"), ("maintenance", "off"),
              ("last_reset_epoch", str(time.time()))]:
        cur.execute("INSERT INTO settings (key,value) VALUES (%s,%s)", s)
    for name, flag in FLAGS.items():
        cur.execute("INSERT INTO secrets (name,flag) VALUES (%s,%s)", (name, flag))


def _write_files():
    invoices = os.path.join(DATA_DIR, "invoices")
    private = os.path.join(DATA_DIR, "private")
    uploads = os.path.join(DATA_DIR, "uploads")
    try:
        if os.path.isdir(DATA_DIR):
            shutil.rmtree(DATA_DIR, ignore_errors=True)
    except OSError:
        pass
    for d in (invoices, private, uploads):
        os.makedirs(d, exist_ok=True)
    bodies = {
        "INV-1001.txt": "Fatura INV-1001\nCliente: Joao Lima\nItem: Licenca Nexora ERP\nTotal: R$ 4.990,00",
        "INV-1002.txt": "Fatura INV-1002\nCliente: Mariana Santos\nItem: Monitor UltraWide 34\nTotal: R$ 2.490,00",
        "INV-1003.txt": "Fatura INV-1003\nCliente: Joao Lima\nItem: Backup Cloud 1TB x3\nTotal: R$ 597,00",
        "INV-1004.txt": "Fatura INV-1004\nCliente: Renata Faria\nItem: Treinamento DevSecOps\nTotal: R$ 3.200,00",
    }
    for name, body in bodies.items():
        with open(os.path.join(invoices, name), "w", encoding="utf-8") as f:
            f.write(body)
    with open(os.path.join(private, "credentials.txt"), "w", encoding="utf-8") as f:
        f.write("# Credenciais internas - NAO PUBLICAR\n"
                f"admin:{ADMIN_PASSWORD}\ndb_root:nx_root_7h3_s3cr3t\n{FLAGS['fs']}\n")
    with open(os.path.join(DATA_DIR, "backup.sql"), "w", encoding="utf-8") as f:
        f.write("-- Dump parcial do banco Nexora\n-- NAO DEVERIA ESTAR ACESSIVEL\n"
                "INSERT INTO users (username,password,role) VALUES\n"
                f"  ('admin','{ADMIN_PASSWORD}','admin'),\n  ('suporte','suporte','support');\n"
                f"-- {FLAGS['leak']}\n")


def ensure_files():
    try:
        _write_files()
    except Exception:
        pass


def reset_world():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute(SCHEMA)
    _seed(cur)
    cur.close()
    conn.close()
    _write_files()


def db_is_empty():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute("SELECT to_regclass('public.users')")
        empty = cur.fetchone()[0] is None
        cur.close()
        conn.close()
        return empty
    except Exception:
        return True


# ===========================================================================
# Templates (DictLoader)
# ===========================================================================
BASE = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{% block title %}Nexora Corp{% endblock %}</title><style>
:root{--bg:#0f1420;--panel:#161d2e;--panel2:#1d2740;--line:#273350;--fg:#e6ebf5;--mut:#8b97b4;--acc:#4f8cff;--acc2:#2bd4a7;--warn:#ff5c7a}
*{box-sizing:border-box}body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg);line-height:1.5}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.topbar{display:flex;align-items:center;justify-content:space-between;padding:14px 24px;background:var(--panel);border-bottom:1px solid var(--line)}
.brand a{font-size:20px;font-weight:700;color:var(--fg)}.brand span{color:var(--acc)}
nav{display:flex;align-items:center;gap:16px;flex-wrap:wrap}nav .who{color:var(--mut);font-size:13px}nav .adm{color:var(--acc2);font-weight:600}
.btn-sm{background:var(--acc);color:#fff;padding:6px 12px;border-radius:6px;font-size:14px}.btn-sm:hover{text-decoration:none;opacity:.9}
main{max-width:1000px;margin:0 auto;padding:28px 24px}
footer{text-align:center;color:var(--mut);font-size:12px;padding:24px;border-top:1px solid var(--line);margin-top:40px}
.banner{background:linear-gradient(135deg,#1d2740,#161d2e);border:1px solid var(--line);border-radius:12px;padding:28px;margin-bottom:28px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:16px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}.card h3{margin:0 0 6px}
.price{color:var(--acc2);font-weight:700;font-size:18px}
.cat{display:inline-block;font-size:11px;color:var(--mut);border:1px solid var(--line);border-radius:20px;padding:2px 10px;margin-top:8px}
form.box,.box{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:20px;max-width:460px}
label{display:block;font-size:13px;color:var(--mut);margin:12px 0 4px}
input,textarea,select{width:100%;padding:10px;border-radius:8px;border:1px solid var(--line);background:var(--panel2);color:var(--fg);font-size:14px}
button{margin-top:16px;background:var(--acc);color:#fff;border:0;padding:10px 18px;border-radius:8px;font-size:14px;cursor:pointer}button:hover{opacity:.9}
.err{background:rgba(255,92,122,.12);border:1px solid var(--warn);color:#ffb3c2;padding:10px 14px;border-radius:8px;margin:12px 0;font-size:14px}
.ok{background:rgba(43,212,167,.12);border:1px solid var(--acc2);color:#9ff0d8;padding:10px 14px;border-radius:8px;margin:12px 0;font-size:14px}
table{width:100%;border-collapse:collapse;margin-top:12px}th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);font-size:14px}th{color:var(--mut)}
.review,.ticket{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:12px;margin:10px 0}.review .author{color:var(--acc);font-weight:600;font-size:13px}
pre{background:#0b1020;border:1px solid var(--line);border-radius:8px;padding:14px;overflow:auto;font-size:13px;color:#cdd7ee}
.muted{color:var(--mut);font-size:13px}.tag{font-size:11px;padding:2px 8px;border-radius:6px;background:var(--panel2);border:1px solid var(--line)}
.preview{border:1px dashed var(--line);border-radius:8px;padding:14px;margin-top:10px}code{color:#9ff0d8}
</style></head><body>
<header class="topbar"><div class="brand"><a href="{{ url_for('index') }}">&#9670; Nexora<span>Corp</span></a></div>
<nav><a href="{{ url_for('index') }}">Inicio</a><a href="{{ url_for('search') }}">Buscar</a>
{% if user %}<a href="{{ url_for('dashboard') }}">Painel</a><a href="{{ url_for('profile') }}">Perfil</a>
<a href="{{ url_for('invoices') }}">Faturas</a><a href="{{ url_for('tickets') }}">Chamados</a><a href="{{ url_for('tools_home') }}">Ferramentas</a>
{% if user.role == 'admin' %}<a href="{{ url_for('admin_home') }}" class="adm">Admin</a>{% endif %}
<span class="who">{{ user.username }}</span><a href="{{ url_for('logout') }}" class="btn-sm">Sair</a>
{% else %}<a href="{{ url_for('login') }}">Entrar</a><a href="{{ url_for('register') }}" class="btn-sm">Criar conta</a>{% endif %}
</nav></header><main>{% block content %}{% endblock %}</main>
<footer><span>Nexora Corp - Portal Interno - v2.3.1</span></footer></body></html>"""

T_INDEX = """{% extends "base.html" %}{% block content %}
<section class="banner"><h1>{{ company }}</h1><p>{{ banner|safe }}</p>
<form action="{{ url_for('search') }}" method="get" style="max-width:420px;margin-top:14px">
<input type="text" name="q" placeholder="Buscar produtos e servicos..."></form></section>
<h2>Catalogo</h2><div class="grid">{% for p in products %}
<div class="card"><h3><a href="{{ url_for('product', pid=p.id) }}">{{ p.name }}</a></h3>
<p class="muted">{{ p.description }}</p><div class="price">R$ {{ '%.2f'|format(p.price) }}</div>
<span class="cat">{{ p.category }}</span></div>{% endfor %}</div>{% endblock %}"""

T_SEARCH = """{% extends "base.html" %}{% block content %}<h2>Buscar</h2>
<form action="{{ url_for('search') }}" method="get" class="box" style="margin-bottom:20px">
<input type="text" name="q" value="{{ q }}" placeholder="Digite sua busca..."><button type="submit">Buscar</button></form>
{% if q %}<p class="muted">Resultados para: {{ q|safe }}</p>{% endif %}
{% if error %}<div class="err">{{ error }}</div>{% endif %}
{% if results %}<table><tr><th>ID</th><th>Nome</th><th>Descricao</th><th>Preco</th></tr>
{% for r in results %}<tr><td>{{ r.id }}</td><td>{{ r.name }}</td><td>{{ r.description }}</td><td>{{ r.price }}</td></tr>{% endfor %}</table>
{% elif q and not error %}<p class="muted">Nenhum resultado.</p>{% endif %}{% endblock %}"""

T_PRODUCT = """{% extends "base.html" %}{% block content %}
<a href="{{ url_for('index') }}" class="muted">&larr; voltar</a><h2>{{ prod.name }}</h2>
<p>{{ prod.description }}</p><div class="price">R$ {{ '%.2f'|format(prod.price) }}</div>
<span class="cat">{{ prod.category }}</span> <span class="muted">- estoque: {{ prod.stock }}</span>
<h3 style="margin-top:28px">Avaliacoes</h3>
{% for r in reviews %}<div class="review"><div class="author">{{ r.author }}</div><div>{{ r.body|safe }}</div></div>
{% else %}<p class="muted">Sem avaliacoes ainda.</p>{% endfor %}
<h3 style="margin-top:24px">Deixe sua avaliacao</h3>
<form method="post" class="box"><label>Seu nome</label><input type="text" name="author" value="{{ user.username if user else '' }}">
<label>Comentario</label><textarea name="body" rows="3"></textarea><button type="submit">Enviar</button></form>{% endblock %}"""

T_LOGIN = """{% extends "base.html" %}{% block content %}<h2>Entrar</h2>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
<form method="post" class="box"><label>Usuario</label><input type="text" name="username" autofocus>
<label>Senha</label><input type="password" name="password"><button type="submit">Entrar</button>
<p class="muted" style="margin-top:14px"><a href="{{ url_for('forgot') }}">Esqueci minha senha</a> - <a href="{{ url_for('register') }}">Criar conta</a></p></form>{% endblock %}"""

T_REGISTER = """{% extends "base.html" %}{% block content %}<h2>Criar conta</h2>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
<form method="post" class="box"><label>Usuario</label><input type="text" name="username">
<label>Senha</label><input type="password" name="password"><label>E-mail</label><input type="email" name="email">
<label>Nome completo</label><input type="text" name="full_name"><button type="submit">Registrar</button></form>{% endblock %}"""

T_FORGOT = """{% extends "base.html" %}{% block content %}<h2>Recuperar senha</h2>
{% if msg %}<div class="ok">{{ msg }}</div>{% endif %}
<form method="post" class="box"><label>Usuario</label><input type="text" name="username"><button type="submit">Enviar instrucoes</button></form>{% endblock %}"""

T_DASH = """{% extends "base.html" %}{% block content %}
<h2>Ola, {{ user.full_name or user.username }}</h2>
<p class="muted">Papel: <span class="tag">{{ user.role }}</span> - ID #{{ user.id }}</p>
<h3 style="margin-top:24px">Seus pedidos</h3>
{% if orders %}<table><tr><th>Pedido</th><th>Produto</th><th>Qtd</th><th>Total</th></tr>
{% for o in orders %}<tr><td>#{{ o.id }}</td><td>{{ o.product_name }}</td><td>{{ o.qty }}</td><td>R$ {{ o.total }}</td></tr>{% endfor %}</table>
{% else %}<p class="muted">Nenhum pedido.</p>{% endif %}
<p style="margin-top:20px"><a href="{{ url_for('invoices') }}">Ver faturas</a> - <a href="{{ url_for('preferences') }}">Preferencias</a></p>{% endblock %}"""

T_PROFILE = """{% extends "base.html" %}{% block content %}<h2>Meu perfil</h2>
<form method="post" class="box"><label>E-mail</label><input type="text" name="email" value="{{ data.email or '' }}">
<label>Nome completo</label><input type="text" name="full_name" value="{{ data.full_name or '' }}">
<label>Bio</label><textarea name="bio" rows="3">{{ data.bio or '' }}</textarea>
<label>Nova senha (deixe em branco para manter)</label><input type="text" name="password" value="{{ data.password }}">
<button type="submit">Salvar</button></form>
<p style="margin-top:16px"><a href="{{ url_for('profile_preview', bio=data.bio) }}">Pre-visualizar bio</a></p>{% endblock %}"""

T_PREVIEW = """{% extends "base.html" %}{% block content %}<h2>Pre-visualizacao da bio</h2>
<p class="muted">Como vai aparecer no seu perfil:</p><div class="box">{{ rendered|safe }}</div>
<p style="margin-top:16px"><a href="{{ url_for('profile') }}">&larr; voltar ao perfil</a></p>{% endblock %}"""

T_INVOICES = """{% extends "base.html" %}{% block content %}<h2>Minhas faturas</h2>
{% if invoices %}<table><tr><th>ID</th><th>Pedido</th><th>Arquivo</th><th></th></tr>
{% for i in invoices %}<tr><td>#{{ i.id }}</td><td>#{{ i.order_id }}</td><td>{{ i.filename }}</td>
<td><a href="{{ url_for('invoice_view', iid=i.id) }}">ver</a> - <a href="{{ url_for('download') }}?f={{ i.filename }}">baixar</a></td></tr>{% endfor %}</table>
{% else %}<p class="muted">Nenhuma fatura.</p>{% endif %}{% endblock %}"""

T_INVOICE_VIEW = """{% extends "base.html" %}{% block content %}
<a href="{{ url_for('invoices') }}" class="muted">&larr; faturas</a><h2>Fatura #{{ inv.id }}</h2>
<p class="muted">Pedido #{{ inv.order_id }} - cliente (user_id) {{ inv.user_id }} - arquivo {{ inv.filename }}</p>
<pre>{{ content }}</pre>{% endblock %}"""

T_TICKETS = """{% extends "base.html" %}{% block content %}<h2>Chamados de suporte</h2>
<form method="post" class="box" style="margin-bottom:20px"><label>Assunto</label><input type="text" name="subject">
<label>Descricao</label><textarea name="body" rows="3"></textarea><button type="submit">Abrir chamado</button></form>
{% for t in tickets %}<div class="ticket"><strong>#{{ t.id }} - {{ t.subject|safe }}</strong>
<span class="tag">{{ t.status }}</span><div style="margin-top:6px">{{ t.body|safe }}</div></div>
{% else %}<p class="muted">Nenhum chamado.</p>{% endfor %}{% endblock %}"""

T_PREFS = """{% extends "base.html" %}{% block content %}<h2>Preferencias</h2>
<form method="post" class="box"><label>Tema</label><select name="theme">
<option {% if prefs.theme=='claro' %}selected{% endif %}>claro</option>
<option {% if prefs.theme=='escuro' %}selected{% endif %}>escuro</option></select>
<label>Idioma</label><select name="lang">
<option {% if prefs.lang=='pt-BR' %}selected{% endif %}>pt-BR</option>
<option {% if prefs.lang=='en-US' %}selected{% endif %}>en-US</option></select>
<button type="submit">Salvar</button></form>
<p class="muted" style="margin-top:12px">Atuais: tema={{ prefs.theme }}, idioma={{ prefs.lang }}</p>{% endblock %}"""

T_TOOLS = """{% extends "base.html" %}{% block content %}<h2>Ferramentas internas</h2>
<p class="muted">Utilitarios operacionais da equipe de infraestrutura.</p><div class="grid">
<div class="card"><h3>Diagnostico de rede</h3><p class="muted">Ping em um host.</p><a href="{{ url_for('diag') }}">abrir</a></div>
<div class="card"><h3>Checar URL</h3><p class="muted">Verifica se um endpoint responde.</p><a href="{{ url_for('fetch') }}">abrir</a></div></div>{% endblock %}"""

T_DIAG = """{% extends "base.html" %}{% block content %}<h2>Diagnostico de rede</h2>
<form method="get" class="box"><label>Host</label><input type="text" name="host" value="{{ host }}" placeholder="ex: 8.8.8.8">
<button type="submit">Executar ping</button></form>{% if output %}<pre>{{ output }}</pre>{% endif %}{% endblock %}"""

T_FETCH = """{% extends "base.html" %}{% block content %}<h2>Checar URL</h2>
<form method="get" class="box"><label>URL</label><input type="text" name="url" value="{{ url }}" placeholder="https://...">
<button type="submit">Buscar</button></form>{% if body %}<pre>{{ body }}</pre>{% endif %}{% endblock %}"""

T_ADMIN = """{% extends "base.html" %}{% block content %}<h2>Painel administrativo</h2>
<p class="muted">Acesso restrito a administracao.</p><h3>Usuarios</h3>
<table><tr><th>ID</th><th>Usuario</th><th>E-mail</th><th>Papel</th><th>Saldo</th></tr>
{% for u in users %}<tr><td>{{ u.id }}</td><td>{{ u.username }}</td><td>{{ u.email }}</td><td>{{ u.role }}</td><td>{{ u.balance }}</td></tr>{% endfor %}</table>
<h3 style="margin-top:24px">Configuracoes do site</h3>
<table><tr><th>Chave</th><th>Valor</th></tr>{% for s in settings %}<tr><td>{{ s.key }}</td><td>{{ s.value }}</td></tr>{% endfor %}</table>
<form method="post" action="{{ url_for('admin_settings') }}" class="box" style="margin-top:12px">
<label>Chave</label><input type="text" name="key" value="homepage_banner"><label>Valor</label><input type="text" name="value"><button type="submit">Atualizar</button></form>
<h3 style="margin-top:24px">Cofre</h3><table><tr><th>Nome</th><th>Flag</th></tr>
{% for s in secrets %}<tr><td>{{ s.name }}</td><td><code>{{ s.flag }}</code></td></tr>{% endfor %}</table>{% endblock %}"""

T_FORBIDDEN = """{% extends "base.html" %}{% block content %}<h2>403 - Acesso negado</h2>
<p class="muted">Voce nao tem permissao para acessar esta area.</p>
<p><a href="{{ url_for('index') }}">Voltar ao inicio</a></p>{% endblock %}"""

TEMPLATES = {
    "base.html": BASE, "index.html": T_INDEX, "search.html": T_SEARCH, "product.html": T_PRODUCT,
    "login.html": T_LOGIN, "register.html": T_REGISTER, "forgot.html": T_FORGOT, "dashboard.html": T_DASH,
    "profile.html": T_PROFILE, "preview.html": T_PREVIEW, "invoices.html": T_INVOICES,
    "invoice_view.html": T_INVOICE_VIEW, "tickets.html": T_TICKETS, "preferences.html": T_PREFS,
    "tools.html": T_TOOLS, "diag.html": T_DIAG, "fetch.html": T_FETCH, "admin.html": T_ADMIN,
    "forbidden.html": T_FORBIDDEN,
}


# ===========================================================================
# App
# ===========================================================================
app = Flask(__name__)
app.jinja_loader = DictLoader(TEMPLATES)
app.teardown_appcontext(close_conn)
app.config["SSTI_FLAG"] = FLAGS["template"]
os.environ["NX_FLAG"] = FLAGS["exec"]
os.environ["NX_FLAG_PREFS"] = FLAGS["pickle"]

import pickle  # usado em /preferences (desserializacao insegura, de proposito)


@app.before_request
def _auto_reset():
    if request.path.startswith("/static") or request.path == "/healthz":
        return
    try:
        now = time.time()
        row = query("SELECT value FROM settings WHERE key = 'last_reset_epoch'", one=True)
        if row:
            if now - float(row["value"]) > RESET_INTERVAL_MIN * 60:
                reset_world()
        else:
            execute("INSERT INTO settings (key,value) VALUES ('last_reset_epoch',%s) "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", (str(now),))
    except Exception:
        pass


@app.route("/healthz")
def healthz():
    return "ok", 200


@app.route("/__maintenance/reset")
def maintenance_reset():
    if request.args.get("token", "") != RESET_TOKEN:
        abort(403)
    reset_world()
    return jsonify({"status": "ok", "message": "mundo reconstruido"})


@app.route("/")
def index():
    return render_template("index.html", products=query("SELECT * FROM products ORDER BY id"),
                           banner=get_setting("homepage_banner"),
                           company=get_setting("company_name", "Nexora Corp"), user=current_user())


@app.route("/search")
def search():
    q = request.args.get("q", "")
    results, error = [], None
    if q:
        sql = ("SELECT id, name, description, price FROM products "
               "WHERE name ILIKE '%" + q + "%' OR description ILIKE '%" + q + "%'")
        try:
            results = query(sql)
        except Exception as e:
            error = str(e)
    return render_template("search.html", q=q, results=results, error=error, user=current_user())


@app.route("/product/<int:pid>", methods=["GET", "POST"])
def product(pid):
    if request.method == "POST":
        execute("INSERT INTO reviews (product_id, author, body) VALUES (%s,%s,%s)",
                (pid, request.form.get("author", "anonimo"), request.form.get("body", "")))
        return redirect(url_for("product", pid=pid))
    prod = query("SELECT * FROM products WHERE id = %s", (pid,), one=True)
    if not prod:
        return "Produto nao encontrado", 404
    reviews = query("SELECT * FROM reviews WHERE product_id = %s ORDER BY id DESC", (pid,))
    return render_template("product.html", prod=prod, reviews=reviews, user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u, p = request.form.get("username", ""), request.form.get("password", "")
        sql = "SELECT * FROM users WHERE username = '" + u + "' AND password = '" + p + "'"
        try:
            row = query(sql, one=True)
        except Exception:
            row = None
        if row:
            token = make_token({"uid": row["id"], "username": row["username"], "role": row["role"]})
            resp = make_response(redirect(url_for("dashboard")))
            resp.set_cookie("nx_session", token, httponly=False, samesite="Lax")
            return resp
        error = "Usuario ou senha invalidos."
    return render_template("login.html", error=error, user=current_user())


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("nx_session")
    return resp


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        if not u or not p:
            error = "Preencha usuario e senha."
        elif query("SELECT 1 FROM users WHERE username = %s", (u,), one=True):
            error = "Usuario ja existe."
        else:
            execute("INSERT INTO users (username,password,email,full_name,role) VALUES (%s,%s,%s,%s,'user')",
                    (u, p, request.form.get("email", ""), request.form.get("full_name", "")))
            return redirect(url_for("login"))
    return render_template("register.html", error=error, user=current_user())


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    msg = None
    if request.method == "POST":
        row = query("SELECT username,email FROM users WHERE username = %s",
                    (request.form.get("username", ""),), one=True)
        msg = (f"Enviamos instrucoes para {row['email']} (conta: {row['username']})."
               if row else "Conta nao encontrada.")
    return render_template("forgot.html", msg=msg, user=current_user())


@app.route("/robots.txt")
def robots():
    return ("User-agent: *\nDisallow: /admin\nDisallow: /backup.sql\n"
            "Disallow: /tools/\nDisallow: /__maintenance/\n"), 200, {"Content-Type": "text/plain"}


@app.route("/backup.sql")
def backup():
    try:
        with open(os.path.join(DATA_DIR, "backup.sql"), "r", encoding="utf-8") as f:
            return f.read(), 200, {"Content-Type": "text/plain"}
    except FileNotFoundError:
        return "Not found", 404


@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    orders = query("SELECT o.*, p.name AS product_name FROM orders o JOIN products p ON p.id = o.product_id "
                   "WHERE o.user_id = %s ORDER BY o.id", (user["id"],))
    return render_template("dashboard.html", user=user, orders=orders)


PROFILE_FIELDS = ["email", "full_name", "bio", "password", "role", "balance"]


@app.route("/profile", methods=["GET", "POST"])
def profile():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if request.method == "POST":
        sets, params = [], []
        for field in PROFILE_FIELDS:
            if field in request.form:
                sets.append(f"{field} = %s")
                params.append(request.form.get(field))
        if sets:
            params.append(user["id"])
            execute(f"UPDATE users SET {', '.join(sets)} WHERE id = %s", params)
        return redirect(url_for("profile"))
    data = query("SELECT * FROM users WHERE id = %s", (user["id"],), one=True)
    return render_template("profile.html", user=user, data=data)


@app.route("/profile/preview")
def profile_preview():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    bio = request.args.get("bio", "")
    try:
        rendered = render_template_string("<div class='preview'>" + bio + "</div>")
    except Exception as e:
        rendered = f"Erro ao renderizar: {e}"
    return render_template("preview.html", user=user, rendered=rendered, bio=bio)


@app.route("/invoices")
def invoices():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    rows = query("SELECT * FROM invoices WHERE user_id = %s ORDER BY id", (user["id"],))
    return render_template("invoices.html", user=user, invoices=rows)


@app.route("/invoices/<int:iid>")
def invoice_view(iid):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    inv = query("SELECT * FROM invoices WHERE id = %s", (iid,), one=True)
    if not inv:
        return "Fatura nao encontrada", 404
    try:
        with open(os.path.join(DATA_DIR, "invoices", inv["filename"]), "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        content = "(arquivo indisponivel)"
    return render_template("invoice_view.html", user=user, inv=inv, content=content)


@app.route("/download")
def download():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    f = request.args.get("f", "")
    try:
        with open(os.path.join(DATA_DIR, "invoices", f), "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(), 200, {"Content-Type": "text/plain; charset=utf-8"}
    except Exception as e:
        return f"Erro: {e}", 404


@app.route("/tickets", methods=["GET", "POST"])
def tickets():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if request.method == "POST":
        execute("INSERT INTO tickets (user_id, subject, body) VALUES (%s,%s,%s)",
                (user["id"], request.form.get("subject", ""), request.form.get("body", "")))
        return redirect(url_for("tickets"))
    return render_template("tickets.html", user=user, tickets=query("SELECT * FROM tickets ORDER BY id DESC"))


@app.route("/preferences", methods=["GET", "POST"])
def preferences():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if request.method == "POST":
        prefs = {"theme": request.form.get("theme", "claro"), "lang": request.form.get("lang", "pt-BR")}
        resp = make_response(redirect(url_for("preferences")))
        resp.set_cookie("nx_prefs", base64.b64encode(pickle.dumps(prefs)).decode(), samesite="Lax")
        return resp
    prefs = {"theme": "claro", "lang": "pt-BR"}
    cookie = request.cookies.get("nx_prefs")
    if cookie:
        try:
            prefs = pickle.loads(base64.b64decode(cookie))
        except Exception:
            pass
    return render_template("preferences.html", user=user, prefs=prefs)


@app.route("/tools")
def tools_home():
    return render_template("tools.html", user=current_user())


@app.route("/tools/diag")
def diag():
    host = request.args.get("host", "")
    output = ""
    if host:
        try:
            output = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True,
                                    text=True, timeout=10).stdout or "(sem saida)"
        except Exception as e:
            output = f"Erro: {e}"
    return render_template("diag.html", user=current_user(), host=host, output=output)


@app.route("/tools/fetch")
def fetch():
    url = request.args.get("url", "")
    body = ""
    if url:
        try:
            with urllib.request.urlopen(url, timeout=8) as r:
                body = r.read(4000).decode("utf-8", errors="replace")
        except Exception as e:
            body = f"Erro: {e}"
    return render_template("fetch.html", user=current_user(), url=url, body=body)


def _is_admin(user):
    return bool(user) and user.get("role") == "admin"


@app.route("/admin")
def admin_home():
    user = current_user()
    if not _is_admin(user):
        return render_template("forbidden.html", user=user), 403
    return render_template("admin.html", user=user,
                           users=query("SELECT id,username,email,role,balance FROM users ORDER BY id"),
                           secrets=query("SELECT name, flag FROM secrets ORDER BY name"),
                           settings=query("SELECT key, value FROM settings ORDER BY key"))


@app.route("/admin/settings", methods=["POST"])
def admin_settings():
    user = current_user()
    if not _is_admin(user):
        return render_template("forbidden.html", user=user), 403
    execute("INSERT INTO settings (key,value) VALUES (%s,%s) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            (request.form.get("key", ""), request.form.get("value", "")))
    return redirect(url_for("admin_home"))


@app.route("/api/products")
def api_products():
    return jsonify([dict(r) for r in query("SELECT id,name,price,category,stock FROM products ORDER BY id")])


@app.route("/api/user/<int:uid>")
def api_user(uid):
    row = query("SELECT * FROM users WHERE id = %s", (uid,), one=True)
    return (jsonify(dict(row)) if row else (jsonify({"error": "not found"}), 404))


@app.route("/api/me")
def api_me():
    user = current_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"id": user["id"], "username": user["username"], "role": user["role"]})


@app.route("/api/search")
def api_search():
    q = request.args.get("q", "")
    sql = "SELECT id,name,price FROM products WHERE name ILIKE '%" + q + "%'"
    try:
        return jsonify([dict(r) for r in query(sql)])
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# --- inicializacao (roda no import, cobre gunicorn e flask run) ---
if DATABASE_URL:
    ensure_files()
    try:
        if db_is_empty():
            reset_world()
    except Exception:
        pass


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
