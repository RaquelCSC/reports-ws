
# 1. Objetivo: Mostrar informações sobre visitação de ecommerce

# a) Acesso por mês
# Histórico de visitas agrupadas por dia
# Total de visitas no mês
# Total de novos usuários no mês
# Tempo médio de engajamento por sessão
# Receita total: ???

# * Modelagem
# Visitor(id/checksum: string, date: datetime, isNew: bool, durationSecs: int)
# Sell(products, visitors, value: int)

# b) Acesso por produto
# Filtro por tipo de atividade: ???
# Histórico dos 7 produtos mais acessados

# Product(id: int, name: string, activityType: string)
# ProductVisit(id: int, product, date: datetime)

# 2. Estudando os dados

# https://github.com/jwodder/apachelogs
# https://apachelogs.readthedocs.io/en/stable/directives.html
# http://httpd.apache.org/docs/current/mod/mod_log_config.html

# host? ip - - [data e hora] "request" http_status_code bytes_size "url" "user"

# remote_host: %h:
# vendas.ecotrilhasserracatarinense.com:443
# vendas.ecotrilhasserracatarinense.com:443
#

# remote_logname: %l
# 189.6.235.31
# 189.6.235.31
# 54.189.230.128

# remote_user: %u
# - -
# - -
# - -

# request_time: %t
# [15/Sep/2021:00:00:33 -0300]
# [15/Sep/2021:00:00:33 -0300]
# [15/Sep/2021:00:05:12 -0300]

# request_line: "%r"
# GET /carrinho/9885 HTTP/2.0
# GET /theme/default/assets/css/styles.css?8 HTTP/2.0
# GET / HTTP/1.1

# final_status: %>s

# bytes_sent: %b

# headers_in:
# Referer: "%{Referer}i"
# User-Agent: "%{User-Agent}i"
import hashlib
import re
from datetime import timedelta

from server.db import fetch_visitor, insert_visitor, insert_visitor_visit, fetch_product, insert_product, \
    insert_product_visit
from server.model import Visitor, VisitorVisit, Product, ProductVisit


def parse_apache_logs(path):
    from apachelogs import LogParser

    entries = []

    with open(path) as file:
        parser = LogParser("%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"")
        for entry in parser.parse_lines(file):
            user_agent = entry.headers_in['User-Agent']
            entries.append({
                'host': entry.remote_host,
                'ip': entry.remote_logname,
                'datetime': entry.request_time,
                'datetime_str': entry.request_time.strftime('%Y/%m/%d %H:%M:%S'),
                'agent_hash': hashlib.md5(user_agent.encode('utf-8')).hexdigest() if user_agent is not None else None,  # Checksum
                'request': entry.request_line
            })

    return entries


# Conclusão: Existem ips diferentes para hosts iguais
def validate_hosts(entries):
    host_groups = {}
    for entry in entries:
        h = entry['host']
        host_groups[h] = host_groups.get(h, [])
        host_groups[h].append(entry)

    count = 0
    for host_group in host_groups.values():
        has_different_ip = len(list(filter(lambda e: host_group[0]['ip'] != e['ip'], host_group))) > 0
        if has_different_ip:
            count += 1

    print(f'Total de hosts é {len(host_groups)} e o total de hosts com ips diferentes é {count}')
    print(f'A razao é de: {count / len(host_groups)}')

    # for v in host_groups['vendas.balonismonachapada.com.br:443']:
    #     print(v)


def validate_empty_hosts(entries):
    for entry in entries:
        if entry['ip'] is None:
            print(entry)


def print_all(trails):
    for trail in trails:
        for entry in trail:
            print(entry)
        print('xxxxxxxxxxxxxxxxx')


def group_data(entries, key):
    groups = {}
    for entry in entries:
        v = entry[key]
        groups[v] = groups.get(v, [])
        groups[v].append(entry)
    return groups


# Validações:
# O log se trata de apenas um dia, então só há como identificar novos usuários
# O fato de um user agent se repetir entre dias não significa que é um antigo usuário
# Agentes se repetindo em horários muito intervalados devem significar visitas diferentes (30 minutos)
# Agentes se repetindo em horários próximos com IPs diferentes são considerados o mesmo
# Quando não existe host, o log é ignorado (Google, Hacks)
# Será considerado 30 minutos como tempo de sessão,
#   sendo extendido em 30 minutos toda vez que o mesmo agente aparecer no mesmo host
def process_user_trails(entries):
    results = []

    host_groups = group_data(entries, 'host')
    for host_group in host_groups.values():
        if host_group[0]['ip'] is None:
            continue

        agent_groups = group_data(host_group, 'agent_hash')
        for agent_group in agent_groups.values():
            if agent_group[0]['agent_hash'] is None:
                continue

            visitor_trail = []
            last_index = len(agent_group) - 1

            for i in range(last_index):
                visitor_trail.append(agent_group[i])
                is_last_one = i == last_index
                is_session_time_exceeded_30_minutes = (
                        agent_group[i]['datetime'] + timedelta(minutes=30) < agent_group[i + 1]['datetime']
                )

                if is_session_time_exceeded_30_minutes or is_last_one:
                    results.append(visitor_trail)
                    visitor_trail = []

    return results


# Para cada trail
# 1- Verificar se visitante já existe
# 2- Se não existe, adicionar a Visitor e pegar registro
# 3- Se existe, pegar registro e adicionar VisitorVisit:
# a) date deve ser o primeiro horário
# b) durationSecs deve ser o tempo em segundos entre a primeira e última data
# c) isNew é descoberto a partir da existência prévia de Visitor
# d) visitorId já é conhecido
def process_visitors(trails):
    for trail in trails:
        first = trail[0]
        last = trail[-1]
        visitor_id = first['agent_hash']
        visitor = fetch_visitor(visitor_id)
        is_new = visitor is None
        duration_secs = (last['datetime'] - first['datetime']).seconds

        if duration_secs < 15:
            continue

        if is_new:
            visitor = Visitor(id=visitor_id)
            print(f'Inserting Visitor: {visitor}')
            insert_visitor(visitor)

        visitor_visit = VisitorVisit(
            date=first['datetime'],
            duration_secs=duration_secs,
            is_new=is_new,
            host=first['host'],
            visitor_id=visitor_id
        )
        print(f'Inserting VisitorVisit: {visitor_visit}')
        insert_visitor_visit(visitor_visit)


# 4- Filtrar entradas contendo "produto={id}" e opcional: /api/produto/{nome}/calendario
# a) Se conseguir encontrar o nome do produto, verifica requests do mesmo grupo ou do cache salvo
# b) name: Verifica se produto existe para pegar nome, senao tentar descobrir
# c) activity_type: impossivel saber
# d) Pegar data e salvar em ProductVisit
def process_products(trails):
    def parse_product_id(text):
        result = re.match(r'.*?produto=(\d+)\D.*?', text)
        return int(result.group(1)) if result is not None else None

    products = {}
    for trail in trails:
        trail = list(filter(
            lambda entry: 'produto' in entry['request'] and '/css' not in entry['request'] and '/js' not in entry['request'],
            trail
        ))

        if len(trail) == 0:
            continue

        product_id = None
        product_name = None
        for entry in trail:
            request = entry['request']

            if 'produto=' in request:
                product_id = parse_product_id(request)
            elif '/api' in request:
                r = re.match(r'.*?/api/produto/(.*?)[/? ].*?', request)
                product_name = r.group(1).replace('-', ' ') if r is not None else None

            if product_id is not None:
                is_product_without_name = len(products.get(product_id, '')) == 0
                if is_product_without_name:
                    if product_name is not None:
                        products[product_id] = product_name
                        product_id = None
                        product_name = None
                    else:
                        products[product_id] = ''

    activity_types = [
        'trilha', 'cachoeira', 'camping', 'salto',
        'cafe', 'casa', 'rota', 'passeio', 'ingresso'
    ]

    for trail in trails:
        trail = list(filter(
            lambda entry: 'produto=' in entry['request'],
            trail
        ))

        for entry in trail:
            product_id = parse_product_id(entry['request'])
            product = fetch_product(product_id)

            if product is None:
                name = products[product_id]
                activity_type = 'outros'
                for t in activity_types:
                    if t in name:
                        activity_type = t
                        break
                product = Product(id=product_id, name=name, activity_type=activity_type)
                print(f'Inserting Product: {product}')
                insert_product(product)

            product_visit = ProductVisit(
                id=-1,
                date=entry['datetime'],
                product_id=product_id
            )
            print(f'Inserting ProductVisit: {product_visit}')
            insert_product_visit(product_visit)


entries = parse_apache_logs('logs/2021-09-15.log')
trails = process_user_trails(entries)
# process_visitors(trails)
process_products(trails)
