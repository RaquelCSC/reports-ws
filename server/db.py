from typing import List

import psycopg2

from server.model import Visitor, VisitorVisit, Product, ProductVisit


def gen_connection():
    return psycopg2.connect(
        user='report',
        password='39yYg7sFKhVRH2z3',
        host='127.0.0.1',
        port='5432',
        database='report'
    )


def insert_visitor(visitor: Visitor):
    with gen_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                'INSERT INTO Visitor (id) VALUES (%s)',
                (visitor.id,)
            )


def insert_visitor_visit(visit: VisitorVisit):
    with gen_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                'INSERT INTO VisitorVisit (date, durationSecs, isNew, host, visitorId) VALUES (%s,%s,%s,%s,%s)',
                (visit.date, visit.duration_secs, visit.is_new, visit.host, visit.visitor_id,)
            )


def insert_product(product: Product):
    with gen_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                'INSERT INTO Product (id, name, activityType) VALUES (%s, %s, %s)',
                (product.id, product.name, product.activity_type)
            )


def insert_product_visit(visit: ProductVisit):
    with gen_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                'INSERT INTO ProductVisit (date, productId) VALUES (%s, %s)',
                (visit.date, visit.product_id,)
            )


def fetch_visitor(visitor_id):
    with gen_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM Visitor WHERE id = %s', (visitor_id,))
            result = cursor.fetchone()
            return None if result is None else Visitor(*result)


def fetch_product(product_id):
    with gen_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM Product WHERE id = %s', (product_id,))
            result = cursor.fetchone()
            return None if result is None else Product(*result)


def query_daily_visits(month: int) -> List[VisitorVisit]:
    with gen_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM VisitorVisit WHERE EXTRACT(MONTH FROM date) = %s', (month,))
            results = cursor.fetchall()
            return [] if results is None else list(map(lambda r: VisitorVisit(*r), results))


def query_duration_secs_visits_by_day(month: int) -> List[VisitorVisit]:
    with gen_connection() as connection:
        with connection.cursor() as cursor:
            # TODO: Como só tem 1 dia, vamos trocar DAY por HOUR para testar
            cursor.execute(
                'SELECT EXTRACT(HOUR FROM date) AS day, SUM(durationSecs) AS value '
                'FROM VisitorVisit '
                'WHERE EXTRACT(MONTH FROM date) = %s'
                'GROUP BY day '
                'ORDER BY day', (month,))
            results = cursor.fetchall()
            return [] if results is None else list(map(lambda r: {'day': int(r[0]) + 1, 'value': r[1]}, results))


def query_total_visits(month: int) -> int:
    with gen_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) FROM VisitorVisit WHERE EXTRACT(MONTH FROM date) = %s', (month,))
            result = cursor.fetchone()
            return result[0] or 0


def query_total_new_visits(month: int) -> int:
    with gen_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) FROM VisitorVisit WHERE EXTRACT(MONTH FROM date) = %s AND isNew = true', (month,))
            result = cursor.fetchone()
            return result[0] or 0


def query_avg_engagement_time_secs(month: int) -> float:
    with gen_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute('SELECT AVG(durationSecs) FROM VisitorVisit WHERE EXTRACT(MONTH FROM date) = %s', (month,))
            result = cursor.fetchone()
            return result[0] or 0.0


def query_total_receipt(month: int) -> float:
    with gen_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute('SELECT SUM(value) FROM Sell WHERE EXTRACT(MONTH FROM date) = %s', (month,))
            result = cursor.fetchone()
            return (result[0] or 0.0) / 100.0


def query_most_visited_activity_types(amount=7):
    with gen_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) AS amount, p.activityType FROM ProductVisit AS pv '
                           'INNER JOIN Product AS p ON pv.productId = p.id '
                           'GROUP BY p.activityType '
                           'ORDER BY amount DESC '
                           'LIMIT %s;', (amount,))
            results = cursor.fetchall()
            return [] if results is None else list(map(lambda r: {'amount': r[0], 'activity_type': r[1]}, results))


def query_most_visited_products_by_activity_type(activity_type: str, amount=7):
    with gen_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(p.id) AS amount, p.id, p.name FROM ProductVisit AS pv '
                           'INNER JOIN Product AS p ON pv.productId = p.id AND p.activityType = %s '
                           'GROUP BY p.id '
                           'ORDER BY amount DESC '
                           'LIMIT %s;', (activity_type, amount,))
            results = cursor.fetchall()
            return [] if results is None else list(map(lambda r: {'amount': r[0], 'id': r[1], 'name': r[2]}, results))

