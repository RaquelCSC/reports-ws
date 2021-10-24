import datetime

from flask import Flask, request
from flask_cors import CORS

from server.db import query_daily_visits, query_total_visits, query_total_new_visits, query_avg_engagement_time_secs, \
    query_most_visited_products_by_activity_type, query_total_receipt, query_duration_secs_visits_by_day
from flask import Flask, request

from server.db import query_daily_visits, query_total_visits, query_total_new_visits, query_avg_engagement_time_secs, \
    query_most_visited_products_by_activity_type, query_total_receipt

app = Flask(__name__)
CORS(app)


@app.route('/hello/', methods=['GET'])
def hello():
    return {'status': 'ok', 'payload': 'Hello World'}


@app.route('/visits/<month>/', methods=['GET'])
def get_daily_visits(month):
    visits = list(map(
        lambda v: {
            'data': datetime.datetime(year=2021, month=int(month), day=v['day']).strftime('%d %b'),
            'segundos': v['value']},
        query_duration_secs_visits_by_day(month)
    ))
    return {'status': 'ok', 'payload': visits}


@app.route('/visits/<month>/total/', methods=['GET'])
def get_total_visits(month):
    return {'status': 'ok', 'payload': query_total_visits(month)}


@app.route('/visits/<month>/total/new/', methods=['GET'])
def get_total_new_visits(month):
    return {'status': 'ok', 'payload': query_total_new_visits(month)}


@app.route('/visits/<month>/engagement/average/', methods=['GET'])
def get_avg_engagement_time_secs(month):
    return {'status': 'ok', 'payload': round(query_avg_engagement_time_secs(month))}


@app.route('/sells/<month>/total/', methods=['GET'])
def get_total_receipt(month):
    return {'status': 'ok', 'payload': query_total_receipt(month)}


@app.route('/products/<activity_type>/', methods=['GET'])
def get_most_visited_products(activity_type):
    amount = request.args.get('amount', 7)
    return {
        'status': 'ok',
        'payload': query_most_visited_products_by_activity_type(activity_type, amount)
    }


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
