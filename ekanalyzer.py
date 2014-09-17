import os
from flask import Flask
from flask import render_template
from flask import request, redirect, url_for
from werkzeug import secure_filename
import hashlib

from celery import Celery
from pymongo import Connection

import dpkt
import sys
import socket

import requests

import time

UPLOAD_FOLDER = 'uploads/'
ALLOWED_EXTENSIONS = set(['pcap'])


# MONGODB Connection
connection = Connection("localhost", 27017)
db = connection.ekanalyzer


app = Flask(__name__)
app.debug = True
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config.update(
    CELERY_BROKER_URL='redis://localhost:6379',
    CELERY_RESULT_BACKEND='redis://localhost:6379'
)

def make_celery(app):
    celery = Celery(app.import_name, broker=app.config['CELERY_BROKER_URL'])
    celery.conf.update(app.config)
    TaskBase = celery.Task
    class ContextTask(TaskBase):
        abstract = True
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return TaskBase.__call__(self, *args, **kwargs)
    celery.Task = ContextTask
    return celery

celery = make_celery(app)

@celery.task()
def perform_results(hash):
    #time.sleep(20)    
    print "Iniciando importacion"
    try:
        f = open(app.config['UPLOAD_FOLDER'] + hash)
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data
            # FIXME: assuming only http traffic on port 80
            if tcp.dport == 80 and len(tcp.data) > 0:
                http = dpkt.http.Request(tcp.data)
                ipaddress =  socket.inet_ntoa(ip.src)
                #requests.append({ 'ip': ipaddress, 'uri' : http.uri, 'headers' : http.headers, 'hash':hash}) 
                
                data = { 'ip' : ipaddress,
                         'uri' : http.uri,
                         'headers' : http.headers,
                         'hash': hash
                       }                      

                db.requests.insert(data)

    except NameError as e:
        print e
    except :
        print "Unexpected error:", sys.exc_info()
        pass


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.route('/upload-ek/', methods=['POST'])
def upload_file():
    file = request.files['pcap']
    if file and allowed_file(file.filename):
 
        hash = hashlib.sha256()
        try:
            for chunk in file.chunks():
                hash.update(chunk)
        finally:
            file.seek(0)
            hash_name = "%s" % (hash.hexdigest())
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], hash_name))
            return redirect(url_for('results', hash=hash_name))

@app.route('/results/<hash>/')
def results(hash):
    result =perform_results.delay(hash)
    #perform_results(hash)
    #print (result.ready())
    #result.get(propagate=True)    
    print "Sleeping"
    time.sleep(3)
    print (result.ready())
    return render_template('results.html', hash=hash)


@app.route('/')
def index():
    return render_template('index.html')


'''
@app.route('/hello/')
@app.route('/hello/<name>')
def hello(name=None):
    return render_template('hello.html', name=name)
'''

if __name__ == '__main__':
    app.run()
