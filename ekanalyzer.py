import os
from flask import Flask
from flask import render_template
from flask import request, redirect, url_for
from werkzeug import secure_filename
import hashlib

from pymongo import Connection

import dpkt
import sys
import socket

import requests

import time

from celery import Celery



# FIXME: move to config.py
ALLOWED_EXTENSIONS = set(['pcap'])


def create_app():
    return Flask("ekanalyzer")

# MONGODB Connection
connection = Connection("localhost", 27017)
db = connection.ekanalyzer


app = create_app()
app.config.from_pyfile('config.py')

app.debug = True

celery = Celery('ekanalyzer', broker=app.config['BROKER_URL'] )



@celery.task
def perform_results(hash):
    time.sleep(20)    
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
    perform_results.delay(hash)
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

if __name__ == "__main__":
    app.run(debug=True)

