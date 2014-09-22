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


from celery import Celery

import requests
from requests import Request, Session


# FIXME: move to config.py
ALLOWED_EXTENSIONS = set(['pcap'])


def create_app():
    return Flask("ekanalyzer")

app = create_app()
app.config.from_pyfile('config.py')


connection = Connection(app.config['MONGODB_SERVER'] , app.config['MONGODB_PORT'])
db = connection.ekanalyzer


app.debug = True

celery = Celery('ekanalyzer', broker=app.config['BROKER_URL'] )


@celery.task
def perform_results(hash):
    try:

        pcap = {'id' : hash}

        result = db.pcap.find(pcap)

        if result.count() > 0:
            return
        else:
            db.pcap.insert(pcap)


        f = open(app.config['UPLOAD_FOLDER'] + hash)
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data
            # FIXME: assuming only http traffic on port 80
            if tcp.dport == 80 and len(tcp.data) > 0:
                http = dpkt.http.Request(tcp.data)
                ipaddress =  socket.inet_ntoa(ip.dst)
                
                data = { 'ip' : ipaddress,
                         'uri' : http.uri,
                         'method' : http.method,
                         'data' : http.data,
                         'headers' : http.headers,
                         'id': hash
                       }                      

                db.requests.insert(data)

        status = process_requests(hash)

    except AttributeError as e:
        print e
    except NameError as e:
        print e
    except :
        print "Unexpected error:", sys.exc_info()
        pass

def process_requests(id):
    request = { 'id' : id}
    result = db.requests.find(request)
    for r in result:
        print process_request.delay(r['ip'], r['uri'], r['method'], r['headers'], r['data'], id)

@celery.task
def process_request(ip, uri, method, headers, data, id):

    user_agents = app.config['USER_AGENTS']
    for user_agent in user_agents:
        headers['user-agent'] = user_agent

        #FIXME: port 80
        #FIXME: ConnectionError
        url = "http://{0}:80{1}".format(ip, uri)


        #proxies = {
        # "http": "http://127.0.0.1:8080"        
        #}

        s = Session()
        req = Request(method, url,
            data=data,
            headers=headers
        )
        prepped = req.prepare()


        resp = s.send(prepped, 
            #proxies=proxies
        )

        #user agent hash
        m = hashlib.md5()
        m.update(user_agent)
        UA = m.hexdigest()


        fpath = "workspace/" + id + "/" + UA + "/" + headers['host'] + uri
        dpath = os.path.dirname(fpath)


        if not os.path.exists(dpath):
            os.makedirs(dpath)

        response = resp.content

        # FIXME: uris ending with / are not saved properly
        if not os.path.isdir(fpath):        
            with open(fpath, "w") as f:
                f.write(response)



        # response hash
        m = hashlib.sha256()
        m.update(response)
        hash = m.hexdigest()

        vt_report = None

        malicious = False

        #if resp.headers['content-type'] != "text/html":
        # check only, jar, swf, exe, zip, pdf, ocx
        if True:

            parameters = {"resource": hash, "apikey": app.config["VIRUSTOTAL_API_KEY"]}
            r = requests.post('https://www.virustotal.com/vtapi/v2/file/report', params=parameters)
            try:
                vt_report = r.json()
                if vt_report['positives'] > 0:
                    malicious = True

            except:
                #print "Unexpected error:", sys.exc_info()
                vt_report = None


        #FIXME: add html/javascript analysis here

        #FIXME: add peepdf based analysis here

        analysis_data = { 'id': id,  'malicious': malicious, 'user-agent': user_agent, 'UA' : UA,  'host': headers['host'], 'uri' : uri, 'data' : data, 'status_code': resp.status_code, 'hash': hash , 'vt' : vt_report }

        db.analysis.insert(analysis_data)



def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.route('/upload-ek/', methods=['POST'])
def upload_file():
    file = request.files['pcap']
    if file and allowed_file(file.filename):
 
        hash = hashlib.sha256()

        try:
            # FIXME: it should be saved before calculate sha256
            hash.update(file.read())
        except:
            print "Unexpected error:", sys.exc_info()
        finally:
            file.seek(0)
            hash_name = "%s" % (hash.hexdigest())
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], hash_name))
            return redirect(url_for('launch', hash=hash_name))

@app.route('/launch/<hash>/')
def launch(hash):
    perform_results.delay(hash)
    return render_template('launch.html', hash=hash)

@app.route('/view/<hash>/')
def view(hash):

    h = { 'id' : hash}

    requests = db.analysis.find(h)    

    return render_template('view.html', requests=requests)

@app.route('/list')
def list():

    pcaps = db.pcap.find()

    analysis = []

    malicious = False

    for pcap in pcaps:
        h = { 'id' : pcap['id']}
        queries = db.analysis.find(h)
        details = []
        for query in queries:
            print query
            print "-----"
            if query['malicious']:
               malicious = True

        analysis.append( {pcap['id'] : malicious})

    print analysis

    return render_template('list.html', analysis=analysis)


@app.route('/details/<hash>/<ua>/')
def details(hash, ua):

    user_agent = { 'UA' : ua, 'id' : hash}

    requests = db.analysis.find(user_agent)    

    return render_template('details.html', requests=requests)


@app.route('/')
def index():
    return render_template('index.html')



if __name__ == "__main__":
    app.run(debug=True)

