import os
from flask import Flask
from flask import render_template
from flask import request, redirect, url_for
from werkzeug import secure_filename
import hashlib

from pymongo import Connection
from bson.code import Code

import dpkt
import sys
import socket


from celery import Celery

import requests
from requests import Request, Session

import magic
import zlib

import yara
import pyclamd

import datetime
from time import sleep

from bson.objectid import ObjectId

from zipfile import ZipFile
import redis
import json

# FIXME: move to config.py
ALLOWED_EXTENSIONS = set(['pcap'])
rules = yara.compile(filepath='yara/ekanalyzer.yar')

cd = pyclamd.ClamdAgnostic()

def create_app():
    return Flask("ekanalyzer")

app = create_app()
app.config.from_pyfile('config.py')


connection = Connection(app.config['MONGODB_SERVER'] , app.config['MONGODB_PORT'])
db = connection.ekanalyzer

memcache = redis.Redis('localhost')


app.debug = True

celery = Celery('ekanalyzer', broker=app.config['BROKER_URL'] )


@celery.task
def perform_results(pcap_id):
    try:

        pcap = {'_id' : ObjectId(pcap_id)}

        result = db.pcap.find_one(pcap)

        #if result.count() > 0:
        #    return
        #else:
        #    db.pcap.insert(pcap)

        pcap_hash = result['id']


        f = open(app.config['UPLOAD_FOLDER'] + pcap_hash, "rb")

        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data
            if type(tcp) is str:
              continue
            # FIXME: assuming only http traffic on port 80
            if tcp.dport == 80 and len(tcp.data) > 0:
                http = dpkt.http.Request(tcp.data)
                ipaddress =  socket.inet_ntoa(ip.dst)
                
                data = { 'ip' : ipaddress,
                         'uri' : http.uri,
                         'method' : http.method,
                         'data' : http.data,
                         'headers' : http.headers,
                         'hash': pcap_hash,
                         'pcap_id' : ObjectId(pcap_id)
                       }                      
                db.requests.insert(data)                       
            #else:
            #    print "Port is " + str(tcp.dport)

    
    except dpkt.NeedData as e:
        print e
    except AttributeError as e:
        print e
    except NameError as e:
        print e
    except :
        print "Unexpected error:", sys.exc_info()
        print pcap_hash
    finally:
        status = process_requests(pcap_id)


def process_requests(pcap_id):

    request = { 'pcap_id' : ObjectId(pcap_id)}

    result = db.requests.find(request)
    nrequests = result.count()
    uas = len(app.config['USER_AGENTS'])
    nrequests*=uas
    nrequests+=1
    memcache.set(str(pcap_id) + "_tasks", str(nrequests))
    memcache.set(str(pcap_id) + "_total_tasks", str(nrequests))

    print "added %s tasks" % str(nrequests)

    for r in result:
        # Maybe hash is not necesary    
        print process_request.delay(r['ip'], r['uri'], r['method'], r['headers'], r['data'], r['hash'], r['pcap_id'])



def extract_zip(input_zip):
    input_zip=ZipFile(input_zip)
    return {name: input_zip.read(name) for name in input_zip.namelist()}

def check_vt(hash, mimetype):
        #
        # This function uses response (buffer) and fpath (path to file)
        # FIX this as soon as the "/" bug be fixed (gridfs)
        #

        vt_report = None

        try:
          vt_report_raw = memcache.get(hash)
          print "report  = " + vt_report_raw
          vt_report = json.loads(vt_report_raw)
          print "vtreport  = " + vt_report
        except Exception, e:
          print "The report cannot be loaded for %s" % hash
          vt_report = None

        if vt_report == None: 

          # Send to VT
          if mimetype == "application/octet-stream" \
              or mimetype == "application/java-archive" \
              or mimetype == "application/zip" \
              or mimetype == "application/pdf" \
              or mimetype == "text/html" \
              or mimetype == "application/x-shockwave-flash":

              parameters = {"resource": hash, "apikey": app.config["VIRUSTOTAL_API_KEY"]}

              last_call_cache  = memcache.get("last_vt_call") 

              if last_call_cache != None:
                last_call = datetime.datetime.strptime(last_call_cache,"%Y-%m-%d %H:%M:%S.%f")
                now = datetime.datetime.utcnow() 
                delta = now - last_call
                sleep_seconds  = 15 - delta.total_seconds()
                if sleep_seconds > 0:
                  sleep(sleep_seconds)


              r = requests.post('https://www.virustotal.com/vtapi/v2/file/report', params=parameters)
              memcache.set("last_vt_call",datetime.datetime.utcnow() )


              try:
                  print r.text
                  vt_report = r.json()
                  memcache.set(hash,r.text)
              except:
                  print "Problem saving the report"
                  print "Unexpected error:", sys.exc_info()
        return vt_report


@celery.task
def process_request(ip, uri, method, headers, data, pcap_hash, pcap_id):


    user_agents = app.config['USER_AGENTS']

    # FIXME: check case
    if 'user-agent' in headers:
        user_agents.append(headers['user-agent'])
    else:
        user_agents.append("")

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


        fpath = "workspace/" + str(pcap_id) + "/" + UA + "/" + headers['host'] + uri
        dpath = os.path.dirname(fpath)


        if not os.path.exists(dpath):
            os.makedirs(dpath)

        response = resp.content

        # FIXME: uris ending with / are not saved properly
        try:
            if not os.path.isdir(fpath):        
                with open(fpath, "w") as f:
                    f.write(response)
        #FIXME: manage files in GridFS
        except IOError:
            pass



        # response hash
        m = hashlib.sha256()
        m.update(response)
        hash = m.hexdigest()


        # filetype & mimetype
        filetype = magic.from_buffer(response)
        mimetype = magic.from_buffer(response, mime=True)


        

        tags = { 'clean' : 0, 'suspicious' : 0, 'malicious' : 0 }

        malicious = False        

        ymatches = None

        unpacked = ''
        
        vt_report = check_vt(hash, mimetype)

        if vt_report != None:
          if vt_report['positives'] > 0:  
            tags['malicious'] += 1
            malicious = True


        # FIXME: check VT after unpack/decompress
        # Prepare for YARA        
        # FIXME: ZWS http://malware-traffic-analysis.net/2014/09/23/index.html
        try:
          if mimetype == "application/x-shockwave-flash" and filetype.find("CWS"):
              #print "compressed SWF detected"
              f = open(fpath, "rb")
              f.read(3) # skip 3 bytes
              tmp = 'FWS' + f.read(5) + zlib.decompress(f.read())
              decompressed = fpath + ".decompressed"
              with open(decompressed, "w") as f:
                  f.write(tmp)
              unpacked = tmp

          elif mimetype == "application/zip":
              extracted = extract_zip(fpath)

              for name, content in extracted.iteritems():
                  unpacked += content 

          else:
              unpacked = response

          ymatches = rules.match(data=unpacked)
          if not bool(ymatches):
              ymatches = None
          else:
              tags['suspicious'] += 1
        except:
          print "Unexpected error:", sys.exc_info()

        # ClamAV analysis
        clamav = cd.scan_stream(unpacked)
        if clamav:
            tags['malicious'] += 1


        #FIXME: add html/javascript analysis here

        #FIXME: add peepdf based analysis here



        # Review tags before analysis
        if tags['malicious'] == 0 and tags['suspicious'] == 0:
            tags['clean'] = 1

        # FIXME: remove 'malicious': malicious
        # FIXME: maybe hash is not necesary
        analysis_data = {   'pcap_id' : ObjectId(pcap_id),
                            'hash': pcap_hash, 
                            'tags': tags, 
                            'filetype': filetype,
                            'mimetype': mimetype, 
                            'yara' : ymatches, 
                            'clamav' : clamav, 
                            'user-agent': user_agent, 
                            'UA' : UA,  
                            'host': headers['host'], 
                            'uri' : uri, 
                            'data' : data, 
                            'status_code': resp.status_code, 
                            'content_hash': hash, 
                            'vt' : vt_report,
                            'date' : datetime.datetime.utcnow() 
                        }

        db.analysis.insert(analysis_data)
        pending_tasks = memcache.get(str(pcap_id) + "_tasks")
        remaining_tasks = int(pending_tasks) - 1
        memcache.set(str(pcap_id) + "_tasks", remaining_tasks )


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

            pcap = {'id' : hash_name}
            pcap_id = db.pcap.insert(pcap)

            return redirect(url_for('launch', pcap_id=pcap_id))


@app.route('/launch/<pcap_id>/')
def launch(pcap_id):

    perform_results.delay(pcap_id)
    return render_template('launch.html', pcap_id=pcap_id)

@app.route('/view/<pcap_id>/')
def view(pcap_id):


    pending_tasks = memcache.get(str(pcap_id) + "_tasks")
    total_tasks = memcache.get(str(pcap_id) + "_total_tasks")

    if pending_tasks != None:
      print "There are %s pending tasks" % pending_tasks
    
    if total_tasks != None:
      print "There are %s tasks" % total_tasks

    pid = { "_id.pcap_id" : ObjectId(pcap_id) }


    # FIXME: this map/reduce is executed each time view is requested
    map = Code("function () {"
        "  emit({ pcap_id : this['pcap_id'], UA : this.UA, 'user-agent' : this['user-agent']}, {malicious: this.tags.malicious, clean: this.tags.clean, suspicious:this.tags.suspicious});"
        "}")

    reduce = Code("function (key, vals) {"
        "  var result = {malicious:0, suspicious:0, clean:0 };"
        "  vals.forEach(function (value) {result.malicious += value.malicious; result.clean += value.clean; result.suspicious += value.suspicious; });"
        "  return result;"
        "}")

    results = db.analysis.map_reduce(map, reduce, 'malicious')

    found = results.find(pid)
    requests = []

    for i in found:
        #print i
        requests.append(i)

    original_request = db.requests.find_one({"pcap_id": ObjectId(pcap_id)})


    original_ua = ''

    try:
        if original_request:
            original_ua = original_request['headers']['user-agent']
    except KeyError:
        pass

    return render_template('view.html', requests=requests, original_ua=original_ua, pending_tasks=int(pending_tasks), total_tasks=int(total_tasks))

@app.route('/list')
def list():

    pcaps = db.pcap.find()

    analysis = []

    malicious = False


    for pcap in pcaps:
        h = { 'pcap_id' :  ObjectId(pcap['_id'])}
        queries = db.analysis.find(h)
        details = []
        tags = { 'malicious' : 0, 'suspicious': 0, 'clean': 0}
    
        for query in queries:
            if query['tags']['malicious']:
               tags['malicious'] += 1
            if query['tags']['suspicious']:
               tags['suspicious'] += 1
            if query['tags']['clean']:
               tags['clean'] += 1


        analysis.append( {pcap['_id'] : tags})
    return render_template('list.html', analysis=analysis)


@app.route('/details/<pcap_id>/<ua>/')
def details(pcap_id, ua):
    user_agent = { 'UA' : ua, 'pcap_id' : ObjectId(pcap_id)}
    requests = db.analysis.find(user_agent)    

    return render_template('details.html', requests=requests)


@app.route('/')
def index():
    return render_template('index.html')



if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)


