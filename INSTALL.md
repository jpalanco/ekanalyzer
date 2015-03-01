Install
=======



### Install services

Install mongo, redis and clamav:

~~~
sudo apt-get install mongodb redis-server clamav-daemon
~~~

Download clamav signatures:

~~~
freshclam
~~~

Install yara

### Virtual enviroment


~~~
sudo pip install virtualenv
cd ekanalyzer
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
mkdir uploads
~~~

### Install dpkt (in your virtualenv)

wget http://dpkt.googlecode.com/files/dpkt-1.8.tar.gz
tar xvfz dpkt-1.8.tar.gz
cd dpkt
python setup.py install


### Recomended: Patch dpkt

The patch is available at patches/ directory
cd venv/local/lib/python2.7/site-packages/dpkt
patch -p1 < /tmp/ekanalyzer/patches/dpkt.patch 




Edit the config.py file and introduce your Virus Total API Key


### Launch

Celery (Terminal 1)

~~~
cd ekanalyzer
source venv/bin/activate
celery -A ekanalyzer:celery worker -l DEBUG
~~~


App (Terminal 2)

~~~
cd ekanalyzer
source venv/bin/activate
python ekanalyzer.py 
~~~





