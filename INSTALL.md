Install
=======



### Install services

Install mongo, redis and clamav:

~~~
sudo apt-get install mongodb redis-server clamav-daemon python-pip build-essential dh-autoreconf python-dev
~~~

Download clamav signatures:

~~~
sudo freshclam
~~~


### Virtual enviroment


~~~
sudo pip install virtualenv
cd ekanalyzer
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
mkdir uploads
~~~

### Install yara (in your virtualenv)

~~~
cd /tmp
wget https://github.com/plusvic/yara/archive/v3.3.0.tar.gz
tar xvfz  v3.3.0.tar.gz
cd yara-3.3.0
./bootstrap.sh
./configure
sudo make install
cd yara-python
python setup.py install
~~~

### Install dpkt (in your virtualenv)

~~~
cd /tmp
wget http://dpkt.googlecode.com/files/dpkt-1.8.tar.gz
tar xvfz dpkt-1.8.tar.gz
cd dpkt-1.8
python setup.py install
~~~


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





