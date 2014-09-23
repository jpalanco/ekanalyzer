Install
=======



### Install services

Install mongo, redis and clamav:

~~~
sudo apt-get install mongodb redis clamav
~~~

Install yara

### Virtual enviroment


~~~
sudo pip install virtualenv
cd ekanalyzer
virtualenv env
source env/bin/activate
pip install -r requirements.txt
~~~

Edit the config.py file and introduce your Virus Total API Key


### Launch

Celery (Terminal 1)

~~~
cd ekanalyzer
source env/bin/activate
celery -A ekanalyzer:celery worker -l DEBUG
~~~


App (Terminal 2)

~~~
cd ekanalyzer
source env/bin/activate
python ekanalyzer.py 
~~~





