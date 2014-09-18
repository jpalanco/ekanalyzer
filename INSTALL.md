Install
=======



### Install services

Install mongo and redis:

~~~
sudo apt-get install mongodb redis
~~~

### Virtual enviroment


~~~
sudo pip install virtualenv
cd ekanalyzer
virtualenv env
source env/bin/activate
pip install -r requirements.txt
~~~

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





