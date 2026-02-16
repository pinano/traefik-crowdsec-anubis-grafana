import gevent.monkey
gevent.monkey.patch_all()

bind = "0.0.0.0:5000"
workers = 1
worker_class = "gevent"
timeout = 600
