ps aux | grep loader | awk '{ print $2}' | xargs kill -9
make SGX=1 start-gramine-server
