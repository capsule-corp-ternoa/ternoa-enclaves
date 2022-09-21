ps aux | grep 4000 | awk '{ print $2}' | xargs kill -9
make SGX=1 start-gramine-server
