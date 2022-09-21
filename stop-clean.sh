ps aux | grep loader | awk '{ print $2}' | xargs kill -9
find . -name *~ | xargs rm
make clean
