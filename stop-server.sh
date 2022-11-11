ps aux | grep 3000 | awk '{ print $2}' | xargs kill -9
find . -name *~ | xargs rm
rm quote/*
make clean
