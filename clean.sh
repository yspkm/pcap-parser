#!/bin/sh 

cd ./bin
rm packet-parser

cd ../src
make clean

cd ../output
rm *.txt

cd ../

echo "Clean Success"

exit 0
