#!/bin/sh 

cd ./bin
./packet-parser ../input/test.pcap > ../output/ans.txt
cat ../output/ans.txt

exit 0