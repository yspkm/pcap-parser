#!/bin/sh 

cd ./bin

# tcp 5 applications 
./packet-parser tcp_apt-get_update.pcap > ../output/ans_tcp_apt-get_update.txt
./packet-parser tcp_git_push.pcap > ../output/ans_tcp_git_push.txt
./packet-parser tcp_lynx_google.pcap > ../output/ans_tcp_lynx_google.txt
./packet-parser tcp_ssh_inuiyeji.pcap > ../output/ans_tcp_ssh_inuiyeji.txt
./packet-parser tcp_w3m_google.pcap > ../output/ans_tcp_w3m_google.txt

# udp 2 applications 
./packet-parser udp_chromium_youtube.pcap > ../output/ans_udp_chromium_youtube.txt
./packet-parser udp_Firefox_google.pcap > ../output/ans_udp_Firefox_google.txt

# fragmented packets
# ping www.google.com -s 1473  
# 1473+28 == 1501 < MTU:1500
./packet-parser icmp_ping_without_DF.pcap > ../output/ans_icmp_ping_without_DF.txt

# Cf. ping www.google.com -s 1472
./packet-parser icmp_ping_with_DF.pcap > ../output/ans_icmp_ping_with_DF.txt

echo "Parsing Complete" 

exit 0
