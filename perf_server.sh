#!/bin/sh
if [ "$#" -lt 1 ]; then
	echo "incorrect number of arguments"
	echo "run script as"
	echo "./perf_server.sh server.list valgrind_check(1/0)"
	echo "the server.list file should contain name of domain sockets to listen on separated by comma"
	echo "if valgrind_analysis(optional) is true, it will perform valgrind analysis, ensure valgrind tool is installed"
	exit
fi

valgrind_analysis=0
count=0
if [ "$#" = 2 ]; then
	valgrind_analysis=$2
fi

if [ $valgrind_analysis = 1 ]; then
	echo "valgrind analysis"
	while IFS='' read -r line || [[ -n "$line" ]]; do
                echo "starting smbconnector on socket: $line"
                ulimit -c unlimited
                nohup valgrind --leak-check=yes --error-limit=no --xml-file=valgrind_report$count.xml --xml=yes /opt/vmware/content-gateway/smb-connector/smbconnector -s $line > server.dat &
	count=$(($count+1))
        done < "$1"
else
	while IFS='' read -r line || [[ -n "$line" ]]; do
    		echo "starting smbconnector on socket: $line"
    		ulimit -c unlimited
    		nohup /opt/vmware/content-gateway/smb-connector/smbconnector -s $line > server.dat &
	count=$(($count+1))
	done < "$1"
fi
