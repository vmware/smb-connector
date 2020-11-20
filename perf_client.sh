#!/bin/sh
if [ "$#" != 3 ]; then
	echo "incorrect number of arguments"
	echo "run script as"
	echo "./perf_client.sh socket.list credentials.file op_code"
	echo "the socket.list file should contain name of domain sockets to which smbconnector clients will connect"
	echo "credentials.file should have url, user-name, password, wrok-group separated by \n in same sequence"
	exit
fi
log_count=0
url=`awk 'NR==1' $2`
user=`awk 'NR==2' $2`
pass=`awk 'NR==3' $2`
wg=`awk 'NR==4' $2`
while IFS='' read -r line || [[ -n "$line" ]]; do
    echo "starting smbconnector in client mode, socket: $line"
    ulimit -c unlimited
    nohup /opt/vmware/content-gateway/smb-connector/smbconnector -m client -s $line -l client$log_count.log -o $3 -g 4 -u $url -n $user -p $pass -w $wg --out_file=out$log_count > client.dat &
    log_count=$((log_count+1))
done < "$1"
