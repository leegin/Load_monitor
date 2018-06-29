#!/bin/bash
PATH=$PATH:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bon:/root/bin

+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
#Author : Leegin Bernads T.S
#Date : 28/06/2018
#version 1.0.0
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
MAX_LOAD=$(grep 'model name' /proc/cpuinfo |wc -l)
echo "====================================================================================="
echo "The maximum allowed load in the server $HOSTNAME is $MAX_LOAD"
echo "====================================================================================="

#One minute load average in the server 
ONE_MIN_LOADAVG=$(cat /proc/loadavg | awk '{print $1}'| cut -d"." -f1)
echo "====================================================================================="
echo "The one min load average in the server $HOSTNAME at `date` is $ONE_MIN_LOADAVG"
echo "====================================================================================="

if [[ $ONE_MIN_LOADAVG -eq $MAX_LOAD ]] || [[ $ONE_MIN_LOADAVG -lt $MAX_LOAD ]];
then
exit 1
else
#create a directory and give correct permission.We are going to place the findings in different files under this directory.
	if [[ -d monitoring_logs ]]
	then
		cd monitoring_logs
	else
		mkdir monitoring_logs;chmod 700 monitoring_logs;cd monitoring_logs
	fi

#ps command result sorted by cpu usage
funct_CPU(){
PS_CPU=`ps -eo uname,pid,ppid,time,cmd,%mem,%cpu --sort=-%cpu | head`
echo "`date`" >> CPU_log && echo "..........................">> CPU_log && echo "$PS_CPU">> CPU_log && echo ".........................." >> CPU_log

#Now lets check if the user using maximum CPU is a cPanel user.
User=`ps -eo uname,pid,ppid,time,cmd,%cpu --sort=-%cpu | head -n 2 | tail -n 1 | awk '{print $1}'`
if [ -f /var/cpanel/users/$User ];
then 
	lsof -p `ps -eo uname,pid,ppid,time,cmd,%mem,%cpu --sort=-%cpu | head -n 2 | tail -n 1 | awk '{print $2}'` >> cpu_file_access_log
	domain=`cat /var/cpanel/users/$User | grep DNS | cut -d"=" -f2`

#check the EA version in the server
if [ -e /etc/issue ]; then
 APACHE="apache2"
elif [ -e /etc/redhat-release ]; then
 APACHE="httpd"
fi
EA= `/usr/local/cpanel/scripts/easyapache --version | grep "Easy Apache" | awk '{print $3}' | cut -d"." -f1`
	if [[ $EA -eq v3 ]];
	then
		less /usr/local/$APACHE/domlogs/$domain/* | grep `date +%d/%b/%Y` | grep POST | awk '{print $1}' | sort | uniq -c | sort -n >> cpu_domlogs
	else
		less /etc/$APACHE/logs/domlogs/$domain/* | grep `date +%d/%b/%Y` | grep POST | awk '{print $1}' | sort | uniq -c | sort -n >> cpu_domlogs
	fi
fi
}
#Reporting CPU usage in the server
funct_CPU

#ps command result sorted by memory usage
funct_MEM(){
PS_MEM=`ps -eo uname,pid,ppid,time,cmd,%mem --sort=-%mem | head`
echo "`date`" >> Mem_log && echo "..........................">> Mem_log && echo "$PS_CPU">> Mem_log && echo ".........................." >> Mem_log

#Now lets check if the user using maximum MEMORY is a cPanel user.
User1=`ps -eo uname,pid,ppid,time,cmd,%mem,%cpu --sort=-%mem | head -n 2 | tail -n 1 | awk '{print $1}'`
echo "The user is $User1" >> Mem_file_access_log
if [ -f /var/cpanel/users/$User1 ];
then
	lsof -p `ps -eo uname,pid,ppid,time,cmd,%mem,%cpu --sort=-%mem | head -n 2 | tail -n 1 | awk '{print $2}'` >> Mem_file_access_log
exit 0
fi
}

#Report the memory usage
funct_MEM

#check for OOM in the server.
funct_OOM(){
TEST_OOM_INTERVAL=5;
LATEST_OOM="$(less /var/log/messages | grep -i "OOM-killer" | tail -n 1)";
LATEST_OOM_TIME=${LATEST_OOM:0:15};
echo $LATEST_OOM_TIME
if [ -n "${LATEST_OOM_TIME}" ]
then
    if [[ $(($((`date +%s` - `date --date="${LATEST_OOM_TIME}" +%s`)) / 60 )) -le ${LATEST_OOM_INTERVAL} ]]
        then
        echo "CRITICAL: OOM within last ${LATEST_OOM_INTERVAL} minutes!"
        echo ${LATEST_OOM}
        exit 2
    else
        echo "OK: Recent OOM but outside last ${LATEST_OOM_INTERVAL} minutes"
        echo "LATEST_OOM: ${LATEST_OOM}"
        exit 0
    fi
else
    echo "OK: No recent OOM"
    exit 0
fi
}
# Memory used by the server 
MEM_TOTAL=$(cat /proc/meminfo | grep -i memtotal | awk '{print $2}')
MEM_FREE=$(cat /proc/meminfo | grep -i memfree | awk '{print $2}')
MEM=$((MEM_TOTAL - MEM_FREE))
MEM_USED=$((MEM/1024))
GT_80=$((($MEM_TOTAL *80/100)/1024))
if [ $MEM_TOTAL -gt $GT_80 ];
then
	funct_MEM
	funct_OOM
fi

#Details regarding the mysql usage
funct_MYSQL(){
echo "Reported at `date`"
mysqladmin extended-status | grep -i "max_used" | awk '{print $2,$4}' >> Mysql_log
mysqladmin extended-status | grep  "Connections" | awk '{print $2,$4}' >> Mysql_log
mysqladmin proc stat >> Mysql_log
}
#Report the MYSQL usage in the server
funct_MYSQL

#The connections to different ports in the server
funct_CONN(){
echo "+++++++++++++++++++++++++++++++++++" >> Netstat_log
echo "Reported at `date`" >> Netstat_log
echo "+++++++++++++++++++++++++++++++++++" >> Netstat_log
echo "`netstat -plant | head |egrep -v '^(Active|Proto)' | mawk '{ip=$5; sub(/:[^:]+/,"",ip); service=$7; sub(/[^:][^:][^:][^:]/,"",service); print ip,service}'`" >> Netstat_log
echo "+----------------------------------------------+" >> Netstat_log
echo " The number of connections from different IPs" >> Netstat_log
echo "+----------------------------------------------+" >> Netstat_log
echo "`netstat -plane | head | egrep -v '^(Active|Proto)' | awk '{print $5}' | rev | cut -d":" -f2 | rev | sort | uniq -c | sort -n`" >> Netstat_log
}

# Reporting the connections in the server
funct_CONN

fi