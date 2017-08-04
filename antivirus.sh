#!/bin/bash
export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$PATH

#set -x

HOST=$(hostname -f)
EMAILTO="hosting-security@example.com"

case $1 in

###################################################################################
# Check for spam attack. Usually every 6 min
#------------------------------------------------------------------------------------------

"spam" )

	LETTERS=$(exim -bpc)

	if [ "$LETTERS" -ge "100" ]				# more than or equal to
	then
		iptables -nv -L OUTPUT | grep "multiport ports 25,465" > /dev/null 2>&1
		if [ 0 -eq $? ]					# equal to
		then
			iptables -D OUTPUT -d 10.0.0.1/32 -p tcp -m multiport --ports 25,465 -j ACCEPT
			iptables -D OUTPUT -d 10.0.0.2/32 -p tcp -m multiport --ports 25,465 -j ACCEPT
		else
			exit 0
		fi
	fi
	;;

###################################################################################
# Maldet scan the last 2 days of file changes. Usually every day at 7
#------------------------------------------------------------------------------------------

"maldet" )

	# sleep for random value to give upstream a bit of headroom
	sleep "$(echo $RANDOM | cut -c1-3)" > /dev/null 2>&1

	# clear quarantine/session/tmp data older then 14 days
	#DIR1="/usr/local/maldetect/sess"
	#DIR2="/usr/local/maldetect/quarantine"

	#DIR3="/usr/local/maldetect/pub/*/"
	#DIR4="/usr/local/maldetect/tmp"

	#for DIRECTORY in $DIR1 $DIR2
	#do
	#	find $DIRECTORY/* -type f -mtime +180 -exec rm -rf {} \;
	#done

	# check for new release version
	/usr/local/maldetect/maldet -d > /dev/null 2>&1

	# check for new definition set
	/usr/local/maldetect/maldet -u > /dev/null 2>&1

	freshclam --quiet > /dev/null 2>&1

	# if were running inotify monitoring, send daily hit summary
	#if [ "$(pgrep -l -u root inotifywait)" ]; then
	if [ "$(ps -A --user root -o "cmd" | grep maldetect | grep inotifywait)" ]; then
	/usr/local/maldetect/maldet --alert-daily > /dev/null 2>&1
	else
		# scan the last 2 days of file changes
		if [ -d "/usr/local/ispconfig" ] ; then

		# ISP-Config
		/usr/local/maldetect/maldet -b -r /var/www 2 > /dev/null 2>&1
		/usr/local/maldetect/maldet -b -r /var/tmp 2 > /dev/null 2>&1
		fi
	fi
	;;

###################################################################################
# Update ip addresses in chain ant_update for update freshclam, maldet, rkhunter, whois. Usually every 1 hour
#------------------------------------------------------------------------------------------

"freshclam" )
	
	iptables -nv -L ant_update > /dev/null 2>&1
	if [ 0 -ne $? ]						# if not equal, not success
	then
		iptables -N ant_update
		iptables -A ant_update -j RETURN
	else
		iptables -F ant_update
		iptables -A ant_update -j RETURN

		iptables -I ant_update 1 -d db.local.clamav.net -p tcp -m multiport --ports 80,443 -j ACCEPT
		iptables -I ant_update 1 -d database.clamav.net -p tcp -m multiport --ports 80,443 -j ACCEPT
		iptables -I ant_update 1 -d db.ua.clamav.net -p tcp -m multiport --ports 80,443 -j ACCEPT
		iptables -I ant_update 1 -d rfxn.com -p tcp -m multiport --ports 80,443 -j ACCEPT
		iptables -I ant_update 1 -d cdn.rfxn.com -p tcp -m multiport --ports 80,443 -j ACCEPT
		iptables -I ant_update 1 -d rkhunter.sourceforge.net -p tcp --dport 80 -j ACCEPT
		iptables -I ant_update 1 -d projects.sourceforge.net -p tcp --dport 80 -j ACCEPT
		iptables -I ant_update 1 -d www.ispconfig.org -p tcp --dport 80 -j ACCEPT	# for ispconfig
		iptables -I ant_update 1 -d 0.0.0.0/0 -p tcp --dport 43 -j ACCEPT		# for whois
	fi

	iptables -nv -L OUTPUT | grep ant_update > /dev/null 2>&1
	if [ 0 -ne $? ]						# if not equal, not success
	then
		iptables -I OUTPUT 1 -p tcp --match multiport --dports 43,80,443 -j ant_update
	fi
	;;

###################################################################################
# Update bases and scan hosting and delete old files from /tmp/quarantine. Usually every Sundays
#------------------------------------------------------------------------------------------

"scan" )

	# result is here /var/log/clamav/antivirus-clamscan.log and /usr/local/maldetect/logs

	find /usr/local/maldetect.bk* -maxdepth 0 -type d -mtime +40 -exec rm -rf {} \;

	# Check if config file changed
	grep '^email_addr="hosting-security@example.com"' /usr/local/maldetect/conf.maldet > /dev/null 2>&1
	check_email="$?"
	grep '^quarantine_hits="1"' /usr/local/maldetect/conf.maldet > /dev/null 2>&1
	check_quar="$?"

	if [ 0 -ne "$check_email" ] || [ 0 -ne "$check_quar" ]
	then
		SUBJ="Maybe maldet was updated. Please change config file conf.maldet. Antivirus unable to quarantine viruses"
		echo "$SUBJ" | mail -s "Maldet config file was changed on $HOST" "$EMAILTO"
	fi

	# update bases
	#-------------------------------------------------------
	/etc/init.d/clamav-daemon start > /dev/null 2>&1
	/etc/init.d/clamav-freshclam start > /dev/null 2>&1

	rkhunter --update > /dev/null 2>&1
	rkhunter --propupd > /dev/null 2>&1
	freshclam --quiet > /dev/null 2>&1

	/usr/local/maldetect/maldet -d > /dev/null 2>&1
	/usr/local/maldetect/maldet -u > /dev/null 2>&1

	# scan hosting for virus
	#-------------------------------------------------------
	/usr/local/maldetect/maldet -a /var/www > /dev/null 2>&1
	/usr/local/maldetect/maldet -a /var/tmp > /dev/null 2>&1

	rkhunter --check --skip-keypress > /dev/null 2>&1

	# variables for ClamAV
	#-------------------------------------------------------
	DATE=$(date +%d-%m-%Y_%H:%M:%S)
	SUBJECT="detected by ClamAV on"
	OUT="/tmp/quarantine/antivirus_out.log"
	EMAILMESSAGE="/tmp/quarantine/antivirus_mail.log"
	LOG="/var/log/clamav/antivirus-clamscan.log"

	# check conditions
	if [ ! -d /tmp/quarantine ]				# if not equal, not success
	then
		mkdir -p /tmp/quarantine > /dev/null 2>&1
		chmod 740 /tmp/quarantine -R > /dev/null 2>&1
		chmod g+s /tmp/quarantine -R > /dev/null 2>&1
	fi

	if [ ! -f /etc/logrotate.d/antivirus-clamscan ]
	then
		cat > /etc/logrotate.d/antivirus-clamscan <<- _EOF_
		/var/log/clamav/antivirus-clamscan.log {
		     weekly
		     missingok
		     rotate 12
		     compress
		     delaycompress
		     minsize 1048576
		     notifempty
		     create 640 clamav adm
		}
		_EOF_
	fi

#	clamscan -ri --exclude="access.log*" --scan-swf=no --move=/tmp/quarantine --no-summary --stdout>$OUT /var/www

	for SCAN_DIR in "/var/www" "/var/tmp"
	do
		clamscan --recursive --infected --exclude="access.log*" --scan-swf=no --move=/tmp/quarantine --stdout>$OUT "$SCAN_DIR"

		CODE="$?"

		# no problems
		#------------------------------------------------------------------------------------------
		if [ 0 -eq "$CODE" ]					# equal
		then
			continue

		# send email with viruses
		#------------------------------------------------------------------------------------------
		elif [ 1 -eq "$CODE" ]					# equal 
		then
			echo "Date: $DATE" > $EMAILMESSAGE
			{
				echo "Foud some viruses during scanning $SCAN_DIR in"
				echo "----------------------------------------------------------"
				cat $OUT
			} >> $EMAILMESSAGE

			cat $EMAILMESSAGE >> $LOG
			echo "" >> $LOG
			mail -s "VIRUSES $SUBJECT $HOST" "$EMAILTO" < $EMAILMESSAGE
			chmod 000 /tmp/quarantine/* > /dev/null 2>&1

		# send email with errors
		#------------------------------------------------------------------------------------------
		elif [ 2 -eq "$CODE" ]					# equal 
		then
			echo "Date: $DATE" > $EMAILMESSAGE
			{
				echo "Foud some ERRORS during scanning $SCAN_DIR in"
				echo "----------------------------------------------------------"
				cat $OUT
			} >> $EMAILMESSAGE

			cat $EMAILMESSAGE >> $LOG
			echo "" >> $LOG
#			mail -s "Errors $SUBJECT $HOST" "$EMAILTO" < $EMAILMESSAGE
		else
			echo "Date: $DATE" > $EMAILMESSAGE
			{
				echo "Foud some PROBLEMS during scanning $SCAN_DIR. End code is $CODE"
				echo "----------------------------------------------------------"
				cat $OUT
			} >> $EMAILMESSAGE

			cat $EMAILMESSAGE >> $LOG
			echo "" >> $LOG
#			mail -s "Problems $SUBJECT $HOST" "$EMAILTO" < $EMAILMESSAGE
		fi
	done

	# Delete viruses from /tmp/quarantine that older 14 days
	#-------------------------------------------------------

	#find /tmp/quarantine/* -type f -mtime +180 -exec rm -rf {} \;

	/etc/init.d/clamav-daemon stop > /dev/null 2>&1
	/etc/init.d/clamav-freshclam stop > /dev/null 2>&1
	;;

esac
