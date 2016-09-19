# manage-antivirus

crontab

03 */2 * * *	/root/scripts/antivirus.sh freshclam > /dev/null 2>&1
09 */2 * * *	/root/scripts/antivirus.sh maldet > /dev/null 2>&1
33 05 * * *	/root/scripts/antivirus.sh scan > /dev/null 2>&1
