#
# Regular cron jobs for the hpkvfs package
#
0 4	* * *	root	[ -x /usr/bin/hpkvfs_maintenance ] && /usr/bin/hpkvfs_maintenance
