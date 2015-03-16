#!/bin/sh
# ESXi_STIG_WeeklyTasks.sh, ABr, 06-SEP-13
#
# Change Log
# ----------
# 06-SEP-13, ABr: Initial creation
# 12-MAR-14, ABr: Testing on ESXi 5.5
#
# ESXi 5.x weekly tasks to meet STIG requirements
#
#######################################################################
# analyze the /dev folder for all character devices, return checksum
esxi_stig_weekly_md5sum_dev() {
  find /dev -type c -name "*" | awk '{print $1}' | sort | md5sum
  return $?
}
#######################################################################
# create a cron job from the passed input line (all parms
esxi_stig_weekly_setupcron() {
  # get args
  l_time_info=$1
  shift
  l_cron_job=$*

  # location of busybox
  l_busybox=/usr/lib/vmware/busybox/bin/busybox

  # first check for the job
  l_cron_tab=/var/spool/cron/crontabs/root
  if ! grep -F "$l_cron_job" $l_cron_tab 2>&1 >/dev/null; then
    # add the line
    echo "Adding: $l_cron_job"
    echo "#" $(date) ": added by esxi_stig_weekly_setupcron" >> $l_cron_tab
    echo "$l_time_info" $l_cron_job >> $l_cron_tab
  fi

  # next check to see if cron is running
  l_cronpid=$(cat /var/run/crond.pid)
  if echo "${l_cronpid}" | grep -e "[0-9]\+" 2>&1 >/dev/null; then
    echo "Killing cron with pid $l_cronpid..."
    kill $l_cronpid
    echo "Restarting cron..."
    $l_busybox crond
  fi

  # finally check for the /etc/rc.local
  # note - the mv commands are required below...otherwise perm problems
  l_etc_rc=/etc/rc.local
  l_etc_rc_old=/etc/rc.local.old
  l_etc_rc_new=/etc/rc.local.new
  if ! grep -F "$l_cron_job" $l_etc_rc 2>&1 >/dev/null; then
    echo "Adding to $l_etc_rc..."
    cat $l_etc_rc > $l_etc_rc_new
    echo "#" $(date) ": added by esxi_stig_weekly_setupcron" >> $l_etc_rc_new
    echo "/bin/kill \$(cat /var/run/crond.pid)" >> $l_etc_rc_new
    echo "/bin/echo \"$l_time_info $l_cron_job\" >> $l_cron_tab" >> $l_etc_rc_new
    echo "$l_busybox crond" >> $l_etc_rc_new
    mv $l_etc_rc $l_etc_rc_old
    mv $l_etc_rc_new $l_etc_rc
    chmod 555 $l_etc_rc
  fi
}
#######################################################################
# setup all weekly programs
esxi_stig_weekly_setup() {
  # invoke to find setuid files and compare to prev - 8:05am every Sunday
  esxi_stig_weekly_setupcron "5 8 * * 6" "/STIG/ESXi_STIG_WeeklyTasks_setuidCheck.sh"
  # invoke to find setgid files and compare to prev - 8:07am every Sunday
  esxi_stig_weekly_setupcron "7 8 * * 6" "/STIG/ESXi_STIG_WeeklyTasks_setgidCheck.sh"
}

