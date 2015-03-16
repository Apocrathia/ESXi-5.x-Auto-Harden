#!/bin/sh
# ESXi_STIG_WeeklyTasks_setgidCheck.sh, ABr, 20-SEP-13
#
# Change Log
# ----------
# 20-SEP-13, ABr: Initial creation
#
# Check for unauthorized setgid files
#
#######################################################################
# variables
l_SETGID_LOGDIR=/var/log/setgid
l_SETGID_MASTER=${l_SETGID_LOGDIR}/master.txt
l_SETGID_CURRENT=${l_SETGID_LOGDIR}/current.txt
l_SETGID_RESULT=${l_SETGID_LOGDIR}/result.txt
#######################################################################
# first check for the setgid folder
[ ! -d "${l_SETGID_LOGDIR}" ] && mkdir "${l_SETGID_LOGDIR}"
if [ ! -d "${l_SETGID_LOGDIR}" ]; then
  echo "Unable to create setgid logdir ${l_SETGID_LOGDIR}"
  exit 1
fi
#######################################################################
# next check for the setgid info master
if [ ! -f "${l_SETGID_MASTER}" ]; then
  echo "Creating setgid master"
  find . -path ./vmfs -prune -o -type f \( -perm -6000 \) -exec ls {} \; 2>/dev/null > "${l_SETGID_MASTER}"
fi
#######################################################################
# check for the current values
echo "Creating setgid current"
find . -path ./vmfs -prune -o -type f \( -perm -6000 \) -exec ls {} \; 2>/dev/null > "${l_SETGID_CURRENT}"
#######################################################################
# compare values
if diff "${l_SETGID_MASTER}" "${l_SETGID_CURRENT}"; then
  echo "OK: setgid unchanged" > "${l_SETGID_RESULT}"
else
  echo "ERROR: setgid change detected" > "${l_SETGID_RESULT}"
fi

