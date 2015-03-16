#!/bin/sh
# ESXi_STIG_WeeklyTasks_setuidCheck.sh, ABr, 18-SEP-13
#
# Change Log
# ----------
# 18-SEP-13, ABr: Initial creation
#
# Check for unauthorized setuid files
#
#######################################################################
# variables
l_SETUID_LOGDIR=/var/log/setuid
l_SETUID_MASTER=${l_SETUID_LOGDIR}/master.txt
l_SETUID_CURRENT=${l_SETUID_LOGDIR}/current.txt
l_SETUID_RESULT=${l_SETUID_LOGDIR}/result.txt
#######################################################################
# first check for the setuid folder
[ ! -d "${l_SETUID_LOGDIR}" ] && mkdir "${l_SETUID_LOGDIR}"
if [ ! -d "${l_SETUID_LOGDIR}" ]; then
  echo "Unable to create setuid logdir ${l_SETUID_LOGDIR}"
  exit 1
fi
#######################################################################
# next check for the setuid info master
if [ ! -f "${l_SETUID_MASTER}" ]; then
  echo "Creating setuid master"
  find . -path ./vmfs -prune -o -type f \( -perm -4000 -o -perm -2000 \) -exec ls {} \; 2>/dev/null > "${l_SETUID_MASTER}"
fi
#######################################################################
# check for the current values
echo "Creating setuid current"
find . -path ./vmfs -prune -o -type f \( -perm -4000 -o -perm -2000 \) -exec ls {} \; 2>/dev/null > "${l_SETUID_CURRENT}"
#######################################################################
# compare values
if diff "${l_SETUID_MASTER}" "${l_SETUID_CURRENT}"; then
  echo "OK: setuid unchanged" > "${l_SETUID_RESULT}"
else
  echo "ERROR: setuid change detected" > "${l_SETUID_RESULT}"
fi

