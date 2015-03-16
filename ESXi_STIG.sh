#!/bin/sh
# ESXi_STIG.sh, ABr, 15-FEB-13
#
# Change Log
# ----------
# 28-FEB-13, ABr: account for "management network" in 
# 25-SEP-13, ABr: finalized ESXi 5.x STIG
# 12-MAR-14, ABr: updated for ESXi 5.0 and 5.5 STIG
# 05-APR-14, ABr: added hack for ESXi 5.0
# 04-JUN-14, ABr: checks for ESXi 5.0 w/additional function
#
# STIG commands for ESXi 5.5 host
#
#######################################################################
# ***BEGIN UTILITY FUNCTIONS***
#######################################################################
# add-subtract-multiply-divide within busybox
#
# check if number is unsigned
is_uint()
{
    case "$1" in
        ''|*[!0-9]*) return 1
                     ;;
    esac
    [ "$1" -ge 0 ]
}
#
# check if number is signed
is_int()
{
    case "${1#-}" in
        ''|*[!0-9]*) return 1
                     ;;
    esac
}
#
# requires seq, grep -n, sort -nr
# reasonably fast
add()
{
    if   ! is_uint "$1" \
      || ! is_uint "$2"; then
        echo "Usage: add <uint1> <uint2>"
        return 1
    fi
    [ "$1" -eq 0 ] && { echo "$2"; return; }
    [ "$2" -eq 0 ] && { echo "$1"; return; }

    {
        seq 1 "$1"
        seq 1 "$2"
    } \
        | grep -n "" \
        | sort -nr \
        | { read num; echo "${num%[-:]*}"; }
}
#
# requires seq, grep -n, sort -nr, uniq -u
# reasonably fast
subtract()
{
    if   ! is_uint "$1" \
      || ! is_uint "$2"; then
        echo "Usage: subtract <uint1> <uint2>"
        return 1
    fi

    if [ "$1" -ge "$2" ]; then
        __x="$1"
        __y="$2"
    else
        __x="$2"
        __y="$1"
    fi

    {
        seq 0 "${__x}"
        seq 0 "${__y}"
    } \
        | sort -n \
        | uniq -u \
        | grep -n "" \
        | sort -nr \
        | \
        {
            read num
            : ${num:=0}
            [ "${__x}" = "$2" ] && [ "$1" -ne "$2" ] && minus='-'
            echo "${minus}${num%:*}"
        }
}

# requires seq, grep -wB
# faster than subtract(), but requires non-standard grep -wB
subtract_nonposix()
{
    if   ! is_uint "$1" \
      || ! is_uint "$2"; then
        echo "Usage: subtract <uint1> <uint2>"
        return 1
    fi

    if [ "$1" -ge "$2" ]; then
        __x="$1"
        __y="$2"
    else
        __x="$2"
        __y="$1"
    fi
    seq 0 "${__x}" \
        | grep -w -B "${__y}" "${__x}" \
        | \
        {
            read num
            [ "${__x}" = "$2" ] && [ "$1" -ne "$2" ] && minus='-'
            echo "${minus}${num}"
        }
}

# requires seq, sort -nr, add()
# very slow if multiplicand or multiplier is large
multiply()
{
    if   ! is_int "$1" \
      || ! is_int "$2"; then
        echo "Usage: multiply <int1> <int2>"
        return 1
    fi
    [ "$2" -eq 0 ] && { echo 0; return; }
    # make sure to use the smaller number for the outer loop
    # to speed up things a little if possible
    if [ $1 -ge $2 ]; then
        __x="$1"
        __y="$2"
    else
        __x="$2"
        __y="$1"
    fi
    __x="${__x#-}"
    __y="${__y#-}"

    seq 1 "${__y}" \
        | while read num; do
            sum="$(add "${sum:-0}" "${__x}")"
            echo "${sum}"
        done \
        | sort -nr \
        | \
        {
            read num
            if   [ "$1" -lt 0 -a "$2" -gt 0 ] \
              || [ "$2" -lt 0 -a "$1" -gt 0 ]; then
                minus='-'
            fi
            echo "${minus}${num}"
        }
}
#
# requires subtract()
# very costly if dividend is large and divisor is small
divide()
{
    if   ! is_int "$1" \
      || ! is_int "$2"; then
        echo "Usage: divide <int1> <int2>"
        return 1
    fi
    [ "$2" -eq 0 ] && { echo "division by zero"; return 1; }

    (
        sum="${1#-}"
        y="${2#-}"
        count=
        while [ "${sum}" -ge "${y}" ]; do
            sum="$(subtract "${sum}" "${y}")"
            # no need to use add() for a simple +1 counter,
            # this is way faster
            count="${count}."
        done

        if   [ "$1" -lt 0 -a "$2" -gt 0 ] \
          || [ "$2" -lt 0 -a "$1" -gt 0 ]; then
            minus='-'
        fi
        echo "${minus}${#count}"
    )
}
#
#######################################################################
# permission translation from "ls -la" output
# example for /etc/ssh/sshd_config: '-rw------T'
# output would be '1600'
esxi_stig_xlat_perms() {
  l_perms="$1"

  # translate to octal
  l_p0="0" # SET-XXX: 1=set-ID; 2=set-group; 4=set-user
  l_p1="0" # USER: 1=execute; 2=write; 4=read
  l_p2="0" # GROUP: 1=execute; 2=write; 4=read
  l_p3="0" # OTHER: 1=execute; 2=write; 4=read

  # check for user permissions
  if echo $l_perms | grep -e "^.r........" >/dev/null 2>&1; then l_p1=$(expr $l_p1 + 4); fi
  if echo $l_perms | grep -e "^..w......." >/dev/null 2>&1; then l_p1=$(expr $l_p1 + 2); fi
  if echo $l_perms | grep -e "^...x......" >/dev/null 2>&1; then l_p1=$(expr $l_p1 + 1); fi
  if echo $l_perms | grep -e "^....r....." >/dev/null 2>&1; then l_p2=$(expr $l_p2 + 4); fi
  if echo $l_perms | grep -e "^.....w...." >/dev/null 2>&1; then l_p2=$(expr $l_p2 + 2); fi
  if echo $l_perms | grep -e "^......x..." >/dev/null 2>&1; then l_p2=$(expr $l_p2 + 1); fi
  if echo $l_perms | grep -e "^.......r.." >/dev/null 2>&1; then l_p3=$(expr $l_p3 + 4); fi
  if echo $l_perms | grep -e "^........w." >/dev/null 2>&1; then l_p3=$(expr $l_p3 + 2); fi
  if echo $l_perms | grep -e "^.........x" >/dev/null 2>&1; then l_p3=$(expr $l_p3 + 1); fi

  # check for 'S' (set-user) in user field
  if echo $l_perms | grep -e "^...S......" >/dev/null 2>&1; then l_p0=$(expr $l_p0 + 4); fi
  if echo $l_perms | grep -e "^...s......" >/dev/null 2>&1; then
    # lower-case 's' indicates execute bit set for user
    l_p0=$(expr $l_p0 + 4);
    l_p1=$(expr $l_p1 + 1);
  fi

  # check for 'S' (set-group) in group field
  if echo $l_perms | grep -e "^......S..." >/dev/null 2>&1; then l_p0=$(expr $l_p0 + 2); fi
  if echo $l_perms | grep -e "^......s..." >/dev/null 2>&1; then
    # lower-case 's' indicates execute bit set for user
    l_p0=$(expr $l_p0 + 2);
    l_p2=$(expr $l_p2 + 1);
  fi

  # check for 'T' (set-ID) in other field
  if echo $l_perms | grep -e "^.........T" >/dev/null 2>&1; then l_p0=$(expr $l_p0 + 1); fi
  if echo $l_perms | grep -e "^.........t" >/dev/null 2>&1; then
    # lower-case 't' indicates execute bit set for other
    l_p0=$(expr $l_p0 + 1);
    l_p3=$(expr $l_p3 + 1);
  fi

  # construct output
  l_result="${l_p0}${l_p1}${l_p2}${l_p3}"
  echo $l_result
  return 0
}
#######################################################################
# handle config file saving
esxi_stig_saveconfig() {
  l_config="$1"
  if [ ! -f "${l_config}-orig" ]; then
    cp "$l_config" "${l_config}-orig"
  else
    l_date=$(date +"%Y%m%d-%T")
    cp -f "${l_config}" "${l_config}"-${l_date}
    sleep 1
  fi
}
# update config file from -new
esxi_stig_updateconfig() {
  l_config="$1"

  # check if file exists
  l_perms=""
  l_chmod_perms=""
  if [ -f "$l_config" ]; then
    # get orig file permissions
    l_perms=$(ls -la "$l_config" | cut -d ' ' -f 1)

    # xlat to octal
    l_chmod_perms=$(esxi_stig_xlat_perms "$l_perms")

    # save the config file
    esxi_stig_saveconfig "$l_config"
  fi

  # copy the new if given
  if [ -f "$l_config"-new ]; then
    cp -f "$l_config"-new "$1"
    rm -f "$l_config"-new

    # set permissions and indicate that problem was "fixed" via return code
    if [ ! "$l_chmod_perms" = "" ]; then
      chmod $l_chmod_perms "$l_config"
    fi
    return 1
  fi

  # FIXME: indicate "fixed" in any event
  return 1
}
# determine if this is ESXi 5.0 or 5.x
esxi_stig_is_ESXi_5_0() {
  # get version
  l_ver=$(vmware -v 2>/dev/null)
  if echo $l_ver | grep -e "ESXi 5.0" 2>&1 >/dev/null; then
    echo "1"
    return 0
  fi
  echo "0"
  return 1
}
# set ESXi persistence
esxi_stig_auto_persist() {
  # name of the compressed file we use
  l_compressed=esxi_stig.tgz
  l_bootbank=/bootbank
  l_boot_cfg=boot.cfg
  l_bootbank_boot_cfg="$l_bootbank/$l_boot_cfg"
  l_bootbank_compressed="$l_bootbank/$l_compressed"
  l_boot_cfg_new="$l_bootbank_boot_cfg-new"
  l_esxi_stig_sh='ESXi_STIG.sh'

  # get the current folder
  l_pwd=$PWD

  # create the compressed file we store with ESXi
  echo "Creating compressed file $l_compressed..."
  rm -f $l_pwd/$l_compressed
  cd / && tar -czvf $l_pwd/$l_compressed $l_pwd/ESXi_STIG* 2>/dev/null | sed -e 's/^/  .../' && cd $l_pwd

  # copy to ESXi bootbank for persistent storage
  echo "Copying to $l_bootbank..."
  cp -f ./$l_compressed $l_bootbank

  # check to see if we are already in the boot.cfg script
  if grep -e "^modules=.* --- $l_compressed" $l_bootbank_boot_cfg 2>&1 >/dev/null; then
    echo "[Already installed to $l_bootbank_boot_cfg...]"
  else
    # learned from experience *not* to put a reference to the tgz file in boot.cfg
    echo "[Not modifying $l_bootbank_boot_cfg; this leads to boot failures...]"
    #echo "Modifying $l_bootbank_boot_cfg to contain $l_compressed..."
    #cat $l_bootbank_boot_cfg | sed -e "s/^\(modules=.*\)/\1 --- $l_compressed/" > $l_boot_cfg_new
    #esxi_stig_updateconfig $l_bootbank_boot_cfg
  fi

  # now setup rc.local to update the banner
  l_rclocal_tag="# -- esxi_stig_auto_persist"
  l_is_5_0=$(esxi_stig_is_ESXi_5_0)
  if [ "$l_is_5_0" = "1" ]; then
    l_etc_rc=/etc/rc.local
  else
    l_etc_rc=/etc/rc.local.d/local.sh
  fi
  l_etc_rc_new="$l_etc_rc"-new
  echo "Setting up $l_etc_rc_new to contain our startup commands..."
  grep -v -e "$l_rclocal_tag" $l_etc_rc | grep -v -e "^exit 0" > $l_etc_rc_new
  echo "$l_rclocal_tag - BEGIN" >> $l_etc_rc_new
  echo "l_pwd=\$PWD $l_rclocal_tag" >> $l_etc_rc_new
  echo "echo 'Uncompressing $l_compressed' $l_rclocal_tag" >> $l_etc_rc_new
  echo "cd / $l_rclocal_tag" >> $l_etc_rc_new
  echo "tar -xzf $l_bootbank_compressed $l_rclocal_tag" >> $l_etc_rc_new
  echo "if [ -d '$l_pwd' -a -f '$l_pwd/$l_esxi_stig_sh' ]; then $l_rclocal_tag" >> $l_etc_rc_new
  echo "  echo 'Setting banners...' $l_rclocal_tag" >> $l_etc_rc_new
  echo "  cd $l_pwd $l_rclocal_tag" >> $l_etc_rc_new
  echo "  ESXI_STIG_DEFINE_ONLY=1 $l_rclocal_tag" >> $l_etc_rc_new
  echo "  . ./$l_esxi_stig_sh $l_rclocal_tag" >> $l_etc_rc_new
  echo "  esxi_stig_SRG_OS_000023_ESXI5 $l_rclocal_tag" >> $l_etc_rc_new
  echo "  unset ESXI_STIG_DEFINE_ONLY $l_rclocal_tag" >> $l_etc_rc_new
  echo "else $l_rclocal_tag" >> $l_etc_rc_new
  echo "  echo 'Unable to uncompress $l_bootbank_compressed...check logs' $l_rclocal_tag" >> $l_etc_rc_new
  echo "fi $l_rclocal_tag" >> $l_etc_rc_new
  echo "cd \$l_pwd $l_rclocal_tag" >> $l_etc_rc_new
  echo "$l_rclocal_tag - END" >> $l_etc_rc_new
  if [ "$l_is_5_0" = "0" ]; then
    # must put in an 'exit 0' for ESXi 5.x (not 5.0)
    echo "exit 0" >> $l_etc_rc_new
  fi
  echo "Updating $l_etc_rc..."
  esxi_stig_updateconfig $l_etc_rc

  return 0
}
#######################################################################
# perform a chkconfig operation
esxi_stig_chkconfig_op() {
  # pass service name, enable/disable (1/0) flag, and start/stop (1/0) flag
  l_service=$1
  l_enableflag=$2
  l_FIXED=0

  # check for enable / disable
  if [ "$l_enableflag" = "1" ]; then
    if chkconfig $l_service | grep -i -e " off\$" >/dev/null 2>&1; then
      echo -n "enabling $l_service..."
      chkconfig $l_service on >/dev/null 2>&1
      l_FIXED=1
    fi
  else
    if chkconfig $l_service | grep -i -e " on\$" >/dev/null 2>&1; then
      echo -n "disabling $l_service..."
      chkconfig $l_service off >/dev/null 2>&1
      l_FIXED=1
    fi
  fi
  return $l_FIXED
}
#######################################################################
# show result of an effort
esxi_stig_showresult() {
  if [ "$1" = "0" ]; then
    echo "[ok]"
  else
    if [ "$1" = "1" ]; then
      echo "Fixed!"
    else
      if [ "$1" = "2" ]; then
        echo "[n/a]"
      else
        echo "[ERROR!]"
      fi
    fi
  fi
  return 0
}
#######################################################################
# standard process to handle a service
esxi_stig_service_setup() {
  l_rulename=$1
  l_service=$2
  l_enableflag=$3
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0
  esxi_stig_chkconfig_op $l_service $l_enableflag
  l_FIXED=$?
  esxi_stig_showresult ${l_FIXED}
  return 0
}
#
#######################################################################
# ***BEGIN sshd_config UTILITY FUNCTIONS***
#######################################################################
#
#######################################################################
# verify sshd configuration
# simplest form of a change
esxi_stig_sshd_SimpleChange() {
  l_allowed_value="$1"
  l_STIG="$2"
  l_SSH_CONFIG_FILE="$3"

  # set parameters
  l_FIXED=0
  if [ "$l_SSH_CONFIG_FILE" = "" ]; then
    l_SSH_CONFIG_FILE=sshd_config
  fi

  # show title
  echo -n "$l_STIG..."

  # extract parameters
  l_firstword=$(echo $l_allowed_value | cut -d ' ' -f 1)
  l_secondword=$(echo $l_allowed_value | cut -d ' ' -f 2)
  l_thirdword=$(echo $l_allowed_value | cut -d ' ' -f 3)

  # check for special condition __DELETE__. this indicates that the
  # value should *not* be in the file.
  if [ "$l_secondword" = "__DELETE__" ]; then
    # just verify that the entry is *not* in the file
    if grep -i -e "^${l_firstword}[ \t]" /etc/ssh/${l_SSH_CONFIG_FILE} >/dev/null 2>&1; then
      # extract all but the line
      if [ -f /etc/ssh/${l_SSH_CONFIG_FILE} ]; then
        cat /etc/ssh/${l_SSH_CONFIG_FILE} | grep -i -v "^$l_firstword" > /etc/ssh/${l_SSH_CONFIG_FILE}-new
      else
        touch /etc/ssh/${l_SSH_CONFIG_FILE}-new
      fi
      echo "# $l_STIG" >> /etc/ssh/${l_SSH_CONFIG_FILE}-new
      echo "# Deleted $l_firstword" >> /etc/ssh/${l_SSH_CONFIG_FILE}-new
      esxi_stig_updateconfig /etc/ssh/${l_SSH_CONFIG_FILE}
      l_FIXED=$?
    fi
  else
    # check to see if this is a verification only
    l_VERIFY_ONLY=0
    if [ "$l_secondword" = "__VERIFY_ONLY__" ]; then
      l_VERIFY_ONLY=1
      l_allowed_value="$l_firstword .*"
    fi

    # check to see if the keyword must exist
    l_ENSURE_EXISTS=0
    if [ "$l_secondword" = "__ENSURE_EXISTS__" ]; then
      l_ENSURE_EXISTS=1
      l_allowed_value="$l_firstword .*"
    fi

    # check for the value
    if ! grep -i -e "^${l_allowed_value}\$" /etc/ssh/${l_SSH_CONFIG_FILE} >/dev/null 2>&1; then
      if [ $l_VERIFY_ONLY -eq 1 ]; then
        echo -n "Missing $l_firstword..."
        l_FIXED=3
      else
        # perform the update
        if [ -f /etc/ssh/${l_SSH_CONFIG_FILE} ]; then
          cat /etc/ssh/${l_SSH_CONFIG_FILE} | grep -i -v "^$l_firstword" > /etc/ssh/${l_SSH_CONFIG_FILE}-new
        else
          touch /etc/ssh/${l_SSH_CONFIG_FILE}-new
        fi
        echo -n "Updating /etc/ssh/${l_SSH_CONFIG_FILE}..."
        echo "# $l_STIG" >> /etc/ssh/${l_SSH_CONFIG_FILE}-new
        if [ $l_ENSURE_EXISTS -eq 1 ]; then
          echo $l_firstword $l_thirdword >> /etc/ssh/${l_SSH_CONFIG_FILE}-new
        else
          echo $l_allowed_value >> /etc/ssh/${l_SSH_CONFIG_FILE}-new
        fi
        esxi_stig_updateconfig /etc/ssh/${l_SSH_CONFIG_FILE}
        l_FIXED=$?
      fi
    fi
  fi

  # show the result to user
  esxi_stig_showresult ${l_FIXED}
}
#
#######################################################################
# ***BEGIN STIG CHECKS***
#######################################################################
#
# GEN002420-ESXI5-00878
esxi_stig_GEN002420_ESXI5_00878() {
  l_rulename="GEN002420-ESXI5-00878"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # if no fstab nothing to do
  if [ ! -f /etc/fstab ]; then
    l_FIXED=2
  else
    # scan for lines
    l_tmp="/tmp/$$.$l_rulename"
    cat /etc/fstab | grep -v "^#" > $l_tmp
    while read line; do
      # check for "nosuid"
      if echo $line | grep -e "nosuid" 2>&1 >/dev/null; then
        if [ $l_first=1 ]; then
          l_first=0
          echo ""
        fi
        echo "  Use nosuid for $line"
        l_FIXED=3
      fi
    done < $l_tmp
    rm -fr $l_tmp
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_GEN002420_ESXI5_00878
#
#######################################################################
# GEN002430-ESXI5
esxi_stig_GEN002430_ESXI5() {
  l_rulename="GEN002430-ESXI5"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # if no fstab nothing to do
  if [ ! -f /etc/fstab ]; then
    l_FIXED=2
  else
    # scan for lines
    l_tmp="/tmp/$$.$l_rulename"
    cat /etc/fstab | grep -v "^#" | grep -i nfs | grep -v "nodev" > $l_tmp
    while read line; do
      # all lines returned are errors
      if [ $l_first=1 ]; then
        l_first=0
        echo ""
      fi
      echo "  Use nodev for $line"
      l_FIXED=3
    done < $l_tmp
    rm -fr $l_tmp
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_GEN002430_ESXI5
#
#######################################################################
# GEN003510-ESXI5-006660
esxi_stig_GEN003510_ESXI5_006660() {
  l_rulename="GEN003510-ESXI5-006660"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # see if anything is active
  if esxcli system coredump partition get | grep -e "Active: ." 2>&1 >/dev/null; then
    # autofix by disabling
    esxcli system coredump partition set --enable false
    l_FIXED=1
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_GEN003510_ESXI5_006660
#
#######################################################################
# GEN005300-ESXI5-000099
esxi_stig_GEN005300_ESXI5_000099() {
  l_rulename="GEN005300-ESXI5-000099"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # see if anything is active
  l_tmp="/tmp/$$.$l_rulename"
  grep -i -e "community|communities" /etc/vmware/snmp.xml 2>&1 > $l_tmp
  if cat $l_tmp | grep -i -e "public|private|password" 2>&1 > /dev/null; then
    # cannot fix
    echo -n "Found default community name - fix manually..."
    l_FIXED=3
  fi
  rm -fr $l_tmp
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_GEN005300_ESXI5_000099
#
#######################################################################
# SRG-OS-000112-ESXI5
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "Protocol 2" SRG-OS-000112-ESXI5 ssh_config
#
#######################################################################
# GEN005515-ESXI5-000100
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "AllowTCPForwarding no" GEN005515-ESXI5-000100
#
#######################################################################
# GEN005516-ESXI5-703
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "Forward __DELETE__" GEN005516-ESXI5-703
#
#######################################################################
# GEN005517-ESXI5-000101
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "GatewayPorts no" GEN005517-ESXI5-000101
#
#######################################################################
# GEN005518-ESXI5-704
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "GatewayPorts no" GEN005518-ESXI5-704 ssh_config
#
#######################################################################
# GEN005519-ESXI5-000102
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "X11Forwarding no" GEN005519-ESXI5-000102
#
#######################################################################
# GEN005520-ESXI5-705
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "ForwardX11 no" GEN005520-ESXI5-705 ssh_config
#
#######################################################################
# GEN005521-ESXI5-000103
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "AllowGroups __ENSURE_EXISTS__ root" GEN005521-ESXI5-000103
#
#######################################################################
# GEN005524-ESXI5-000104
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "GSSAPIAuthentication no" GEN005524-ESXI5-000104
#
#######################################################################
# GEN005525-ESXI5-09994
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "GSSAPIAuthentication no" GEN005525-ESXI5-09994 ssh_config
#
#######################################################################
# GEN005526-ESXI5-000105
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "KerberosAuthentication no" GEN005526-ESXI5-000105
#
#######################################################################
# GEN005528-ESXI5-000106
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "AcceptEnv LOCALE" GEN005528-ESXI5-000106
#
#######################################################################
# GEN005529-ESXI5-708
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "AcceptEnv LOCALE" GEN005529-ESXI5-708 ssh_config
#
#######################################################################
# GEN005530-ESXI5-000107
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "PermitUserEnvironment no" GEN005530-ESXI5-000107
#
#######################################################################
# GEN005531-ESXI5-000108
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "PermitTunnel no" GEN005531-ESXI5-000108
#
#######################################################################
# GEN005532-ESXI5-709
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "PermitTunnel no" GEN005532-ESXI5-709 ssh_config
#
#######################################################################
# GEN005536-ESXI5-000110
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "StrictModes no" GEN005536-ESXI5-000110
#
#######################################################################
# GEN005537-ESXI5-000111
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "UsePrivilegeSeparation no" GEN005537-ESXI5-000111
#
#######################################################################
# GEN005538-ESXI5-000112
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "RhostsRSAAuthentication no" GEN005538-ESXI5-000112
#
#######################################################################
# GEN005539-ESXI5-000113
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "Compression no" GEN005539-ESXI5-000113
#
#######################################################################
# GEN005900-ESXI5-00891
esxi_stig_GEN005900_ESXI5_00891() {
  l_rulename="GEN005900-ESXI5-00891"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # if no fstab nothing to do
  if [ ! -f /etc/fstab ]; then
    l_FIXED=2
  else
    # scan for lines
    l_tmp="/tmp/$$.$l_rulename"
    cat /etc/fstab | grep -v "^#" | grep -i nfs | grep -v "nosuid" > $l_tmp
    while read line; do
      # all lines returned are errors
      if [ $l_first=1 ]; then
        l_first=0
        echo ""
      fi
      echo "  Use nosuid for $line"
      l_FIXED=3
    done < $l_tmp
    rm -fr $l_tmp
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_GEN005900_ESXI5_00891
#
#######################################################################
# GEN007700-ESXI5-000116
esxi_stig_GEN007700_ESXI5_000116() {
  l_rulename="GEN007700-ESXI5-000116"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # read to see if IPv6 is enabled
  l_tmp="/tmp/$$.$l_rulename"
  esxcli system module parameters list -m tcpip3 | grep -e "^ipv6" | sed -e "s#[ \t]\+# #g" > $l_tmp
  l_ipv6_enabled=$(cat $l_tmp | cut -d ' ' -f 3)
  if [ "$l_ipv6_enabled" = "1" ]; then
    # turn off IPv6
    esxcli system module parameters set -m tcpip3 -p ipv6=0 2>&1 >/dev/null
    l_RC=$?
    if [ $l_RC -eq 0 ]; then
      # fixed
      l_FIXED=1
      echo -n "ESXi host reboot necessary..."
    else
      # not fixed
      l_FIXED=3
    fi
  fi
  rm -fr $l_tmp

  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_GEN007700_ESXI5_000116
#
#######################################################################
# GEN007740-ESXI5-000118
esxi_stig_GEN007740_ESXI5_000118() {
  l_rulename="GEN007740-ESXI5-000118"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # NOTE: handled by GEN007700-ESXI5-000116 above
  echo -n "already handled by GEN007700-ESXI5-000116..."

  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_GEN007740_ESXI5_000118
#
#######################################################################
# SRG-OS-000023-ESXI5
esxi_stig_SRG_OS_000023_ESXI5() {
  l_rulename="SRG-OS-000023-ESXI5"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # always set this
  echo 'echo "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only."' > /etc/banner-new
  echo 'echo "By using this IS (which includes any device attached to this IS), you consent to the following conditions:"' >>/etc/banner-new
  echo 'echo "-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations."' >>/etc/banner-new
  echo 'echo "-At any time, the USG may inspect and seize data stored on this IS."' >>/etc/banner-new
  echo 'echo "-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose."' >>/etc/banner-new
  echo 'echo "-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy."' >>/etc/banner-new
  echo 'echo "-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."' >>/etc/banner-new
  esxi_stig_updateconfig /etc/banner
  l_FIXED=1

  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_000023_ESXI5
#
#######################################################################
# SRG-OS-000027-ESXI5
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "MaxSessions 1" SRG-OS-000027-ESXI5
#
#######################################################################
# SRG-OS-000033-ESXI5
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "Protocol 2" SRG-OS-000033-ESXI5
#
#######################################################################
# SRG-OS-000069-ESXI5
esxi_stig_SRG_OS_000069_ESXI5() {
  l_rulename="SRG-OS-000069-ESXI5"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # check for defaults
  if grep -e 'min=8,8,8,7,6' /etc/pam.d/passwd 2>&1 >/dev/null; then
    echo -n "Updating password complexity..."
    cat /etc/pam.d/passwd | sed -e 's#min=8,8,8,7,6#similar=deny min=disabled,disabled,disabled,disabled,14#' >/etc/pam.d/passwd-new 
    esxi_stig_updateconfig /etc/pam.d/passwd
    l_FIXED=1
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_000069_ESXI5
#
#######################################################################
# SRG-OS-000070-ESXI5
esxi_stig_SRG_OS_000070_ESXI5() {
  l_rulename="SRG-OS-000070-ESXI5"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  echo -n "already handled by SRG-OS-000069-ESXI5..."

  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_000070_ESXI5
#
#######################################################################
# SRG-OS-000071-ESXI5
esxi_stig_SRG_OS_000071_ESXI5() {
  l_rulename="SRG-OS-000071-ESXI5"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  echo -n "already handled by SRG-OS-000069-ESXI5..."

  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_000071_ESXI5
#
#######################################################################
# SRG-OS-000072-ESXI5
esxi_stig_SRG_OS_000072_ESXI5() {
  l_rulename="SRG-OS-000072-ESXI5"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  echo -n "already handled by SRG-OS-000069-ESXI5..."

  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_000072_ESXI5
#
#######################################################################
# SRG-OS-000077-ESXI5
esxi_stig_SRG_OS_000077_ESXI5() {
  l_rulename="SRG-OS-000077-ESXI5"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # read the password setting
  l_tmp="/tmp/$$.$l_rulename"
  grep "^password" /etc/pam.d/passwd | grep sufficient | grep "remember=" 2>/dev/null > $l_tmp
  if [ $? -eq 0 ]; then
    # condition: there is a "remember=" entry so we check it
    l_remember_value=$(cat $l_tmp | sed -e "s#.* remember=\([^ \t]\+\).*#\1#")


    # verify numeric
    l_fix_remember=1
    if echo $l_remember_value | grep -e "^[0-9]\+\$" 2>&1 >/dev/null; then
      # it is numeric
      l_fix_remember=0
      if [ $l_remember_value -lt 5 ]; then
        # it must be corrected
        l_fix_remember=1
      fi
    fi

    # if we must fix it in place, do so
    if [ $l_fix_remember -eq 1 ]; then
      echo -n "Updating remember=$l_remember_value..."
      cat /etc/pam.d/passwd | sed -e 's#remember=[^ \t]\+#remember=5#' >/etc/pam.d/passwd-new 
      esxi_stig_updateconfig /etc/pam.d/passwd
      l_FIXED=1
    fi
  else
    # no "remember=" entry so we create it
    echo -n "Creating remember=5..."
    cat /etc/pam.d/passwd | sed -e "s#^\(password[ \t]\+sufficient[ \t]\+\)\(.*\)#\1\2 remember=5#" >/etc/pam.d/passwd-new 
    esxi_stig_updateconfig /etc/pam.d/passwd
    l_FIXED=1
  fi
  rm -fr $l_tmp
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_000077_ESXI5
#
#######################################################################
# SRG-OS-000078-ESXI5
esxi_stig_SRG_OS_000078_ESXI5() {
  l_rulename="SRG-OS-000078-ESXI5"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  echo -n "already handled by SRG-OS-000069-ESXI5..."

  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_000078_ESXI5
#
#######################################################################
# SRG-OS-000095-ESXI5
esxi_stig_SRG_OS_000095_ESXI5() {
  l_rulename="SRG-OS-000095-ESXI5"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # this changed since ESXi5 STIG.

  # get all non-empty, non-commented lines other than sshd/authd
  l_tmp="/tmp/$$.$l_rulename"
  cat /var/run/inetd.conf | grep -v "^[ \t]*#" | grep -v "^[ \t]*\$" | grep -v "^[ \t]*\(ssh\|authd\)" 2>/dev/null >$l_tmp
  while read line; do
    # parse out the name
    l_modname=$(echo $line | sed -e "s#^\([^ \t]\+\).*#\1#")
    if [ $l_first -eq 1 ]; then
      echo -n '/var/run/inetd.conf: '
      l_first=0
    else
      echo -n ','
    fi
    echo -n "$l_modname"
    l_FIXED=3
  done < $l_tmp
  rm -fr $l_tmp
  if [ $l_first -eq 0 ]; then echo -n '...'; fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_000095_ESXI5
#
#######################################################################
# SRG-OS-000104-ESXI5
esxi_stig_SRG_OS_000104_ESXI5() {
  l_rulename="SRG-OS-000104-ESXI5"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # simple check
  l_tmp="/tmp/$$.$l_rulename"
  cat /etc/passwd | cut -f 3 -d ":" | sort | uniq -d > $l_tmp
  if [ -s $l_tmp ]; then
    echo -n "Duplicate UIDs detected..."
    l_FIXED=3
  fi
  rm -fr $l_tmp
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_000104_ESXI5
#
#######################################################################
# SRG-OS-000109-ESXI5
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "PermitRootLogin no" SRG-OS-000109-ESXI5
#
#######################################################################
# SRG-OS-000112-ESXI5
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "Protocol 2" SRG-OS-000112-ESXI5
#
#######################################################################
# SRG-OS-000113-ESXI5
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "Protocol 2" SRG-OS-000113-ESXI5
#
#######################################################################
# SRG-OS-000120-ESXI5
esxi_stig_SRG_OS_000120_ESXI5() {
  l_rulename="SRG-OS-000120-ESXI5"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # first check to see if sha512 already in use
  if grep "^password[ \t]\+sufficient[ \t]" /etc/pam.d/passwd | grep sha512 2>&1 >/dev/null; then
    # it's OK
    echo -n "Using sha512..."
  else
    # remove any others
    l_FIXED=1
    if cat /etc/pam.d/passwd | grep -e "\(^password[ \t]\+sufficient[ \t]\)\(.*\)\(md5\|des\|sha256\)\(.*\)" 2>&1 >/dev/null; then
      echo -n "Replacing with sha512..."
      cat /etc/pam.d/passwd | sed -e "s#\(^password[ \t]\+sufficient[ \t]\)\(.*\)\(md5\|des\|sha256\)\(.*\)#\1\2sha512\4#g" > /etc/pam.d/passwd-new
    else
      echo -n "Adding sha512..."
      cat /etc/pam.d/passwd | sed -e "s#\(^password[ \t]\+sufficient[ \t].*\)#\1 sha512#g" > /etc/pam.d/passwd-new
    fi
    esxi_stig_updateconfig /etc/pam.d/passwd
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_000120_ESXI5
#
#######################################################################
# SRG-OS-000121-ESXI5
esxi_stig_SRG_OS_000121_ESXI5() {
  l_rulename="SRG-OS-000121-ESXI5"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # simple check
  l_tmp="/tmp/$$.$l_rulename"
  cat /etc/passwd | cut -f 1 -d ":" | sort | uniq -d > $l_tmp
  if [ -s $l_tmp ]; then
    echo -n "Duplicate users detected..."
    l_FIXED=3
  fi
  rm -fr $l_tmp
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_000121_ESXI5
#
#######################################################################
# SRG-OS-000126-ESXI5
esxi_stig_SRG_OS_000126_ESXI5() {
  l_rulename="SRG-OS-000126-ESXI5"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # first get the current value
  l_fixme=0
  l_value=$(esxcli system settings advanced list -o /UserVars/ESXiShellTimeOut | grep "^[ \t]\+Int Value:" | sed -e "s#.*: \(.*\)#\1#")
  if [ ! -z "$l_value" ]; then
    if [ $l_value -lt 1 -o $l_value -gt 900 ]; then
      echo -n "Invalid shell timeout $l_value..."
      l_fixme=1
    fi
  else
    echo -n "Missing shell timeout..."
    l_fixme=1
  fi

  # fix if necessary. note that the STIG calls for a value of "15" but they
  # indicate this is *minutes*. the actual value is passed in *seconds* where
  # 900 seconds is 15 minutes.
  if [ $l_fixme -eq 1 ]; then
    esxcli system settings advanced set -o /UserVars/ESXiShellTimeOut -i 900
    l_FIXED=1
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_000126_ESXI5
#
#######################################################################
# SRG-OS-000157-ESXI5
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" SRG-OS-000157-ESXI5 ssh_config
#
#######################################################################
# SRG-OS-000158-ESXI5
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "Macs hmac-sha1" SRG-OS-000158-ESXI5 ssh_config
#######################################################################
# SRG-OS-000159-ESXI5
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" SRG-OS-000159-ESXI5 ssh_config
#
#######################################################################
# SRG-OS-000163-ESXI5
esxi_stig_SRG_OS_000163_ESXI5() {
  l_rulename="SRG-OS-000163-ESXI5"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  echo -n "already handled by SRG-OS-000126-ESXI5..."

  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_000163_ESXI5
#
#######################################################################
# SRG-OS-000193-ESXI5
esxi_stig_SRG_OS_000193_ESXI5() {
  l_rulename="SRG-OS-000193-ESXI5"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # first get the current value
  l_value=$(esxcli software acceptance get)
  if [ "$l_value" = "CommunitySupported" ]; then
    echo -n "Changing to PartnerSupported..."
    esxcli software acceptance set --level=PartnerSupported 2>&1 >/dev/null
    l_FIXED=1
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_000193_ESXI5
#
#######################################################################
# SRG-OS-000197-ESXI5
esxi_stig_SRG_OS_000197_ESXI5() {
  l_rulename="SRG-OS-000197-ESXI5"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # first get the current value
  l_value=$(esxcli system syslog config get | grep -i -e "Remote Host:" | sed -e "s#[^:]\+:\(.*\)#\1#" | sed -e "s#^[ \t]\+##")
  if [ "$l_value" = "" ]; then
    echo -n "Set a SYSLOG host..."
    l_FIXED=3
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_000197_ESXI5
#
#######################################################################
# SRG-OS-000215-ESXI5
esxi_stig_SRG_OS_000215_ESXI5() {
  l_rulename="SRG-OS-000215-ESXI5"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  echo -n "already handled by SRG-OS-000197-ESXI5..."

  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_000215_ESXI5
#
#######################################################################
# SRG-OS-000217-ESXI5
esxi_stig_SRG_OS_000217_ESXI5() {
  l_rulename="SRG-OS-000217-ESXI5"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  echo -n "already handled by SRG-OS-000197-ESXI5..."

  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_000217_ESXI5
#
#######################################################################
# SRG-OS-000248-ESXI5
esxi_stig_SRG_OS_000248_ESXI5() {
  l_rulename="SRG-OS-000248-ESXI5"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # check for /etc/hosts.equiv
  if [ -s /etc/hosts.equiv ]; then
    echo -n "Manually remove /etc/hosts.equiv..."
    l_FIXED=3
  fi

  # search for any .rhosts
  l_rhosts=$(find / | grep .rhosts)
  if [ ! -z "$l_rhosts" ]; then
    echo -n "Manually remove all .rhosts..."
    l_FIXED=3
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_000248_ESXI5
#
#######################################################################
# SRG-OS-000250-ESXI5
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_sshd_SimpleChange "Macs hmac-sha1" SRG-OS-000250-ESXI5
#
#######################################################################
# SRG-OS-000070-ESXI5
esxi_stig_SRG_OS_000266_ESXI5() {
  l_rulename="SRG-OS-000266-ESXI5"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  echo -n "already handled by SRG-OS-000069-ESXI5..."

  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_000266_ESXI5
#
#######################################################################
# SRG-OS-99999-ESXI5-000132
esxi_stig_SRG_OS_99999_ESXI5_000132() {
  l_rulename="SRG-OS-99999-ESXI5-000132"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # get value of /scratch
  l_value=$(ls -la /scratch | sed -e "s#\(.*/scratch -> \)\(.*\)#\2#")
  if [ "$l_value" = "/tmp/scratch" ]; then
    echo -n "/scratch must be non-local link..."
    l_FIXED=3
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_99999_ESXI5_000132
#
#######################################################################
# SRG-OS-99999-ESXI5-000137
esxi_stig_SRG_OS_99999_ESXI5_000137() {
  l_rulename="SRG-OS-99999-ESXI5-000137"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # get value of /scratch
  l_value=$(vim-cmd proxysvc/service_list | grep proxy-mob)
  if [ ! -z "$l_value" ]; then
    echo -n "Disabling MOB..."
    vim-cmd proxysvc/remove_service "/mob" "httpsWithRedirect" 2>&1 >/dev/null
    l_FIXED=1
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_99999_ESXI5_000137
#
#######################################################################
# SRG-OS-99999-ESXI5-000144
esxi_stig_SRG_OS_99999_ESXI5_000144() {
  l_rulename="SRG-OS-99999-ESXI5-000144"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # get value of /scratch
  l_value=$(esxcli system snmp get | grep -e "Enable: " | sed -e "s#\(Enable: \)\(.*\)#\2#" | sed -e "s#^[ \t]\+##")
  if [ "$l_value" = "true" ]; then
    echo -n "Disable SNMP..."
    l_FIXED=3
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_99999_ESXI5_000144
#
#######################################################################
# SRG-OS-99999-ESXI5-000152
esxi_stig_SRG_OS_99999_ESXI5_000152() {
  l_rulename="SRG-OS-99999-ESXI5-000152"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # check for authorized keys
  if [ -s /etc/ssh/keys-root/authorized_keys ]; then
    echo -n "Zero /etc/ssh/keys-root/authorized_keys..."
    l_FIXED=3
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_99999_ESXI5_000152
#
#######################################################################
# SRG-OS-99999-ESXI5-000158
esxi_stig_SRG_OS_99999_ESXI5_000158() {
  l_rulename="SRG-OS-99999-ESXI5-000158"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # read all modules (skip the first 2 lines)
  l_tmp="/tmp/$$.$l_rulename"
  esxcli system module list | tail -n +3 > $l_tmp
  #set -x
  while read line; do
    # parse out the name
    l_modname=$(echo $line | sed -e "s#^\([^ \t]\+\).*#\1#")
    if [ ! -z "$l_modname" ]; then
      # now look at the modul info to see if it is signed
      l_issigned=$(esxcli system module get -m $l_modname | grep -e "Signed Status: " | sed -e "s#\(.*Signed Status: \)\(.*\)#\2#")
      if [ ! "$l_issigned" = "VMware Signed" ]; then
        echo -n "$l_modname..."
        l_FIXED=3
      fi
    fi
  done < $l_tmp
  #set +x
  rm -fr $l_tmp
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_99999_ESXI5_000158
#
#######################################################################
# GEN000950-ESXI5-444
esxi_stig_GEN000950_ESXI5_444() {
  l_rulename="GEN000950-ESXI5-444"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # simple check
  if grep -e '^[ \t]*[^#]' /etc/vmware/config \
    | grep -e LD_PRELOAD >/dev/null 2>&1; then
    echo -n "remove LD_PRELOAD from /etc/vmware/config..."
    l_FIXED=3
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_GEN000950_ESXI5_444
#
#######################################################################
# GEN001375-ESXI5-000086
esxi_stig_GEN001375_ESXI5_000086() {
  l_rulename="GEN001375-ESXI5-000086"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # simple check
  l_tmp="/tmp/$$.$l_rulename"
  esxcli network ip dns server list | grep DNSServers | sed -e 's/.*DNSServers: \(.*\)/\1/' > $l_tmp
  if [ ! -s "$l_tmp" ]; then
    echo -n "DNSServers not set..."
    l_FIXED=3
  else
    l_check=$(cat $l_tmp | head -n 1)
    if ! echo $l_check \
      | grep -e '[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9], [0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+' \
      >/dev/null 2>&1; then
      echo -n "Must have 2 DNSServers ($l_check)..."
      l_FIXED=3
    fi
  fi
  rm -fr $l_tmp
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_GEN001375_ESXI5_000086
#
#######################################################################
# GEN000940-ESXI5-000042
esxi_stig_GEN000940_ESXI5_000042() {
  l_rulename="GEN000940-ESXI5-000042"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # simple check
  l_check=$(cat /etc/profile | grep -e '^[ \t]*[^#]' | grep -e '^[ \t]*PATH' | sed -e 's/.*PATH=\(.*\)/\1/')
  if [ ! $l_check = '/bin:/sbin' ]; then
    echo -n "set /etc/profile PATH to '/bin:sbin'..."
    l_FIXED=3
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_GEN000940_ESXI5_000042
#
#######################################################################
# GEN002120-ESXI5-000045
esxi_stig_GEN002120_ESXI5_000045() {
  l_rulename="GEN002120-ESXI5-000045"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # simple check
  if [ ! -s /etc/shells ]; then
    echo -n "/etc/shells must exist with non-zero size..."
    l_FIXED=3
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_GEN002120_ESXI5_000045
#
#######################################################################
# GEN002140-ESXI5-000046
esxi_stig_GEN002140_ESXI5_000046() {
  l_rulename="GEN002140-ESXI5-000046"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # read /etc/shells
  l_tmp="/tmp/$$.$l_rulename"
  cat /etc/shells > $l_tmp
  #set -x
  l_ctr=0
  l_dummy=0
  while read line; do
    l_ctr=$(add $l_ctr 1)
    case $line in
      /bin/ash) l_dummy=0 ;;
      /bin/sh) l_dummy=0 ;;
      *) 
        if [ $l_first -eq 1 ]; then
          echo -n '/etc/shells invalid shell: '
          l_first=0
        else
          echo -n ', '
        fi
        echo -n "line $l_ctr"
        l_FIXED=3
        ;;
    esac
  done < $l_tmp
  #set +x
  rm -fr $l_tmp
  if [ $l_first -ne 1 ]; then
    echo -n '...'
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_GEN002140_ESXI5_000046
#
#######################################################################
# GEN007840-ESXI5-000119
esxi_stig_GEN007840_ESXI5_000119() {
  l_rulename="GEN007840-ESXI5-000119"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # first get hostname
  l_tmp="/tmp/$$.$l_rulename"
  l_hostname=$(esxcli system hostname get | grep -e "Fully Qualified" 2>/dev/null | sed -e 's/.*Domain Name: \(.*\)/\1/')
  if [ -z "$l_hostname" ]; then
    echo -n "must set FQDN with domain..."
    l_FIXED=3
  else
    # now ping that hostname
    ping -c 1 $l_hostname 2>/dev/null > $l_tmp
    l_pingline=$(grep -i -e "64 bytes from " $l_tmp 2>/dev/null)
    if [ -z "$l_pingline" ]; then
      echo -n "ping $l_hostname failed..."
      l_FIXED=3
    else
      # get the IP address
      l_ipaddr=$(echo $l_pingline | sed -e 's/64 bytes from \([^:]\+\).*/\1/')
      if [ -z "$l_ipaddr" ]; then
        echo -n "Unable to get IP for $l_hostname..."
        l_FIXED=3
      else
        # relate to an interface
        l_int=$(esxcli network ip interface ipv4 get | grep -e $l_ipaddr 2>/dev/null)
        if [ -z "$l_int" ]; then
          echo -n "Unable to locate IPv4 interface for $l_hostname:$l_ipaddr..."
          l_FIXED=3
        else
          # get the 'Name' field #1 from the interface info
          l_vmkName=$(echo $l_int | sed -e 's/[ \t]\+/ /g' | cut -d ' ' -f 1)

          # get the 'Address Type' field #5 from the interface info
          l_addrtype=$(echo $l_int | sed -e 's/[ \t]\+/ /g' | cut -d ' ' -f 5)
          if [ "$l_addrtype" != "STATIC" ]; then
            echo -n "IPv4 '$l_vmkName' ($l_hostname:$l_ipaddr) must be STATIC..."
            l_FIXED=3
          fi
        fi
      fi
    fi
  fi
  rm -fr $l_tmp
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_GEN007840_ESXI5_000119
#
#######################################################################
# SRG-OS-99999-ESXI5-000131
esxi_stig_SRG_OS_99999_ESXI5_000131() {
  l_rulename="SRG-OS-99999-ESXI5-000131"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # simple check for at least one NTP time server
  if ! grep -e "^server ." /etc/ntp.conf 2>&1 >/dev/null; then
    echo -n "define an NTP server..."
    l_FIXED=3
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_99999_ESXI5_000131
#
#######################################################################
# services stuff
  # disable DCUI
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_service_setup "SRG-OS-99999-ESXI5-000135" 'DCUI' 0
  # disable ESXi shell
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_service_setup "SRG-OS-99999-ESXI5-000136" 'ESXShell' 0
  # disable SSH shell
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_service_setup "SRG-OS-99999-ESXI5-000138" 'SSH' 0
#
#######################################################################
# SRG-OS-99999-ESXI5-000154
esxi_stig_SRG_OS_99999_ESXI5_000154() {
  l_rulename="SRG-OS-99999-ESXI5-000154"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # is AD configured?
  if cat /etc/krb5.conf | grep -e default_realm >/dev/null 2>&1; then
    # check for any local users (UID of 1000 or higher)
    l_local_user=0
    while read line; do
      # parse out the user name and UID
      l_uname=$(echo $line | cut -d ':' -f 1)
      l_uid=$(echo $line | cut -d ':' -f 3)
      if [ "$l_uid" -ge "1000" ]; then
        l_local_user=1
      fi
    done < /etc/passwd
    if [ "$l_local_user" -eq "1" ]; then
      echo -n "AD in use; detected local users, remove them..."
      l_FIXED=3
    fi
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_99999_ESXI5_000154
#
#######################################################################
# SRG-OS-99999-ESXI5-000155
esxi_stig_SRG_OS_99999_ESXI5_000155() {
  l_rulename="SRG-OS-99999-ESXI5-000155"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # is AD configured?
  if cat /etc/krb5.conf | grep -e default_realm >/dev/null 2>&1; then
    # STIG has confusing wording about "local accounts". However, the
    # fixtext clearly indicates that if AD is used and "ESX Admins" group
    # is specified, this is the finding. check for use of "ESX Admins" group.
    l_esxAdminsGroupValue=$(vim-cmd hostsvc/advopt/view Config.HostAgent.plugins.hostsvc.esxAdminsGroup | grep -e "value = ")
    l_esxAdminsGroup=$(echo $l_esxAdminsGroupValue | sed -e 's/.* = "\([^"]*\).*/\1/')
    l_usesESX_Admins=$(echo $l_esxAdminsGroup | grep -i -e '^ESX Admins$')
    if [ ! -z "$l_usesESX_Admins" ]; then
      echo -n "AD in use; do not use 'ESX Admins'..."
      l_FIXED=3
    fi
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_99999_ESXI5_000155
#
#######################################################################
# SRG-OS-99999-ESXI5-000156
esxi_stig_SRG_OS_99999_ESXI5_000156() {
  l_rulename="SRG-OS-99999-ESXI5-000156"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # check for MOB...this is a bogus check and it is a problem that
  # vim-cmd doesn't permit a more exact match.
  if vim-cmd proxysvc/service_list | grep -e '"/mob"' >/dev/null 2>&1; then
    # best we can determine, MOB is enabled. disable it.
    echo -n "disabling /mob..."
    vim-cmd proxysvc/remove_service "/mob" "httpsWithRedirect" 2>&1 >/dev/null
    l_FIXED=1
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_99999_ESXI5_000156
#
#######################################################################
# VLAN checks
esxi_stig_VLAN_check() {
  l_rulename="$1"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0
  l_tmp="/tmp/$$.$l_rulename"

  # iterate over the VLAN ranges
  l_vlan_in="$2"
  l_vlan2_in="$3"
  shift; shift
  while [ "$l_vlan_in" != "" ]; do
    # get all of the portgroups - note wierdness for embedded spaces
    esxcli network vswitch standard portgroup list \
      | tail -n -2 \
      | sed -e 's/\(  \)\+/:/g' \
      | sed -e 's/: \+/:/g' > $l_tmp
    while read line; do
      # extract name (field 1) and VLAN ID (field 4)
      l_name=$(echo $line | cut -d ':' -f 1)
      l_vlan=$(echo $line | cut -d ':' -f 4)

      # check ranges
      l_bad=0
      if [ "$l_vlan" -ge "$l_vlan_in" -a "$l_vlan" -le "$l_vlan2_in" ]; then
        l_bad=1
      fi

      # handle error
      if [ "$l_bad" = "1" ]; then
        if [ "$l_first" -eq "1" ]; then
          echo -n "VLAN $l_vlan use: "
        else
          echo -n ','
        fi
        l_first=0
        echo -n "$l_name"
        l_FIXED=3
      fi
    done < $l_tmp

    # next set of VLAN values
    l_vlan_in="$2"
    l_vlan2_in="$3"
    shift; shift
  done
  rm -fr $l_tmp
  if [ "$l_first" -eq "0" ]; then
    echo -n '...'
  fi 
  esxi_stig_showresult ${l_FIXED}
}
esxi_stig_ESXI5_VMNET_000010() {
 esxi_stig_VLAN_check "ESXI5-VMNET-000010" "1" "1"
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_ESXI5_VMNET_000010
esxi_stig_ESXI5_VMNET_000011() {
 esxi_stig_VLAN_check "ESXI5-VMNET-000011" "4095" "4095"
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_ESXI5_VMNET_000011
esxi_stig_ESXI5_VMNET_000012() {
 esxi_stig_VLAN_check "ESXI5-VMNET-000012" "1001" "1024" "3968" "4047" "4094" "4094"
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_ESXI5_VMNET_000012
#######################################################################
# ESXCLI VSWITCH / PORTGROUP FUNCTIONS
#
# parse out value from passed esxcli name:value option
esxi_stig_esxcli_namevalue_get() {
  # get the name to extract
  l_name=$1
  shift

  # trim spaces from rest
  l_fixline=$(echo $* | sed -e 's/^[ \t]\+//')

  # check for the value
  if echo $l_fixline | grep -e "^$l_name: " 2>&1 >/dev/null; then
    # extract the value
    l_value=$(echo $l_fixline | sed -e "s/^$l_name: \(.*\)/\1/")
    echo $l_value
    return 0
  fi

  # nothing to do, empty string
  echo ""
  return 1
}
#
# get parsed vswitch of correct type (standard/dvs)
esxi_stig_esxcli_vswitch_get() {
  l_type_in=$1
  shift
  l_vswitch_value_in="$*"

  # is this vswitch the correct type?
  l_type=$(echo $l_vswitch_value_in | cut -d ':' -f 1)
  if [ "$l_type" = "$l_type_in" ]; then
    l_vswitch=$(echo $l_vswitch_value_in | cut -d ':' -f 2)
    echo $l_vswitch
    return 0
  fi
  return 1
}
#
# get security policy option within a vswitch (standard only)
esxi_stig_esxcli_vswitch_policy_security_get() {
  l_vswitch_in=$1
  l_policy_security_name_in=$2
  l_tmp_vswitch_policy_security_get="/tmp/$$.esxi_stig_esxcli_vswitch_policy_security_get"
  esxcli network vswitch standard policy security get -v $l_vswitch_in >$l_tmp_vswitch_policy_security_get
  l_rc=1
  while read line; do
    l_value=$(esxi_stig_esxcli_namevalue_get "$l_policy_security_name_in" $line)
    if [ $? -eq 0 ]; then
      echo "$l_value"
      l_rc=0
    fi
  done < $l_tmp_vswitch_policy_security_get
  rm -fr $l_tmp_vswitch_policy_security_get
  return $l_rc
}
#
# get list of all switches (standard and dvs)
esxi_stig_vswitch_get() {
  l_tmp_vswitch_get="/tmp/$$.esx_stig_vswitch_get"

  # read all standard switches
  echo "reading standard vswitch"
  esxcli network vswitch standard list 2>/dev/null >$l_tmp_vswitch_get
  while read line; do
    l_value=$(esxi_stig_esxcli_namevalue_get 'Name' $line)
    if [ $? -eq 0 ]; then
      echo "standard:$l_value"
    fi
  done < $l_tmp_vswitch_get

  # read all dvs switches
  echo "reading dvs vswitch"
  esxcli network vswitch dvs vmware list 2>/dev/null >$l_tmp_vswitch_get
  while read line; do
    l_value=$(esxi_stig_esxcli_namevalue_get 'Name' $line)
    if [ $? -eq 0 ]; then
      echo "dvs:$l_value"
    fi
  done < $l_tmp_vswitch_get
  rm -fr $l_tmp_vswitch_get
}
#
# parse portgroups with optional prefix
esxi_stig_parse_pgs() {
  l_prefix=$1
  l_value=$2
  l_ctr=0
  l_continue=1
  l_pgname_prev=""
  while [ $l_continue -eq 1 ]; do
    # next field
    l_ctr=$(add $l_ctr 1)
    l_pgname=$(echo $l_value | cut -d ',' -f $l_ctr)
    l_pgname_fixed=$(echo $l_pgname | sed -e 's/^[ \t]\+//')

    # anything left?
    if [ "$l_pgname_fixed" = "" ]; then
      # all done
      l_continue=0
    else
      # cut always returns the last parsable field...check!
      if [ "$l_pgname_prev" = "$l_pgname_fixed" ]; then
        # kinda lame...assume end of list
        l_continue=0
      else
        # write it out
        l_pgname_prev=$l_pgname_fixed
        echo "$l_prefix$l_pgname_fixed"
      fi
    fi
  done
  return 0
}
#
# iterate portgroups
esxi_stig_iter_pgs() {
  l_vswitch_type=$1

  l_curswitch=""
  while read line; do
    # read switch name
    l_value=$(esxi_stig_esxcli_namevalue_get 'Name' $line)
    if [ $? -eq 0 ]; then
      l_curswitch=$l_value
    fi

    # now portgroup
    l_value=$(esxi_stig_esxcli_namevalue_get 'Portgroups' $line)
    if [ $? -eq 0 ]; then
      # parse each portgroup name (comma-separated)
      esxi_stig_parse_pgs "$l_vswitch_type:$l_curswitch:" "$l_value"
    fi
  done
}
#
# get list of all portgroups (standard and dvs)
esxi_stig_pg_get() {
  l_tmp_pg_get="/tmp/$$.esxi_stig_pg_get"

  # read all standard switches
  esxcli network vswitch standard list 2>/dev/null >$l_tmp_pg_get
  esxi_stig_iter_pgs "standard" < $l_tmp_pg_get
  rm -fr $l_tmp
}
#
# utility function to check security policy settings
esxi_stig_vswitch_standard_secpol_check() {
  l_rulename=$1
  l_key=$2
  l_setarg=$3
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0
  
  l_tmp="/tmp/$$.$l_rulename"
  esxi_stig_vswitch_get >$l_tmp
  while read line; do
    # must be standard switch
    l_vswitch=$(esxi_stig_esxcli_vswitch_get "standard" $line)
    if [ $? -eq 0 ]; then
      # get details
      l_isSet=$(esxi_stig_esxcli_vswitch_policy_security_get $l_vswitch "$l_key")
      if [ "$l_isSet" = "true" ]; then
        if [ $l_first -eq 1 ]; then
          echo -n "$l_key: "
          l_first=0
        else
          echo -n ","
        fi
        echo -n "$l_vswitch"

        # fix the problem
        l_didSet=$(esxcli network vswitch standard policy security set -v $l_vswitch $l_setarg false)
        l_RC=$?
        #echo ";didset: '$l_didSet'"
        if [ $l_RC -eq 0 ]; then
          # fixed OK
          if [ $l_FIXED -eq 0 ]; then l_FIXED=1; fi
        else
          # unable to fix, do it manually
          l_FIXED=3
        fi
      fi
    fi
  done < $l_tmp
  rm -fr $l_tmp

  if [ $l_first -eq 0 ]; then
    echo -n "..."
  fi
  esxi_stig_showresult ${l_FIXED}
}
#
# ESXI5-VMNET-000013
esxi_stig_ESXI5_VMNET_000013() {
  esxi_stig_vswitch_standard_secpol_check 'ESXI5-VMNET-000013' 'Allow Forged Transmits' '--allow-forged-transmits'
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_ESXI5_VMNET_000013
#
# ESXI5-VMNET-000016
esxi_stig_ESXI5_VMNET_000016() {
  esxi_stig_vswitch_standard_secpol_check 'ESXI5-VMNET-000016' 'Allow MAC Address Change' '--allow-mac-change'
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_ESXI5_VMNET_000016
# ESXI5-VMNET-000018
esxi_stig_ESXI5_VMNET_000018() {
  esxi_stig_vswitch_standard_secpol_check 'ESXI5-VMNET-000018' 'Allow Promiscuous' '--allow-promiscuous'
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_ESXI5_VMNET_000018
#
#######################################################################
# GEN000945-ESXI5-000333
esxi_stig_GEN000945_ESXI5_000333() {
  l_rulename="GEN000945-ESXI5-000333"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # simple check
  l_libdir=$(grep -e '^[ \t]*[^#]' /etc/vmware/config | grep -e "^libdir" 2>/dev/null)
  if [ "$l_libdir" = "" ]; then
    echo -n "/etc/vmware/config: missing libdir..."
    l_FIXED=3
  else
    l_value=$(echo $l_libdir | sed -e 's/^[^=]\+= "\([^"]*\).*/\1/')
    if [ "$l_value" != "/usr/lib/vmware" ]; then
      echo -n "/etc/vmware/config: libdir is '$l_value'..."
      l_FIXED=3
    fi
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_GEN000945_ESXI5_000333
#
#######################################################################
# SRG-OS-000152-ESXI5
esxi_stig_SRG_OS_000152_ESXI5() {
  l_rulename="SRG-OS-000152-ESXI5"
  l_first=1
  echo -n "$l_rulename..."
  l_FIXED=0

  # list of known services and related firewall rules. the rules were
  # gotten by using:
  #   esxcli network firewall ruleset rule list \
  #     | grep Inbound | cut -d ' ' -f 1 | sort -u
  # each rule was associated with its given service. for the check, we
  # look at the service and only analyze the rule for IP access if the
  # service is *running* (regardless of startup type). this is per the
  # actual STIG checklist text.
  l_fwrules=""
  l_fwrules="sfcbd:CIMHttpServer"
  l_fwrules="$l_fwrules sfcbd:CIMHttpsServer"
  l_fwrules="$l_fwrules sfcbd:CIMSLP"
  # DHCPv6 - unknown correct settings; leave alone
  # DVFilter - unknown correct settings; leave alone
  # DVSSync - unknown correct settings; leave alone
  l_fwrules="$l_fwrules iked:IKED"
  # NFC - this is port 902 but that is also covered by vSphere Client
  # dhcp - unknown correct settings; leave alone
  # dns - unknown correct settings; leave alone
  # faultTolerance - unknown correct settings; leave alone
  # fdm - unknown correct settings; leave alone
  # ftpClient - unknown correct settings; leave alone
  # gdbserver - unknown correct settings; leave alone
  # remoteSerialPort - unknown correct settings; leave alone
  l_fwrules="$l_fwrules snmpd:snmp"
  l_fwrules="$l_fwrules SSH:sshServer"
  # vMotion - unknown correct settings; leave alone
  l_fwrules="$l_fwrules N/A:vSphereClient" # always check this one
  # vprobeServer - unknown correct settings; leave alone
  l_fwrules="$l_fwrules N/A:webAccess" # always check this one
  
  # iterate over the settings
  for i in $l_fwrules; do
    # parse out the service name and the firewall rule name
    l_svc=$(echo $i | cut -d ':' -f 1)
    l_fwrule=$(echo $i | cut -d ':' -f 2)

    # if service is 'N/A' then always process, otherwise check status
    l_process=0
    if [ "$l_svc" = "N/A" ]; then
      l_process=1
    else
      # check the service status (stopped/started...*not* chkconfig)
      l_svc_status=$(/etc/init.d/$l_svc status)
      if echo $l_svc_status | grep -e 'login enabled\|is started\|is running$' 2>&1 >/dev/null; then
        l_process=1
      fi
    fi

    # now we check the firewall rule
    if [ $l_process -eq 1 ]; then
      l_all_ips=$(esxcli network firewall ruleset allowedip list | grep -e $l_fwrule 2>/dev/null)
      if echo $l_all_ips | grep -e 'All[ \t]*$' 2>&1 >/dev/null; then
        # all IPs allowed, we have a problem
        if [ $l_first -eq 1 ]; then
          echo -n "Disable 'All IPs': "
          l_first=0
        else
          echo -n ','
        fi
        echo -n $l_fwrule
        l_FIXED=3
      fi
    fi
  done

  # show result
  if [ $l_first -eq 0 ]; then
    echo -n '...'
  fi
  esxi_stig_showresult ${l_FIXED}
}
[ "$ESXI_STIG_DEFINE_ONLY" = "" ] && esxi_stig_SRG_OS_000152_ESXI5

