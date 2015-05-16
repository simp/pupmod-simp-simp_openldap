#!/bin/sh

# By default, we should not bootstrap.
retval=1

# The main check to see if we should run.
/usr/sbin/slaptest -u -Q

if [ $? -eq 0 ]; then
  if [ `/bin/ls /var/lib/ldap/db* | /usr/bin/wc -l` -eq 0 ]; then
    retval=0
  else
    cat_out=`/sbin/runuser ldap -s /bin/sh --session-command /usr/sbin/slapcat`
    retval=$?
    if [ $retval -eq 0 ]; then
      if [ `/bin/echo $cat_out | /usr/bin/wc -l` -eq 0 ]; then
        retval=$?
      else
        retval=1
      fi
    fi
  fi
fi

# A secondary check to make sure that we don't blow away the replication
# settings for a configured slave system.

if [ $retval -eq 0 ]; then
  if [ -f /etc/openldap/slapd.conf ]; then
    /bin/grep -q syncrepl /etc/openldap/slapd.conf
    if [ $? -eq 0 ]; then
      retval=1
    fi
  fi

  if [ -f /etc/openldap/dynamic_includes ]; then
    /bin/grep -q syncrepl /etc/openldap/dynamic_includes
    if [ $? -eq 0 ]; then
      retval=1
    fi
  fi
fi

exit $retval
