#!/usr/bin/python

import subprocess
import basecore
from ipv6prefix import IPv6Prefix


class DhcpClient(object):
    """Class for controlling an ISC DHCP client in ProAct"""
    dhclient_binary = '/sbin/dhclient'
    STATE_PREFIX_DETACHED = 0
    STATE_PREFIX_ATTACHED = 1
    EVENT_DHCP_PREFIX_DETACHED = 0
    EVENT_DHCP_PREFIX_ATTACHED = 1
    
    def __init__(self, owner, devname, pidfilebase='/var/run'):
        self.state = self.STATE_PREFIX_DETACHED
        self.owner = owner
        self.devname = devname
        self.pidfilebase = pidfilebase
        self.pidfile = self.pidfilebase + '/dhclient6.' + self.devname + '.pid'
        self.old_prefixes = []
        self.new_prefixes = []
        try:
            with open(self.pidfile):
                self.killDhclientProcess() 
        except IOError:
            pass


    def __del__(self):
        self.release()
    
    
    def __str__(self, *args, **kwargs):
        s_prefixes = ''
        for prefix in self.new_prefixes:
            s_prefixes += str(prefix) + ' '
        return '<DhcpClient [' + self.devname + '] [state: ' + str(self.state) + '] ' + s_prefixes + ' ' + '>'


    def request(self):
        'call ISC dhclient with following parameters: /sbin/dhclient -v -6 -P -pf ${PIDFILE} ${IFACE}'
        try:
            dhclient_cmd = self.dhclient_binary + ' -q -P -1 -pf ' + self.pidfile + ' ' + self.devname
            print 'DHCP request: executing command => ' + str(dhclient_cmd.split())
            self.process = subprocess.Popen(dhclient_cmd.split(), shell=False, stdout=subprocess.PIPE)
            rc = self.process.communicate()
            
            self.old_prefixes = []
            self.new_prefixes = []
        
            do_bind = False
            
            for line in rc[0].split('\n'):
                try:                    
                    (self.type, self.reason, old_prefix, new_prefix) = line.split()
                    s_old_prefix = IPv6Prefix(old_prefix.split('=')[1].split('/')[0], old_prefix.split('=')[1].split('/')[1])
                    s_new_prefix = IPv6Prefix(new_prefix.split('=')[1].split('/')[0], new_prefix.split('=')[1].split('/')[1])
                    if not s_old_prefix in self.old_prefixes:
                        self.old_prefixes.append(s_old_prefix)
                    if not s_new_prefix in self.new_prefixes:
                        self.new_prefixes.append(s_new_prefix)
                    print 'DHCP request received: ' + str(self)
                    if self.reason == 'BOUND6' or self.reason == 'REBIND6':
                        do_bind = True
                except ValueError:
                    pass
                except IndexError:
                    pass
                        
            if do_bind:
                self.state = self.STATE_PREFIX_ATTACHED
                self.owner.addEvent(basecore.BaseCoreEvent(self, self.EVENT_DHCP_PREFIX_ATTACHED))
            
        except ValueError, e:
            print 'unable to acquire prefixes ' + str(self)
        
        
    
    def release(self):
        print "sending DHCP release: " + str(self)
        try:
            dhclient_cmd = self.dhclient_binary + ' -q -N -r -pf ' + self.pidfile + ' ' + self.devname
            print 'DHCP release: executing command => ' + str(dhclient_cmd.split())
            process = subprocess.Popen(dhclient_cmd.split(), shell=False, stdout=subprocess.PIPE)
            rc = process.communicate()
            if process.returncode == 0:
                self.state = self.STATE_PREFIX_DETACHED
                self.owner.addEvent(basecore.BaseCoreEvent(self, self.EVENT_DHCP_PREFIX_DETACHED))
        except:
            print 'unable to release prefixes ' + str(self)
        

    def killDhclientProcess(self):
        """destroy any running dhclient process associated with this object"""
        f = open(self.pidfile)
        kill_cmd = 'kill -INT ' + f.readline()
        #print "kill-cmd: " + kill_cmd
        subprocess.call(kill_cmd.split())
        #if os.path.exists(self.pidfile):
        #    os.unlink(self.pidfile)
        return True
        
        
    def is_PREFIX_attached(self):
        if self.state == self.STATE_PREFIX_ATTACHED:
            return True
        else:
            return False



if __name__ == "__main__":
    pass

    
