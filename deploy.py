#!/usr/bin/env python

import requests
import logging
import argparse
from fabric.api import env, run, settings, warn_only, cd, put, path
from fabric.colors import blue, green, red, yellow
import yaml
import pprint
import sys
import os
import time


class ServerDeploy(object):
    """
    I chose to use a class because we're sharing a lot of information between methods, and this could morph into an
    interactive curses-like utility, so starting from a class-based system seemed reasonable.
    """

    def __init__(self):
        """
        The __init__ method in a class sets up the basic tooling we need. We create a couple empty arrays (dictionaries)
        and setup our argument parsing, logging, and finally parse and load a configuration file.
        """
        self.cfg = {}  # set up empty dict for username/password/url cfg
        self.deploycfg = {}  # st up empty dict for deployfile config
        self.serverlist = {}
        self.setup_argparse()
        self.setup_logging()
        self.setupcfg()


    """
    The following methods are for 'setup' - they configure our basic tooling for the script to function
    """

    def setup_argparse(self):
        """
        This method is ran in the __init__ for the class (visible directly above this method, in fact) and parses
        all the CLI arguments, creating an array (dictionary) of all the args. If the len()[gth] of the  args is less
        than 1 then we'll print out the help() (built in function to argparse) to display the options.
        NOTE: some of the actions are 'store_true' - this just sets a boolean True/False for that argument.
        The 'store' actions are what store/use actual values.
        :return: self.args argparse object
        """
        parser = argparse.ArgumentParser(description='command line flags for interacting with servers in Singlehop '
                                                     'The available options are below, note that you can also create '
                                                     'a configuration file with the singlehop username/password/url'
                                                     'so you dont have to pass them in here',
                                         epilog='you can hit https://<atlassian_URL> for more info') #TODO: enter url
        # arguments that store boolean values (aka True/False flags)
        parser.add_argument('--list-servers', help='list servers in singlehop account', action='store_true',
                            required=False)
        parser.add_argument('--search-server', help='search for a server in singlehop - this doesnt support anything '
                                                    'fancy, just a partial hostname', required=False)
        parser.add_argument('--download-server-list', action='store_true',
                            help='creates a yaml file in currdir with a list of servers in singlehop', required=False)
        parser.add_argument('--get-server-password', help='get the singlehop root password for a server. requires -pin '
                                                          'and -serverid', action='store_true', required=False)
        parser.add_argument('--get-server-ip', help='get the public IP for this server - requires '
                                                    '-serverid', action='store_true', required=False)
        parser.add_argument('--get-server-disks', help='get the disks for this server - requires '
                                                    '-serverid', action='store_true', required=False)

        parser.add_argument('--get-server-info', help='get the basic info for this server - requires '
                                                    '-serverid', action='store_true', required=False)
        parser.add_argument('--deploy-server', help='deploy OS to a server, including formatting disks - requires '
                                                      '-serverid and -deployfile', action='store', required=False)
        parser.add_argument('--deploy-servers', metavar='server1, or even: server1 server2 serverN', type=str, nargs='+',
                            help='one or more servernames to deploy to')
        # arguments that pass in a value
        parser.add_argument('-serverid', help='singlehop serverid', action='store', required=False)
        parser.add_argument('-deployfile', help='append path to yaml deployfile', action='store', required=False)
        parser.add_argument('-debug', help='debug logs!', action='store_true', required=False)
        parser.add_argument('-raw', help='raw output for building text files', action='store_true', required=False)

        self.args = parser.parse_args()
        if len(sys.argv) <= 1:
            parser.print_help()

    def setupcfg(self):
        """
        We can load our configuration from a config.yaml or pass it in using arguments, setupcfg will attempt to
        set configuration, initially from args, and if they're not set, a config.yaml file in the current dir.
        NOTE: we could put the config.yaml in a home dir, or in /etc/somewhere if we so chose, and would need to
        edit this method to enable setting a config file path.
        :return:
        """
        if os.path.isfile('config.yaml'):
            with open('config.yaml', 'r') as fh:
                self.cfg = yaml.safe_load(fh)
            logging.debug('loaded config file from config.yaml')
        else:
            if len(sys.argv) > 1:
                logging.error(red('No config.yaml exists, please make a config file as shown in the README.md\n'))
            sys.exit(1)

    def setup_logging(self):
        """
        set up logging - very basic, no frills - a step up from print()
        #TODO: add a --log handler to log to a file
        :return:
        """
        facilityname = "deploy-app" # enter your custom name here if wanted
        log = logging.getLogger(facilityname)
        if self.args.debug:
            handler = logging.basicConfig(level=logging.DEBUG,
                                          format='%(asctime)s [%(levelname)s] %(message)-20s',
                                          datefmt='%Y-%m-%d %H:%M:%S')
        else:
            handler = logging.basicConfig(level=logging.INFO,
                                          format='%(asctime)s [%(levelname)s] %(message)-20s',
                                          datefmt='%Y-%m-%d %H:%M:%S')
        logging.StreamHandler(sys.stdout)
        log.addHandler(handler)


    """
    The following methods are for interacting with the API, and gathering information about the servers
    """

    def leap3api(self, method='get', endpoint=None, data=None):
        """
        The purpose of this is to interact with leap3 API endpoint
        You have to pass in the relevant endpoint, and, optionally if its
        a post vs get (we default to get)
        :param method: what method is used? GET or POST
        :param endpoint: what endpoint is hit? http://dropzonewiki.singlehop.com/index.php?title=Server
        :param data: what data is sent? For example, the POST to get the server root password requires a pin to be sent
        :return: json data from the leap3 api endpoint
        """
        if method == 'get':
            try:
                output = requests.get(self.cfg['sh']['url'] + endpoint,
                                      auth=(self.cfg['sh']['username'], self.cfg['sh']['password']))
                if output.status_code == 200:
                    return output.json()['data']
                else:
                    logging.error('unable to get data from URL err: {} {}'.format(output.status_code, output.text))
            except Exception as e:
                logging.error(red('exception getting data from singlehop error related to: {}'.format(e, exc_info=1)))
        elif method == 'post':
            try:
                output = requests.post(self.cfg['sh']['url'] + endpoint, data=data,
                                       auth=(self.cfg['sh']['username'], self.cfg['sh']['password']))
                if output.status_code == 200:
                    if output.json()['data']:
                        return output.json()['data']
                    else:
                        return output.content
                else:
                    logging.error('unable to get data from URL err: {} {}'.format(output.status_code, output.text))
                    sys.exit(1)
            except Exception as e:
                logging.error(red('exception posting data to singlehop error related to: {} \n {}'.format(e, output.content, exc_info=1)))
        else:
            logging.error("must specify a method")

    def downloadserverlist(self):
        """
        This method will create a 'serverlist.yaml' with a list of all the singlehop servers in the account, with
        some basic information about those servers
        :return:
        """
        serverlist = {}
        raw = self.leap3api(method='get', endpoint='/server/list')
        for k, v in raw.items():
            serverlist[k] = v
        with open('serverlist.yaml', 'w') as fh2:
            fh2.write(yaml.dump(serverlist, default_flow_style=False))
        logging.debug('updated serverlist.yaml to latest data from singlehop')

    def _getserverlist(self):
        """
        This is a built-in ("private) method that just gets a list of servers from singlehop and returns them as a json
        object. Not to be directly consumed, but useful for chaining information to other methods
        :return: json list of servers from singlehop
        """
        hosts = {}
        raw = self.leap3api(method='get', endpoint='/server/list')
        for k, v in raw.items():
            hosts[v['hostname']] = {
                'id': k,
                'ip': v.get('publicip', '')
            }
        return hosts

    def listservers(self):
        """
        Print a full list of the servers in singlehop to stdout, sorted and justified for ease of reading
        :return: stdout printout of servers and their ID's from singlehop
        """
        hosts = self._getserverlist()
        logging.info(green("below are the servers and singlehop server id's: \n"))
        for host in sorted(hosts):
            # the :<30 here pads the printout so it looks better on screen
            logging.info("{0:<30} serverid: {1}".format(host, hosts[host]['id']))

    def searchserver(self, searchterm=None, internal=False):
        """
        This takes a list of hosts and executes a (very fuzzy) search on them, and returns any matching servers,
        server ID and server IP
        PLUS: rampant dictionary comprehensions, because who needs to understand this code in a few months?
        (Kidding, I hope its fairly obvious what its doing. If not, yell at me)
        :return:
        """
        try:
            hosts = self._getserverlist()
            hostlist = {x: {'id': hosts[x]['id'], 'ip': hosts[x]['ip'], 'searchterm': searchterm} for x in sorted(hosts) if searchterm in x}
            if internal:
                return hostlist  # we just wanna search and use the hosts to deploy
            else:
                if len(hostlist) > 0:
                    if self.args.raw:
                        logging.info(yellow("found {number} matching server(s)!".format(number=len(hostlist))))
                        logging.info(red("\n{h}, {i}, {d}".format(h="Hostname", i="IP", d="ID")))
                        for server in sorted(hostlist.items()):  # sort them so they're in numerical order
                            print(green("{host}, {ip}, {id}".format(host=server[0], ip=server[1]['ip'], id=server[1]['id'])))
                    else:
                        logging.info(yellow("found {number} matching server(s)! NOTE: you can Use the -raw flag to get CSV for script building".format(number=len(hostlist))))
                        logging.info(red("{h:<30} {i:<25} {d}".format(h="Hostname", i="IP", d="ID")))
                        for server in sorted(hostlist.items()):  # sort them so they're in numerical order
                            logging.info(green("{host:<30} {ip:<25} {id}".format(host=server[0], ip=server[1]['ip'], id=server[1]['id'])))
                else:
                    logging.error(red("Couldn't find any matching servers, sorry!"))
        except Exception as e:
            logging.error('Somehow I threw an exception? Don\'t use special characters please bad server: {}'.format(server), e)

    def getserverdisks(self, serverid=None):
        """
        This method gets a list of the disks on the server (only 'real' disks, not partitions) and returns them
        as a json array/dictionary. serverid is required.
        :param serverid:
        :return:
        """
        disks = {}
        if not serverid:
            logging.warning(red("need to set serverid for me to find the server"))
            sys.exit(1)
        if self.cfg.get('sh').get('pin'):
            pin = self.cfg['sh']['pin']
        else:
            logging.warning(red("need to set a pin in the cfg file"))
            sys.exit(1)
        status = self.getserverstatus(serverid=serverid)
        if status == 'rescue':
            ssh_password = self.getserverpassword(serverid=serverid, pin=pin)
        elif status == 'online':
            ssh_password = self.cfg.get('ssh_password', self.getserverpassword(serverid=serverid, pin=pin))
        hostip = self.getserverip(serverid=serverid)
        try:
            with settings(host_string=hostip, user="root", password=ssh_password, no_agent=True, no_keys=True):
                output = run('lsblk -n -d -r -io KNAME,TYPE,ROTA,SIZE')
            for line in output.splitlines():
                raw = line.rstrip().split()
                disks[raw[0]] = {
                    'disk': raw[0],
                    'type': raw[1],
                    'rotation': raw[2],
                    'size': raw[3]
                }
            return disks
        except Exception as e:
            logging.warning('unable to get server disks! {}'.format(e, exc_info=1))

    def getnetworks(self, serverid=None):
        """
        This method gets the 5 public IP's, and 1 private IP associated with this serverID and returns them
        like this:
        { 'public': {'allips': ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5'], 'nm': '255.255.255.0',
        'gw': '6.6.6.6'}, 'private': {'ip': '1.2.3.4', 'nm': 255.255.255.0, 'gw': '5.6.7.8' }
        :param serverid:
        :return:  JSON blob of network info
        """
        networks = {}
        raw = self.leap3api(method='get', endpoint='/server/network/{}'.format(serverid))
        networks['public'] = {
            'ip': raw['public'][0]['firstip'],
            'allips': raw['public'][0]['allips'],
            'gw': raw['public'][0]['gateway'],
            'nm': raw['public'][0]['netmask']
        }
        networks['private'] = {
            'ip': raw['private_networks'][0]['ip'],
            'gw': raw['private_networks'][0]['gateway'],
            'nm': raw['private_networks'][0]['netmask']
        }
        return networks

    def getserverinfo(self, serverid=None):
        """
        This method allows you to get full info from a singlehop server, given its serverid
        :param serverid:
        :return: json data structure on server information
        """
        raw = self.leap3api(method='get', endpoint='/server/view/{}'.format(serverid))
        return raw

    def getserverstatus(self, serverid=None):
        raw = self.leap3api(method='get', endpoint='/server/view/{}'.format(serverid))
        return raw['status']


    def getserverip(self, serverid=None):
        raw = self.leap3api(method='get', endpoint='/server/view/{}'.format(serverid))
        ip = raw['primaryip']
        return ip

    def getserverpassword(self, serverid=None, pin=None):
        if serverid:
            if pin:
                sh_pin = {'pin': pin}
                return self.leap3api(method='post', endpoint='/server/getpassword/{id}'.format(id=serverid), data=sh_pin)
            else:
                logging.error('you have to have a pin set to use this!')
        else:
            logging.error("you have to set serverid to use this!")

    def enterrecoverymode(self, serverid=None, pin=None):
        """
        This method will hit the endpoint to enter recovery mode
        :param serverid:
        :return:
        """
        if pin:
            sh_pin = {'pin': pin}
            return self.leap3api(method='post', endpoint='/server/bailout/start/{id}'.format(id=serverid), data=sh_pin)
        else:
            logging.error("you have to set serverid to use this!")

    def exitrecoverymode(self, serverid=None, pin=None):
        """
        This method will hit the endpoint to exit recovery mode and reboot into normal mode
        :param serverid:
        :return:
        """
        if pin:
            sh_pin = {'pin': pin}
            return self.leap3api(method='post', endpoint='/server/bailout/stop/{id}'.format(id=serverid), data=sh_pin)
        else:
            logging.error("you have to set serverid to use this!")


    """
    The following methods actually 'do' the work. I've tried to ensure they're as explicit as possible to make it 
    obvious what is going on in each. They're roughly in the right order, and its the  'deployserver()' method 
    near the bottom that actually calls each method in a mostly Object Oriented pattern.
    """


    def partitiondisks(self, serverid=None, disks=None):
        """
        This method will format disks based on the yaml config we pass in
        :param serverid:
        :return:
        """
        # First, ensure this server is in rescue mode, bail if it isn't (we can add a flag to reboot to recovery)
        if self.getserverstatus(serverid=serverid) == 'rescue':
            if len(disks['osraid']) == 2:
                with warn_only():  # only want to warn on this, as they may not exist (for example, new disks)
                    # warn_only() is a fabric method that tells it not to exit 1 on failures.
                    # first warm up mdadm so the next 2 correctly find and remove the boot/root md's
                    run('mdadm --detail --scan')
                    # identify the correct name of the md, we're making -bootmd and -rootmd, then stop them
                    run('mdadm --stop --force `mdadm --detail --scan | grep \'bootmd\' | awk \'{printstatement}\'`'.format(printstatement='{print $2}'))
                    run('mdadm --stop --force `mdadm --detail --scan | grep \'rootmd\' | awk \'{printstatement}\'`'.format(printstatement='{print $2}'))
                    # then zero the superblock on the disks - could probably for loop this, but its more obvious this way
                    run('mdadm --zero-superblock /dev/{disk}1'.format(disk=disks['osraid'][0]))
                    run('mdadm --zero-superblock /dev/{disk}1'.format(disk=disks['osraid'][1]))
                    run('mdadm --zero-superblock /dev/{disk}2'.format(disk=disks['osraid'][0]))
                    run('mdadm --zero-superblock /dev/{disk}2'.format(disk=disks['osraid'][1]))
                # blow away any existing partition tables
                run('dd if=/dev/zero of=/dev/{disk} bs=1M count=1000'.format(disk=disks['osraid'][0]))
                run('dd if=/dev/zero of=/dev/{disk} bs=1M count=1000'.format(disk=disks['osraid'][1]))
                # also blow away sd{a,b}2 partition header
                run('dd if=/dev/zero of=/dev/{disk} bs=1M count=1000 skip=1023'.format(disk=disks['osraid'][0]))
                run('dd if=/dev/zero of=/dev/{disk} bs=1M count=1000 skip=1023'.format(disk=disks['osraid'][1]))
                # finally create the partitions
                run(' parted --script /dev/{disk} mklabel msdos mkpart primary 1MiB 2000MiB mkpart primary 2001MiB -- -1 set 1 boot on set 2 raid on'.format(disk=disks['osraid'][0]))
                run(' parted --script /dev/{disk} mklabel msdos mkpart primary 1MiB 2000MiB mkpart primary 2001MiB -- -1 set 1 boot on set 2 raid on'.format(disk=disks['osraid'][1]))
            else:
                logging.error("incorrect number of disks assigned to osraid, please double check your deployfile")
                sys.exit(1)
        else:
            logging.error(red("server doesn't appear to be in recovery mode, bailing"))
            sys.exit(1)

    def raiddisks(self, disks=None, hostname=None):
        """
        This method will create an MDADM raid based on the disks specified in the deployfile
        :param disks:
        :return:
        """
        # create the /boot raid (md0)
        run('mdadm -C /dev/md0 -R -v --name={hostname}-bootmd -l 1 -n 2 /dev/{disk0}1 /dev/{disk1}1'.format(
            disk0=disks['osraid'][0], disk1=disks['osraid'][1], hostname=hostname))
        # create the / raid (md1)
        run('mdadm -C /dev/md1 -R -v --name={hostname}-rootmd -l 1 -n 2 /dev/{disk0}2 /dev/{disk1}2'.format(
            disk0=disks['osraid'][0], disk1=disks['osraid'][1], hostname=hostname))
        
    def encryptdisks(self, raid_name=None, disks=None):
        """
        this method will encrypt the disks with the passphrase set in the config file
        :return:
        """
        run('echo -n \'{passphrase}\' | cryptsetup --cipher aes-xts-plain64 --key-size 256 --hash sha256 --iter-time 2000 --use-urandom luksFormat /dev/{root_raid} -'.format(passphrase=disks['passphrase'], root_raid=raid_name))

    def unlockluks(self, disks=None):
        """
        This method will pass in the passphrase set in the disks section of the deploy file to unlock the LUKS container
        created in the encryptdisks() method
        :param disks:
        :return:
        """
        run('echo -n \'{passphrase}\' | cryptsetup luksOpen /dev/md1 cryptroot -'.format(passphrase=disks['passphrase']))

    def lvmdisks(self, disks=None):
        """
        This method will create a volgroup on cryptroot (the unlocked luks volume) and then create 2 LVM containers:
        Swap based on swap size set in the deploy file, and root for the rest of the size
        :param disks:
        :return:
        """
        run('pvcreate /dev/mapper/cryptroot && vgcreate OS /dev/mapper/cryptroot')
        run('lvcreate -n SWAP -L {swapsize} OS'.format(swapsize=disks['swapsize']))
        run('lvcreate -n ROOT -l 95%FREE OS')

    def formatdisks(self):
        """
        This method will format the lvm disks we created
        :return:
        """
        run('mkfs.ext4 /dev/md0')
        run('mkswap /dev/mapper/OS-SWAP')
        run('mkfs.ext4 /dev/mapper/OS-ROOT')

    def mountdisks(self):
        """
        This method will mount the disks we've formatted
        :return:
        """
        run('swapon /dev/mapper/OS-SWAP')
        run('mount /dev/mapper/OS-ROOT /mnt')
        run('mkdir /mnt/boot')
        run('mount /dev/md0 /mnt/boot')

    def pushrootfs(self):
        """
        This method will push the root archive and extract it
        :return:
        """
        osversion = self.deploycfg['osversion']
        put('./{}'.format(osversion), '/mnt/')
        with cd(env.chroot):
            checksum = run('md5sum {} | awk \'{printmsg}\' '.format(osversion, printmsg='{print $1}'))
            if checksum == self.deploycfg['checksum']:
                logging.debug(green('checksum matches! Extracting'))
                run('tar -zxpf {}'.format(osversion))
            else:
                logging.error(red('MD5SUM did not match on root tarball! Please try again'))
                sys.exit(1)

    def dropbearsetup(self):
        """
        This method will setup and install the dropbear SSH daemon for remote LUKS unlock
        :return:
        """
        gw = run('route -n | grep \'UG[ \t]\' | awk \'{print_sub}\''.format(print_sub='{print $2}'))  # silly, the $2 gets evaluated so we have to str fmt it
        nm = run('route -n | grep \'U[ \t]\' | grep \'eth0\' | awk \'{print_sub}\''.format(print_sub='{print $3}'))
        run('echo "export IP={ip_addr}::{gw_addr}:{subnet}:{hostname}:eth0:off" > /mnt/etc/initramfs-tools/conf.d/network_tools'.format(
            ip_addr=self.deploycfg['networks']['public']['ip'], gw_addr=gw, subnet=nm, hostname=self.deploycfg['hostname']))
        run('mkdir -p /mnt/etc/initramfs-tools/root/.ssh')
        run('cp /mnt/home/rewt/.ssh/authorized_keys /mnt/etc/initramfs-tools/root/.ssh/authorized_keys')
        run(('cat << EOF > /mnt/etc/initramfs-tools/hooks/mount_cryptroot \n'
            '#!/bin/sh \n'
            '# This script generates the /root/mount_cryptroot.sh script that expects the unlock passphrase to stdin \n'
            '# so you\'ll want to run "./mount_cryptroot.sh unlockpassphrase" \n'
            'if [ -z ${DESTDIR} ]; then \n'
            '    exit \n'
            'fi \n'
            'SCRIPT="${DESTDIR}/root/mount_cryptroot.sh" \n'
            'cat > "${SCRIPT}" << \'EOF\' \n'
            'while [ -n "`pidof askpass plymouth`" ]; do \n'
            '  echo -n $1 | /sbin/cryptsetup -T 1 --allow-discards luksOpen /dev/md1 cryptroot && kill -9 `pidof askpass plymouth` && echo "Success" || echo "Failed! Please try unlocking manually" \n'
            'done \n'
            'EOF \n'
            'chmod +x "${SCRIPT}" \n'))

    def networksetup(self, networks=None):
        """
        This method creates the /etc/network/interfaces file - right now we only do eth0
        string formatting is /fun/
        :return:
        """
        run(('cat << EOF > /mnt/etc/network/interfaces \n'
             '# The loopback network interface \n'
             'auto lo \n'
             'iface lo inet loopback \n'
             '\n'
             '# The primary network interface \n'
             'auto eth0 \n'
             'iface eth0 inet static \n'
             '    address {pub_addr} \n'
             '    gateway {pub_gw} \n'
             '    netmask {pub_nm}      \n'
             '        pre-up ip addr flush dev eth0 \n'
             '\n'
             '# if we need to add IPs to eth0, here is an example block: \n'
             '#auto eth0:0 \n'
             '#iface eth0:0 inet static \n'
             '#        address 1.2.3.4 \n'
             '#        netmask 255.255.255.248 \n'
             '\n'
             'auto eth1 \n'
             'iface eth1 inet static \n'
             '        address {priv_addr} \n'
             '        netmask {priv_netmask} \n'
             '        up route add -net 10.0.0.0 netmask 255.0.0.0 gw {priv_gw} dev eth1 \n'
             '	      up ethtool -s eth1 speed 100 duplex full autoneg on \n'
             '        down route del -net 10.0.0.0 netmask 255.0.0.0 gw {priv_gw} dev eth1 \n'
             ).format(pub_addr=networks['public']['ip'], pub_gw=networks['public']['gw'],
                      pub_nm=networks['public']['nm'], priv_addr=networks['private']['ip'],
                      priv_gw=networks['private']['gw'], priv_netmask=networks['private']['nm']))
        # setup resolv.conf too
        run(('cat << EOF > /mnt/etc/resolv.conf \n'
             '# initial resolv.conf, salt will override \n'
             '\n'
             'nameserver 8.8.8.8 \n'
             ))

    def networkudevrules(self):
        """
        This method sets up /etc/udev/rules.d/70-persistent-net so we ensure our eth0/1 devices are the same
        :return:
        """
        eth0_mac = run('ip link show eth0 | grep ether | awk \'{print_sub}\''.format(print_sub='{print $2}'))
        eth1_mac = run('ip link show eth1 | grep ether | awk \'{print_sub}\''.format(print_sub='{print $2}'))
        run((
            'cat << EOF > /mnt/etc/udev/rules.d/70-persistent-net.rules \n'
            'SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", ATTR{address}=="{eth0_mac}", ATTR{dev_id}=="0x0", ATTR{type}=="1", KERNEL=="eth*", NAME="eth0" \n'
            '\n'
            'SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", ATTR{address}=="{eth1_mac}", ATTR{dev_id}=="0x0", ATTR{type}=="1", KERNEL=="eth*", NAME="eth1" \n'
            '\n'
            .format(eth0_mac=eth0_mac, eth1_mac=eth1_mac, address='{address}', type='{type}', dev_id='{dev_id}')
        ))
        run('echo "export NEED_PERSISTENT_NET=yes" > /mnt/etc/initramfs-tools/conf.d/persistent_net_setup')

    def raidresyncspeed(self):
        """
        Maybe pull this out? But we need to set the re-sync speed...
        :return:
        """
        run('\n'
            'cat << EOF >> /mnt/etc/sysctl.conf\n'
            'dev.raid.speed_limit_min = 1000\n'
            'dev.raid.speed_limit_max = 20000\n'
            )

    def preparechroot(self):
        """
        Mount required filesystems for chroot'ing
        :return:
        """
        run('for i in /sys /proc /run /dev; do mkdir -p "/mnt$i"; done')
        run('for i in /sys /proc /run /dev; do mount --bind "$i" "/mnt$i"; done')

    def _exec_with_chroot(self, command):
        """
        This command enables us to just run a command in the chroot without doing run('chroot /mnt su blah...)
        but its not quite working 'right' for some commands (need to figure out why...)
        :param command:
        :return:
        """
        run('chroot "%s" %s' % (env.chroot, command))

    def chrootconfig(self):
        """
        These commands will execute from within the chrooted fs
        :return:
        """
        self.networkudevrules()
        self.networksetup(networks=self.deploycfg['networks'])
        run('echo {hostname} > /mnt/etc/hostname'.format(hostname=self.deploycfg['hostname']))
        run('echo "cryptroot $(blkid | grep \'crypto_LUKS\' | awk \'{print $2}\' | tr -d \'"\') none luks,discard" > /mnt/etc/crypttab')
        run('echo "/dev/md0 /boot ext4 defaults 0 1" > /mnt/etc/fstab')
        run('echo "/dev/mapper/OS-ROOT / ext4 noatime,errors=remount-ro 0 1" >> /mnt/etc/fstab')
        run('echo "/dev/mapper/OS-SWAP none swap defaults 0 0 " >> /mnt/etc/fstab')
        run('echo \'GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"\' >> /mnt/etc/default/grub')
        run('echo \'test -f /etc/ssh/ssh_host_dsa_key || dpkg-reconfigure openssh-server\' >> /mnt/etc/rc.local')
        run('mdadm --detail --scan >> /mnt/etc/mdadm/mdadm.conf')
        run('chroot /mnt su - root -c "grub-install --recheck --modules=\'lvm\' /dev/sda"')
        run('chroot /mnt su - root -c "grub-install --recheck --modules=\'lvm\' /dev/sdb"')
        run('echo {hostname} > /mnt/etc/salt/minion_id'.format(hostname=self.deploycfg['hostname']))
        run('chroot /mnt su - root -c "userdel -r rewt"')
        run('chroot /mnt su - root -c "update-grub"')
        run('chroot /mnt su - root -c "update-initramfs -u -k all"')

    def rebootserver(self):
        """
        Unmount disks and reboot server into new OS!
        :return:
        """
        run('rm -rf /mnt/*.tar.gz')
        run('for i in /sys /proc /run /dev; do umount -l "/mnt$i"; done')
        run('sync')
        run('reboot')

    def deploy(self, *args, **kwargs):
        """
        Deploy wrapper. If multiple hosts are specified, check for deployfiles + match serverID's and prompt for 'OK'
        before running. We'll do sequence first, maybe later thread and parallel.
        :param args:
        :param kwargs:
        :return:
        """
        hosts = {}
        for hn in args[0]:
            hosts[hn] = self.searchserver(searchterm=hn, internal=True)
        for host in hosts.values():
            if len(host.keys()) > 1:
                logging.error(yellow("You may have accidentally done a fuzzy search, you got {number} matching servers when searching for \"{server}\"".format(number=len(host.keys()), server=host)))
                for name in host.keys():
                    logging.error(red(name))
                logging.error(yellow("Try again with FQDN! (for example if you searched shazweb1 you'd hit this)"))
                sys.exit(1)

        logging.info(green("I found {} servers to deploy: \n".format(len(hosts.keys()))))
        for h in hosts.values():
            for k, v in h.items():
                logging.info("{host}, ID: {id}".format(host=k, id=v['id']))
        time.sleep(1)  # input likes to race the logs...
        raw = input("\nAre these correct? Y/N: ")
        if 'y' in raw.lower():
            for newhost in hosts.values():
                hst = list(newhost.keys())[0].split('.')[0]
                if os.path.exists('{}.yaml'.format(hst)):
                    for v in host.values():
                        self.deployserver(serverid=v['id'], deployfile='{}.yaml'.format(hst))
                else:
                    logging.error("I could not find a deploy file for {}, please make one!".format(hst))
                    sys.exit(1)
        else:
            logging.error("You didn't say yes, bailing!")
            sys.exit(1)


        if 'serverid' in kwargs.keys():
            if 'deployfile' in kwargs.keys():
                self.deployserver(serverid=kwargs['serverid'], deployfile=kwargs['deployfile'])



    def deployserver(self, serverid=None, deployfile=None):
        """
        This method will deploy a server based on a yaml config file we pass in. We set some basic configuration in the
        beginning, then open up the specified deployfile and parse it, loading some shared info in the self.deploycfg
        array/dictionary. Then we iterate through each method, starting with partitiondisks() and finally ending with
        exiting the recovery mode.
        NOTE: some of the methods require data to be passed in, some don't. The ones that don't either don't require
        any added data, or they use the self.deploycfg array/dict. If a method needs data from another method, we should
        specify the data required, and pass it in.
        :return:
        """
        while True:
            self.deploycfg = {}
            env.chroot = '/mnt'
            status = self.getserverstatus(serverid=serverid)
            if str(status) != str('rescue'):
                logging.warning(red('Server must be in recovery/rescue mode to run this! It is currently in {} mode\n'.format(status)))
                ans = input('do you want to reboot into recovery/rescue mode? Y/N ? ')
                if 'y' in str(ans).lower():
                    self.enterrecoverymode(serverid=serverid, pin=self.cfg['sh']['pin'])
                    logging.warning(blue('sleeping for 240 seconds to let the server reboot (yes, that is really long)'))
                    time.sleep(240)
                    logging.warning(green('go ahead and re-run the script, server should be in recovery now.'))
                    return
                else:
                    logging.warning('you didn\'t say yes, bailing!')
                    sys.exit(1)
            if os.path.exists(deployfile):
                # "with" is a context manager. We're going to open up the deployfile and create a dictionary at of its values
                with open(deployfile, 'r') as fh:
                    deploy = yaml.safe_load(fh)
                    self.deploycfg = {
                        'networks': self.getnetworks(serverid=serverid),
                        'ssh_password': self.getserverpassword(serverid=serverid, pin=self.cfg['sh']['pin']),
                        'raid_name': 'md1',  # encrypted raid is on the md1 (root) raid cluster
                        'hostname': deploy['hostname'],
                        'osversion': deploy['os']['version'],
                        'checksum': deploy['os']['checksum'],
                        'serverid': deploy['serverid']
                    }
                if int(serverid) == int(self.deploycfg['serverid']):
                    env.reject_unknown_hosts = False  # the host SSH keys are randomly generated in the recovery env
                    with settings(host_string=self.deploycfg['networks']['public']['ip'], user='root', password=self.deploycfg['ssh_password'],
                                  no_agent=True, no_keys=True):
                        self.partitiondisks(serverid=serverid, disks=deploy['disks'])
                        self.raiddisks(disks=deploy['disks'], hostname=self.deploycfg['hostname'])
                        self.encryptdisks(raid_name=self.deploycfg['raid_name'], disks=deploy['disks'])
                        self.unlockluks(disks=deploy['disks'])
                        self.lvmdisks(disks=deploy['disks'])
                        self.formatdisks()
                        self.mountdisks()
                        self.pushrootfs()
                        self.preparechroot()
                        self.dropbearsetup()
                        self.raidresyncspeed()
                        self.chrootconfig()
                        self.exitrecoverymode(serverid=serverid, pin=self.cfg['sh']['pin'])
                        self.rebootserver()
                        break  # lets not loop this
                else:
                    logging.error("server ID I found does not match deployfile, please validate! host: {} serverid: {}".format(self.deploycfg['hostname'], serverid))
                    sys.exit(1)
            else:
                logging.error("incorrect deployfile path, please pass in a fully qualified path to a valid yaml deployfile")
                sys.exit(1)


    def main(self):
        """
        The main thread - we iterate through the args list and execute whatever is designated. If no args are designated
        we print the help function and exit. (This is handled in the self.args setup)
        :return:
        """
        if self.args.list_servers:
            self.listservers()
        elif self.args.search_server:
            self.searchserver(searchterm=self.args.search_server)
        elif self.args.get_server_password:
            password = self.getserverpassword(serverid=self.args.serverid, pin=self.cfg['sh']['pin'])
            logging.info(green("password for this server is: {}".format(password)))
        elif self.args.get_server_ip:
            logging.info(green('server public IP is: {}'.format(self.getserverip(serverid=self.args.serverid))))
        elif self.args.download_server_list:
            self.downloadserverlist()
        elif self.args.get_server_disks:
            logging.info(blue(self.getserverdisks(serverid=self.args.serverid)))
        elif self.args.get_server_info:
            pprint.pprint(self.getserverinfo(serverid=self.args.serverid))
        elif self.args.deploy_servers:
            self.deploy(self.args.deploy_servers)
            #self.deployserver(serverid=self.args.serverid, deployfile=self.args.deployfile)


if __name__ == '__main__':
    """
    When we run this script interactively, first instantiate it as 'sd' (triggering __init__) then run main()
    """
    sd = ServerDeploy()
    sd.main()
