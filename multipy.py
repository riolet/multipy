#!/usr/bin/python
import getopt
import subprocess
from binascii import hexlify
import getpass
import os
import socket
import sys
import traceback
from paramiko.py3compat import input

import paramiko



def agent_auth(transport, username):
    """
    Attempt to authenticate to the given transport using any of the private
    keys available from an SSH agent.
    """

    agent = paramiko.Agent()
    agent_keys = agent.get_keys()
    if len(agent_keys) == 0:
        return

    for key in agent_keys:
        print('Trying ssh-agent key %s' % hexlify(key.get_fingerprint()))
        try:
            transport.auth_publickey(username, key)
            print('... success!')
            return
        except paramiko.SSHException:
            print('... nope.')


def manual_auth(t, username, hostname):
    default_auth = 'p'
    auth = input('Auth by (p)assword, (r)sa key, or (d)ss key? [%s] ' % default_auth)
    if len(auth) == 0:
        auth = default_auth

    if auth == 'r':
        default_path = os.path.join(os.environ['HOME'], '.ssh', 'id_rsa')
        path = input('RSA key [%s]: ' % default_path)
        if len(path) == 0:
            path = default_path
        try:
            key = paramiko.RSAKey.from_private_key_file(path)
        except paramiko.PasswordRequiredException:
            password = getpass.getpass('RSA key password: ')
            key = paramiko.RSAKey.from_private_key_file(path, password)
        t.auth_publickey(username, key)
    elif auth == 'd':
        default_path = os.path.join(os.environ['HOME'], '.ssh', 'id_dsa')
        path = input('DSS key [%s]: ' % default_path)
        if len(path) == 0:
            path = default_path
        try:
            key = paramiko.DSSKey.from_private_key_file(path)
        except paramiko.PasswordRequiredException:
            password = getpass.getpass('DSS key password: ')
            key = paramiko.DSSKey.from_private_key_file(path, password)
        t.auth_publickey(username, key)
    else:
        pw = getpass.getpass('Password for %s@%s: ' % (username, hostname))
        t.auth_password(username, pw)

def main(argv):
    print subprocess.Popen("echo Hello World", shell=True, stdout=subprocess.PIPE).stdout.read()

    try:
        opts, args = getopt.getopt(argv, "hu:c:i:", ["user=", "command=", "key"])
    except getopt.GetoptError as err:
        print str(err)
        print 'multipy.py -u user -c command [-i key]'
        sys.exit(2)
    if len(opts) < 1:
        print 'multipy.py -u user -c command [-i key]'
        sys.exit(2)

    username = ''
    command = ''
    key_file = ''
    key_section = ''
    for opt, arg in opts:
        if opt == '-h':
            print 'multipy.py -u user -c command -i key'
            sys.exit()
        elif opt in ("-u", "--user"):
            username = arg.strip()
        elif opt in ("-c", "--command"):
            command = arg.strip()
        elif opt in ("-i", "--key"):
            command = arg.strip()
    # setup logging
    paramiko.util.log_to_file('demo.log')

    try:
        keys = paramiko.util.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
    except IOError:
        try:
            keys = paramiko.util.load_host_keys(os.path.expanduser('~/ssh/known_hosts'))
        except IOError:
            print('*** Unable to open host keys file')
            keys = {}

    for hostname_ in sys.stdin:
        hostname = hostname_.strip()
        print "Executing "+command+" on "+hostname
        #print subprocess.Popen("ssh "+key_section+user+"@"+hostname+" -o StrictHostKeyChecking=no \""+command+"\"",
        #                    shell=True, stdout=subprocess.PIPE).stdout.read()
        if len(hostname) == 0:
            print('*** Hostname required.')
            sys.exit(1)
        port = 22
        if hostname.find(':') >= 0:
            hostname, portstr = hostname.split(':')
            port = int(portstr)

        # now connect
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((hostname, port))
        except Exception as e:
            print('*** Connect failed: ' + str(e))
            traceback.print_exc()
            sys.exit(1)

        try:
            t = paramiko.Transport(sock)
            try:
                t.start_client()
            except paramiko.SSHException:
                print('*** SSH negotiation failed.')
                sys.exit(1)



            # check server's host key -- this is important.
            key = t.get_remote_server_key()
            if hostname not in keys:
                print('*** WARNING: Unknown host key!')
            elif key.get_name() not in keys[hostname]:
                print('*** WARNING: Unknown host key!')
            elif keys[hostname][key.get_name()] != key:
                print('*** WARNING: Host key has changed!!!')
                sys.exit(1)
            else:
                print('*** Host key OK.')

            # get username
            if username == '':
                default_username = getpass.getuser()
                username = input('Username [%s]: ' % default_username)
                if len(username) == 0:
                    username = default_username

            agent_auth(t, username)
            if not t.is_authenticated():
                manual_auth(t, username, hostname)
            if not t.is_authenticated():
                print('*** Authentication failed. :(')
                t.close()
                sys.exit(1)

            chan = t.open_session()
            buf_size = -1
            timeout = None
            chan.settimeout(timeout)
            chan.exec_command(command)
            stdin = chan.makefile('wb', buf_size)
            stdout = chan.makefile('r', buf_size)
            stderr = chan.makefile_stderr('r', buf_size)
            for line in stdout:
                print '... ' + line.strip('\n')
            chan.close()
            t.close()
        except Exception as e:
            print('*** Caught exception: ' + str(e.__class__) + ': ' + str(e))
            traceback.print_exc()
            try:
                t.close()
            except:
                pass
            sys.exit(1)

            # if key_file:
            #     key_section = "-i "+key_file
            #
            # for host in sys.stdin:
            #     print "Executing "+command+" on "+host
            #     print subprocess.Popen("ssh "+key_section+user+"@"+host+" -o StrictHostKeyChecking=no \""+command+"\"",
            #                        shell=True, stdout=subprocess.PIPE).stdout.read()

if __name__ == "__main__":
    main(sys.argv[1:])