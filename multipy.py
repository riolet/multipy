#!/usr/bin/python
import getopt
from binascii import hexlify
import getpass
import os
import socket
import sys
import traceback
from paramiko.py3compat import input
import paramiko
from threading import Thread
from Queue import Queue
import logging


multipy_queue = Queue()
multipy_logger = logging.getLogger(__name__)


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
        multipy_logger.info('Trying ssh-agent key %s' % hexlify(key.get_fingerprint()))
        try:
            transport.auth_publickey(username, key)
            multipy_logger.info('... success!')
            return
        except paramiko.SSHException:
            multipy_logger.warn('... nope.')


def manual_auth(t, username, hostname, key_file):
    default_auth = 'password_auth'

    if len(key_file) == 0:
        key_file = os.path.join(os.environ['HOME'], '.ssh', 'id_rsa')
        auth = 'rsa_auth'
    else:
        with open('key_file.txt', 'r') as f:
            first_line = f.readline()
            if "RSA" in first_line:
                auth = 'rsa_auth'
            else:
                auth = 'dsa_auth'

    if not os.path.isfile(key_file):
        key_file = os.path.join(os.environ['HOME'], '.ssh', 'id_dsa')
        auth = 'dsa_auth'
    else:
        multipy_logger.warn("Unable to locate key file. Defaulting to " + auth)
        auth = default_auth

    if auth == 'rsa_auth':
        default_path = os.path.join(os.environ['HOME'], '.ssh', 'id_rsa')
        if len(key_file) == 0:
            key_file = default_path
        try:
            key = paramiko.RSAKey.from_private_key_file(key_file)
        except paramiko.PasswordRequiredException:
            password = getpass.getpass('RSA key password: ')
            key = paramiko.RSAKey.from_private_key_file(key_file, password)
        t.auth_publickey(username, key)
    elif auth == 'dsa_auth':
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


def host_action(username, command, key_file, hostname, script_file_name, files_to_transfer, keys, match):
    if command:
        multipy_logger.info("Executing " + command + " on " + hostname)
    else:
        multipy_logger.info("Executing " + script_file_name + " on " + hostname)

    if len(hostname) == 0:
        multipy_logger.error('*** Hostname required.')
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
        multipy_logger.error('*** Connect failed: ' + str(e))
        traceback.print_exc()
        sys.exit(1)

    try:
        t = paramiko.Transport(sock)
        try:
            t.start_client()
        except paramiko.SSHException:
            multipy_logger.error('*** SSH negotiation failed.')
            sys.exit(1)
        # check server's host key -- this is important.
        key = t.get_remote_server_key()
        if hostname not in keys:
            multipy_logger.warn('*** WARNING: Unknown host key!')
        elif key.get_name() not in keys[hostname]:
            multipy_logger.warn('*** WARNING: Unknown host key!')
        elif keys[hostname][key.get_name()] != key:
            multipy_logger.error('*** WARNING: Host key has changed!!!')
            sys.exit(1)
        else:
            multipy_logger.info('*** Host key OK.')

        # get username
        if username == '':
            default_username = getpass.getuser()
            username = input('Username [%s]: ' % default_username)
            if len(username) == 0:
                username = default_username

        agent_auth(t, username)
        if not t.is_authenticated():
            manual_auth(t, username, hostname, key_file)
        if not t.is_authenticated():
            print('*** Authentication failed. :(')
            t.close()
            sys.exit(1)

        multipy_logger.info(hostname + ': Opening session')
        chan = t.open_session()
        buf_size = -1
        timeout = None
        chan.settimeout(timeout)
        command_lines = []

        stdin = chan.makefile('wb', buf_size)
        stdout = chan.makefile('r', buf_size)
        stderr = chan.makefile_stderr('r', buf_size)

        if command:
            command_lines.append(command+"\n")
        else:
            with open(script_file_name) as script_file:
                command_lines = script_file.readlines()

        chan.invoke_shell()
        multipy_logger.info("Match "+match)
        for command_line in command_lines:

            multipy_logger.info(hostname + ':' + command_line)
            chan.send(command_line)

            buff = chan.recv(1024)
            while chan.recv_ready():
                resp = chan.recv(1024)
                buff += resp

            if not match or (match in buff):
                print hostname + ':\n' + buff


        chan.close()
        t.close()

    except Exception as e:
        multipy_logger.error('*** Caught exception: ' + str(e.__class__) + ': ' + str(e))
        traceback.print_exc()
        try:
            t.close()
        except:
            pass
        sys.exit(1)


def multipy_worker():
    while True:
        item = multipy_queue.get()
        host_action(item['username'], item['command'], item['key_file'], item['hostname'],
                    item['script_file'], item['files_to_transfer'], item['keys'], item['match'])
        multipy_queue.task_done()


def multipy(username, command, key_file, stream, script_file, files_to_transfer, max_threads, verbosity, match):
    # setup logging
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    multipy_logger.addHandler(ch)

    if verbosity > 0:
        multipy_logger.setLevel(verbosity)

    try:
        keys = paramiko.util.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
    except IOError:
        try:
            keys = paramiko.util.load_host_keys(os.path.expanduser('~/ssh/known_hosts'))
        except IOError:
            multipy_logger.error('*** Unable to open host keys file')
            keys = {}

    if max_threads > 0:
        for i in range(max_threads):
            t = Thread(target=multipy_worker)
            t.daemon = True
            t.start()

    for hostname_ in stream:
        hostname = hostname_.strip()
        if max_threads > 0:
            multipy_queue.put({"username": username, "command": command, "key_file": key_file,
                   "hostname": hostname, "script_file": script_file,
                   "files_to_transfer": files_to_transfer, "keys": keys, "match": match})
        else:
            host_action(username, command, key_file, hostname, script_file, files_to_transfer, keys)

    if max_threads > 0:
        multipy_queue.join()


def usage():
    print 'multipy.py -u user [-c command] [-i key] [-s script]\
        [-f files,to,transfer] [-t threads] [-v verbosity] [-g grep]'
    sys.exit(2)


def main(argv):
    try:
        opts, args = getopt.getopt(argv,
                                   "hu:c:i:f:s:t:v:m:",
                                   ["user=", "command=", "key=", "files=", "script=",
                                    "threads=", "verbosity=", "match="])
    except getopt.GetoptError as err:
        print str(err)
        usage()
    if len(opts) < 1:
        usage()

    username = ''
    command = ''
    key_file = ''
    script_file = ''
    files_to_transfer = ''
    max_threads = 0
    verbosity = 1
    match = ''
    for opt, arg in opts:
        if opt == '-h':
            usage()
            sys.exit()
        elif opt in ("-u", "--user"):
            username = arg.strip()
        elif opt in ("-c", "--command"):
            command = arg.strip()
        elif opt in ("-i", "--key"):
            key_file = arg.strip()
        elif opt in ("-s", "--script"):
            script_file = arg.strip()
        elif opt in ("-f", "--files"):
            files_to_transfer = arg.strip()
        elif opt in ("-t", "--threads"):
            max_threads = int(arg.strip())
        elif opt in ("-v", "--verbosity"):
            verbosity = int(arg.strip())
        elif opt in ("-m", "--match"):
            match = arg.strip()
    if not username:
        print 'Username required'
        usage()

    if not (command or script_file):
        print 'Command or script required'
        usage()

    multipy(username, command, key_file, sys.stdin, script_file, files_to_transfer, max_threads, verbosity, match)


if __name__ == "__main__":
    main(sys.argv[1:])