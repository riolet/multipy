__author__ = 'rohana'
import subprocess
import sys
import getopt

class BCOLORS:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

oidDict = {'hrStorageDescr': '.1.3.6.1.2.1.25.2.3.1.3',
           'hrStorageAllocationUnits': '.1.3.6.1.2.1.25.2.3.1.4',
           'hrStorageSize': '.1.3.6.1.2.1.25.2.3.1.5',
           'hrStorageUsed': '.1.3.6.1.2.1.25.2.3.1.6'}


def usage():
    print '%s [-H hosts] -o oid'%sys.argv[0]
    sys.exit(2)


def main(argv):
    opts = ''
    try:
        opts, args = getopt.getopt(argv,
                                   "hH:o:",
                                   ["host=", "oid="])

    except getopt.GetoptError as err:
        print str(err)
        usage()

    hosts = ''
    for opt, arg in opts:
        if opt == '-h':
            usage()
            sys.exit()
        elif opt in ("-H", "--hosts"):
            hosts = arg.strip()

    if not hosts:
        source = sys.stdin
    else:
        source = hosts.split(',')


    hrStorageDescrArr = []
    hrStorageSizeArr = []
    hrStorageUsedArr = []
    hrStorageAllocationUnitsArr = []

    for hostname_ in source:
        hostname = hostname_.strip()
        print hostname
        command = ['snmpwalk', '-v', '2c', '-c', 'public', hostname, oidDict['hrStorageDescr']]
        shell = subprocess.Popen(command, stdout=subprocess.PIPE)
        stdout, stderr = shell.communicate()
        for line in stdout.splitlines():
            so_parts = line.split(':')
            hrStorageDescr = so_parts[len(so_parts)-1].strip().translate(None, '"')
            hrStorageDescrArr.append(hrStorageDescr)

        command = ['snmpwalk', '-v', '2c', '-c', 'public', hostname, oidDict['hrStorageAllocationUnits']]
        shell = subprocess.Popen(command, stdout=subprocess.PIPE)
        stdout, stderr = shell.communicate()
        for line in stdout.splitlines():
            so_parts = line.split(':')
            hrStorageAllocationUnits = int(so_parts[len(so_parts)-1].strip().translate(None, '"'))
            hrStorageAllocationUnitsArr.append(hrStorageAllocationUnits)

        command = ['snmpwalk', '-v', '2c', '-c', 'public', hostname, oidDict['hrStorageSize']]
        shell = subprocess.Popen(command, stdout=subprocess.PIPE)
        stdout, stderr = shell.communicate()
        for line in stdout.splitlines():
            so_parts = line.split(':')
            hrStorageSize = int(so_parts[len(so_parts)-1])
            hrStorageSizeArr.append(hrStorageSize)

        command = ['snmpwalk', '-v', '2c', '-c', 'public', hostname, oidDict['hrStorageUsed']]
        shell = subprocess.Popen(command, stdout=subprocess.PIPE)
        stdout, stderr = shell.communicate()
        i=0
        for line in stdout.splitlines():
            so_parts = line.split(':')
            hrStorageDescr = hrStorageDescrArr[i]
            hrStorageSize = (hrStorageSizeArr[i]*(hrStorageAllocationUnitsArr[i]/1024))
            hrStorageUsed = int(so_parts[len(so_parts)-1])
            hrStorageUsedArr.append(so_parts[len(so_parts)-1])
            hrStorageUsed *= hrStorageAllocationUnitsArr[i]/1024
            storagefree = hrStorageSize - hrStorageUsed
            used = 0
            if hrStorageSize > 0:
                used = hrStorageUsed*100/hrStorageSize
            if hrStorageDescr.startswith('/'):
                if used == 100:
                    print BCOLORS.FAIL,
                elif used > 95:
                    print BCOLORS.WARNING,

                print '{:>30}\t{:>12}\t{:>12}\t{:>12}\t{:>12}'.format(hrStorageDescr,str(hrStorageSize),str(hrStorageUsed),str(storagefree),str(used))

                if used > 95:
                    print BCOLORS.ENDC,
            i += 1

if __name__ == "__main__":
    main(sys.argv[1:])



