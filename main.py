from boto.sdb.connection import SDBConnection
from boto.ec2.connection import EC2Connection
from boto.s3.connection import S3Connection
import sys,md5
import logging
import time
import M2Crypto
from tempfile import NamedTemporaryFile
import paramiko
import inspect
import re
import urllib2,urllib
from config import *

import socket
socket.setdefaulttimeout(60)

S3_BUCKET               = md5.new(USER_ID+"mpi-keys").hexdigest()
OPTIONS_VALUE           = 0
OPTIONS_IDX             = 1

# General Helper Functions
def choose(options,message,return_type=OPTIONS_VALUE):
    """
    UI Helper function, prompts user with a list of options and a message 
    and returns the choice.

    options - List of options to present to the user
    message - The prompt message
    return_type (optional) - Specify what to return, the value of the option or the
        index. Must be one of OPTIONS_VALUE or OPTIONS_IDX. OPTIONS_VALUE is default.

    Example:
        color,color_idx = choose(['red','blue','green'],"Pick a color")
    """
    count = 1
    for item in options:
        print "%d) %s"%(count,item)
        count += 1
    while 1:
        choice = raw_input("%s (q to Quit): "%message)
        if choice == "q":
            exit()
        elif int(choice) < count:
            break
        else:
            continue
    if return_type == OPTIONS_VALUE:
        return options[int(choice)-1]
    else:
        return int(choice)-1
def genKey():
    """
    Returns a tuple of public key, private key, meta data. 
    The keys are returned as strings, and the meta data as a dict. The meta data
    is used to store info we display to the user when choosing a key.
    """
    pub = NamedTemporaryFile('rw') 
    pri = NamedTemporaryFile('rw')
    key = M2Crypto.RSA.gen_key(1024,17)
    key.save_pub_key(pub.name)
    key.save_key(pri.name,cipher=None)
    pub.seek(0)
    pri.seek(0)
    pubstr = pub.read()
    pristr = pri.read()
    pub.close()
    pri.close()
    return pubstr,pristr
def genTempURL(url):
    data = urllib.urlencode({'url':url,'output':"text"})
    req = urllib2.Request("http://turl.mumrah.net/create",data)
    try:
        resp = urllib2.urlopen(req)
        out = resp.read()
        return out
    except Exception,err:
        print "Could not generate temporary URL, please try again"
        print err
        sys.exit()
def listfunc():
    me = __import__(inspect.getmodulename(__file__))
    for name in dir(me):
        obj = getattr(me,name)
        if inspect.isfunction(obj):
            yield obj
def sendFile(host,filestring,filename):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            username='root',
            key_filename=AWS_KEYPAIR_PATH,
            timeout=10)
    except Exception, err:
        print err
        raise paramiko.SSHException("SSH Error, probably timeout")
    sftp = client.open_sftp()
    fp = sftp.open(filename,'w')
    fp.write(filestring)
    fp.close()
    sftp.close()
    client.close()
def sendCommand(host,string):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            username='root',
            key_filename=AWS_KEYPAIR_PATH,
            timeout=10)
    except Exception, err:
        print err
        raise paramiko.SSHException("SSH Error, probably timeout")
    stdin,stdout,stderr = client.exec_command(string)
    stdout = stdout.read()
    stderr = stderr.read()
    client.close()
    return stdout,stderr


# Amazon Helper Functions
def SDB(domain_name):
    """
    Create connection to SimpleDB and return the specifed domain.
    
    domain_name - the SimpleDB domain you wish to return
    """
    conn = SDBConnection(ACCESS_KEY_ID,SECRET_ACCESS_KEY)
    domain = conn.lookup(domain_name)
    if not domain:
        domain = conn.create_domain(domain_name)
    return domain
def saveInstanceMetaData(the_reservation):
    sdb = SDB("clusters")
    ec2 = EC2Connection(ACCESS_KEY_ID,SECRET_ACCESS_KEY)
    reservations = ec2.get_all_instances()
    for reservation in reservations:
        r_id = reservation.id
        if r_id != the_reservation.id:
            continue
        print "Updating SimpleDB entries for reservation, %s"%r_id
        for instance in reservation.instances:
            id = instance.id
            item_id = md5.new("%s%s"%(r_id,id)).hexdigest()
            item = sdb.new_item(item_id)
            item['reservation'] = r_id
            item['instance'] = id
            item['public_dns'] = instance.public_dns_name
            item['private_dns'] = instance.private_dns_name
            item['keyname'] = instance.key_name
            item['idx'] = instance.ami_launch_index
            item.save()
class EC2SSH:
    def __init__(self,hostname,pk_path,timeout=60):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(hostname=hostname,timeout=timeout,key_filename=pk_path)
def getActiveReservations():
    """
    Since a Reservation will remain in EC2 some time after it has
    been destroyed, we must check out SDB records to see if a 
    Reservation has active instances.

    Returns list of reservation ids
    """
    ec2 = EC2Connection(ACCESS_KEY_ID,SECRET_ACCESS_KEY)
    sdb = SDB("clusters")
    reservations = ec2.get_all_instances()
    r_ids = []
    for reservation in reservations:
        if reservation.instances[0].update() == u'terminated':
            continue
        r_ids += [reservation.id]
    # Get items from SDB for each reservation (this will exclude terminated instances
    # if the reservation still exists)
    if len(r_ids) == 0:
        return [] 
    query_predicates = ["['reservation' = '%s']"%r_id for r_id in r_ids]
    query = " union ".join(query_predicates)
    items = sdb.query(query)
    # Get unique reservation ids from result
    r_ids = []
    for item in items:
        if item['reservation'] not in r_ids:
            r_ids += [item['reservation']]
    return r_ids

# Actions
def _action_create():
    """
    Create a cluster of instances. User chooses architecture and reservation size
    """
    sdb = SDB("clusters")
    ec2 = EC2Connection(ACCESS_KEY_ID,SECRET_ACCESS_KEY)
    images = ec2.get_all_images(owners=USER_ID)
    arch = choose(["i386","x86_64"],"Choose architecture")
    the_image = None
    for image in images:
        if image.architecture == arch:
            the_image = image 
    num = choose([2,4,8,16,32,64],"Number of instances") 
    available_keys = _get_keys()
    if len(available_keys) == 0:
        print "You don't have any keys, creating one now"
        _action_genkey()
        mpi_key = _get_keys()[0]
    else:
        available_keys += ["Create a new key"]
        mpi_key = choose(available_keys,"Choose a key to use for MPI communication")
    if mpi_key == "Create a new key":
        mpi_key = _action_genkey()[1]
    # Generate temporary URLs to keys on S3
    s3 = S3Connection(ACCESS_KEY_ID,SECRET_ACCESS_KEY)
    bucket = s3.lookup(S3_BUCKET)
    pri_key = bucket.get_key("id-%s"%mpi_key)
    pub_key = bucket.get_key("id-%s.pub"%mpi_key)
    pri_key_url = pri_key.generate_url(300)
    pub_key_url = pub_key.generate_url(300)
    startup_script = """#!/bin/bash
cd /tmp
# Download SSH keys
curl '%(pri_key_url)s' > id_rsa
# Install SSH keys
mv id_rsa /root/.ssh/id_rsa
chmod 400 /root/.ssh/id_rsa
ssh-keygen -y -f /root/.ssh/id_rsa > /root/.ssh/id_rsa.pub
cat /root/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys
chmod -R 400 /root/.ssh
# Mount S3 Volume
apt-get -y install fuse-utils
modprobe fuse
echo '%(access_key)s:%(secret_key)s' > /etc/passwd-s3fs
chmod 400 /etc/passwd-s3fs
echo 's3fs#1892529bd3211f42c872e87e63e3ce5a /vol fuse allow_other 0 0' >> /etc/fstab
mount /vol
    """ % {'access_key':ACCESS_KEY_ID,
            'secret_key':SECRET_ACCESS_KEY,
            'bucket':S3_BUCKET,
            'pri_key_url':pri_key_url,
            'pub_key_url':pub_key_url}

    reservation = ec2.run_instances(image_id=the_image.id,min_count=num,max_count=num,key_name=AWS_KEYPAIR_NAME,instance_type="m1.small",placement="us-east-1a",user_data=startup_script)
    for instance in reservation.instances:
        if instance.update() == u'running':
            print "Instance ",instance," is running"
            continue
        else:
            while 1:
                time.sleep(5)
                if instance.update() == u'running':
                    print "Instance ",instance," is running"
                    break
                else:
                    continue
    saveInstanceMetaData(reservation) # Update SimpleDB entries

    # Build machinefile and upload to master node
    master_node = None
    worker_nodes = []
    machinestring = ""
    for instance in reservation.instances:
        if instance.ami_launch_index == u'0':
            master_node = instance
        else:
            worker_nodes += [instance]
        machinestring += instance.private_dns_name+"\n"
    # Send machinefile and setup known_hosts for seemless SSH
    max_attempt = 10
    attempt = 1
    while 1:
        try:
            print "Sending machinefile and setting up SSH (attempt %d of %d)" % (attempt,max_attempt) 
            sendFile(master_node.public_dns_name,machinestring,"/root/machines")
            stdout,stderr = sendCommand(master_node.public_dns_name,"""rm -f /root/.ssh/known_hosts ; cat /root/machines | awk '{ system("ssh-keyscan " $0 " >> /root/.ssh/known_hosts") }'""")   
            known_hosts = len(stderr.split("\n"))
            if known_hosts == num+1:
                break
            else:
                print "stdout: ",stdout
                print "stderr: ",stderr
                print len(stderr.split("\n"))
                raise paramiko.SSHException("Looks like networking is not yet available")
        except paramiko.SSHException,err :
            if attempt == max_attempt:
                print "You fail too hard, sir."
                sys.exit()
            print "SSH Error, trying again: ",err
            time.sleep(5)
            attempt += 1
            continue 

    print "All Instances are available. Master node can be accessed at:"
    print master_node.public_dns_name

def _action_debugdb():
    sdb = SDB("clusters")
    items = sdb.query()
    for item in items:
#        sdb.delete_item(item)
        print item

def _action_destroy():
    """
    Present a list of active reservations and prompt user which to destroy.
    Need to get all active reservations based on SDB records
    """
    sdb = SDB("clusters")
    ec2 = EC2Connection(ACCESS_KEY_ID,SECRET_ACCESS_KEY)
    sdb = SDB("clusters")
    reservations = ec2.get_all_instances()
    r_ids = getActiveReservations()
    r_id = choose(r_ids,"Choose a cluster to destroy")
    for reservation in reservations:
        if reservation.id == r_id:
            for instance in reservation.instances:
                if instance.update() != u'running':
                    continue
                id = instance.id
                item_id = md5.new("%s%s"%(r_id,id)).hexdigest()
                item = sdb.get_item(item_id)
                sdb.delete_item(item)
            reservation.stop_all()

def _action_genkey():
    """
    Generate a keypair for the MPI cluster to communicate with. Upload the key
    to S3 and set the permissions

    Returns a tuple of the exit code and the generated key's name
    """
    pub,pri = genKey()
    s3 = S3Connection(ACCESS_KEY_ID,SECRET_ACCESS_KEY)
    bucket = s3.lookup(S3_BUCKET)
    if not bucket:
        bucket = s3.create_bucket(S3_BUCKET)
    bucket.set_acl('private')
    keyname = raw_input("Choose a name for the key (q to Quit): ")
    while 1:
        if keyname == "q":
            exit()
        elif keyname == "":
            keyname = raw_input("Choose a name for the key (q to Quit): ")
        elif bucket.get_key("id-%s"%keyname):
            print "That key name is already in use."
            keyname = raw_input("Choose a name for the key (q to Quit): ")
        else:
            break
    keyname = keyname.replace(" ","-")
    pub_key = bucket.new_key("id-%s.pub"%keyname)
    pub_key.set_contents_from_string(s=pub,policy='private')
    pri_key = bucket.new_key("id-%s"%keyname)
    pri_key.set_contents_from_string(s=pri,policy='private')
    return 1,keyname
     
def _action_help():
    print """Usage: python main.py [action]
Actions:
    create - create cluster
    debugdb - show current records in SimpleDB domain for this utility
    destroy - destroy cluster
    genkey - generate a keypair for MPI
    help - display this help
    keys - list all keys available for MPI
    list - list current clusters
    """

def _get_keys():
    "Get all of the available private keys from S3 for use with MPI"
    s3 = S3Connection(ACCESS_KEY_ID,SECRET_ACCESS_KEY)
    bucket = s3.lookup(S3_BUCKET)
    if not bucket:
        return None
    keys = bucket.list('id-')
    available_keys = []
    for key in keys:
        m = re.match(r'id\-([\w\W\d\D]+)\.pub',key.name)
        if m:
            available_keys += [m.group(1)]
    return available_keys

def _action_keys():
    available_keys = _get_keys()
    if len(available_keys) == 0:
        print "No keys available"
        return 1
    print "Keys available for use:"
    for key in available_keys:
        print " - %s"%key
    return 1

def _action_list():
    sdb = SDB("clusters")
    ec2 = EC2Connection(ACCESS_KEY_ID,SECRET_ACCESS_KEY)
    r_ids = getActiveReservations()
    reservations = ec2.get_all_instances()
    for reservation in reservations:
        if reservation.id not in r_ids:
            # Only show active reservations
            continue
        print "Cluster: ",reservation.id
        print "-"*80
        for instance in reservation.instances:
            item_id = md5.new("%s%s"%(reservation.id,instance.id)).hexdigest()
            item = sdb.get_item(item_id)
            print "Idx: %s\tPublic DNS: %s\tPrivate DNS: %s" % \
                    (item['idx'],item['public_dns'],item['private_dns'])

def main():
    if len(sys.argv) < 2:
        print "Missing argument, try 'help' for more info"
        exit()
    else:
        action = sys.argv[1]
    available_actions = [x.__name__ for x in listfunc() if x.__name__.find("_action_") == 0]
    me = __import__(inspect.getmodulename(__file__))
    if "_action_"+action in available_actions:
        if action == "help":
            getattr(me,"_action_"+action)()
            return 
        print "Running action '%s'"%action
        t1 = time.time()
        getattr(me,"_action_"+action)()
        t2 = time.time()
        print "Finished in %1.4fs" % (t2-t1)
    else:
        print "Action not defined"
        getattr(me,"_action_help")()
if __name__ == "__main__":
    main()
