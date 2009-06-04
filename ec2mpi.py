import boto
import sys,md5,os
import logging
import time
from datetime import datetime
import M2Crypto
from tempfile import NamedTemporaryFile
import paramiko
import inspect
import re
import urllib2,urllib
from config import *
import util
import cPickle as pickle
import random
from collections import defaultdict
from sets import Set
import socket
socket.setdefaulttimeout(60)

S3_BUCKET = md5.new(USER_ID+"mpi-keys").hexdigest()

class EC2MPI:
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
    echo 's3fs#%(mpi_bucket)s /vol fuse allow_other 0 0' >> /etc/fstab
    mount /vol"""
    # AWS Connections
    ec2 = boto.connect_ec2(ACCESS_KEY_ID,SECRET_ACCESS_KEY)
    s3  = boto.connect_s3(ACCESS_KEY_ID,SECRET_ACCESS_KEY)
    sdb = boto.connect_sdb(ACCESS_KEY_ID,SECRET_ACCESS_KEY)
    domain = util.getAWS(sdb,"clusters")
    bucket = util.getAWS(s3,S3_BUCKET)
    @staticmethod
    def rand_name():
        return "c%08x" % random.randint(0x00,0xFFFFFFFF)
    
    @staticmethod
    def get_mpi_keys():
        keys = bucket.list('id-')
        available_keys = []
        for key in keys:
            m = re.match(r'id\-([\w\W\d\D]+)\.pub',key.name)
            if m:
                available_keys += [m.group(1)]
        return available_keys
    
    @staticmethod
    def gen_mpi_key():
        pub,pri = util.genKey()
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
        return keyname
    @staticmethod
    def recover_startup(config):
        ""
                            
    @staticmethod
    def start_cluster(config=None):
        # See if user is passing in a config
        if not config:
            config = EC2MPI.run_config()
        cluster = Cluster(config)
        util.getAWS(EC2MPI.s3,config['mpi_bucket'])
        bucket = util.getAWS(EC2MPI.s3,config['s3_bucket'])
        pri_key = bucket.get_key("id-%s" % config['mpi_key'])
        pub_key = bucket.get_key("id-%s.pub" % config['mpi_key'])
        pri_key_url = pri_key.generate_url(300)
        pub_key_url = pub_key.generate_url(300)
        startup_script_dict = {'access_key':ACCESS_KEY_ID,
                    'secret_key':SECRET_ACCESS_KEY,
                    'bucket':config['s3_bucket'],
                    'pri_key_url':pri_key_url,
                    'pub_key_url':pub_key_url,
                    'mpi_bucket':config['mpi_bucket']}
        
        # Startup the instances
        print "Starting up"
        reservation = EC2MPI.ec2.run_instances(image_id=config['ami'],
            min_count=cluster.min_count,
            max_count=cluster.max_count,
            key_name=AWS_KEYPAIR_NAME,
            instance_type=cluster.instance_type,
            placement=cluster.placement,
            user_data=EC2MPI.startup_script % startup_script_dict)
        cluster.reservation = reservation.id
        cluster.status = "starting" 
        cluster.save()
        
        # Wait for instances to all be available
        print "Waiting for instances"
        instances = reservation.instances
        while 1:
            for instance in instances:
                if instance.update() == u'running':
                    print "Instance %s is running" % instance.id
                    instances.remove(instance)
            if len(instances) == 0:
                print "All done"
                break 
            else:
                time.sleep(2)
        reservation = EC2MPI.get_reservation(cluster.reservation)
        count = 0
        instance_ids = []
        for instance in reservation.instances:
            if instance.update() == u"running":
                count += 1
                instance_ids += [instance.id]
            print instance.update(),instance.ami_launch_index,instance.public_dns_name
        cluster.instances = instance_ids
        cluster.count = count
        cluster.status = "pending" 
        cluster.save()
        
        # Build machinefile and upload to master node
        cluster.update_machinefile()
            
        print "Cluster is up and ready"
        cluster.hostname =  master_node.public_dns_name
        cluster.status = 'running'
        cluster.save()
        return cluster
        
    @staticmethod
    def get_cluster(name):
        cluster_item = EC2MPI.domain.select("select * from `clusters` where `name` = '%s'" % name)
        cluster = Cluster(cluster_item.next())
        if cluster.name == name:
            return cluster
        else:
            return None
            
    @staticmethod
    def list_clusters():
        cluster_items = EC2MPI.domain.select("select * from `clusters` where `status` in ('pending','running')")
        for cluster_item in cluster_items:
            cluster = Cluster(cluster_item)
            print "Cluster %s (%s instances) %s %s" % (cluster.name,cluster.count,cluster.status,cluster.reservation)
   
    @staticmethod
    def get_reservation(rid):
        reservations = EC2MPI.ec2.get_all_instances()
        for reservation in reservations:
            if reservation.id == rid:
                return reservation
        return None
        
    @staticmethod
    def run_config():
        config = {}
        images = EC2MPI.ec2.get_all_images(owners=USER_ID)
        # Choose the architecture
        arch = util.choose(["i386","x86_64"],"Choose architecture")
        for image in images:
            if image.architecture == arch:
                config['ami'] = image.id
        # Choose architecture
        if arch == "i386":
            config['instance_type'] = util.choose(["m1.small","c1.medium"],"Choose instance size")
        elif arch == "x86_64":
            config['instance_type'] = util.choose(["m1.large","m1.xlarge","c1.xlarge"],"Choose instance size")
        else:
            print "Sorry, bad arch"
            sys.exit()
        # Choose the number of instances
        config['max_count'] = util.choose([2,4,8,16,32,64,128,256],"Number of instances")
        # If this is a large cluster, set the min at 80% of the requested
        if config['max_count'] > 32:
            config['min_count'] = int(0.8*config['count'])
        else:
            config['min_count'] = config['max_count']
        # Choose the SSH key to use
        available_keys = EC2MPI.get_mpi_keys()
        if len(available_keys) == 0:
            print "You don't have any keys, creating one now"
            config['mpi_key'] = EC2MPI.gen_mpi_key()
        else:
            available_keys += ["Create a new key"]
            mpi_key = util.choose(available_keys,"Choose a key to use for MPI communication")
        if mpi_key == "Create a new key":
            config['mpi_key'] = EC2MPI.gen_mpi_key()
        else:
            config['mpi_key'] = mpi_key
        rand_name = EC2MPI.rand_name()
        cluster_name = raw_input("Name this cluster (q to Quit) [%s]: " % rand_name)
        while 1:
            if cluster_name == u'q':
                sys.exit()
            if cluster_name == u'':
                cluster_name = rand_name
            if EC2MPI.domain.get_item(cluster_name):
                print "Name is already taken"
                rand_name = EC2MPI.rand_name()
                cluster_name = raw_input("Name this cluster (q to Quit) [%s]: " % rand_name)
            else:
                config['name'] = cluster_name
                break
        config['status'] = "config"
        config['reservation'] = ""
        config['s3_bucket'] = S3_BUCKET
        config['mpi_bucket'] = md5.new(config['name']).hexdigest()
        config['placement'] = "us-east-1a"
        return config
        
class Cluster:
    """Cluster object, is kept in synch with a SimpleDB record via the save
    method."""
    keys = ('name','status','reservation','ami','min_count','max_count',
        'placement','s3_bucket','mpi_bucket','instance_type','mpi_key',
        'instances','last_modified','count','hostname')
    def __init__(self,config=None):
        if config:
            config = defaultdict(str,config)
            for k in Cluster.keys:
                setattr(self,k,config[k])
        self.sdb = boto.connect_sdb(ACCESS_KEY_ID,SECRET_ACCESS_KEY)
        self.domain = util.getAWS(self.sdb,"clusters")
    def __repr__(self):
        out = "Cluster %s\n" % self.name
        for k in Cluster.keys:
            out += "%s: %s\n" % (k,getattr(self,k,''))
        return out
    def save(self):
        item = self.domain.new_item(self.name)
        self.last_modified = datetime.now().isoformat()
        self.instances = [x for x in Set(self.instances)]
        for k in Cluster.keys:
            item[k] = getattr(self,k,'')
        item.save()
        #print item  
    def shutdown(self):
        reservations = EC2MPI.ec2.get_all_instances(self.instances)
        for reservation in reservations:
            reservation.stop_all()   
        self.status = 'terminated'
        self.save()
    def add_instance(self):
        image = EC2MPI.ec2.get_image(self.ami)
        util.getAWS(EC2MPI.s3,self.mpi_bucket)
        bucket = util.getAWS(EC2MPI.s3,self.s3_bucket)
        pri_key = bucket.get_key("id-%s" % self.mpi_key)
        pub_key = bucket.get_key("id-%s.pub" % self.mpi_key)
        pri_key_url = pri_key.generate_url(300)
        pub_key_url = pub_key.generate_url(300)
        startup_script_dict = {'access_key':ACCESS_KEY_ID,
                    'secret_key':SECRET_ACCESS_KEY,
                    'bucket':self.s3_bucket,
                    'pri_key_url':pri_key_url,
                    'pub_key_url':pub_key_url,
                    'mpi_bucket':self.mpi_bucket}
        print "Starting up new instance"
        reservation = image.run(min_count=1,max_count=1,
                    key_name=AWS_KEYPAIR_NAME,
                    instance_type=self.instance_type,
                    placement=self.placement,
                    user_data=EC2MPI.startup_script % startup_script_dict)
        print reservation
        while 1:
            if reservation.instances[0].update() == u'running':
                break
            else:
                time.sleep(2)
        self.instances += [reservation.instances[0].id]
        self.count = int(self.count) + 1
        self.save()
        print "Instance is ready"
        self.update_machinefile()
    def login(self):
        "SSH the user into the machine"
        os.execl('/usr/bin/ssh','ssh','-i',AWS_KEYPAIR_PATH,'-l','root','-v',self.hostname)
    def update_machinefile(self):
        # Build machinefile and upload to master node
        machinestring = ""
        reservations = EC2MPI.ec2.get_all_instances(self.instances)
        hostnames = []
        for reservation in reservations:
            for instance in reservation.instances:
                hostnames += [instance.private_dns_name]
        machinestring = "\n".join(hostnames)
        # Send machinefile and setup known_hosts for seemless SSH
        max_attempt = 10
        attempt = 1
        while 1:
            try:
                print "Sending machinefile and setting up SSH (attempt %d of %d)" % (attempt,max_attempt) 
                util.sendFile(self.hostname,machinestring,"/root/machines")
                stdout,stderr = util.sendCommand(self.hostname,
"""rm -f /root/.ssh/known_hosts ; cat /root/machines | awk '{ system("ssh-keyscan " $0 " >> /root/.ssh/known_hosts") }'""")   
                known_hosts = len(stderr.split("\n"))
                if known_hosts == int(self.count) + 1:
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
        
if __name__ == "__main__":
    c = EC2MPI.get_cluster("c70521b78")
    c.shutdown()
