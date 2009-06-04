import M2Crypto
from tempfile import NamedTemporaryFile
import paramiko
import urllib
import urllib2
import inspect
import boto.sdb.connection
from config import *

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
            
# SSH Helper functions
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
    
# AWS Helper functions
def getAWS(conn,target):
    if isinstance(conn,getattr(boto.sdb.connection,"SDBConnection")):
        obj = conn.lookup(target)
        if not obj:
            obj = conn.create_domain(target)
    elif isinstance(conn,getattr(boto.s3.connection,"S3Connection")):
        obj = conn.lookup(target)
        if not obj:
            obj = conn.create_bucket(target)
            obj.set_acl('private')
    elif isinstance(conn,getattr(boto.sqs.connection,"SQSConnection")):
        obj = conn.lookup(target)
        if not obj:
            obj = conn.create_queue(target)
    else:
        print "Unknown AWS connection"
        return None
    return obj