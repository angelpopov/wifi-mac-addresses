import telnetlib
import time
import itertools
import os.path
import sqlite3

client_options = "bssid,mac,type,firsttime,lasttime,manuf,llcpackets,datapackets,cryptpackets,gpsfixed,minlat,minlon,minalt,minspd,maxlat,maxlon,maxalt,maxspd,agglat,agglon,aggalt,aggpoints,signal_dbm,noise_dbm,minsignal_dbm,minnoise_dbm,maxsignal_dbm,maxnoise_dbm,signal_rssi,noise_rssi,minsignal_rssi,minnoise_rssi,maxsignal_rssi,maxnoise_rssi,bestlat,bestlon,bestalt,atype,ip,gatewayip,datasize,maxseenrate,encodingset,carrierset,decrypted,channel,fragments,retries,newpackets,freqmhz,cdpdevice,cdpport,dot11d,dhcphost,dhcpvendor,datacryptset".split(",")

def create_db(fname):
    conn = sqlite3.connect(fname)
    c = conn.cursor()
    cmd = "CREATE TABLE MACINFO ('bssid', 'mac', 'type', 'firsttime', 'lasttime', 'manuf', 'llcpackets', 'datapackets', 'cryptpackets', 'gpsfixed', 'minlat', 'minlon', 'minalt', 'minspd', 'maxlat', 'maxlon', 'maxalt', 'maxspd', 'agglat', 'agglon', 'aggalt', 'aggpoints', 'signal_dbm', 'noise_dbm', 'minsignal_dbm', 'minnoise_dbm', 'maxsignal_dbm', 'maxnoise_dbm', 'signal_rssi', 'noise_rssi', 'minsignal_rssi', 'minnoise_rssi', 'maxsignal_rssi', 'maxnoise_rssi', 'bestlat', 'bestlon', 'bestalt', 'atype', 'ip', 'gatewayip', 'datasize', 'maxseenrate', 'encodingset', 'carrierset', 'decrypted', 'channel', 'fragments', 'retries', 'newpackets', 'freqmhz', 'cdpdevice', 'cdpport', 'dot11d', 'dhcphost', 'dhcpvendor', 'datacryptset')"
    e = c.execute(cmd)
    conn.commit()
    return conn

def init_db(fname):
    conn=None
    if not os.path.isfile(fname):
        conn = create_db(fname);
    else:
        conn = sqlite3.connect(fname)
    
    return conn

g_conn = init_db("ml-macinfo.sq3")

def init_kismet():
    tn = telnetlib.Telnet("localhost", 2501)
    time.sleep(5)
    tn.write("\n!1 remove time\n")
    tn.write("\n!2 enable CLIENT "+",".join(client_options)+"\n")
    return tn

def remove_spaces(str):
    return "_".join(str.split(" "))

def readClient(tn):
    """ read row from kismet server """
    while True:
        raw = tn.read_until('\n',5).split("\x01")
        if raw == '':
            continue
        no_spaces =  "".join([ remove_spaces(x) if y%2!=0 else x for (x,y) in zip(raw,range(0,len(raw)))])
        c = no_spaces.split(" ")
        if c[0]!='*CLIENT:':
            print "First item is not as expected"
            print c
            print raw
            continue

    
        if len(client_options) != len(c[1:-1]):
            print "Length of the info is not expected"
            print c
            print raw
            continue
        d = {x:y for x,y in zip(client_options, c[1:])}
        #d["firsttime"] = time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(int(d["firsttime"])))
        #d["lasttime"] = time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(int(d["lasttime"])))
        
        d['coef']=0
        yield d

def compress_silence(all,new):
    if new > 500:
        new = -new
    if len(all)==0:
        return all+[new]
    if all[-1]>=0 and new >=0:
        all=all[:-1]+ [all[-1]+new]
    else:
        all=all+[new]
    return all

def group_by_mac(all,new):
    if not all.has_key(new["mac"]):
        all[new["mac"]] = []

    fields=",".join([repr(new[k]) for k in client_options])
    g_conn.cursor().execute("insert into macinfo values("+fields+")")

    all[new["mac"]].append(new)
    if len(all[new["mac"]])> 200:
            all[new["mac"]]=all[new["mac"]][-200:]
    return all

def collect_items(tn,count=100,d={}):
    return reduce (group_by_mac, itertools.islice(readClient(tn),count), d)

def diffs(l1):
    l = sorted(l1)
    return map(lambda x,y:y - x,l[:-1],l[1:])

def avg_difference(l):
    return sum( diffs(l))/(len(l)-1 if len(l)>1 else 1)

def get_items(d):
    d = collect_items(10,d)
    for x in sorted([(avg_difference([int(x["lasttime"])
                                      for x in v]),diffs([int(x["lasttime"]) for x in v]),k) for (k,v) in d.iteritems()]):
        print x
    return d

def show_mac(list):
    for o in client_options:
        print
        print o,
        for x in set([d[o] for d in list]):
            if o == "lasttime" or o == "firsttime":
                print time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(int(x)))
            print x,
def main():
    known={'94:DE:80:7B:A7:55':'               pc',
           '30:B5:C2:AF:23:7E':'      tp-link-lan',
           '30:B5:C2:AF:23:7F':'      tp-link-wan',
           '54:EF:92:07:6C:40':'    Clock android',
           '30:A8:DB:08:19:0B':'    Ioana android',
           '78:00:9E:DF:EE:F8':'    Sasha android',
           '7C:D1:C3:F5:74:F7':'        Mitko Mac',
           'A8:8E:24:3A:F6:09':'     Mitko iPhone',
           '54:EF:92:5A:16:1D':'    Angel android',
           'C4:36:6C:32:B1:76':'     Sysed Foxcon',
           'C4:46:19:54:59:EF':'             acer',
           'DC:CF:96:42:2D:CB':'         SamsungM'}
    
    d = {}
    tn = init_kismet()
    commit = 100
    while True:
        commit = commit - 1
        if commit == 0:
            print "-------------------"
            g_conn.commit()
            commit = 100
        d = collect_items(tn, d=d, count=1)
        print
        print time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(time.time()))
        print
        for x in sorted([(k,(int(time.time())-int(v[-1]["lasttime"]))/10,
                          diffs([int(x["lasttime"]) for x in v]))
                         for (k,v) in d.iteritems()]):
            k,idle_time,intervals = x
            if intervals == None:
                continue
            if len(intervals)> 10:
                print known.get(k, k), "-" * min(idle_time/3, 50), reduce(compress_silence,intervals , []), "   ", idle_time,d[k][-1]["manuf"]
            if len(intervals)<2 and idle_time > 360000:
                del d[k]
                            
main()

