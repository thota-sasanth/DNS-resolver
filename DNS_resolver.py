
# dependency - dnspython[dnssec]
import dns.message       # required imports
import dns.query
import time,datetime,sys


rootservers = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13','192.203.230.10','192.5.5.241','192.112.36.4','198.97.190.53',
               '192.36.148.17','192.58.128.30','193.0.14.129','199.7.83.42','202.12.27.33']   #taken from https://www.iana.org/domains/root/servers 


def dnsudpresolve(query,dnstype,servertocheck):   # actually resolving a single iterative DNS query
  dnsform_query = dns.message.make_query(query, dnstype)
  try:
    dnsresp = dns.query.udp(dnsform_query, where =servertocheck, timeout=10)
  except:
    return None
  return dnsresp  

def hasanswer(dnsresp, dnstype):   # handling answer in DNS response and all cases
  anslist = []
  if len(dnsresp.answer) == 0:
    return []
  
  x = str(dnsresp.answer[0]).split('\n')
  for i in range(len(x)):
    y = x[i].split(' ')
    if dnstype == 'MX':
      if y[-3] == 'MX':
        anslist.append(y[-1])
    else:
      if y[-2] == dnstype:
        anslist.append(y[-1])
  if len(anslist) > 0:
    return anslist
    
  x = str(dnsresp.answer[0]).split('\n')
  for i in range(len(x)):
    y = x[i].split(' ')
    if y[-2] == 'CNAME':
      return client(y[-1],'A')
  return []



def dnsrespchecking(dnsresp,domainname,dnstype,ans): 
  dnsresp = dnsudpresolve(domainname,dnstype,ans)     #resolving one single iterative DNS query
  MSG_size = sys.getsizeof(dnsresp)
  if dnsresp is None:
    return []   
 
  servs = hasanswer(dnsresp, dnstype)                 # checking if we got the answer in response
  if len(servs) !=0:
    MSG_size = sys.getsizeof(dnsresp)
    return servs

  dnsserver = checkAdditional(dnsresp)                # checking in additional for IPs
  if dnsserver:
    return dnsrespchecking(dnsresp,domainname,dnstype,dnsserver)    
  
  dnsserver = checkAuthority(dnsresp)     # checking in authority for servers
  if dnsserver:
    return dnsrespchecking(dnsresp,domainname,dnstype,dnsserver)     
  return []

def dnsresolvefromroot(lastheader,dnstype):
  for root in rootservers:                                # trying to get output from root server
    dnsresp = dnsudpresolve(lastheader,dnstype,root)      # moves on to next root if old root doesn't give output
    if dnsresp is not None:                     
      return root


def client(domainname,dnstype):                 # dns resolution request from client machine
  root = dnsresolvefromroot(domainname,dnstype)    # solving part of DNS from root servers
  return dnsrespchecking(None,domainname,dnstype,root)    # solving dns


def mydig(domainname, dnstype):
  return client(domainname,dnstype)


answerl= mydig(domainname, dnstype)    # calling my dig tool

