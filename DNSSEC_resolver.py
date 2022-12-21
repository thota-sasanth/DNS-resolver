import dns.message,dns.name   # required imports
import dns.query
import time,datetime,sys

rootservers = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13','192.203.230.10','192.5.5.241','192.112.36.4','198.97.190.53',
               '192.36.148.17','192.58.128.30','193.0.14.129','199.7.83.42','202.12.27.33']
root_dsksklist =  ['19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5','20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d']  # valid root ds record taken from http://data.iana.org/root-anchors/root-anchors.xml

def dnsudpresolve(query,dnstype,servertocheck):     
  dnsform_query = dns.message.make_query(query, dnstype,want_dnssec = True)
  try:
    dnsresp = dns.query.udp(dnsform_query, where =servertocheck, timeout=10)  #actually resolving a single iterative DNS query with dnssec on
  except:
    return None
  return dnsresp  

def hasanswer(dnsresp, dnstype):     # handling answer in DNS response and all cases
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

def validation(dns_rrset,dns_zsk ,dns_ksk, dns_rrsig, domain, dsksklist, hashalgo ):  # validating the DNSKEY RRSET,DNSKEY RRSIG, DS, DS RRSIG
  if dns_rrset and dns_zsk  and dns_ksk and dns_rrsig and (len(dsksklist) !=0):
    try :
      dns.dnssec.validate(dns_rrset,dns_rrsig,{dns.name.from_text(domain) : dns_rrset } )   # validating DNS RRSET
    except:
      print("DNSSec verification failed")    # return if validation failed
      return False
    hashed_dnsksk = dns.dnssec.make_ds(str(domain)+'.', dns_ksk, hashalgo)  

    for dsksk in dsksklist:
      if str(dsksk) == str(hashed_dnsksk):        # validating DS with DNSKEY of child server
        return True
    print("DNSSec verification failed")   # return if verification fails
    return False
  print("DNSSEC not supported")    # return if we cannot get dnssec data such as dns rrset/dnskeydns/rrsig/etc.. 
  return False


def dnsrespchecking(dnsresp,domainname,dnstype,ans,ans_pubksk,domainlist,s,hash_algo):   
  if s == len(domainlist):   # spliting domain for DNSKEY query
    domainname_dns = ''  
  elif s > 0 :
    domainname_dns = '.'.join(domainlist[s:])
  else:
    domainname_dns = domainname
  
  dnsresp_dns = dnsudpresolve(domainname_dns,'DNSKEY',ans)   # DSNKEY query to server
  x = dnskeyres(dnsresp_dns.answer)
  dns_rrset, dns_zsk , dns_ksk ,dns_rrsig = x[0], x[1], x[2], x[3]
  if not validation(dns_rrset,dns_zsk , dns_ksk, dns_rrsig, domainname_dns,ans_pubksk, hash_algo):  # calling our main validation function
    return []              # retunr empty if not validated
  
  dnsresp_sec = dnsudpresolve(domainname,'A',ans)     # resolving one single iterative DNS query with type 'A' to server
  y = dskeyres(dnsresp_sec)
  ds,hash_algo1,ds_rrsig = y[0],y[1],y[2]

  dnsresp = dnsresp_sec

  if dnsresp is None:
    return []
 
  servs = hasanswer(dnsresp, dnstype)   # checking if we got the answer in response
  if len(servs) !=0:
    return servs

  dnsserver = checkAdditional(dnsresp)    # checking in additional for IPs
  if dnsserver:
    return dnsrespchecking(dnsresp,domainname,dnstype,dnsserver,ds,domainlist,s-1,hash_algo1)
  
  dnsserver = checkAuthority(dnsresp)     # checking in authority for servers
  if dnsserver:
    return dnsrespchecking(dnsresp,domainname,dnstype,dnsserver,ds,domainlist,s-1,hash_algo1)
  return []

def dnsresolvefromroot(domain,dnstype):
  for root in rootservers:                            # moves on to next root if old root doesn't give output
    dnskeyresp = dnsudpresolve('.','DNSKEY',root)   # trying to get DNSKEY output from root server
    if dnskeyresp is not None: 
      dnsresp = dnsudpresolve(domain,dnstype,root)  # trying to get "A" output from root server
      if dnsresp is not None:
        return root
  return None


def client(domainname,dnstype):             # dnssec resolution request from client machine
  domainnamelist = domainname.split('.')    # split domain to send last part to root
  if domainnamelist[-1].strip() == '':
    domainnamelist = domainnamelist[:-1]

  root = dnsresolvefromroot(domainname,dnstype) 
  if not root:
    return []

  return dnsrespchecking(None,domainname,dnstype,root,root_dsksklist,domainnamelist,len(domainnamelist), 'sha256') # solving dnssec


def mydig(domainname, dnstype):
  return client(domainname,dnstype)


answerl= mydig(domainname, dnstype)
