# DNSSEC-resolver
## Description
The aim of this project is to build a custom DNS resolver that supports the DNSSEC (Domain Name System Security Extensions) protocol. The resolver performs the traditional DNS resolution on different domain types (A, NS, MX) and also reports performance metrics such as the query resolution time. To have a secure resolution, the DNS resolver uses the DNSSEC protocol. <br>

## Working
Workflow of a DNSSEC resolver - <br>
<br>
<p align="center">
  <img src="https://github.com/thota-sasanth/DNSSEC-resolver/blob/main/DNSSEC_workflow.jpeg" width="600" height="500">
</p>
<br>
## Implementation
First, we take input the "<domainname>" for which we want to do the DNSSEC resolution.
We start with the root and do the dnssec resolution iteratively.
We split the domain name with "." and keep appending each part of domain name for every
query we send with type “DNSKEY” to nameservers . We first start by sending "." with type
“DNSKEY” to root server. If there is no response from root we take the subsequent root in our predefined roots list.
This query returns DNSKEY RRSET which contains public ZSK, KSK, and DNS RRSIG.
<br>
<br>
<p align="center">
  <img src="https://github.com/thota-sasanth/DNSSEC-resolver/blob/main/RRset.png" width="500" height="200">
</p>
<br>

We then validate the DNS RRSET using our user-defined function called “validation”. In validation,
we check if DNSKEY records are present or not. If no DNSKEY records are present, that means
the DNSSEC is not supported on those servers.If records are returned, then, we use dnspython custom function to validate the DNSKEY
RRSET and DNSKEY RRSIG. If validation fails, we return “DNSSec verification failed”.
  
Once we have verified DNSKEY records, we then send our DNS “A” request to server. This
returns us the partial domain (say ‘com.’) name server IP address as well as parent zone’ DS
record for child (i.e ‘com.’ name server) and DS RRSIG. We store the DS record of child as we
need it for validation of chain of trust. We validate the parent zone’ DS record for child by using
the parent server’s pub ZSK.
  
Now, we send a DNSKEY request to child server since we have already received it’s IP earlier. We
get DNSKEY RRSET, DNSKEY RRSIG. Now we validate if the pub KSK in the DNSKEY RRSET
with the DS record by using hashing function. IF hashes are not same then we cannot trust the
child server. Hence, we return “DNSSec verification failed” in that case.
If hashes match then we can trust the child server and the chain of trust expands. 

Now we repeat the same process for the child server until we get to the authoritative name server which
has the actual IP of our domain name. We get the response from the authoritative name server
and return it as “Verified IP Address”.


## Results
The following are the results of our DNSSEC resolver for different DNS types : 
<br>
<br>
<p align="center">
  <img src="https://github.com/thota-sasanth/DNSSEC-resolver/blob/main/A_type.png" width="800" height="200">
</p>
<br>
<br>
<br>
<p align="center">
  <img src="https://github.com/thota-sasanth/DNSSEC-resolver/blob/main/NS_type.png" width="800" height="200">
</p>
<br>
<br>
<br>
<p align="center">
  <img src="https://github.com/thota-sasanth/DNSSEC-resolver/blob/main/MX%20type.png" width="800" height="200">
</p>
<br>
<br>
<br>
