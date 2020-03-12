# HTTProxy  
Simple Host based HTTP(S) proxy  
-------
So… You need a proxy, but can't actually set a proxy?  
HTTProxy is here for you!
  
It couldn't be simpler.  
It just ignores the destination address(you(or similar, not here to judge any men in the middle)) and proxies it to the address specified in the "Host" header.  
  
Great for when you are trying to get through SSL connections while using DNS poisoning, in which case you lose the destination address, or with ARP poisoning, in which case you just need something to open the connection for you!  
  
You will need a cert:  
```openssl req -x509 -nodes -newkey rsa:2048 -keyout server.pem -out server.pem```  
  
~~It doesn't really extract much as I am just commiting this to be able to retrieve and finish it later, hopefuly I will remember to update this in the future.~~ 

Done! It does more useful stuff now. 

Good Luck!
