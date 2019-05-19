#ifndef _NCOT_CONNECTION_
#define _NCOT_CONNECTION_

/* A connection is a securely encrypted TCP connection. As the whole
   thing is to provide a working proof of concept, we need encrypted
   connections right from the beginning. There were thoughts of
   implementing the principle of rings and nodes with unsecure tcp
   connections to get a running sample more quick, but the decision
   was made to implement with secure connections (and all the involved
   overhead) just from the beginning.
*/

struct ncotconnection {
  
}

#endif
