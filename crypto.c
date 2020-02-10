/** This is the result of weeks of research about how to implement a
 * single secure point to point connection over an untrusted network
 * without a CA, but with ssh-like public/private key files and out of
 * band security token verfifcation to authenticate the peer endpoint.
 *
 * One might think why not use the ssh protocol directly ? In fact it
 * looks like we do very similar, but we were unable to find a library
 * aleady implementing the protocl/crypto stuff like we need it to fit
 * with its api into our application needs. That is, we need full
 * control over the bytes read/written to the many sockets to act
 * accordingly and dispatch packets, take action upon it. Use
 * callbacks to a minimum.
 *
 * So we decided to implement a subset of the ssh protocol, extend it
 * to our needs based upon a low level crypto api, currently nettle.*/

