libncot	                     {#mainpage}
=======

Network of Trust
----------------
For information about nodes and rings of trust refer for example to the documentation of the struct ncot_node or refer directly to src/node.h.

libncot aims to help you to regain control over your data which may be scattered all over the Internet in untrusted locations. Huge centralized structures like social media sites, content aggregatores, search engines, cloud services only provide you with something you can do easily by yourself.

You can:

    - connect directly to any other device connected to the Internet (PC, Smartphone, Tablet). No centralized structure needed.
    - host your content, messages, comments, posts, pictures on your own devices or a docker server. No centralized structure needed.
    - can search the Internet for interesting content, messages, comments, posts, pictures using a network of circle of trust. No centralized structure needed.
    - decide on your own which content you expose to whom, based on the level of trust you have to others. No centralized structure needed.

A network of trust is a loosely connection of rings of trust, where each node of a ring represents a user. Every user in a ring of trust trusts the other participants in the same ring, and vice versa. Rings can be established, resolved, extended, participants can come and go. Every user can take part in as many rings as he wants. But all rings have one thing in common: they are decentralized. There is no server involved. All communication happens inside the rings and over the nodes. There is no need for a centralized structure at all. Every participant decides how he wants to take part in the whole network of trust. There comes a search request ? Decide on your own which data or content you want to expose to the whole public, and which only to your trusted friends. Another category could be the friends of your trusted friends and so on. Send a search request to your friends in your rings, and see what interesting search results are generated by the nodes of your friends itself. There is no need for a search engine. The decentralized Network of Trust propagates search requests and the results are directly send back by nodes which have appropriate data available. But thats not all. Rings can maintain policies, so any request which do not meet the requirements (Spam, Bulk Mail etc.) may be dropped. Networks of Trust put the use of the Internet to a new level.

### Can i use the Network of Trust with my webbrowser (Opera, Mozilla, lynx) ?
Yes, there will be dedicated web servers which will provide http access to nodes in the network.

### Can i view search results natively in my browser ?
Search responses for example will come from many different nodes in the network at once for any single search request, with latency. This does not fit so well into the limitations of the http/html protocol and language pattern. We are working on new standards.
    
### Where do i put my comments for youtube videos ?
There are docker images for hosting several types of content in an easy and manageable way. They use Plone and Castle CMS so you have security and control over your data. Viewing your comments below a youtube video requires the use of a proxy layer which aggregates the comments for this particular video from the network of trust participants and renders it. So you decide when and if your comment is available, and who may see it. Better host your videos your own and expose them to your friends or the public with fine grained access control.

### Can i send email over the network of trust ?
Messages can be sent directly to any participating node of the Internet in fact, there is no need for an email server in principle. But we use what we have. There is a docker image with a preinstalled and preconfigured sendmail and dovecot and squirrel which only needs your domain name, username and password to start up. No huge centralized structure needed.

### So what do i need to participate in the Network of Trust ?
libncot is in the early design, proof of concept and basic implementation stage. It compiles on Linux, uses autoconf Makefiles and aims portability to many other platforms.


This writing is part of the first publication process. 