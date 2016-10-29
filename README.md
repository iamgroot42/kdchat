# kdchat

## About

A chat server to allow exchange of message between two parties, with authentication and authorization. Made as a course assignment for Network Security (CSE550). Implements Needham–Schroeder protocol for 2-party authentication and encryption of messages.
The following commands are supported :

* `/register <USERNAME> <PASSWORD>` : register yourself with the server
* `/login <USERNAME> <PASSWORD>` : register yourself with the server
* `/who` : see all the users who're logged in right now
* `/exit` : log out and exit from the service
* `/msg <USERNAME> <MESSAGE>` : send a message to a specific user
* `/handshake <USERNAME>` : negotiate a common encryption key with the KDC

## Working

### Server

* Three threads work in parallel.
* One thread listens on the port assigned for registration of users.
* One thread clears the outgoing message queue by sending data to respective users.
* One thread creates a new thread (for communication) for every incoming request by the client. This thread is deleted once the client is done with their interaction with the server.


### Client
* Two threads work in parallel.
* One thread listens to the server for incoming data (which may be sent by the server itself, or data redirected by the server).
* One thread is for HCI; sending data to the server as the user requests.


## Running it
* To run the server, run:  ` make`. Then, run it as `./server` (from server folder).
* To run a client, run:  ` make`. Then, run it as `./client <SERVER ADDRESS>` (from client folder)
* Run `make clean` to remove compiled programs.


## Specifics
* Default users (hello,world) & (test,user) for testing.
* Maximum length per message (before encryption): 1024 characters.
* strtok() is not thread safe (as standard implementation doesn't use TLS). Thus, strtok_r() has been used.
* 'User is offline/doesn't exist' is flashed to the client if they try messaging a user who is offline or doesn't exist (further specification isn't provided to avoid any secutiry attacks).


## Cases tested (& handled)



### Example (for client)
```


```
