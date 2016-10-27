// Author : iamgroot42

#include <bits/stdc++.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/sendfile.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#define REGISTER_PORT 5004 //Port for registrations
#define IRC_PORT 5005 //Port for normal communication
#define BUFFER_SIZE 512 //Maximum size per message

using namespace std;
// Indicator variables for status of server connection, login status
bool server_down = false, logged_in = false;
map<string,string> stage_two;
map<string,string> kdc_resp;

// Send data via the given socket-fd
int send_data(string data, int sock){
    const char* commy = data.c_str();
    if( (write(sock, commy, strlen(commy)) < 0) ){
        return 0;
    }
    return 1;
}

// Thread to read incoming data (from server)
void* server_feedback(void* void_listenfd){
	long listenfd = (long)void_listenfd;
	char buffer[BUFFER_SIZE];
	int ohho = 0;
	while(1){
		memset(buffer,'0',sizeof(buffer));
		ohho = read(listenfd,buffer,sizeof(buffer));
		// If server shuts down/terminates connection
		if(!ohho){
			cout<<">> Connection with server terminated!"<<endl;
			server_down = true;
			close(listenfd);
			return 0;
		}
		buffer[ohho] = 0;
		// Normal conversation; display on console
		cout<<">> "<<buffer<<endl;	
		char *pch = strtok_r(buffer," ", &STRTOK_SHARED);
		string command(pch);
		if(!command.compare("/handshake")){
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string alice(pch);
			srand(time(NULL));
			long nonce_B = long(rand());
			string encrypted_packet = encrypt(alice + " " + to_string(nonce_B), private_key);
			// Generate a nonce and return it with A, encrypted with Kbs
			string ret_ticket = "/check_ticket " + alice + " " + encrypted_packet;
			send_data(ret_ticket, listenfd);
		}
		else if(!command.compare("/receive_key")){
			string data(pch);
			data = decrypt(data, private_key);
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string shared_key(pch);
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string A(pch);
			// Assert that this is the same user as the one from which I received this packet
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string nonceB(pch);
			// Assert that this nonce is the same as the one I sent
			// Set global flag indicating successful NS exchange
		}
	}
}

// Create a socket connection for the given IP and port
int create_socket_and_connect(char* address, int port){
	int sock = 0;
	struct sockaddr_in serv_addr;
	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        cerr<<">> Socket creation error"<<endl;
        return 0;
    } 
	memset(&serv_addr, '0', sizeof(serv_addr)); 
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port); 
    if(inet_pton(AF_INET, address, &serv_addr.sin_addr)<=0){
        cerr<<">> Invalid address"<<endl;
        return 0;
    } 
    if( connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
        cerr<<">> Connection Failed"<<endl;
        return 0;
    }
    return sock;
}

string negotiate_key(int irc_sock, string alice, string bob){
	// Send a message to B, with my username
	string send, b_ticket, kdc_response;
	send = "/handshake " + alice;
	send_data(send, irc_sock);
	// B replies with (A,nonceB)Kbs
	while(1){
		nanosleep(1e5);
		if(stage_two.find(bob) != stage_two.end()){
			b_ticket = stage_two[bob];
			break;
		}
	}
	srand(time(NULL));
	// A sends a request to KDC with A,B,nonceA and above packet
	long nonceA = long(rand());
	send = "/negotiate " +  alice + " " + bob + " " + to_string(nonceA) + " " + b_ticket;
	send_data(send, irc_sock);
	// Server responds with (nonceA, Kab, B, (Kab,A,nonceB)Kbs)Kas
	while(1){
		nanosleep(1e5);
		if(kdc_resp.find(bob) != kdc_resp.end()){
			kdc_response = kdc_resp[bob];
			break;
		}
	}
	kdc_response = decrypt(kdc_response);
	char* buffer = kdc_response.c_str();
	char *pch = strtok_r(buffer," ", &STRTOK_SHARED);
	string a_nonce(pch);
	pch = strtok_r (NULL, " ", &STRTOK_SHARED);
	string Kab(pch);
	pch = strtok_r (NULL, " ", &STRTOK_SHARED);
	string bob_check(pch);
	pch = strtok_r (NULL, " ", &STRTOK_SHARED);
	string send_to_b(pch);
	// A sends (Kab,A,nonceB)Kbs as it is to B
	send = "/receive_key " + send_to_b;
	send_data(send, irc_sock);
	// At this stage, both parties have the shared key, which can be used for encryption
	return Kab;
}

int main(int argc, char *argv[]){
	// Argument: IP address of server
	if(argc<2){
		cout<<"Usage: "<<argv[0]<<" <server ip>"<<endl;
		return 0;
	}
	// Establish connection
	long irc_sock,register_sock;
	irc_sock = create_socket_and_connect(argv[1], IRC_PORT);
	register_sock = create_socket_and_connect(argv[1], REGISTER_PORT);
    // Create thread for receiving messages on irc socket
	pthread_t pot;
    pthread_create(&pot, NULL, server_feedback, (void*)irc_sock);
    // Create thread for receiving messages on register socket
	pthread_t pot2;
    pthread_create(&pot2, NULL, server_feedback, (void*)register_sock);
	string send, username, password, command,current_username = "";
	cout<<">> Welcome to kdchat!"<<endl;
	cout<<">> 1. Idenfity yourself\n>> 2. Register"<<endl;
	int option;
	// Log in/Register user
	cin>>option;
	if(option == 1){
		cout<<">> Enter your username"<<endl;
		cin>>current_username;
	}
	else{
		REGISTER_YOURSELF:
		cin>>user
		cin>>password;
		send = username + " " + password;
		current_username = username;
		if(!send_data(send, register_sock)){
			cout<<">> Error in registration. Please try again."<<endl;
			goto REGISTER_YOURSELF;
		}
	}
	while(1){
		// Kill main thread if server is down.
		if(server_down){
			return 0;
		}
		if(current_username.empty()){
			cout<<">> Identify yourself/Register "
		}
		cin>>command;
		if(!command.compare("/exit")){
			// Communicate logout action to server
			bool kill = true;
			if(logged_in){
				if(!send_data(command ,irc_sock)){
					cout<<">> Error logging out. Please try again."<<endl;
					kill = false;
				}
			}
			if(kill){
				// Kill thread listening for feedback
				pthread_kill(pot,0);
				close(irc_sock);
				close(register_sock);
				cout<<">> Exiting!\nThanks for using IRsea!"<<endl;
				return 0;
			}
		}
		else if(!command.compare("/who") && logged_in){
			send = command + " " +  username + " " + password;
			if(!send_data(send, irc_sock)){
				cout<<">> Error communicating with server. Please try again."<<endl;
			}
		}
		else if(!command.compare("/msg") && logged_in){
			cin>>username;
			getline(cin, password);
			send = command + " " + username + " " + password;
			// Check if session key is stale or not. If it is, re-negotiate it with KDC
			if(!send_data(send, irc_sock)){
				cout<<">> Error communicating with server. Please try again."<<endl;
			}
		}
		else{
			// Invalid command(s)
			if(logged_in){
				cout<<">> Invalid command! Please read the README for the list of supported commands"<<endl;
			}
			// Not logged in
			else{
				cout<<">> Not signed in!"<<endl;	
			}
		}
	}
	return 0;
}
