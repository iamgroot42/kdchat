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
#define BUFFER_SIZE 1024 //Maximum size per message

using namespace std;
// Indicator variables for status of server connection, login status
bool server_down = false, logged_in = false;
map<string,string> shared_keys;
map<string, string> sent_nonce;
set<string> good_to_go;
string my_username, my_private_key, self_nonce;

// Send data via the given socket-fd
int send_data(string data, int sock){
    const char* commy = data.c_str();
    if( (write(sock, commy, strlen(commy)) < 0) ){
        return 0;
    }
    return 1;
}

string encrypt(string data, string key){
	return data;
}

string decrypt(string data, string key){
	return data;
}

// Thread to read incoming data (from server)
void* server_feedback(void* void_listenfd){
	long listenfd = (long)void_listenfd;
	char buffer[BUFFER_SIZE];
	char* STRTOK_SHARED;
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
		char *pch = strtok_r(buffer," ", &STRTOK_SHARED);
		string command(pch);
		if(!command.compare("/msg")){
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string message(pch);
			cout<<">> "<<message<<endl;
		}
		else if(!command.compare("/handshake")){
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string alice(pch);
			srand(time(NULL));
			long nonce_B = long(rand());
			sent_nonce[alice] = to_string(nonce_B);
			string encrypted_packet = encrypt(alice + " " + to_string(nonce_B), my_private_key);
			// Generate a nonce and return it with A, encrypted with Kbs
			string ret_ticket = "/check_ticket " + alice + " " +  encrypted_packet;
			send_data(ret_ticket, listenfd);
		}
		else if(!command.compare("/receive_key")){
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string data(pch);
			data = decrypt(data, my_private_key);
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
		else if(!command.compare("/check_ticket")){
			pch = strtok_r(NULL, " ", &STRTOK_SHARED);
			string bob(pch);
			// Extract b_ticket
			pch = strtok_r(NULL, " ", &STRTOK_SHARED);
			string b_ticket(pch);
			srand(time(NULL));
			// A sends a request to KDC with A,B,nonceA and above packet
			self_nonce = to_string(long(rand()));
			string send = "/negotiate " +  my_username + " " + bob + " " + self_nonce + " " + b_ticket;
			send_data(send, listenfd);	
		}
		else if(!command.compare("/negotiated_key")){
			string decr_this(STRTOK_SHARED);
			char *dup = strdup(decrypt(decr_this, my_private_key).c_str());
			pch = strtok_r (dup, " ", &STRTOK_SHARED);
			string nonce_a(pch);
			//Verify that nonce is same
			assert(!self_nonce.compare(nonce_a));
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string k_ab(pch);
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string bob(pch);
			// Set shared key for future communication
			shared_keys[bob] = k_ab;
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string bob_confirmticket(pch);
			// Forward confirm_ticket as it is to bob
			string send = "/bob_receive " + bob + " " + bob_confirmticket;
			send_data(send, listenfd);
		}
		else if(!command.compare("/bob_receive")){
			char *dup = strdup(decrypt(pch, my_private_key).c_str());
			pch = strtok_r (dup, " ", &STRTOK_SHARED);
			string k_ab(pch);
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string alice(pch);
			// Set shared key for future communication
			shared_keys[alice] = k_ab;
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string b_nonce(pch);
			// Check that bnonce hasn't been tampered with
			assert(!b_nonce.compare(self_nonce));
			send_data("/okay " + alice, listenfd);
		}
		else if(!command.compare("/okay")){
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string bob(pch);
			// we can now start exchanging encrypted messages with bob
			good_to_go.insert(bob);
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
		cin>>current_username;
		cin>>password;
		send = current_username + " " + password;
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
			cout<<">> Identify yourself/Register"<<endl;
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
			if(good_to_go.find(username) != good_to_go.end() && !shared_keys.count(username)){
				getline(cin, password);
				password = encrypt(password, shared_keys[username]);
				send = command + " " + username + " " + password;
			}
			else{
				cout<<">> Shared key not negotiated. Please run /negotiate."<<endl;
			}
			if(!send_data(send, irc_sock)){
				cout<<">> Error communicating with server. Please try again."<<endl;
			}
		}
		else if(!command.compare("/handshake")){
			cin>>username;
			send = "/handshake " + username + " " + my_username;
			send_data(send, irc_sock);
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
