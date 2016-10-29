// Author : iamgroot42

#include <bits/stdc++.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/sendfile.h>
#include <arpa/inet.h> 

#define REGISTER_PORT 5009 //Port for registrations
#define KDC_PORT 5010 //Port for normal communication
#define BUFFER_SIZE 1024 //Maximum size per message
#define USER_FILENAME "users" //Filename containing username & passwords

using namespace std;

// Create a 1-1 mapping between current socket and username (for efficient access)
map<string,int> name_id;
map<int,string> id_name;
// A set of FDs of currently active users
set<int> active_users;
// Username-password mapping..stored as cache, written to memory when program ends
map<string, string> username_password;
// A queue which contains outgoing p2p data
queue< pair<int, string> > chat;

// Send data back to the client
int send_data(string data, int sock)
{
    const char* commy = data.c_str();
    if( (write(sock, commy, strlen(commy)) < 0) )
    {
        return 0;
    }
    return 1;
}

// Read registered accounts from file
void populate_userlist(){
	fstream file(USER_FILENAME, ios::in);
	char* STRTOK_SHARED;
	string line;
	if (file.is_open()){
	    while(getline(file,line)){
      		char* pch = strtok_r(strdup(line.c_str()), " ", &STRTOK_SHARED);
      		string username(pch);
      		pch = strtok_r(NULL, " ", &STRTOK_SHARED);
      		string password(pch);
      		username_password[username] = password;
    	}
    	file.close();
  	}
  	else{
  		cout<<"LOG : users' file not created yet."<<endl;
  	}
}

string encrypt(string data, string key){
	return data;
}

string decrypt(string data, string key){
	return data;
}

// Create a shared-key for Alice and Bob
string mutual_key(string alice, string bob){
	return username_password[alice] + "ohho" + username_password[bob];
}

// Thread to listen to register users
void* register_user(void* argv){
	// Populate username_password
	populate_userlist();
	// Open file for writing username-password pairs
	fstream file(USER_FILENAME, ios::app);
    // Socket creation snippet
	char buffer[BUFFER_SIZE];
	char* STRTOK_SHARED;
    string confirm = "Registered!";
	int listenfd = 0, connfd = 0, ohho = 0;
	sockaddr_in serv_addr; 
	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&serv_addr, '0', sizeof(serv_addr)); 
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(REGISTER_PORT); 
	bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)); 
	listen(listenfd, 5);
	while(1){
		connfd = accept(listenfd, (struct sockaddr*)NULL, NULL); 
		if(connfd >= 0){
            char *pch;
            memset(buffer,'0',sizeof(buffer));
            ohho = read(connfd,buffer,sizeof(buffer));
            if(!ohho){
                continue;
            }
            buffer[ohho] = 0;
            cout<<"LOG : /register "<<buffer<<endl;
            pch = strtok_r(buffer," ", &STRTOK_SHARED);
            string username(pch);
            pch = strtok_r (NULL, " ", &STRTOK_SHARED);
            string password(pch);
            username_password.insert(make_pair(username,password));
            send_data(confirm, connfd);
            // Write to file (not working rn)
            file<<username<<" "<<password<<endl;
        }
    }
    file.close(); 
}

// Checks if the given combination is valid, and this user is currently logged in
bool is_online(int x){
	if(active_users.find(x) != active_users.end()){
    	return true;
    }
    return false;
}

// String representation of all users currently online
string online_users(){
	string ret_val = "";
	for (set<int>::iterator it=active_users.begin(); it!=active_users.end(); ++it){
		ret_val += id_name[*it] + "\n";
	}
	return ret_val.substr(0, ret_val.size()-1);
}

// Client ended connection; remove everything associated with them
void remove_user(int c){
	active_users.erase(c);
	name_id.erase(id_name[c]);
	id_name.erase(c);
	// Close this connection
	close(c);
}

// A thread spawned per connection, to handle all incoming requests from there
void* per_user(void* void_connfd){
    string current_username;
	long connfd = (long)void_connfd;
	int ohho = 0, logged_in = 0;
	char buffer[BUFFER_SIZE];
	char* STRTOK_SHARED;
    while(1){
    	memset(buffer,'0',sizeof(buffer));
		ohho = read(connfd,buffer,sizeof(buffer));
		if(!ohho){
			remove_user(connfd); // Remove active-user
			return 0; //End thread
		}
		buffer[ohho] = 0;
		cout<<"LOG : "<<buffer<<endl;
		// Extract command type from incoming data
		char *pch = strtok_r(buffer," ", &STRTOK_SHARED);
		string command(pch);
		logged_in = is_online(connfd);
		if(!command.compare("/login")){
			try{
				pch = strtok_r (NULL, " ", &STRTOK_SHARED);
				string username(pch);
                pch = strtok_r (NULL, " ", &STRTOK_SHARED);
                string password(pch);
				if(!username_password[username].compare(password)){
					send_data("Signed-in!", connfd);
					// Update 1-1(effective) mapping of connectionID and username
                    current_username = username;
					name_id[username] = connfd;
					id_name[connfd] = username;
					active_users.insert(connfd); // Update list of active users
				}
				else{
					send_data("Error signing in!", connfd);
				}
			}
			catch(...){
				send_data("Malformed message!", connfd);
			}
		}
		else if(!command.compare("/who") && logged_in){
        	send_data(online_users().c_str(), connfd);
     	}
     	else if(!command.compare("/exit") && logged_in){
			remove_user(connfd); // Remove active-user
			return 0; //End thread;
     	}
     	else if(!command.compare("/msg") && logged_in){
     		try{
     			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
				string to(pch);
                cout<<STRTOK_SHARED<<" GOT IT ;)\n";
				string data(STRTOK_SHARED);
                if (!is_online(name_id[to])){
                    send_data("User is offline/doesn't exist!", connfd);
                }
                string msg("/msg");
                data = "(" + id_name[connfd] + ") " + data;
				chat.push(make_pair(name_id[to], data)); // Push outgoing message to queue
			}
			catch(...){
				send_data("Malformed message!", connfd);
			}
     	}
        // else if((!command.compare("/handshake") || !command.compare("/msg")) && logged_in){
        else if(!command.compare("/handshake") && logged_in){
            pch = strtok_r (NULL, " ", &STRTOK_SHARED);
            string to(pch);
            pch = strtok_r (NULL, " ", &STRTOK_SHARED);
            string data(pch);
            if (!is_online(name_id[to])){
                send_data("User is offline/doesn't exist!", connfd);
            }
            data = command + " " + data;
            chat.push(make_pair(name_id[to], data)); // Push outgoing message to queue
        }
        else if(!command.compare("/check_ticket") && logged_in){
            pch = strtok_r (NULL, " ", &STRTOK_SHARED);
            string to(pch);
            string data(STRTOK_SHARED);
            if (!is_online(name_id[to])){
                send_data("User is offline/doesn't exist!", connfd);
            }
            data = command + " " + id_name[connfd] + " " + data;
            chat.push(make_pair(name_id[to], data)); // Push outgoing message to queue   
        }
        else if(!command.compare("/bob_receive") && logged_in){
            pch = strtok_r (NULL, " ", &STRTOK_SHARED);
            string to(pch);
            string data(STRTOK_SHARED);
            if (!is_online(name_id[to])){
                send_data("User is offline/doesn't exist!", connfd);
            }
            data = command + " " + data;
            chat.push(make_pair(name_id[to], data)); // Push outgoing message to queue   
        }
        else if(!command.compare("/okay") && logged_in){
            pch = strtok_r (NULL, " ", &STRTOK_SHARED);
            string to(pch);
            if (!is_online(name_id[to])){
                send_data("User is offline/doesn't exist!", connfd);
            }
            string data = command + " " + id_name[connfd];
            chat.push(make_pair(name_id[to], data)); // Push outgoing message to queue   
        }
     	else if(!command.compare("/negotiate") && logged_in){
     		try{
     			pch = strtok_r(NULL, " ", &STRTOK_SHARED);
     			string alice(pch);
     			// Assert is Alice sent this packet
     			assert(!alice.compare(id_name[connfd]));
     			pch = strtok_r(NULL, " ", &STRTOK_SHARED);
     			string bob(pch);
     			pch = strtok_r(NULL, " ", &STRTOK_SHARED);
     			string a_nonce(pch);
     			string b_ticket(STRTOK_SHARED);
     			// Decrypt b_ticket to extract B_nonce
     			b_ticket = decrypt(b_ticket, username_password[bob]);
     			char *dup = strdup(b_ticket.c_str());
     			char *temp = strtok_r(dup," ", &STRTOK_SHARED);
     			string should_be_alice(temp);
     			// Unnecessary check
     			assert(!should_be_alice.compare(alice));
     			string b_nonce(strtok_r(NULL," ", &STRTOK_SHARED));
     			// Come up with Kab	
     			string b_retticket, Kab;
     			Kab = mutual_key(alice, bob);
     			b_retticket = Kab + " " + alice + " " + b_nonce;
     			b_retticket = encrypt(b_retticket, username_password[bob]);
     			string data = a_nonce + " " + Kab + " " + bob + " " + b_retticket;
     			data = encrypt(data, username_password[alice]);
     			chat.push(make_pair(name_id[alice], "/negotiated_key " + data));
     		}
     		catch(...){
     			send_data("Malformed message!", connfd);	
     		}
     	}
	}
}

// Empties the send-queue by sending messages to respective clients
void* send_back(void* argv){
	pair<int, string> x;
	while(true){
		while(chat.size()){
			x = chat.front();
			chat.pop();
			send_data(x.second, x.first);
		}	
	}
}

// Main process
int main(){
    pthread_t pot,pot2;
    // Thread to handle registrations
    pthread_create(&pot, NULL, register_user, NULL);
    // Thread to handle out-going p2p messages
    pthread_create(&pot2, NULL, send_back, NULL);
    // Main thread
    int listenfd = 0;
    long connfd = 0;
    sockaddr_in serv_addr; 
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr)); 
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(KDC_PORT); 
    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)); 
    listen(listenfd, 15);
    while(1){
        connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);
        // New thread per user (for communication)
    	pthread_t pot_temp;
        pthread_create(&pot_temp, NULL, per_user, (void*)connfd);
    } 
    return 0;
}
