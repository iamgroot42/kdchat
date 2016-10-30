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
#include <openssl/evp.h>

#define REGISTER_PORT 5009 //Port for registrations
#define KDC_PORT 5010 //Port for normal communication
#define BUFFER_SIZE 1024 //Maximum size per message

using namespace std;
// Indicator variables for status of server connection, login status
bool server_down = false, logged_in = false;
map<string,string> shared_keys;
map<string, string> sent_nonce;
set<string> good_to_go;
string my_username, my_private_key;

// Send data via the given socket-fd
int send_data(string data, int sock){
    const char* commy = data.c_str();
    if( (write(sock, commy, strlen(commy)) < 0) ){
        return 0;
    }
    return 1;
}

string random_string(int length){
    static const char alphanum[] ="0123456789!@#$^&*ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    int stringLength = sizeof(alphanum) - 1;
    srand(time(NULL));
    string rand_str("");
    for(int i = 0; i < length; ++i){
        rand_str = rand_str + alphanum[rand() % stringLength];
    }
    return rand_str;
}

string encrypt(string data, string pass_key, string init_vector){
	unsigned char *plaintext, *key, *iv;
	plaintext = (unsigned char*)data.c_str();
	key = (unsigned char*)pass_key.c_str();
	iv = (unsigned char*)init_vector.c_str();
	unsigned char ciphertext[data.length() * 8];
	EVP_CIPHER_CTX *ctx;
	int len, ciphertext_len, plaintext_len;
	plaintext_len = data.length();
	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
	ciphertext_len = len;
	EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	string encrypted_text((const char*)ciphertext);
	return encrypted_text;
}

string decrypt(string data, string pass_key, string init_vector){
	unsigned char  *ciphertext, *key, *iv;
	unsigned char plaintext[data.length() * 1];
	ciphertext = (unsigned char*)data.c_str();
	key = (unsigned char*)pass_key.c_str();
	iv = (unsigned char*)init_vector.c_str();
	EVP_CIPHER_CTX *ctx;
	int len, plaintext_len, ciphertext_len;
	ciphertext_len = data.length();
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
  	plaintext_len = len;
  	EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
  	plaintext_len += len;
  	EVP_CIPHER_CTX_free(ctx);
  	string decrypted_text((const char*)plaintext);
	return decrypted_text;
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
		char *pch = strtok_r(buffer," ", &STRTOK_SHARED);
		string command(pch);
		if(!command.compare("/handshake")){
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string alice(pch);
			srand(time(NULL));
			long nonce_B = long(rand());
			sent_nonce[alice] = to_string(nonce_B);
			string iv = random_string(16);
			string encrypted_packet = encrypt(alice + " " + to_string(nonce_B), my_private_key, iv);
			// Generate a nonce and return it with A, encrypted with Kbs
			string ret_ticket = "/check_ticket " + alice + " " + iv + " " + encrypted_packet;
			send_data(ret_ticket, listenfd);
		}
		else if(!command.compare("/check_ticket")){
			pch = strtok_r(NULL, " ", &STRTOK_SHARED);
			string bob(pch);
			pch = strtok_r(NULL, " ", &STRTOK_SHARED);
			string iv(pch);
			// Extract b_ticket
			string b_ticket(STRTOK_SHARED);
			srand(time(NULL));
			// A sends a request to KDC with A,B,nonceA and above packet
			sent_nonce[bob] = to_string(long(rand()));
			string send = "/negotiate " +  my_username + " " + bob + " " + sent_nonce[bob] + " " + iv + " " + b_ticket;
			send_data(send, listenfd);	
		}
		else if(!command.compare("/negotiated_key")){
			pch = strtok_r(NULL, " ", &STRTOK_SHARED);
			string iv_a(pch);
			string decr_this(STRTOK_SHARED);
			char *dup = strdup(decrypt(decr_this, my_private_key, iv_a).c_str());
			pch = strtok_r (dup, " ", &STRTOK_SHARED);
			string nonce_a(pch);
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string k_ab(pch);
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string bob(pch);
			//Verify that nonce is same
			assert(!sent_nonce[bob].compare(nonce_a));
			// Set shared key for future communication
			shared_keys[bob] = k_ab;
			string bob_confirmticket(STRTOK_SHARED);
			// Forward confirm_ticket as it is to bob
			string send = "/bob_receive " + bob + " " + bob_confirmticket;
			send_data(send, listenfd);
		}
		else if(!command.compare("/bob_receive")){
			pch = strtok_r(NULL, " ", &STRTOK_SHARED);
			string iv_b(pch);
			string decryp(STRTOK_SHARED);
			char *dup = strdup(decrypt(decryp, my_private_key, iv_b).c_str());
			pch = strtok_r (dup, " ", &STRTOK_SHARED);
			string k_ab(pch);
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string alice(pch);
			// Set shared key for future communication
			shared_keys[alice] = k_ab;
			good_to_go.insert(alice);
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string b_nonce(pch);
			// Check that bnonce hasn't been tampered with
			assert(!b_nonce.compare(sent_nonce[alice]));
			send_data("/okay " + alice, listenfd);
		}
		else if(!command.compare("/okay")){
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string bob(pch);
			// we can now start exchanging encrypted messages with bob
			good_to_go.insert(bob);
		}
		else if(!command.compare("/msg")){
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string bob(pch);
			pch = strtok_r (NULL, " ", &STRTOK_SHARED);
			string iv(pch);
			string data(STRTOK_SHARED);
			string message = decrypt(data, shared_keys[bob], iv);
			string printout = "(" + bob + ") " + message;
			cout<<">> "<<printout<<endl;
		}
		else{
			if(!strcmp("Signed-in!",buffer)){
				logged_in = true;
			}
			cout<<">> "<<buffer<<endl;
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
	long kdc_sock,register_sock;
	kdc_sock = create_socket_and_connect(argv[1], KDC_PORT);
	register_sock = create_socket_and_connect(argv[1], REGISTER_PORT);
    // Create thread for receiving messages on irc socket
	pthread_t pot;
    pthread_create(&pot, NULL, server_feedback, (void*)kdc_sock);
    // Create thread for receiving messages on register socket
	pthread_t pot2;
    pthread_create(&pot2, NULL, server_feedback, (void*)register_sock);
	string send, username, password, command;
	cout<<">> Welcome to kdchat!"<<endl;
	while(1){
		// Kill main thread if server is down.
		if(server_down){
			return 0;
		}
		cin>>command;
		if(!command.compare("/register") ){
			cin>>username;
			cin>>password;
			unsigned char hashed[128];
			// Calculate hash of password
			PKCS5_PBKDF2_HMAC(password.c_str(),-1,NULL,0,128,EVP_sha256(),5,hashed);
			string hashed_password((const char*)hashed);
			send = username + " " + hashed_password;
			if(!send_data(send, register_sock)){
				cout<<">> Error in registration. Please try again."<<endl;
			}
		}
		else if(!command.compare("/login")){	
			cin>>username;
			cin>>password;
			unsigned char hashed[128];
			// Calculate hash of password
			PKCS5_PBKDF2_HMAC(password.c_str(),-1,NULL,0,128,EVP_sha256(),5,hashed);
			string hashed_password((const char*)hashed);
			if(logged_in){
				cout<<">> Already logged in!"<<endl;
			}
			else{
				send = "/login " + username + " " + hashed_password;
				if(!send_data(send, kdc_sock)){
					cout<<">> Error logging-in. Please try again."<<endl;
				}
				else{
					my_username = username;
					my_private_key = hashed_password;
				}
			}
		}
		else if(!command.compare("/exit")){
			// Communicate logout action to server
			bool kill = true;
			if(logged_in){
				if(!send_data(command ,kdc_sock)){
					cout<<">> Error logging out. Please try again."<<endl;
					kill = false;
				}
			}
			if(kill){
				// Kill thread listening for feedback
				pthread_kill(pot,0);
				close(kdc_sock);
				close(register_sock);
				cout<<">> Exiting!\nThanks for using IRsea!"<<endl;
				return 0;
			}
		}
		else if(!command.compare("/who") && logged_in){
			if(!send_data(command, kdc_sock)){
				cout<<">> Error communicating with server. Please try again."<<endl;
			}
		}
		else if(!command.compare("/msg") && logged_in){
			cin>>username;
			if(good_to_go.find(username) != good_to_go.end() && shared_keys.count(username)){
				getline(cin, password);
				string iv = random_string(16);
				password = encrypt(password, shared_keys[username], iv);
				send = command + " " + username + " " + iv + " " + password;
			}
			else{
				cout<<">> Shared key not negotiated. Please run /handshake."<<endl;
			}
			if(!send_data(send, kdc_sock)){
				cout<<">> Error communicating with server. Please try again."<<endl;
			}
		}
		else if(!command.compare("/handshake") && logged_in){
			cin>>username;
			send = "/handshake " + username + " " + my_username;
			send_data(send, kdc_sock);
		}
		else{
			if(!logged_in){
				cout<<">> Not logged in. Please log in first!"<<endl;
			}
			else{
				cout<<">> Invalid command! Please read the README for the list of supported commands"<<endl;
			}
		}
	}
	return 0;
}
