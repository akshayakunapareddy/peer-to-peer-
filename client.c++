# Peer-to-Peer Group Based File Sharing System

## Prerequisites

**Software Requirement**

1. G++ compiler
   - **To install G++ :** `sudo apt-get install g++`
2. OpenSSL library

   - **To install OpenSSL library :** `sudo apt-get install openssl`

**Platform:** Linux <br/>

## Installation

```
1. cd client
2. make
3. cd ../tracker
5. make
6. cd ..
```

## Usage

### Tracker

1. Run Tracker:

```
cd tracker
./tracker​ <TRACKER INFO FILE> <TRACKER NUMBER>
ex: ./tracker tracker_info.txt 1
```

`<TRACKER INFO FILE>` contains the IP, Port details of all the trackers.

```
Ex:
127.0.0.1
5000
127.0.0.1
6000
```

2. Close Tracker:

```
quit
```

### Client:

1. Run Client:

```
cd client
./client​ <IP>:<PORT> <TRACKER INFO FILE>
ex: ./client 127.0.0.1:18000 tracker_info.txt
```

2. Create user account:

```
create_user​ <user_id> <password>
```

3. Login:

```
login​ <user_id> <password>
```

4. Create Group:

```
create_group​ <group_id>
```

5. Join Group:

```
join_group​ <group_id>
```

6. Leave Group:

```
leave_group​ <group_id>
```

7. List pending requests:

```
list_requests ​<group_id>
```

8. Accept Group Joining Request:

```
accept_request​ <group_id> <user_id>
```

9. List All Group In Network:

```
list_groups
```

10. List All sharable Files In Group:

```
list_files​ <group_id>
```

11. Upload File:

```
​upload_file​ <file_path> <group_id​>
```

12. Download File:​

```
download_file​ <group_id> <file_name> <destination_path>
```

13. Logout:​

```
logout
```

14. Show_downloads: ​

```
show_downloads
```

15. Stop sharing: ​

```
stop_share ​<group_id> <file_name>
```

## Working

1. User should create an account and register with tracker.
2. Login using the user credentials.
3. Tracker maintains information of clients with their files(shared by client) to assist the clients for the communication between peers.
4. User can create Group and hence will become admin of that group.
5. User can fetch list of all Groups in server.
6. User can join/leave group.
7. Group admin can accept group join requests.
8. Share file across group: Shares the filename and SHA1 hash of the complete file as well as piecewise SHA1 with the tracker.
9. Fetch list of all sharable files in a Group.
10. Download:
    1. Retrieve peer information from tracker for the file.
    2. Download file from multiple peers (different pieces of file from different peers - ​piece selection algorithm​) simultaneously and all the files which client downloads will be shareable to other users in the same group. File integrity is ensured using SHA1 comparison.
11. Piece selection algorithm used: Selects random piece and then downloads it from a random peer having that piece.
12. Show downloads.
13. Stop sharing file.
14. Logout - stops sharing all files.
15. Whenever client logins, all previously shared files before logout should automatically be on sharing mode.

## Assumptions

1. Only one tracker is implemented and that tracker should always be online.
2. The peer can login from different IP addresses, but the details of his downloads/uploads will not be persistent across sessions.
3. SHA1 integrity checking doesn't work correctly for binary files, even though in most likelihood the file would have downloaded correctly.
4. File paths should be absolute.
 12 changes: 12 additions & 0 deletions12  
client/Makefile
@@ -0,0 +1,12 @@
CC = g++
CFLAGS = -Wall
DEPS = client_header.h
OBJ = client.o calcSHA.o commands.o peerToPeer.o uploadAndDownload.o utilities.o
%.o: %.cpp $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

client: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto -pthread 

clean:
	rm -rf *o client
 98 changes: 98 additions & 0 deletions98  
client/calcSHA.cpp
@@ -0,0 +1,98 @@
#include "client_header.h"

long long file_size(char *path){
    FILE *fp = fopen(path, "rb"); 

    long size=-1;
    if(fp){
        fseek (fp, 0, SEEK_END);
        size = ftell(fp)+1;
        fclose(fp);
    }
    else{
        printf("File not found.\n");
        return -1;
    }
    return size;
}

void getStringHash(string segmentString, string& hash){
    unsigned char md[20];
    if(!SHA1(reinterpret_cast<const unsigned char *>(&segmentString[0]), segmentString.length(), md)){
        printf("Error in hashing\n");
    }
    else{
        for(int i=0; i<20; i++){
            char buf[3];
            sprintf(buf, "%02x", md[i]&0xff);
            hash += string(buf);
        }
    }
    hash += "$$";
}

/*************************************************************/
/*        Returns combined PIECEWISE hash of the file        */
/*************************************************************/
string getHash(char* path){

    int  i, accum;
    FILE *fp1;

    long long fileSize = file_size(path);
    if(fileSize == -1){
        return "$";
    }
    int segments = fileSize/FILE_SEGMENT_SZ + 1;
    char line[SIZE + 1];
    string hash = "";

    fp1 = fopen(path, "r");

    if(fp1){ 
        for(i=0;i<segments;i++){
            accum = 0;
            string segmentString;

            int rc;
            while(accum < FILE_SEGMENT_SZ && (rc = fread(line, 1, min(SIZE-1, FILE_SEGMENT_SZ-accum), fp1))){
                line[rc] = '\0';
                accum += strlen(line);
                segmentString += line;
                memset(line, 0, sizeof(line));
            }

            getStringHash(segmentString, hash);

        }

        fclose(fp1);
    }
    else{
        printf("File not found.\n");
    }
    hash.pop_back();
    hash.pop_back();
    return hash;
}

string getFileHash(char* path){

    ostringstream buf; 
    ifstream input (path); 
    buf << input.rdbuf(); 
    string contents =  buf.str(), hash;

    unsigned char md[SHA256_DIGEST_LENGTH];
    if(!SHA256(reinterpret_cast<const unsigned char *>(&contents[0]), contents.length(), md)){
        printf("Error in hashing\n");
    }
    else{
        for(int i=0; i<SHA256_DIGEST_LENGTH; i++){
            char buf[3];
            sprintf(buf, "%02x", md[i]&0xff);
            hash += string(buf);
        }
    }
    return hash;
}
 73 changes: 73 additions & 0 deletions73  
client/client.cpp
@@ -0,0 +1,73 @@
#include "client_header.h"

string logFileName, tracker1_ip, tracker2_ip, peer_ip, seederFileName;
uint16_t peer_port, tracker1_port, tracker2_port;
bool loggedIn;
unordered_map<string, unordered_map<string, bool>> isUploaded; // group -> filename -> bool
unordered_map<string, vector<int>> fileChunkInfo;
vector<vector<string>> curDownFileChunks;
unordered_map<string, string> fileToFilePath;
vector<string> curFilePiecewiseHash;
unordered_map<string, string> downloadedFiles;
bool isCorruptedFile;

int main(int argc, char* argv[]){

    if(argc != 3){
        cout << "Give arguments as <peer IP:port> and <tracker info file name>\n";
        return -1;
    }
    processArgs(argc, argv);

    int sock = 0; 
    struct sockaddr_in serv_addr; 
    pthread_t serverThread;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {  
        printf("\n Socket creation error \n"); 
        return -1; 
    } 
    writeLog("Peer socket created");

    if(pthread_create(&serverThread, NULL, runAsServer, NULL) == -1){
        perror("pthread"); 
        exit(EXIT_FAILURE); 
    }

    if(connectToTracker(1, serv_addr, sock) < 0){
        exit(-1); 
    }

    while(true){ 
        cout << ">> ";
        string inptline, s;
        getline(cin, inptline);

        if(inptline.length() < 1) continue;

        stringstream ss(inptline);
        vector<string> inpt;
        while(ss >> s){
            inpt.push_back(s);
        } 

        if(inpt[0] == "login" && loggedIn){
            cout << "You already have one active session" << endl;
            continue;
        }
        if(inpt[0] != "login" && inpt[0] != "create_user" && !loggedIn){
             cout << "Please login / create an account" << endl;
                continue;
        }

        if(send(sock , &inptline[0] , strlen(&inptline[0]) , MSG_NOSIGNAL ) == -1){
            printf("Error: %s\n",strerror(errno));
            return -1;
        }
        writeLog("sent to server: " + inpt[0]);

        processCMD(inpt, sock);
    }
    close(sock);
    return 0; 
}
 57 changes: 57 additions & 0 deletions57  
client/client_header.h
@@ -0,0 +1,57 @@
#ifndef CLIENT_HEADER 
#define CLIENT_HEADER

#include <bits/stdc++.h>
#include <openssl/sha.h>
#include <arpa/inet.h> 
#include <sys/socket.h> 
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
using namespace std;

#define FILE_SEGMENT_SZ 524288
#define SIZE 32768
#define SA struct sockaddr 
#define ll long long int

extern string logFileName, tracker1_ip, tracker2_ip, peer_ip, seederFileName;
extern uint16_t peer_port, tracker1_port, tracker2_port;
extern unordered_map<string, string> downloadedFiles;
extern bool loggedIn;
extern bool isCorruptedFile;
extern unordered_map<string, unordered_map<string, bool>> isUploaded; // group -> filename -> bool
extern unordered_map<string, vector<int>> fileChunkInfo;
extern vector<vector<string>> curDownFileChunks;
extern unordered_map<string, string> fileToFilePath;
extern vector<string> curFilePiecewiseHash;

string getHash(char*);
string getFileHash(char*);
long long file_size(char*);
void writeLog(const string &);
void getStringHash(string, string&);
void writeLog(const string &);
void clearLog();
vector<string> splitString(string, string);
vector<string> getTrackerInfo(char*);
void setChunkVector(string, ll, ll, bool);
void processArgs(int, char **);
void sendChunk(char*, int, int);
int writeChunk(int, ll cnkNum, char*);
void handleClientRequest(int);
string connectToPeer(char*, char*, string);
void* runAsServer(void*);
void piecewiseAlgo(vector<string>, vector<string>);
int downloadFile(vector<string>, int);
int uploadFile(vector<string>, int);
int list_groups(int);
int list_requests(int);
void accept_request(int);
void leave_group(int);
void show_downloads();
void list_files(int);
int processCMD(vector<string>, int);
int connectToTracker(int, struct sockaddr_in &, int);

#endif
 161 changes: 161 additions & 0 deletions161  
client/commands.cpp
@@ -0,0 +1,161 @@
#include "client_header.h"

int list_groups(int sock){
    char dum[5];
    strcpy(dum, "test");
    write(sock, dum, 5);

    char reply[3*SIZE];
    memset(reply, 0, sizeof(reply));
    read(sock, reply, 3*SIZE);
    writeLog("list of groups reply: " + string(reply));

    vector<string> grps = splitString(string(reply), "$$");

    for(size_t i=0; i<grps.size()-1; i++){
        cout << grps[i] << endl;
    }
    return 0;
}

int list_requests(int sock){
    writeLog("waiting for response");

    char dum[5];
    strcpy(dum, "test");
    write(sock, dum, 5);

    char reply[3*SIZE];
    memset(reply, 0, 3*SIZE);
    read(sock, reply, 3*SIZE);
    if(string(reply) == "**err**") return -1;
    if(string(reply) == "**er2**") return 1;
    writeLog("request list: " + string(reply));

    vector<string> requests = splitString(string(reply), "$$");
    writeLog("list request response size: "+ to_string(requests.size()));
    for(size_t i=0; i<requests.size()-1; i++){
        cout << requests[i] << endl;
    }
    return 0;
}

void accept_request(int sock){
    char dum[5];
    strcpy(dum, "test");
    write(sock, dum, 5);

    char buf[96];
    read(sock, buf, 96);
    cout << buf << endl;
}

void leave_group(int sock){
    writeLog("waiting for response");
    char buf[96];
    read(sock, buf, 96);
    cout << buf << endl;
}

void list_files(int sock){
    char dum[5];
    strcpy(dum, "test");
    write(sock, dum, 5);

    char buf[1024];
    bzero(buf, 1024);
    read(sock, buf, 1024);
    vector<string> listOfFiles = splitString(string(buf), "$$");

    for(auto i: listOfFiles)
        cout << i << endl;
}

void show_downloads(){
    for(auto i: downloadedFiles){
        cout << "[C] " << i.second << " " << i.first << endl;
    }
}

int processCMD(vector<string> inpt, int sock){
    char server_reply[10240]; 
    bzero(server_reply, 10240);
    read(sock , server_reply, 10240); 
    cout << server_reply << endl;
    writeLog("primary server response: " + string(server_reply));

    if(string(server_reply) == "Invalid argument count") return 0;
    if(inpt[0] == "login"){
        if(string(server_reply) == "Login Successful"){
            loggedIn = true;
            string peerAddress = peer_ip + ":" + to_string(peer_port);
            write(sock, &peerAddress[0], peerAddress.length());
        }
    }
    else if(inpt[0] == "logout"){
        loggedIn = false;
    }
    else if(inpt[0] == "upload_file"){
        if(string(server_reply) == "Error 101:"){
            cout << "Group doesn't exist" << endl;
            return 0;
        }
        else  if(string(server_reply) == "Error 102:"){
            cout << "You are not a member of this group" << endl;
            return 0;
        }
        else  if(string(server_reply) == "Error 103:"){
            cout << "File not found." << endl;
            return 0;
        }
        return uploadFile(inpt, sock);
    }
    else if(inpt[0] == "download_file"){
        if(string(server_reply) == "Error 101:"){
            cout << "Group doesn't exist" << endl;
            return 0;
        }
        else  if(string(server_reply) == "Error 102:"){
            cout << "You are not a member of this group" << endl;
            return 0;
        }
        else  if(string(server_reply) == "Error 103:"){
            cout << "Directory not found" << endl;
            return 0;
        }
        if(downloadedFiles.find(inpt[2])!= downloadedFiles.end()){
            cout << "File already downloaded" << endl;
            return 0;
        }
        return downloadFile(inpt, sock);
    }
    else if(inpt[0] == "list_groups"){
        return list_groups(sock);
    }
    else if(inpt[0] == "list_requests"){
        int t;
        if((t = list_requests(sock)) < 0){
            cout << "You are not the admin of this group\n";
        }
        else if(t>0){
            cout << "No pending requests\n";
        }
        else return 0;
    }
    else if(inpt[0] == "accept_request"){
        accept_request(sock);
    }
    else if(inpt[0] == "leave_group"){
        leave_group(sock);
    }
    else if(inpt[0] == "list_files"){
        list_files(sock);
    }
    else if(inpt[0] == "stop_share"){
        isUploaded[inpt[1]].erase(inpt[2]);
    }
    else if(inpt[0] == "show_downloads"){
        show_downloads();
    }
    return 0;
}
 191 changes: 191 additions & 0 deletions191  
client/peerToPeer.cpp
@@ -0,0 +1,191 @@
#include "client_header.h"

/*************************************************************/
/*           Handles different requests from peer client     */
/*************************************************************/
void handleClientRequest(int client_socket){
    string client_uid = "";

    writeLog("\nclient socket num: " + to_string(client_socket) + "\n");
    char inptline[1024] = {0}; 

    if(read(client_socket , inptline, 1024) <=0){
        close(client_socket);
        return;
    }

    writeLog("client request at server " + string(inptline));
    vector<string> inpt = splitString(string(inptline), "$$");
    writeLog(inpt[0]);

    if(inpt[0] == "get_chunk_vector"){
        writeLog("\nsending chunk vector..");
        string filename = inpt[1];
        vector<int> chnkvec = fileChunkInfo[filename];
        string tmp = "";
        for(int i: chnkvec) tmp += to_string(i);
        char* reply = &tmp[0];
        write(client_socket, reply, strlen(reply));
        writeLog("sent: " + string(reply));
    }
    else if(inpt[0] == "get_chunk"){
        //inpt = [get_chunk, filename, to_string(chunkNum), destination]
        writeLog("\nsending chunk...");
        string filepath = fileToFilePath[inpt[1]];
        ll chunkNum = stoll(inpt[2]);
        writeLog("filepath: "+ filepath);

        writeLog("sending " + to_string(chunkNum) + " from " + string(peer_ip) + ":" + to_string(peer_port));

        sendChunk(&filepath[0], chunkNum, client_socket);

    }
    else if(inpt[0] == "get_file_path"){
        string filepath = fileToFilePath[inpt[1]];
        writeLog("command from peer client: " +  string(inptline));
        write(client_socket, &filepath[0], strlen(filepath.c_str()));
    }
    close(client_socket);
    return;
}

/****************************************************************/
/*Connects to <serverPeerIP:serverPortIP> and sends it <command>*/
/****************************************************************/
string connectToPeer(char* serverPeerIP, char* serverPortIP, string command){
    int peersock = 0;
    struct sockaddr_in peer_serv_addr; 

    writeLog("\nInside connectToPeer");

    if ((peersock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {  
        printf("\n Socket creation error \n"); 
        return "error"; 
    } 
    writeLog("Socket Created");

    peer_serv_addr.sin_family = AF_INET; 
    uint16_t peerPort = stoi(string(serverPortIP));
    peer_serv_addr.sin_port = htons(peerPort); 
    writeLog("\n needs to connect to " + string(serverPeerIP) + ":" + to_string(peerPort));

    if(inet_pton(AF_INET, serverPeerIP, &peer_serv_addr.sin_addr) < 0){ 
        perror("Peer Connection Error(INET)");
    } 
    if (connect(peersock, (struct sockaddr *)&peer_serv_addr, sizeof(peer_serv_addr)) < 0) { 
        perror("Peer Connection Error");
    } 
    writeLog("Connected to peer " + string(serverPeerIP) + ":" + to_string(peerPort));

    string curcmd = splitString(command, "$$").front();
    writeLog("current command " + curcmd);

    if(curcmd == "get_chunk_vector"){
        if(send(peersock , &command[0] , strlen(&command[0]) , MSG_NOSIGNAL ) == -1){
            printf("Error: %s\n",strerror(errno));
            return "error"; 
        }
        writeLog("sent command to peer: " + command);
        char server_reply[10240] = {0};
        if(read(peersock, server_reply, 10240) < 0){
            perror("err: ");
            return "error";
        }
        writeLog("got reply: " + string(server_reply));
        close(peersock);
        return string(server_reply);
    }
    else if(curcmd == "get_chunk"){
        //"get_chunk $$ filename $$ to_string(chunkNum) $$ destination
        if(send(peersock , &command[0] , strlen(&command[0]) , MSG_NOSIGNAL ) == -1){
            printf("Error: %s\n",strerror(errno));
            return "error"; 
        }
        writeLog("sent command to peer: " + command);
        vector<string> cmdtokens = splitString(command, "$$");

        string despath = cmdtokens[3];
        ll chunkNum = stoll(cmdtokens[2]);
        writeLog("\ngetting chunk " + to_string(chunkNum) + " from "+ string(serverPortIP));

        writeChunk(peersock, chunkNum, &despath[0]);

        return "ss";
    }
    else if(curcmd == "get_file_path"){
        if(send(peersock , &command[0] , strlen(&command[0]) , MSG_NOSIGNAL ) == -1){
            printf("Error: %s\n",strerror(errno));
            return "error"; 
        }
        char server_reply[10240] = {0};
        if(read(peersock, server_reply, 10240) < 0){
            perror("err: ");
            return "error";
        }
        writeLog("server reply for get file path:" + string(server_reply));
        fileToFilePath[splitString(command, "$$").back()] = string(server_reply);
    }

    close(peersock);
    writeLog("terminating connection with " + string(serverPeerIP) + ":" + to_string(peerPort));
    return "aa";
}

/*****************************************************************************/
/* The peer acts as a server, continuously listening for connection requests */
/*****************************************************************************/
void* runAsServer(void* arg){
    int server_socket; 
    struct sockaddr_in address; 
    int addrlen = sizeof(address); 
    int opt = 1; 

    writeLog("\n" + to_string(peer_port) + " will start running as server");
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    } 
    writeLog(" Server socket created.");

    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) { 
        perror("setsockopt"); 
        exit(EXIT_FAILURE); 
    } 
    address.sin_family = AF_INET; 
    address.sin_port = htons(peer_port); 

    if(inet_pton(AF_INET, &peer_ip[0], &address.sin_addr)<=0)  { 
        printf("\nInvalid address/ Address not supported \n"); 
        return NULL; 
    } 

    if (bind(server_socket, (SA *)&address,  sizeof(address))<0) { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
    writeLog(" Binding completed.");

    if (listen(server_socket, 3) < 0) { 
        perror("listen"); 
        exit(EXIT_FAILURE); 
    } 
    writeLog("Listening...\n");

    vector<thread> vThread;
    while(true){

        int client_socket;

        if((client_socket = accept(server_socket, (SA *)&address, (socklen_t *)&addrlen)) < 0){
            perror("Acceptance error");
            writeLog("Error in accept"); 
        }
        writeLog(" Connection Accepted");

        vThread.push_back(thread(handleClientRequest, client_socket));
    }
    for(auto it=vThread.begin(); it!=vThread.end();it++){
        if(it->joinable()) it->join();
    }
    close(server_socket);
}
 4 changes: 4 additions & 0 deletions4  
client/tracker_info.txt
@@ -0,0 +1,4 @@
127.0.0.1
5000
127.0.0.1
6000
 298 changes: 298 additions & 0 deletions298  
client/uploadAndDownload.cpp
@@ -0,0 +1,298 @@
#include "client_header.h"

typedef struct peerFileDetails{
    string serverPeerIP;
    string filename;
    ll filesize;
} peerFileDetails;

typedef struct reqdChunkDetails{
    string serverPeerIP;
    string filename;
    ll chunkNum; 
    string destination;
} reqdChunkDetails;


void sendChunk(char* filepath, int chunkNum, int client_socket){

    std::ifstream fp1(filepath, std::ios::in|std::ios::binary);
    fp1.seekg(chunkNum*FILE_SEGMENT_SZ, fp1.beg);

    writeLog("sending data starting at " + to_string(fp1.tellg()));
    char buffer[FILE_SEGMENT_SZ] = {0}; 
    int rc = 0;
    string sent = "";

    fp1.read(buffer, sizeof(buffer));
    int count = fp1.gcount();

    if ((rc = send(client_socket, buffer, count, 0)) == -1) {
        perror("[-]Error in sending file.");
        exit(1);
    }

    writeLog("sent till "+to_string(fp1.tellg()));

    fp1.close();
} 

int writeChunk(int peersock, ll chunkNum, char* filepath){  

    int n, tot = 0;
    char buffer[FILE_SEGMENT_SZ];

    string content = "";
    while (tot < FILE_SEGMENT_SZ) {
        n = read(peersock, buffer, FILE_SEGMENT_SZ-1);
        if (n <= 0){
            break;
        }
        buffer[n] = 0;
        fstream outfile(filepath, std::fstream::in | std::fstream::out | std::fstream::binary);
        outfile.seekp(chunkNum*FILE_SEGMENT_SZ+tot, ios::beg);
        outfile.write(buffer, n);
        outfile.close();

        writeLog("written at: "+ to_string(chunkNum*FILE_SEGMENT_SZ + tot));
        writeLog("written till: " + to_string(chunkNum*FILE_SEGMENT_SZ + tot + n-1) +"\n");

        content += buffer;
        tot += n;
        bzero(buffer, FILE_SEGMENT_SZ);
    }

    string hash = "";
    getStringHash(content, hash);
    hash.pop_back();
    hash.pop_back();
    if(hash != curFilePiecewiseHash[chunkNum]){
        isCorruptedFile = true;
    } 

    string filename = splitString(string(filepath), "/").back();
    setChunkVector(filename, chunkNum, chunkNum, false);

    return 0;
}

void getChunkInfo(peerFileDetails* pf){

    writeLog("Getting chunk info of : "+ pf->filename + " from "+ pf->serverPeerIP);

    vector<string> serverPeerAddress = splitString(string(pf->serverPeerIP), ":");
    string command = "get_chunk_vector$$" + string(pf->filename);
    string response = connectToPeer(&serverPeerAddress[0][0], &serverPeerAddress[1][0], command);

    for(size_t i=0; i<curDownFileChunks.size(); i++){
        if(response[i] == '1'){
            curDownFileChunks[i].push_back(string(pf->serverPeerIP));
        }
    }

    delete pf;
}

void getChunk(reqdChunkDetails* reqdChunk){

    writeLog("Chunk fetching details :" + reqdChunk->filename + " " + 
            reqdChunk->serverPeerIP + " " + to_string(reqdChunk->chunkNum));

    string filename = reqdChunk->filename;
    vector<string> serverPeerIP = splitString(reqdChunk->serverPeerIP, ":");
    ll chunkNum = reqdChunk->chunkNum;
    string destination = reqdChunk->destination;

    string command = "get_chunk$$" + filename + "$$" + to_string(chunkNum) + "$$" + destination;
    connectToPeer(&serverPeerIP[0][0], &serverPeerIP[1][0], command);

    delete reqdChunk;
    return;
}

void piecewiseAlgo(vector<string> inpt, vector<string> peers){
    // inpt = [command, group id, filename, destination]
    ll filesize = stoll(peers.back());
    peers.pop_back();
    ll segments = filesize/FILE_SEGMENT_SZ+1;
    curDownFileChunks.clear();
    curDownFileChunks.resize(segments);

    writeLog("Started piecewise algo");

    vector<thread> threads, threads2;

    for(size_t i=0; i<peers.size(); i++){
        peerFileDetails* pf = new peerFileDetails();
        pf->filename = inpt[2];
        pf->serverPeerIP = peers[i];
        pf->filesize = segments;
        threads.push_back(thread(getChunkInfo, pf));
    }
    for(auto it=threads.begin(); it!=threads.end();it++){
        if(it->joinable()) it->join();
    }

    writeLog("filled in default values to file");
    for(size_t i=0; i<curDownFileChunks.size(); i++){
        if(curDownFileChunks[i].size() == 0){
            cout << "All parts of the file are not available." << endl;
            return;
        }
    }

    threads.clear();
    srand((unsigned) time(0));
    ll segmentsReceived = 0;

    string des_path = inpt[3] + "/" + inpt[2];
    FILE* fp = fopen(&des_path[0], "r+");
	if(fp != 0){
		printf("The file already exists.\n") ;
        fclose(fp);
        return;
	}
    string ss(filesize, '\0');
    fstream in(&des_path[0],ios::out|ios::binary);
    in.write(ss.c_str(),strlen(ss.c_str()));  
    in.close();

    fileChunkInfo[inpt[2]].resize(segments,0);
    isCorruptedFile = false;

    vector<int> tmp(segments, 0);
    fileChunkInfo[inpt[2]] = tmp;

    string peerToGetFilepath;

    while(segmentsReceived < segments){
        writeLog("getting segment no: " + to_string(segmentsReceived));

        ll randompiece;
        while(true){
            randompiece = rand()%segments;
            writeLog("randompiece = " + to_string(randompiece));
            if(fileChunkInfo[inpt[2]][randompiece] == 0) break;
        }
        ll peersWithThisPiece = curDownFileChunks[randompiece].size();
        string randompeer = curDownFileChunks[randompiece][rand()%peersWithThisPiece];

        reqdChunkDetails* req = new reqdChunkDetails();
        req->filename = inpt[2];
        req->serverPeerIP = randompeer;
        req->chunkNum = randompiece;
        req->destination = inpt[3] + "/" + inpt[2];

        writeLog("starting thread for chunk number "+ to_string(req->chunkNum));
        fileChunkInfo[inpt[2]][randompiece] = 1;

        threads2.push_back(thread(getChunk, req));
        segmentsReceived++;
        peerToGetFilepath = randompeer;
    }    
    for(auto it=threads2.begin(); it!=threads2.end();it++){
        if(it->joinable()) it->join();
    } 

    if(isCorruptedFile){
        cout << "Downloaded completed. The file may be corrupted." << endl;
    }
    else{
         cout << "Download completed. No corruption detected." << endl;
    }
    downloadedFiles.insert({inpt[2], inpt[1]});

    vector<string> serverAddress = splitString(peerToGetFilepath, ":");
    connectToPeer(&serverAddress[0][0], &serverAddress[1][0], "get_file_path$$" + inpt[2]);
    return;
}

int downloadFile(vector<string> inpt, int sock){
    // inpt -  download_file​ <group_id> <file_name> <destination_path>
    if(inpt.size() != 4){
        return 0;
    }
    string fileDetails = "";
    fileDetails += inpt[2] + "$$";
    fileDetails += inpt[3] + "$$";
    fileDetails += inpt[1];
    // fileDetails = [filename, destination, group id]

    writeLog("sending file details for download : " + fileDetails);
    if(send(sock , &fileDetails[0] , strlen(&fileDetails[0]) , MSG_NOSIGNAL ) == -1){
        printf("Error: %s\n",strerror(errno));
        return -1;
    }

    char server_reply[524288] = {0}; 
    read(sock , server_reply, 524288); 

    if(string(server_reply) == "File not found"){
        cout << server_reply << endl;
        return 0;
    }
    vector<string> peersWithFile = splitString(server_reply, "$$");

    char dum[5];
    strcpy(dum, "test");
    write(sock, dum, 5);

    bzero(server_reply, 524288);
    read(sock , server_reply, 524288); 

    vector<string> tmp = splitString(string(server_reply), "$$");
    curFilePiecewiseHash = tmp;

    piecewiseAlgo(inpt, peersWithFile);
    return 0;
}

int uploadFile(vector<string> inpt, int sock){
    if(inpt.size() != 3){
            return 0;
    }
    string fileDetails = "";
    char* filepath = &inpt[1][0];

    string filename = splitString(string(filepath), "/").back();

    if(isUploaded[inpt[2]].find(filename) != isUploaded[inpt[2]].end()){
        cout << "File already uploaded" << endl;
        if(send(sock , "error" , 5 , MSG_NOSIGNAL ) == -1){
            printf("Error: %s\n",strerror(errno));
            return -1;
        }
        return 0;
    }
    else{
        isUploaded[inpt[2]][filename] = true;
        fileToFilePath[filename] = string(filepath);
    }

    string piecewiseHash = getHash(filepath);

    if(piecewiseHash == "$") return 0;
    string filehash = getFileHash(filepath);
    string filesize = to_string(file_size(filepath));

    fileDetails += string(filepath) + "$$";
    fileDetails += string(peer_ip) + ":" + to_string(peer_port) + "$$";
    fileDetails += filesize + "$$";
    fileDetails += filehash + "$$";
    fileDetails += piecewiseHash;

    writeLog("sending file details for upload: " + fileDetails);
    if(send(sock , &fileDetails[0] , strlen(&fileDetails[0]) , MSG_NOSIGNAL ) == -1){
        printf("Error: %s\n",strerror(errno));
        return -1;
    }

    char server_reply[10240] = {0}; 
    read(sock , server_reply, 10240); 
    cout << server_reply << endl;
    writeLog("server reply for send file: " + string(server_reply));

    setChunkVector(filename, 0, stoll(filesize)/FILE_SEGMENT_SZ + 1, true);

    return 0;
}
 119 changes: 119 additions & 0 deletions119  
client/utilities.cpp
@@ -0,0 +1,119 @@
#include "client_header.h"

void writeLog(const string &text ){
    ofstream log_file(logFileName, ios_base::out | ios_base::app );
    log_file << text << endl;
}

void clearLog(){
    ofstream out;
    out.open(logFileName);
    out.clear();
    out.close();
}

vector<string> splitString(string address, string delim = ":"){
    vector<string> res;

    size_t pos = 0;
    while ((pos = address.find(delim)) != string::npos) {
        string t = address.substr(0, pos);
        res.push_back(t);
        address.erase(0, pos + delim.length());
    }
    res.push_back(address);

    return res;
}

vector<string> getTrackerInfo(char* path){
    fstream trackerInfoFile;
    trackerInfoFile.open(path, ios::in);

    vector<string> res;
    if(trackerInfoFile.is_open()){
        string t;
        while(getline(trackerInfoFile, t)){
            res.push_back(t);
        }
        trackerInfoFile.close();
    }
    else{
        cout << "Tracker Info file not found.\n";
        exit(-1);
    }
    return res;
}

void setChunkVector(string filename, ll l, ll r, bool isUpload){
    if(isUpload){
        vector<int> tmp(r-l+1, 1);
        fileChunkInfo[filename] = tmp;
    }
    else{
        fileChunkInfo[filename][l] = 1;
        writeLog("chunk vector updated for " + filename + " at " + to_string(l));
    }
}

void processArgs(int argc, char *argv[]){
    string peerInfo = argv[1];
    string trackerInfoFilename = argv[2];

    logFileName = peerInfo + "_log.txt";
    clearLog();

    vector<string> peeraddress = splitString(peerInfo);
    peer_ip = peeraddress[0];
    peer_port = stoi(peeraddress[1]);

    char curDir[128];
    getcwd(curDir, 128);

    string path = string(curDir);
    path += "/" + trackerInfoFilename;
    vector<string> trackerInfo = getTrackerInfo(&path[0]);

    tracker1_ip = trackerInfo[0];
    tracker1_port = stoi(trackerInfo[1]);
    tracker2_ip = trackerInfo[2];
    tracker2_port = stoi(trackerInfo[3]);

    writeLog("Peer Address : " + string(peer_ip)+ ":" +to_string(peer_port));
    writeLog("Tracker 1 Address : " + string(tracker1_ip)+ ":" +to_string(tracker1_port));
    writeLog("Tracker 2 Address : " + string(tracker2_ip)+ ":" +to_string(tracker2_port));
    writeLog("Log file name : " + string(logFileName) + "\n");
}

int connectToTracker(int trackerNum, struct sockaddr_in &serv_addr, int sock){
    char* curTrackIP;
    uint16_t curTrackPort;
    if(trackerNum == 1){
        curTrackIP = &tracker1_ip[0]; 
        curTrackPort = tracker1_port;
    }
    else{
        curTrackIP = &tracker2_ip[0]; 
        curTrackPort = tracker2_port;
    }

    bool err = 0;

    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(curTrackPort); 

    if(inet_pton(AF_INET, curTrackIP, &serv_addr.sin_addr)<=0)  { 
        err = 1;
    } 
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) { 
        err = 1;
    } 
    if(err){
        if(trackerNum == 1)
            return connectToTracker(2, serv_addr, sock);
        else
            return -1;
    }
    writeLog("connected to server " + to_string(curTrackPort));
    return 0;
}
 12 changes: 12 additions & 0 deletions12  
