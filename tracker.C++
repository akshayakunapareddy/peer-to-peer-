tracker/Makefile
@@ -0,0 +1,12 @@
CC = g++
CFLAGS = -Wall
DEPS = tracker_header.h
OBJ = tracker.o commands.o utilities.o
%.o: %.cpp $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

tracker: $(OBJ)
	$(CC) $(CFLAGS) -pthread -o $@ $^ 

clean:
	rm -rf *o tracker
 446 changes: 446 additions & 0 deletions446  
tracker/commands.cpp
Large diffs are not rendered by default.

 86 changes: 86 additions & 0 deletions86  
tracker/tracker.cpp
@@ -0,0 +1,86 @@
#include "tracker_header.h"

string logFileName, tracker1_ip, tracker2_ip, curTrackerIP,
            seederFileName;
uint16_t tracker1_port, tracker2_port, curTrackerPort;
unordered_map<string, string> loginCreds;
unordered_map<string, bool> isLoggedIn;
unordered_map<string, unordered_map<string, set<string>>> seederList; // groupid -> {map of filenames -> peer address}
unordered_map<string, string> fileSize;
unordered_map<string, string> grpAdmins;
vector<string> allGroups;
unordered_map<string, set<string>> groupMembers;
unordered_map<string, set<string>> grpPendngRequests;
unordered_map<string, string> unameToPort;
unordered_map<string, string> piecewiseHash; 

int main(int argc, char *argv[]){ 

    if(argc != 3){
        cout << "Give arguments as <tracker info file name> and <tracker_number>\n";
        return -1;
    }

    processArgs(argc, argv);

    int tracker_socket; 
    struct sockaddr_in address; 
    int opt = 1; 
    int addrlen = sizeof(address); 
    pthread_t  exitDetectionThreadId;

    if ((tracker_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    } 
    writeLog("Tracker socket created.");

    if (setsockopt(tracker_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) { 
        perror("setsockopt"); 
        exit(EXIT_FAILURE); 
    } 
    address.sin_family = AF_INET; 
    address.sin_port = htons(curTrackerPort); 

    if(inet_pton(AF_INET, &curTrackerIP[0], &address.sin_addr)<=0)  { 
        printf("\nInvalid address/ Address not supported \n"); 
        return -1; 
    } 

    if (bind(tracker_socket, (SA *)&address,  sizeof(address))<0) { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
    writeLog("Binding completed.");

    if (listen(tracker_socket, 3) < 0) { 
        perror("listen"); 
        exit(EXIT_FAILURE); 
    } 
    writeLog("Listening...");

    vector<thread> threadVector;

    if(pthread_create(&exitDetectionThreadId, NULL, check_input, NULL) == -1){
        perror("pthread"); 
        exit(EXIT_FAILURE); 
    }

    while(true){
        int client_socket;

        if((client_socket = accept(tracker_socket, (SA *)&address, (socklen_t *)&addrlen)) < 0){
            perror("Acceptance error");
            writeLog("Error in accept"); 
        }
        writeLog("Connection Accepted");

        threadVector.push_back(thread(handle_connection, client_socket));
    }
    for(auto i=threadVector.begin(); i!=threadVector.end(); i++){
        if(i->joinable()) i->join();
    }

    writeLog("EXITING.");
    return 0; 
} 
 62 changes: 62 additions & 0 deletions62  
tracker/tracker_header.h
@@ -0,0 +1,62 @@
#ifndef SERVER_HEADER 
#define SERVER_HEADER

#include <bits/stdc++.h>
#include <openssl/sha.h>
#include <sys/socket.h> 
#include <sys/types.h> 
#include <signal.h> 
#include <string.h> 
#include <unistd.h> 
#include <arpa/inet.h> 
#include <stdarg.h> 
#include <errno.h> 
#include <fcntl.h>
#include <sys/time.h> 
#include <sys/ioctl.h> 
#include <netdb.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
using namespace std; 

#define TRACKER_PORT 18000
#define ll long long int
#define MAXLINE 4096 
#define SA struct sockaddr 

extern string logFileName, tracker1_ip, tracker2_ip, curTrackerIP, seederFileName;
extern uint16_t tracker1_port, tracker2_port, curTrackerPort;
extern unordered_map<string, string> loginCreds;
extern unordered_map<string, bool> isLoggedIn;
extern unordered_map<string, unordered_map<string, set<string>>> seederList; // groupid -> {map of filenames -> peer address}
extern unordered_map<string, string> fileSize;
extern unordered_map<string, string> grpAdmins;
extern vector<string> allGroups;
extern unordered_map<string, set<string>> groupMembers;
extern unordered_map<string, set<string>> grpPendngRequests;
extern unordered_map<string, string> unameToPort;
extern unordered_map<string, string> piecewiseHash; 

void handle_connection(int);
void list_files(vector<string>, int);
void stop_share(vector<string>, int, string);
void leave_group(vector<string>, int, string);
void accept_request(vector<string>, int, string);
void list_requests(vector<string>, int, string);
void join_group(vector<string>, int, string);
void list_groups(vector<string>, int);
int create_group(vector<string>, int, string);
void downloadFile(vector<string>, int, string);
void uploadFile(vector<string>, int, string);
int validateLogin(vector<string>);
int createUser(vector<string>);
void clearLog();
void writeLog(const string &);
bool pathExists(const string &s);
vector<string> splitString(string, string);
void* check_input(void*);
vector<string> getTrackerInfo(char*);
void processArgs(int, char **);

#endif
 4 changes: 4 additions & 0 deletions4  
tracker/tracker_info.txt
@@ -0,0 +1,4 @@
127.0.0.1
5000
127.0.0.1
6000
 87 changes: 87 additions & 0 deletions87  
tracker/utilities.cpp
@@ -0,0 +1,87 @@
#include "tracker_header.h"

void clearLog(){
    ofstream out;
    out.open(logFileName);
    out.clear();
    out.close();
}

void writeLog(const string &text ){
    ofstream log_file(logFileName, ios_base::out | ios_base::app );
    log_file << text << endl;
}

bool pathExists(const string &s){
  struct stat buffer;
  return (stat (s.c_str(), &buffer) == 0);
}

vector<string> splitString(string str, string delim){
    vector<string> res;

    size_t pos = 0;
    while ((pos = str.find(delim)) != string::npos) {
        string t = str.substr(0, pos);
        res.push_back(t);
        str.erase(0, pos + delim.length());
    }
    res.push_back(str);

    return res;
}

/******************************************************/
/* Thread function which detects if quit was typed in */
/******************************************************/
void* check_input(void* arg){
    while(true){
        string inputline;
        getline(cin, inputline);
        if(inputline == "quit"){
            exit(0);
        }
    }
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

void processArgs(int argc, char *argv[]){
    logFileName = "trackerlog" + string(argv[2]) + ".txt";
    clearLog();

    vector<string> trackeraddress = getTrackerInfo(argv[1]);
    if(string(argv[2]) == "1"){
        tracker1_ip = trackeraddress[0];
        tracker1_port = stoi(trackeraddress[1]);
        curTrackerIP = tracker1_ip;
        curTrackerPort = tracker1_port;
    }
    else{
        tracker2_ip = trackeraddress[2];
        tracker2_port = stoi(trackeraddress[3]);
        curTrackerIP = tracker2_ip;
        curTrackerPort = tracker2_port;
    }

    writeLog("Tracker 1 Address : " + string(tracker1_ip)+ ":" +to_string(tracker1_port));
    writeLog("Tracker 2 Address : " + string(tracker2_ip)+ ":" +to_string(tracker2_port));
    writeLog("Log file name : " + string(logFileName) + "\n");
}