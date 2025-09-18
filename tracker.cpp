#include <arpa/inet.h>
#include <bits/stdc++.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace std;

void error(string msg) {
    perror(msg.c_str());
    exit(1);
}

struct user_info {
    string username, password;
    bool login_status;
};

struct group {
    string owner;
    set<string> member;
    set<string> request;
};


struct tracker {
    string ip;
    int port;
};

map<string, user_info> users;
map<int, string> session_map;
map<string, group> group_map;

// void sync_function(const string &msg, int sync_port) {
//     char buffer[256];

//     int sync_sockfd = socket(AF_INET, SOCK_STREAM, 0);
//     if (sync_sockfd < 0)
//         return;

//     struct sockaddr_in sync_track_add;
//     bzero((char *) &sync_track_add, sizeof(sync_track_add));
//     sync_track_add.sin_family = AF_INET;
//     sync_track_add.sin_port = htons(sync_port);

//     if (inet_pton(AF_INET, "127.0.0.1", &sync_track_add.sin_addr) <= 0) {
//         perror("invalid sync server IP");
//         close(sync_sockfd);
//         return;
//     }

//     if (connect(sync_sockfd,(struct sockaddr *) &sync_track_add,sizeof(sync_track_add)) < 0)
//         return;

//     cout << "connection established" << endl;

//     ssize_t sent = send(sync_sockfd, msg.c_str(), msg.size(), 0);

//     cout << "connection established 2" << endl;

//     ssize_t bytes_received = recv(sync_sockfd, buffer, sizeof(buffer)-1, 0);

//     cout << buffer << endl;

//     close(sync_sockfd);
// }

void client_handler(int newsockfd) {
    while(1) {
        char buffer[256];
        memset(buffer, 0, sizeof(buffer));
        ssize_t n = recv(newsockfd, buffer, sizeof(buffer), 0);
        if (n == 0) {
            cout << "Buffer empty" << endl;
            break;;
        }

        vector<string> words;
		char *token = strtok(buffer, " ");

        while (token != NULL) {
            words.push_back(token);
            token = strtok(NULL, " ");
        }

        string msg;
        if (words[0] == "create_user") {
            if (users.find(words[1]) == users.end()) {
                struct user_info uc;
                uc.username = words[1];
                uc.password = words[2];
                uc.login_status = false;
                users[words[1]] = uc;
                msg = "User created successfully";
            }
            else {
                msg = "User already exists";
            }
            send(newsockfd, msg.c_str(), msg.size(), 0);
        }
        else if (words[0] == "login") {
            if (session_map.find(newsockfd) != session_map.end()){
                msg = "User already loggedin";
                send(newsockfd, msg.c_str(), msg.size(), 0);
                continue;
            }
            if (users.find(words[1]) == users.end()) {
                msg = "No such user found";
            }
            else {
                struct user_info uc = users[words[1]];
                if (words[2] == uc.password) {
                    uc.login_status = true;
                    session_map[newsockfd] = words[1];
                    msg = "login successful";
                }
                else {
                    msg = "Incorrect Password";
                }
            }
            send(newsockfd, msg.c_str(), msg.size(), 0);
        }
        else if (words[0] == "create_group") {
            if (session_map.find(newsockfd) == session_map.end()){
                msg = "Please login first";
            }
            else if(group_map.find(words[1]) != group_map.end()) {
                msg = "group_id already exists";
            }
            else {
                string userid = session_map[newsockfd];
                group gm = {userid, {},{}};
                group_map[words[1]] = gm;
                msg = "Created group Successfully";
            }
            send(newsockfd, msg.c_str(), msg.size(), 0);
        }
        else if (words[0] == "join_group") {
            if (session_map.find(newsockfd) == session_map.end()){
                msg = "Please login first";
            }
            else if(group_map.find(words[1]) != group_map.end()) {
                group group_info = group_map[words[1]];
                if (group_info.owner == session_map[newsockfd])
                    msg = "You are the owner of the group";
                else {
                    group_info.request.insert(session_map[newsockfd]);
                    msg = "Join request sent to owner";
                }
            }
            else {
                msg = "group doesnot exist";
            }
            send(newsockfd, msg.c_str(), msg.size(), 0);
        }
        else if (words[0] == "leave_group") {
            
        }
        else if (words[0] == "list_groups") {
            for (const auto &pair : group_map)
                msg += pair.first + "\n";
            if (!msg.empty()) msg.pop_back();
            if (msg.empty()) msg = "No groups found";
            send(newsockfd, msg.c_str(), msg.size(), 0);
        }
        else if (words[0] == "list_requests") {
            if (session_map.find(newsockfd) == session_map.end()){
                msg = "Please login first";
            }
            else {
                group gp = group_map[words[1]];
                if (session_map[newsockfd] == gp.owner) {
                    for (string req : gp.request)
                        msg += req + "\n";
                    if (!msg.empty()) msg.pop_back();
                    if (msg.empty()) msg = "No requests found";
                }
                else {
                    msg = "You are not the owner";
                }
            }
            send(newsockfd, msg.c_str(), msg.size(), 0);
        }
        else if (words[0] == "accept_requests") {

        }
        else if (words[0] == "logout") {
            if (session_map.find(newsockfd) != session_map.end()){
                session_map.erase(newsockfd);
                msg = "User Logged out";
            }
            else {
                msg = "No user logged in";
            }
            send(newsockfd, msg.c_str(), msg.size(), 0);
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        cout << "Invalid Arguments" << endl;
        return 0;
    }

    char* tracker_fname = argv[1];
    int sno = stoi(argv[2]);
    char filebuffer[256];
    vector<tracker> tracker_list;
    ifstream file(tracker_fname);
    string line;

    while (getline(file, line)) {
        int pos = line.find(' ');
        string ip=line.substr(0, pos);
        int port=stoi(line.substr(pos+1));
        tracker_list.push_back({ip, port});
    }
    file.close();
    
    int sync_port = tracker_list[1].port;
    if (sno == 1)
        sync_port = tracker_list[0].port;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        error("Unable to open Socket");

    struct sockaddr_in track_add, client_addr;
    track_add.sin_family = AF_INET;
    track_add.sin_port = htons(tracker_list[sno-1].port);
    track_add.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *) &track_add, sizeof(track_add)) != 0)
        error("Error while binding");

    cout << "Connected to port - " << tracker_list[sno-1].port << endl;

    if (listen(sockfd, 5) < 0)
        error("Error while listening");

    socklen_t cli_len = sizeof(client_addr);
    thread t1;
    while(1) {
        int newsockfd = accept(sockfd, (struct sockaddr *) &client_addr, &cli_len);
        if (newsockfd < 0) {
            cout << "ERROR on accept" << endl;
            continue;
        }

        t1 =  thread(client_handler, newsockfd);
        cout << "client connection success" << endl;
       
    }
    t1.join();

        // char buffer[256];
        // int log_fd = open("tracker_log.txt", O_RDWR | O_APPEND | O_CREAT, 0644);
        // if(log_fd < 0)
        // error("Unable to open the file"); 


    // close(log_fd);
    close(sockfd);
    return 0;
}