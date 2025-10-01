#include <arpa/inet.h>
#include <bits/stdc++.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/sha.h>
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
    vector<string> member;
    vector<string> request;
    vector<string> filesinGroup;
};

struct tracker {
    string ip;
    int port;
};

struct file {
    string file_name;
    long file_size;
    vector<pair<string,bool>> file_users;	
    vector<string> chunk_hashes;
    string file_hash;
};

map<string, user_info> users;
map<int, string> session_map;
map<string, group> group_map;
map<string, file> file_map;

void quit_func(int i){
    string input;
    while(1){
        getline(cin,input);
        if(input == "quit")
            exit(0);
    }
}

void cmd_log() {

}

bool isUserPresent(vector<pair<string,bool>> file_users, string user_name) {
    for (auto itr: file_users)
        if(itr.first == user_name)
            return true;
    return false;
}

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
                users[words[1]] = {words[1], words[2], false};
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
            else if (group_map.find(words[1]) == group_map.end()) {
                msg = "group doesnot exist";
            }
            else {
                string curr_user = session_map[newsockfd];
                group group_info = group_map[words[1]];
                for(int i=0; i<group_info.member.size(); i++)
                    if(group_info.member[i] == curr_user) {
                        msg = "You are already a member of this group";
                        send(newsockfd, msg.c_str(), msg.size(), 0);
                        continue;
                    }
                if (group_info.owner == curr_user)
                    msg = "You are the owner of the group";
                else {
                    group_info.request.push_back(curr_user);
                    msg = "Join request sent to owner";
                }
            }
            send(newsockfd, msg.c_str(), msg.size(), 0);
        }
        else if (words[0] == "leave_group") {
            if (session_map.find(newsockfd) == session_map.end()){
                msg = "Please login first";
            }
            else if (group_map.find(words[1]) == group_map.end()) {
                msg = "group doesnot exist";
            }
            else {
                string curr_user = session_map[newsockfd];
                group gp = group_map[words[1]];
                auto itr = find(gp.member.begin(), gp.member.end(), curr_user);
                if (itr != gp.member.end()) {
                    msg = "You are not a member of this group";
                }
                else {
                    gp.member.erase(itr);
                    msg = "Group left";
                }
            }
            send(newsockfd, msg.c_str(), msg.size(), 0);
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
            if (session_map.find(newsockfd) == session_map.end()){
                msg = "Please login first";
            }
            else if (users.find(words[2]) == users.end()) {
                msg = "No such user found";
            }
            else if (group_map.find(words[1]) == group_map.end()) {
                msg = "group doesnot exist";
            }
            else if (session_map[newsockfd] == group_map[words[1]].owner){
                msg = "Please login with owner of the group";
            }
            else {
                struct group gp = group_map[words[1]];
                bool flag=false;
                for(int i=0;i<gp.request.size(); i++)
                    if(gp.request[i] == words[2]) {
                        gp.request.erase(find(gp.request.begin(),gp.request.end(),words[2]));
                        gp.member.push_back(words[2]);
                        msg = "Request Accepted";
                        flag=true;
                        break;
                    }
                if (flag)
                    msg = "No pending request found for the user";
            }
            send(newsockfd, msg.c_str(), msg.size(), 0);
        }
        else if (words[0] == "logout") {
            if (session_map.find(newsockfd) != session_map.end()){
                string curr_user = session_map[newsockfd];
                user_info uc = users[curr_user];
                uc.login_status=false;
                session_map.erase(newsockfd);
                msg = "User Logged out";
            }
            else {
                msg = "No user logged in";
            }
            send(newsockfd, msg.c_str(), msg.size(), 0);
        }
        else if (words[0] == "upload_file") {
            string group_id = words[1];
            string curr_user = session_map[newsockfd];
            string msg;
            if(group_map.find(group_id) == group_map.end()){
                msg = group_id + " group ID doesn't exist";
            }
            else{
                // if(!groups[words[1]]->isFileInGroup(words[3])){
                // 	groups[words[1]]->filesinGroup.push_back(words[3]);
                // }
                if(file_map.find(words[2]) != file_map.end()){
                    // check for user already present
                    file fl = file_map[words[2]];
                    if(isUserPresent(fl.file_users, curr_user)){
                        msg="file already has been uploaded by user ID: "+curr_user;
                    }
                    else{
                        fl.file_users.push_back({curr_user,1});
                        // users[commands[2]]->fnameToPath[commands[3]] = commands[4];
                        msg = "file uploaded successfully by user ID: "+curr_user;
                    }
                }
                else{
                    file fl;
                    fl.file_size = stoi(words[4]);
                    fl.file_name = words[2];
                    fl.file_users.push_back({curr_user,1});
                    fl.file_hash = words[6];
                    // users[commands[2]]->fnameToPath[commands[3]] = commands[4];
                    for(int i=7; i<words.size(); i++)
                        fl.chunk_hashes.push_back(words[i]);
                    file_map[words[2]] = fl;

                    msg = "file uploaded successfully by user ID: "+curr_user;
                }
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
    vector<thread> threads_list;
    thread quit_thread(quit_func, 1);
    char buffer[256];
    int log_fd = open("tracker_log.txt", O_RDWR | O_APPEND | O_CREAT, 0644);
    if(log_fd < 0)
        error("Unable to open the file");

    while(1) {
        int newsockfd = accept(sockfd, (struct sockaddr *) &client_addr, &cli_len);
        if (newsockfd < 0) {
            cout << "ERROR on accept" << endl;
            continue;
        }

        threads_list.push_back(thread(client_handler,newsockfd));
        cout << "client connection success" << endl;
    }
    for(int i=0;i<threads_list.size(); i++)
		threads_list[i].join();
        
    close(log_fd);

    close(sockfd);
    return 0;
}