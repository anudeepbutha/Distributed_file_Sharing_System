#include <arpa/inet.h>
#include <bits/stdc++.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace std;

mutex log_mutex;
ofstream log_file;

void init_log(const string &filename) {
    log_file.open(filename, std::ios::app);
    if (!log_file.is_open()) {
        cout << "Cannot open log file: " << filename << std::endl;
        exit(1);
    }
}

void log_message(const std::string &msg) {
    lock_guard<mutex> lock(log_mutex);
    auto now = chrono::system_clock::now();
    time_t t = chrono::system_clock::to_time_t(now);
    tm tm{};
    localtime_r(&t, &tm);
    log_file << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "  " << msg << std::endl;
    log_file.flush();
}

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
    int chunks_count;
    vector<pair<string,bool>> file_users;	
    vector<pair<string, string>> peer_addresses;
    vector<string> chunk_hashes;
    string file_hash;
};

map<string, user_info> users;
map<int, string> session_map;
map<int, pair<string, string>> peer_info_map;
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

bool isGroupMember(vector<string> members, string s){
    for (string str: members)
        if(str == s)
            return true;
    return false;
}

void client_handler(int newsockfd) {
    while(1) {
        char buffer[4096];
        memset(buffer, 0, sizeof(buffer));
        ssize_t n = recv(newsockfd, buffer, sizeof(buffer), 0);
        if (n <= 0) {
            cout << "Client disconnected" << endl;

            if (session_map.find(newsockfd) != session_map.end()) {
                string curr_user = session_map[newsockfd];
                if (users.find(curr_user) != users.end()) {
                    users[curr_user].login_status = false;
                }
                session_map.erase(newsockfd);
            }

            if (peer_info_map.find(newsockfd) != peer_info_map.end()) {
                peer_info_map.erase(newsockfd);
            }

            close(newsockfd);
            break;
        }

        vector<string> words;
        char *token = strtok(buffer, " ");

        while (token != NULL) {
            words.push_back(token);
            token = strtok(NULL, " ");
        }

        if (words.size() == 0) continue;

        string msg;
        if (words[0] == "create_user") {
            if (users.find(words[1]) == users.end()) {
                users[words[1]] = {words[1], words[2], false};
                msg = "User created successfully";
                log_message("created User: " + words[1]);
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
                if (words[2] == users[words[1]].password) {
                    users[words[1]].login_status = true;
                    session_map[newsockfd] = words[1];
                    msg = "login successful";
                    log_message("User logged in: " + words[1]);
                }
                else {
                    msg = "Incorrect Password";
                }
            }
            send(newsockfd, msg.c_str(), msg.size(), 0);
        }
        else if (words[0] == "register_peer") {
            if (session_map.find(newsockfd) == session_map.end()){
                msg = "Please login first";
                send(newsockfd, msg.c_str(), msg.size(), 0);
                continue;
            }

            string peer_ip = words[1];
            string peer_port = words[2];
            string curr_user = session_map[newsockfd];

            peer_info_map[newsockfd] = {peer_ip, peer_port};

            for (auto& file_pair : file_map) {
                file& fl = file_pair.second;
                for (auto& user_pair : fl.file_users) {
                    if (user_pair.first == curr_user && user_pair.second) {
                        bool found = false;
                        for (auto& peer : fl.peer_addresses) {
                            if (peer.first == peer_ip && peer.second == peer_port) {
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            fl.peer_addresses.push_back({peer_ip, peer_port});
                        }
                    }
                }
            }

            msg = "Peer address registered";
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
                group gm = {userid, {}, {}, {}};
                group_map[words[1]] = gm;
                msg = "Created group Successfully";
                log_message("Created group: " + words[1]);
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
                group& group_info = group_map[words[1]];
                
                bool already_member = false;
                for(int i=0; i<group_info.member.size(); i++) {
                    if(group_info.member[i] == curr_user) {
                        already_member = true;
                        msg = "You are already a member of this group";
                        break;
                    }
                }

                if (!already_member) {
                    if (group_info.owner == curr_user) {
                        msg = "You are the owner of the group";
                    }
                    else {
                        bool already_requested = false;
                        for(auto& req : group_info.request) {
                            if(req == curr_user) {
                                already_requested = true;
                                break;
                            }
                        }
                        
                        if (!already_requested) {
                            group_info.request.push_back(curr_user);
                            msg = "Join request sent to owner";
                            log_message("User " + curr_user + " requested to join group " + words[1]);
                        } else {
                            msg = "Request already pending";
                        }
                    }
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
                group& gp = group_map[words[1]];
                
                if (gp.owner == curr_user) {
                    msg = "Owner cannot leave the group";
                }
                else {
                    auto itr = find(gp.member.begin(), gp.member.end(), curr_user);
                    if (itr != gp.member.end()) {
                        gp.member.erase(itr);
                        msg = "Group left successfully";
                        log_message("User " + curr_user + " left group " + words[1]);
                    }
                    else {
                        msg = "You are not a member of this group";
                    }
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
            else if (group_map.find(words[1]) == group_map.end()) {
                msg = "group doesnot exist";
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
        else if (words[0] == "accept_request") {
            if (session_map.find(newsockfd) == session_map.end()){
                msg = "Please login first";
            }
            else if (users.find(words[2]) == users.end()) {
                msg = "No such user found";
            }
            else if (group_map.find(words[1]) == group_map.end()) {
                msg = "group doesnot exist";
            }
            else if (session_map[newsockfd] != group_map[words[1]].owner){
                msg = "You are not the owner of the group";
            }
            else {
                group& gp = group_map[words[1]];
                bool flag = false;
                for(int i=0; i<gp.request.size(); i++) {
                    if(gp.request[i] == words[2]) {
                        gp.request.erase(find(gp.request.begin(), gp.request.end(), words[2]));
                        gp.member.push_back(words[2]);
                        msg = "Request Accepted";
                        flag = true;
                        log_message("User " + words[2] + " joined group " + words[1]);
                        break;
                    }
                }
                if (!flag)
                    msg = "No pending request found for the user";
            }
            send(newsockfd, msg.c_str(), msg.size(), 0);
        }
        else if (words[0] == "logout") {
            if (session_map.find(newsockfd) != session_map.end()){
                string curr_user = session_map[newsockfd];
                users[curr_user].login_status = false;
                session_map.erase(newsockfd);

                if (peer_info_map.find(newsockfd) != peer_info_map.end()) {
                    peer_info_map.erase(newsockfd);
                }
                
                msg = "User Logged out";
            }
            else {
                msg = "No user logged in";
            }
            send(newsockfd, msg.c_str(), msg.size(), 0);
        }
        else if (words[0] == "upload_file") {
            string group_id = words[1];
            
            if (session_map.find(newsockfd) == session_map.end()){
                msg = "Please login first";
                send(newsockfd, msg.c_str(), msg.size(), 0);
                continue;
            }

            string curr_user = session_map[newsockfd];

            if(group_map.find(group_id) == group_map.end()){
                msg = group_id + " group ID doesn't exist";
            }
            else{
                group& gp = group_map[group_id];
                bool is_member = false;
                if (gp.owner == curr_user) {
                    is_member = true;
                } else {
                    for (auto& member : gp.member) {
                        if (member == curr_user) {
                            is_member = true;
                            break;
                        }
                    }
                }

                if (!is_member) {
                    msg = "You are not a member of this group";
                    send(newsockfd, msg.c_str(), msg.size(), 0);
                    continue;
                }

                string filename = words[2];
                string filepath = words[3];

                if(file_map.find(filename) != file_map.end()){
                    file& fl = file_map[filename];
                    if(isUserPresent(fl.file_users, curr_user)){
                        msg = "file already has been uploaded by user ID: " + curr_user;
                    }
                    else{
                        fl.file_users.push_back({curr_user, true});
                        if (peer_info_map.find(newsockfd) != peer_info_map.end()) {
                            auto peer = peer_info_map[newsockfd];
                            bool peer_exists = false;
                            for (auto& p : fl.peer_addresses) {
                                if (p.first == peer.first && p.second == peer.second) {
                                    peer_exists = true;
                                    break;
                                }
                            }
                            if (!peer_exists) {
                                fl.peer_addresses.push_back(peer);
                            }
                        }
                        msg = "file uploaded successfully by user ID: " + curr_user;
                    }
                }
                else{
                    file fl;
                    fl.file_size = stol(words[4]);
                    fl.file_name = filename;
                    fl.chunks_count = stoi(words[5]);
                    fl.file_users.push_back({curr_user, true});
                    fl.file_hash = words[6];
                    
                    for(int i = 7; i < words.size(); i++) {
                        fl.chunk_hashes.push_back(words[i]);
                    }

                    if (peer_info_map.find(newsockfd) != peer_info_map.end()) {
                        fl.peer_addresses.push_back(peer_info_map[newsockfd]);
                    }

                    file_map[filename] = fl;

                    if (find(gp.filesinGroup.begin(), gp.filesinGroup.end(), filename) == gp.filesinGroup.end()) {
                        gp.filesinGroup.push_back(filename);
                    }
                    log_message("File " + filename + " is uploaded by " + curr_user);
                    msg = "file uploaded successfully by user ID: " + curr_user;
                }
            }
            send(newsockfd, msg.c_str(), msg.size(), 0);
        }
        else if (words[0] == "list_files") {
            if (session_map.find(newsockfd) == session_map.end()){
                msg = "Please login first";
            }
            else if (group_map.find(words[1]) == group_map.end()) {
                msg = "group does not exist";
            }
            else {
                group gp = group_map[words[1]];
                string curr_user = session_map[newsockfd];
                bool is_member = false;

                if (gp.owner == curr_user) {
                    is_member = true;
                } else {
                    for (auto& member : gp.member) {
                        if (member == curr_user) {
                            is_member = true;
                            break;
                        }
                    }
                }

                if (!is_member) {
                    msg = "You are not a member of this group";
                } else {
                    for (const string& fname : gp.filesinGroup) {
                        msg += fname + "\n";
                    }
                    if (!msg.empty()) msg.pop_back();
                    if (msg.empty()) msg = "No files in this group";
                }
            }
            send(newsockfd, msg.c_str(), msg.size(), 0);
        }
        else if(words[0] == "download_file"){
            if (session_map.find(newsockfd) == session_map.end()){
                msg = "Please login first";
                send(newsockfd, msg.c_str(), msg.size(), 0);
                continue;
            }

            string group_id = words[1];
            string file_name = words[2];
            string curr_user = session_map[newsockfd];

            if (group_map.find(group_id) == group_map.end()) {
                msg = "Error Group does not exist";
                send(newsockfd, msg.c_str(), msg.size(), 0);
                continue;
            }

            group gid = group_map[group_id];

            bool is_member = false;
            if (gid.owner == curr_user) {
                is_member = true;
            } else {
                for (auto& member : gid.member) {
                    if (member == curr_user) {
                        is_member = true;
                        break;
                    }
                }
            }

            if (!is_member) {
                msg = "Error You are not a member of this group";
                send(newsockfd, msg.c_str(), msg.size(), 0);
                continue;
            }

            if (file_map.find(file_name) == file_map.end()) {
                msg = "Error File not found in group";
                send(newsockfd, msg.c_str(), msg.size(), 0);
                continue;
            }

            file fl = file_map[file_name];

            if (fl.file_users.empty()) {
                msg = "Error No peers available for this file";
                send(newsockfd, msg.c_str(), msg.size(), 0);
                continue;
            }

            msg = to_string(fl.file_size) + " " + 
                  to_string(fl.chunks_count) + " " + 
                  fl.file_hash + " ";

            for (int i = 0; i < fl.chunk_hashes.size(); i++) {
                msg += fl.chunk_hashes[i] + " ";
            }

            for (auto& peer : fl.peer_addresses) {
                msg += peer.first + ":" + peer.second + " ";
            }
            
            if (fl.peer_addresses.empty()) {
                msg = "Error No active peers available for this file";
            }

            send(newsockfd, msg.c_str(), msg.size(), 0);
        }
        else if (words[0] == "download_complete") {
            if (session_map.find(newsockfd) == session_map.end()){
                msg = "Please login first";
                send(newsockfd, msg.c_str(), msg.size(), 0);
                continue;
            }

            string group_id = words[1];
            string file_name = words[2];
            string curr_user = session_map[newsockfd];

            if (file_map.find(file_name) != file_map.end()) {
                file& fl = file_map[file_name];

                bool found = false;
                for (auto& user_pair : fl.file_users) {
                    if (user_pair.first == curr_user) {
                        user_pair.second = true;
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    fl.file_users.push_back({curr_user, true});
                }

                if (peer_info_map.find(newsockfd) != peer_info_map.end()) {
                    auto peer = peer_info_map[newsockfd];
                    bool peer_exists = false;
                    for (auto& p : fl.peer_addresses) {
                        if (p.first == peer.first && p.second == peer.second) {
                            peer_exists = true;
                            break;
                        }
                    }
                    if (!peer_exists) {
                        fl.peer_addresses.push_back(peer);
                    }
                }

                msg = "Download registered successfully";
            } else {
                msg = "Error File not found";
            }

            send(newsockfd, msg.c_str(), msg.size(), 0);
        }
        else if (words[0] == "stop_share") {
            if (session_map.find(newsockfd) == session_map.end()){
                msg = "Please login first";
                send(newsockfd, msg.c_str(), msg.size(), 0);
                continue;
            }

            string group_id = words[1];
            string file_name = words[2];
            string curr_user = session_map[newsockfd];
            
            if (file_map.find(file_name) != file_map.end()) {
                file& fl = file_map[file_name];

                for (auto& user_pair : fl.file_users) {
                    if (user_pair.first == curr_user) {
                        user_pair.second = false;
                        break;
                    }
                }

                if (peer_info_map.find(newsockfd) != peer_info_map.end()) {
                    auto peer = peer_info_map[newsockfd];
                    auto it = fl.peer_addresses.begin();
                    while (it != fl.peer_addresses.end()) {
                        if (it->first == peer.first && it->second == peer.second) {
                            it = fl.peer_addresses.erase(it);
                        } else {
                            ++it;
                        }
                    }
                }
                log_message("Stopped sharing file " + file_name + " by user " + curr_user +
                " in group " + group_id);
                msg = "Stopped sharing file";
            } else {
                msg = "Error File not found";
            }

            send(newsockfd, msg.c_str(), msg.size(), 0);
        }
        else {
            msg = "Invalid command";
            send(newsockfd, msg.c_str(), msg.size(), 0);
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        cout << "Invalid Arguments" << endl;
        return 0;
    }

    init_log("tracker_log.txt");

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

    int option = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0)
        error("setsockopt failed");

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
    quit_thread.detach();

    while(1) {
        int newsockfd = accept(sockfd, (struct sockaddr *) &client_addr, &cli_len);
        if (newsockfd == -1) {
            cout << "ERROR on accept" << endl;
            continue;
        }

        threads_list.push_back(thread(client_handler, newsockfd));
        threads_list.back().detach();
        cout << "client connection success" << endl;
    }

    close(sockfd);
    return 0;
}