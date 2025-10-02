#include <bits/stdc++.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include <mutex>

#define CHUNK_SIZE 524288

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

struct file {
    string file_name;
    long file_size;
    int chunks_count;
    string file_hash;
    vector<string> chunk_hashes;
    vector<bool> chunks_downloaded;
    string file_path;
};

map<string, file> local_files;
mutex file_mutex;
string current_user;
string peer_ip, peer_port;
bool is_logged_in = false;

void error(string msg) {
    perror(msg.c_str());
    exit(1);
}

string send_message(int sockfd, vector<string> words) {
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));
    string msg = "";
    for (string str:words)
        msg = msg + str + " ";
    send(sockfd, msg.c_str(), msg.size(), 0);
    ssize_t n = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (n <= 0) return "";
    buffer[n] = '\0';
    return buffer;
}

string ssend_message(int sockfd, string msg) {
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));
    send(sockfd, msg.c_str(), msg.size(), 0);
    ssize_t n = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (n <= 0) return "";
    buffer[n] = '\0';
    return buffer;
}

string filepath_to_filename(string& file_path) {
    size_t pos = file_path.find_last_of('/');
    if (pos != string::npos)
        return file_path.substr(pos + 1);
    return file_path;
}

void share_chunk(int sockfd){
    char buffer[2048];
    memset(buffer, 0, sizeof(buffer));
    ssize_t n = recv(sockfd, buffer, sizeof(buffer), 0);
    if (n <= 0) {
        close(sockfd);
        return;
    }

    vector<string> words;
    char *token = strtok(buffer, " ");
    while (token != NULL) {
        words.push_back(token);
        token = strtok(NULL, " ");
    }

    if (words.size() < 3 || words[0] != "get_chunk") {
        string msg = "Invalid request";
        send(sockfd, msg.c_str(), msg.size(), 0);
        close(sockfd);
        return;
    }

    string filename = words[1];
    int chunk_no = stoi(words[2]);

    file_mutex.lock();
    if (local_files.find(filename) == local_files.end()) {
        file_mutex.unlock();
        string msg = "File not found";
        send(sockfd, msg.c_str(), msg.size(), 0);
        close(sockfd);
        return;
    }

    file fl = local_files[filename];
    file_mutex.unlock();

    if (chunk_no >= fl.chunks_count) {
        string msg = "Invalid chunk number";
        send(sockfd, msg.c_str(), msg.size(), 0);
        close(sockfd);
        return;
    }

    int fd = open(fl.file_path.c_str(), O_RDONLY);
    if (fd < 0) {
        string msg = "Cannot open file";
        send(sockfd, msg.c_str(), msg.size(), 0);
        close(sockfd);
        return;
    }

    off_t offset = (off_t)chunk_no * CHUNK_SIZE;
    lseek(fd, offset, SEEK_SET);

    char chunk_buffer[CHUNK_SIZE];
    memset(chunk_buffer, 0, sizeof(chunk_buffer));
    ssize_t bytes_read = read(fd, chunk_buffer, CHUNK_SIZE);
    close(fd);

    if (bytes_read <= 0) {
        string msg = "Error reading chunk";
        send(sockfd, msg.c_str(), msg.size(), 0);
        close(sockfd);
        return;
    }

    string size_msg = to_string(bytes_read);
    send(sockfd, size_msg.c_str(), size_msg.size(), 0);
    
    char ack[10];
    memset(ack, 0, sizeof(ack));
    recv(sockfd, ack, sizeof(ack), 0);

    ssize_t sent = 0;
    ssize_t total_sent = 0;
    while (total_sent < bytes_read) {
        sent = send(sockfd, chunk_buffer + total_sent, bytes_read - total_sent, 0);
        if (sent <= 0) break;
        total_sent += sent;
    }

    close(sockfd);
}

void peer_connection(string ip, string port){
    int listen_sock;
    if((listen_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        cout << "Error in socket creation" << endl;
        return;
    }

    int option = 1;
    if(setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) == -1){ 
        cout << "Error in setsockopt" << endl;
        close(listen_sock);
        return;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(stoi(port)); 

    if(bind(listen_sock, (struct sockaddr *) &addr, sizeof(addr)) == -1){ 
        cout << "Error in binding" << endl;
        close(listen_sock);
        return;
    }

    if(listen(listen_sock, 10) == -1){ 
        cout << "Error in listen" << endl;
        close(listen_sock);
        return;
    }

    cout << "Peer server listening on port " << port << endl;

    socklen_t len = sizeof(addr);
    while(1){
        int new_sock;
        if ((new_sock = accept(listen_sock, (struct sockaddr *) &addr, &len)) == -1){
            continue;
        }
        thread serv(share_chunk, new_sock);
        serv.detach();
    }
}

bool download_chunk_from_peer(string peer_ip, string peer_port, string filename, int chunk_no, char* chunk_buffer, int& bytes_received) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return false;
    }

    struct sockaddr_in serv_addr;
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(stoi(peer_port));

    if (inet_pton(AF_INET, peer_ip.c_str(), &serv_addr.sin_addr) <= 0) {
        close(sockfd);
        return false;
    }

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        close(sockfd);
        return false;
    }

    string msg = "get_chunk " + filename + " " + to_string(chunk_no);
    if (send(sockfd, msg.c_str(), msg.size(), 0) <= 0) {
        close(sockfd);
        return false;
    }

    char size_buffer[64];
    memset(size_buffer, 0, sizeof(size_buffer));
    ssize_t n = recv(sockfd, size_buffer, sizeof(size_buffer), 0);
    if (n <= 0) {
        close(sockfd);
        return false;
    }
    size_buffer[n] = '\0';

    int chunk_size = atoi(size_buffer);
    if (chunk_size <= 0 || chunk_size > CHUNK_SIZE) {
        close(sockfd);
        return false;
    }

    string ack = "OK";
    send(sockfd, ack.c_str(), ack.size(), 0);

    memset(chunk_buffer, 0, CHUNK_SIZE);
    int total_received = 0;
    while (total_received < chunk_size) {
        n = recv(sockfd, chunk_buffer + total_received, chunk_size - total_received, 0);
        if (n <= 0) break;
        total_received += n;
    }

    close(sockfd);
    bytes_received = total_received;
    return (total_received == chunk_size);
}

bool verify_chunk_hash(char* chunk_data, int size, string expected_hash) {
    unsigned char hash_raw[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(chunk_data), size, hash_raw);

    char hash_hex[41];
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(hash_hex + (i * 2), "%02x", hash_raw[i]);
    hash_hex[40] = '\0';

    return (expected_hash == string(hash_hex));
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        cout << "Invalid Arguments" << endl;
        cout << "Usage: ./client <IP>:<PORT> <tracker_info.txt>" << endl;
        return 0;
    }

    init_log("client_log.txt");

    string client_details = argv[1];
    size_t cpos = client_details.find(':');
    string client_ip = client_details.substr(0, cpos);
    string client_port = client_details.substr(cpos + 1);
    
    peer_ip = client_ip;
    peer_port = client_port;

    char* tracker_fname = argv[2];
    int tracker_ports[2];
    string tracker_ips[2];
    ifstream tra_file(tracker_fname);
    string line;
    int counter = 0;
    while (getline(tra_file, line)) {
        int pos = line.find(' ');
        tracker_ips[counter] = line.substr(0, pos);
        tracker_ports[counter] = stoi(line.substr(pos+1));
        counter++;
    }
    tra_file.close();

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");

    bool connected = false;
    for (int i = 0; i < 2; i++) {
        struct sockaddr_in client_add;
        bzero((char *) &client_add, sizeof(client_add));
        client_add.sin_family = AF_INET;
        client_add.sin_addr.s_addr = INADDR_ANY;
        client_add.sin_port = htons(tracker_ports[i]);

        if (connect(sockfd, (struct sockaddr *) &client_add, sizeof(client_add)) == 0){
            cout << "Connection Successful on port " << tracker_ports[i] << endl;
            connected = true;
            break;
        }
        else
            cout << "Unable to connect to port - " << tracker_ports[i] << endl;
    }

    if (!connected) {
        cout << "Could not connect to any tracker" << endl;
        close(sockfd);
        return 0;
    }

    thread peer_thread(peer_connection, client_ip, client_port);
    peer_thread.detach();

    int log_fd = open("client_log.txt", O_RDWR | O_APPEND | O_CREAT, 0644);
    if(log_fd < 0)
        error("Unable to open the file");
    
    while (1) {
        string line_read;
        cout << "$> ";
        getline(cin, line_read);
        
        if (line_read.empty()) continue;
        
        vector<string> words;
        char *token = strtok(const_cast<char*>(line_read.c_str()), " ");

        while (token != NULL) {
            words.push_back(token);
            token = strtok(NULL, " ");
        }
        
        if (words.size() == 0) continue;

        if (words[0] == "create_user" && words.size() == 3) {
            string reply = send_message(sockfd, words);
            cout << "Received from tracker: " << reply << endl;
        }
        else if (words[0] == "login" && words.size() == 3) {
            string reply = send_message(sockfd, words);
            cout << "Received from tracker: " << reply << endl;
            
            if (reply.find("successful") != string::npos) {
                is_logged_in = true;
                current_user = words[1];
                
                string peer_msg = "register_peer " + peer_ip + " " + peer_port;
                string peer_reply = ssend_message(sockfd, peer_msg);
                cout << "Peer registration: " << peer_reply << endl;
            }
        }
        else if (words[0] == "create_group" && words.size() == 2){
            string reply = send_message(sockfd, words);
            cout << "Received from tracker: " << reply << endl;
        }
        else if (words[0] == "join_group" && words.size() == 2) {
            string reply = send_message(sockfd, words);
            cout << "Received from tracker: " << reply << endl;
        }
        else if (words[0] == "leave_group" && words.size() == 2) {
            string reply = send_message(sockfd, words);
            cout << "Received from tracker: " << reply << endl;
        }
        else if (words[0] == "list_groups" && words.size() == 1) {
            string reply = send_message(sockfd, words);
            cout << "Available groups are:\n" << reply << endl;
        }
        else if (words[0] == "list_requests" && words.size() == 2) {
            string reply = send_message(sockfd, words);
            cout << "Pending requests:\n" << reply << endl;
        }
        else if (words[0] == "accept_request" && words.size() == 3) {
            string reply = send_message(sockfd, words);
            cout << "Received from tracker: " << reply << endl;
        }
        else if (words[0] == "list_files" && words.size() == 2) {
            string reply = send_message(sockfd, words);
            cout << "Available files:\n" << reply << endl;
        }
        else if (words[0] == "logout" && words.size() == 1) {
            string reply = send_message(sockfd, words);
            cout << "Received from tracker: " << reply << endl;
            is_logged_in = false;
            current_user = "";
        }
        else if (words[0] == "quit" && words.size() == 1) {
            if (is_logged_in) {
                vector<string> logout_cmd = {"logout"};
                send_message(sockfd, logout_cmd);
            }
            break;
        }
        else if (words[0] == "upload_file" && words.size() == 3) {
            if (!is_logged_in) {
                cout << "Please login first" << endl;
                continue;
            }

            string group_id = words[1];
            string file_path = words[2];
            string filename = filepath_to_filename(file_path);
            
            int fd = open(file_path.c_str(), O_RDONLY);
            if (fd < 0) {
                cout << "No such file exists" << endl;
                continue;
            }

            off_t file_size = lseek(fd, 0, SEEK_END);
            lseek(fd, 0, SEEK_SET);
            if (file_size < 0) {
                close(fd);
                error("Issue with file size");
            }

            int chunks_count = file_size / CHUNK_SIZE;
            int last_chunk_size = file_size % CHUNK_SIZE;
            if (last_chunk_size > 0)
                chunks_count++;

            cout << "Uploading file: " << filename << endl;
            cout << "File Size: " << file_size << " bytes" << endl;
            cout << "Number of chunks: " << chunks_count << endl;

            vector<string> chunk_hashes;
            char hash_buffer[CHUNK_SIZE];
            off_t bytes_read = 0;

            SHA_CTX file_ctx;
            SHA1_Init(&file_ctx);

            while(bytes_read < file_size){
                memset(hash_buffer, 0, sizeof(hash_buffer));
                ssize_t n = read(fd, hash_buffer, CHUNK_SIZE);
                if (n <= 0) break;

                SHA1_Update(&file_ctx, hash_buffer, n);

                unsigned char hash_raw[SHA_DIGEST_LENGTH];
                SHA1(reinterpret_cast<const unsigned char *>(hash_buffer), n, hash_raw);

                char output_buffer[41];
                for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
                    sprintf(output_buffer + (i * 2), "%02x", hash_raw[i]);
                output_buffer[SHA_DIGEST_LENGTH * 2] = '\0';
                chunk_hashes.push_back(output_buffer);
                bytes_read += n;
            }

            unsigned char file_hash_raw[SHA_DIGEST_LENGTH];
            SHA1_Final(file_hash_raw, &file_ctx);

            char file_hash[41];
            for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
                sprintf(file_hash + (i * 2), "%02x", file_hash_raw[i]);
            file_hash[SHA_DIGEST_LENGTH * 2] = '\0';
            close(fd);

            string msg = "upload_file " + group_id + " " + filename + " " + file_path + " " +
                        to_string(file_size) + " " + to_string(chunks_count) + " " + file_hash + " ";
            for (int i = 0; i < chunk_hashes.size(); i++)
                msg += chunk_hashes[i] + " ";

            string reply = ssend_message(sockfd, msg);
            cout << reply << endl;

            if (reply.find("successfully") != string::npos) {
                file fl;
                fl.file_name = filename;
                fl.file_size = file_size;
                fl.chunks_count = chunks_count;
                fl.file_hash = string(file_hash);
                fl.chunk_hashes = chunk_hashes;
                fl.chunks_downloaded = vector<bool>(chunks_count, true);
                fl.file_path = file_path;

                file_mutex.lock();
                local_files[filename] = fl;
                file_mutex.unlock();
            }
        }
        else if(words[0] == "download_file" && words.size() == 4){
            if (!is_logged_in) {
                cout << "Please login first" << endl;
                continue;
            }

            string group_id = words[1];
            string file_name = words[2];
            string destination_path = words[3];
            
            string msg = "download_file " + group_id + " " + file_name;
            string reply = ssend_message(sockfd, msg);
            
            if (reply.empty() || reply.find("Error") == 0) {
                cout << reply << endl;
                continue;
            }

            vector<string> response_parts;
            char* tok = strtok(const_cast<char*>(reply.c_str()), " ");
            while (tok != NULL) {
                response_parts.push_back(tok);
                tok = strtok(NULL, " ");
            }

            if (response_parts.size() < 3) {
                cout << "Invalid response from tracker" << endl;
                continue;
            }

            long file_size = stol(response_parts[0]);
            int chunks_count = stoi(response_parts[1]);
            string file_hash = response_parts[2];
            
            vector<string> chunk_hashes;
            for (int i = 3; i < 3 + chunks_count; i++) {
                if (i < response_parts.size())
                    chunk_hashes.push_back(response_parts[i]);
            }

            vector<pair<string, string>> peers;
            for (int i = 3 + chunks_count; i < response_parts.size(); i++) {
                string peer_info = response_parts[i];
                size_t colon_pos = peer_info.find(':');
                if (colon_pos != string::npos) {
                    string ip = peer_info.substr(0, colon_pos);
                    string port = peer_info.substr(colon_pos + 1);
                    peers.push_back({ip, port});
                }
            }

            if (peers.empty()) {
                cout << "No peers available for download" << endl;
                continue;
            }

            cout << "\nStarting download of " << file_name << endl;
            cout << "File size: " << file_size << " bytes" << endl;
            cout << "Chunks: " << chunks_count << endl;
            cout << "Available peers: " << peers.size() << endl;

            string dest_file = destination_path;
            if (dest_file.back() != '/')
                dest_file += "/";
            dest_file += file_name;

            int dest_fd = open(dest_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (dest_fd < 0) {
                cout << "Cannot create destination file at " << dest_file << endl;
                continue;
            }
            if (ftruncate(dest_fd, file_size) < 0) {
                perror("ftruncate");
                close(dest_fd);
                continue;
            }
            vector<bool> chunks_downloaded(chunks_count, false);
            int chunks_completed = 0;

            for (int chunk_no = 0; chunk_no < chunks_count; chunk_no++) {
                bool chunk_success = false;
                char chunk_buffer[CHUNK_SIZE];
                int bytes_received = 0;

                for (auto& peer : peers) {
                    if (download_chunk_from_peer(peer.first, peer.second, file_name, chunk_no, chunk_buffer, bytes_received)) {
                        if (chunk_no < chunk_hashes.size() && verify_chunk_hash(chunk_buffer, bytes_received, chunk_hashes[chunk_no])) {
                            off_t offset = (off_t)chunk_no * CHUNK_SIZE;
                            pwrite(dest_fd, chunk_buffer, bytes_received, offset);
                            chunks_downloaded[chunk_no] = true;
                            chunks_completed++;
                            chunk_success = true;
                            
                            cout << "Downloaded chunk " << (chunk_no + 1) << "/" << chunks_count << " (" 
                                 << (chunks_completed * 100 / chunks_count) << "%)" << endl;
                            break;
                        } else {
                            cout << "Chunk " << (chunk_no + 1) << " hash verification failed, retrying..." << endl;
                        }
                    }
                }

                if (!chunk_success) {
                    cout << "Failed to download chunk " << (chunk_no + 1) << endl;
                }
            }

            close(dest_fd);

            if (chunks_completed == chunks_count) {
                cout << "\n[C] [" << group_id << "] " << file_name << endl;
                cout << "Download completed successfully!\n" << endl;

                file fl;
                fl.file_name = file_name;
                fl.file_size = file_size;
                fl.chunks_count = chunks_count;
                fl.file_hash = file_hash;
                fl.chunk_hashes = chunk_hashes;
                fl.chunks_downloaded = chunks_downloaded;
                fl.file_path = dest_file;

                file_mutex.lock();
                local_files[file_name] = fl;
                file_mutex.unlock();

                string notify_msg = "download_complete " + group_id + " " + file_name;
                ssend_message(sockfd, notify_msg);
            } else {
                cout << "\nDownload incomplete. Completed " << chunks_completed << "/" << chunks_count << " chunks" << endl;
            }
        }
        else if (words[0] == "stop_share" && words.size() == 3) {
            string reply = send_message(sockfd, words);
            cout << "Received from tracker: " << reply << endl;
        }
        else {
            cout << "Invalid command or arguments" << endl;
        }
    }
    close(log_fd);
    close(sockfd);
    return 0;
}