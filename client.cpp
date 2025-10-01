#include <bits/stdc++.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHUNK_SIZE 524288

using namespace std;

void error(string msg) {
    perror(msg.c_str());
    exit(1);
}

string send_message(int sockfd, vector<string> words) {
    char buffer[1024];
    string msg = "";
    for (string str:words)
        msg= msg+str+" ";
    send(sockfd, msg.c_str(), msg.size(), 0);
    ssize_t n = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    buffer[n]='\0';
    return buffer;
}

string ssend_message(int sockfd, string msg) {
    char buffer[1024];
    send(sockfd, msg.c_str(), msg.size(), 0);
    ssize_t n = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    buffer[n]='\0';
    return buffer;
}

string filepath_to_filename(string& file_path) {
    size_t pos = file_path.find_last_of('/');

    if (pos != string::npos)
        return file_path.substr(pos + 1);

    return file_path;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        cout << "Invalid Arguments" << endl;
        return 0;
    }

    char* client_details = argv[1];
    
    char* tracker_fname = argv[2];
    int tracker_ports[2];
    ifstream file(tracker_fname);
    string line;
    int counter=0;
    while (getline(file, line)) {
        int pos = line.find(' ');
        string ip=line.substr(0, pos);
        tracker_ports[counter]=stoi(line.substr(pos+1));
        counter++;
    }
    file.close();

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");

    for (int i=0; i<2; i++) {
        struct sockaddr_in client_add;
        bzero((char *) &client_add, sizeof(client_add));
        client_add.sin_family = AF_INET;
        client_add.sin_addr.s_addr = INADDR_ANY;
        client_add.sin_port = htons(tracker_ports[i]);

        if (connect(sockfd,(struct sockaddr *) &client_add,sizeof(client_add)) == 0){
            cout << "Connection Successfull on port" << tracker_ports[i] << endl;
            break;
        }
        else
            cout << "Unable to connect to port - " << tracker_ports[i] << endl;
    }

    int log_fd = open("client_log.txt", O_RDWR | O_APPEND | O_CREAT, 0644);
    if(log_fd < 0)
        error("Unable to open the file");
    while (1) {
        string line_read;
        cout << "$>";
        getline(cin,line_read);
        vector<string> words;
        char *token = strtok(const_cast<char*>(line_read.c_str()), " ");

        while (token != NULL) {
            words.push_back(token);
            token = strtok(NULL, " ");
        }
        // Empty string
        if (words.size() == 0) continue;

        if (words[0] == "create_user" && words.size() == 3) {
            string reply = send_message(sockfd, words);
            cout << "Recieved from tracker: " << reply << endl;
        }
        else if (words[0] == "login" && words.size() == 3) {
            string reply = send_message(sockfd, words);
            cout << "Recieved from tracker: " << reply << endl;
        }
        else if (words[0] == "create_group" && words.size() == 2){
            string reply = send_message(sockfd, words);
            cout << "Recieved from tracker: " << reply << endl;
        }
        else if (words[0] == "join_group" && words.size() == 2) { // Need to test
            string reply = send_message(sockfd, words);
            cout << "Recieved from tracker: " << reply << endl;
        }
        else if (words[0] == "leave_group" && words.size() == 2) {
            string reply = send_message(sockfd, words);
            cout << "Recieved from tracker: " << reply << endl;
        }
        else if (words[0] == "list_groups" && words.size() == 1) {
            string reply = send_message(sockfd, words);
            cout << "Available groups are\n" << reply << endl;
        }
        else if (words[0] == "list_requests" && words.size() == 2) {
            string reply = send_message(sockfd, words);
            cout << "Available groups are\n" << reply << endl;
        }
        else if (words[0] == "accept_request" && words.size() == 3) {
            string reply = send_message(sockfd, words);
            cout << "Available groups are\n" << reply << endl;
        }
        else if (words[0] == "logout" && words.size() == 1) {
            string reply = send_message(sockfd, words);
            cout << "Recieved from tracker: " << reply << endl;
        }
        else if (words[0] == "quit" && words.size() == 1) {
            break;
        }
        else if (words[0] == "upload_file" && words.size() == 3) {
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
            if (file_size < 0)
                error("Issue with file size");
            int chunks_count = file_size / CHUNK_SIZE;
            int last_chunk_size = file_size % CHUNK_SIZE;
            if (last_chunk_size>0)
                chunks_count++;
            cout << "Uploading file: " << filename << endl;
            cout << "File Size: " << file_size << endl;
            cout << "Number of chunks - " << chunks_count << endl;

            vector<string> chunk_hashes;
            char hash_buffer[CHUNK_SIZE];
            off_t bytes_read = 0;

            SHA_CTX file_ctx;
            SHA1_Init(&file_ctx);

            while(bytes_read < file_size){
                memset(hash_buffer, 0, sizeof(hash_buffer));
                ssize_t n = read(fd, hash_buffer, CHUNK_SIZE);
                if (n<=0) break;

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
            string msg="upload_file " + group_id + " " + filename + " " + file_path + " " +
            to_string(file_size) + " " + to_string(chunks_count) + " " + file_hash + " ";
            for (int i=0; i<chunk_hashes.size(); i++)
                msg += chunk_hashes[i] + " ";
            string reply = ssend_message(sockfd, msg);
            cout << reply << endl;
        }
        else {
            cout << "Invalid Arguments" << endl;
        }
    }
    close(log_fd);
    close(sockfd);
    return 0;
}