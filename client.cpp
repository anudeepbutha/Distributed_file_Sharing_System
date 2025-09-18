#include <bits/stdc++.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

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

int main(int argc, char *argv[]) {
    if (argc < 3) {
        cout << "Invalid Arguments" << endl;
        return 0;
    }

    char* tracker_fname = argv[1];
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

        }
        else if (words[0] == "logout" && words.size() == 1) {
            string reply = send_message(sockfd, words);
            cout << "Recieved from tracker: " << reply << endl;
        }
        else {
            cout << "Invalid Arguments" << endl;
        }
    }
    close(log_fd);
    close(sockfd);
    return 0;
}