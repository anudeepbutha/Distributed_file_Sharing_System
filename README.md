Peer-to-Peer Distributed File Sharing System

This document provides the essential commands for using the Tracker-Client-based file sharing system.

Compilation Tracker:
>g++ tracker.cpp -o tracker

Compilation Client:
>g++ client.cpp -o client -lcrypto -lssl

Run Tracker:
>./tracker tracker_info.txt <tracker_no>
- tracker_info.txt: File containing IP and port details of all trackers.
- tracker_no: Tracker number identifier.

Run Client:
>./client <IP>:<PORT> tracker_info.txt
- <IP>:<PORT>: IP and port of the tracker.
- tracker_info.txt: File containing details of all trackers.

User and Group Management

1. Create User a new user account:
>create_user <user_id> <password>

2. Login:
>login <user_id> <password>

3. Create a new group:
>create_group <group_id>

4. Request to join an existing group:
>join_group <group_id>

5. Leave a group you’re a member of:
>leave_group <group_id>

6. Display all available groups in the system:
>list_groups

7. Show pending join requests:
>list_requests <group_id>

8. Accept Group Joining Request:
>accept_request <group_id> <user_id>

9. Logout:
>logout

File Operations Commands

1. List All Shareable Files in a Group:
>list_files <group_id>

2. Upload File:
>upload_file <file_path> <group_id>

3. Download File:
>download_file <group_id> <file_name> <destination_path>

4. Stop Sharing a File:
>stop_share <group_id> <file_name>

Architectural Overview
- Tracker: Central coordinator; stores file metadata, chunk hashes, peer lists.
- Client (Peer): Acts as both downloader and uploader.
- Files are divided into fixed-size chunks (512 KB).
- Each chunk and file has a SHA1 hash for integrity verification.
- Peers exchange chunks using TCP sockets and a custom message protocol.

Directory Structure:
├── README.md
├── tracker/
    └── tracker.cpp
└── client/
    └── client.cpp
