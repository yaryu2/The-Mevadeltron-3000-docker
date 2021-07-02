# The Mevadeltron 3000

A server security system that works in a **one-way link** mechanism. 
The server only accepts protocols defined by the server operator. 
The system is generic and new protocols can be added simply and quickly.

## Technologies

One way link technology is designed so that any hacker who tries to attack the protective server will encounter a black box that will make it very difficult for him to understand his way of implementation. In addition there is a high probability that it will also be blocked by the system.

```mermaid
graph LR
A(Clint) -- some pack --> B(Client proxy)
B -- Signed Internal Protocol --> C(Filter pack)
C -- Signed Internal Protocol --> D(Server proxy)
D -- some pack --> E(Server)
```

### Project is created with:
* Python 3.7
* SQLite
* Bash
* Scapy
* Socket
* Docker


## Setup

To run this project, To run this project, you must first download a Docker:
[Docker Desktop Installer (for windows users)](https://desktop.docker.com/win/stable/amd64/Docker%20Desktop%20Installer.exe)

Once downloaded, all it takes to run the project is to download it from git, and open 4 windows of cmd's in the project folder and type:
* the first one:
```bash
docker-compose run --rm db
```  
* the second one:
```bash
docker-compose run --rm out
```  
* the third one:
```bash
docker-compose run --rm mid
```  
* the fourth one: 
```bash
docker-compose run --rm in
```  
It should be done in the order I presented.
**You did it! the project run successfully**

## Add new protocol support
To add support for a new protocol all you have to do is after running the system you have to press on each machine:
``` Key down
ctrl + D 
```
Then write the command:
``` bash
python3 conf.py 
```
and then follow the instructions given.
