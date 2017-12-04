Install docker

1. curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
2. add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
3. apt-get update
4. apt-cache policy docker-ce
5. apt-get install -y docker-ce
6. systemctl status docker


Install docker-compose

1. apt-get install python-pip
2. pip install docker-compose

Run containers

1. cd <CMPE281>/docker/
2. Go to folder web1 and web2 put the private key as id_rsa for git to clone
3. docker-compose up -d
4. Containers started running at port 8080, 8081
