#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include "pthread.h"

#define PORT "35325"  // the port users will be connecting to
#define BACKLOG 10     // how many pending connections queue will hold
#define MAXDATASIZE 200000
#define N 3
typedef enum { false, true } bool;


struct record
{
	char name[100];
	char hostname[100];
  char msg_received[1000];
};

struct record mails_present[N];

void sigchld_handler(int s)
{
    while(waitpid(-1, NULL, WNOHANG) > 0);
}

char* concat(char *s1, char *s2)
{
    char *result = malloc(strlen(s1)+strlen(s2)+1);//+1 for the zero-terminator
    //in real code you would check for errors in malloc here
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}


void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void printlist(struct addrinfo *res)
{
	struct addrinfo *p;
	char ipstr[INET6_ADDRSTRLEN];

	 for(p = res;p != NULL; p = p->ai_next)
	 {
	 		void *addr;
      char *ipver;

      if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        } else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }

        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        printf("  %s: %s\n", ipver, ipstr);
	 }


}

void write_to_file(char * file_path, char * message)
{
  FILE *fp = fopen(file_path, "ab");
   if (fp != NULL)
    {
        fputs(message, fp);
        fclose(fp);
    }
}

void reuse_port(int port)
{
	int yes = 1;
	if (setsockopt(port,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int)) == -1) 
    perror("setsockopt");
    exit(1);
}


void * receiveMsg(void * socket)
{
		bool helo_received = false; 
		char *HELO = "HELO";
	 	int sockfd, ret;
 		char code[5];
	 char buffer[MAXDATASIZE];
	 sockfd = (int)socket;
	 memset(buffer, 0, MAXDATASIZE);
	 for (;;) {  
  	ret = recvfrom(sockfd, buffer, MAXDATASIZE, 0, NULL, NULL);
  	if (ret < 0) {    
   printf("Error receiving data!\n");      
  } else {  
   //printf("client: "); 
   
   fputs(buffer, stdout); 
   //printf("\n");   
  }  
 }  

}

char * check_self_mail(char * value)
{
  const char *v1 = strstr(value, "@")+1;
    const char *v2 = strstr(v1, ">");
    size_t length = v2-v1;
    char *result = (char*)malloc(sizeof(char)*(length+1));
    strncpy(result, v1, length);
    result[length] = '\0';
    return result;
}

char * check_name_present(char * value)
{
  const char *v1 = strstr(value, "<")+1;
  const char *v2 = strstr(v1, "@");
  size_t length = v2-v1;
  char *result = (char*)malloc(sizeof(char)*(length+1));
  strncpy(result, v1, length);
  result[length] = '\0';
  return result;
}

char * get_host_string(char * second_buf)
{
  char *saveptr;
  char *first;
  char *second;

  first = strtok_r(second_buf, " ", &saveptr);
  second = strtok_r(NULL, " ", &saveptr);
  return second;
}


struct addrinfo * fill_addr_info(const char *hostname)
{
	struct addrinfo hints, *res, *p;
  int status;
  char ipstr[INET6_ADDRSTRLEN];

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
  hints.ai_socktype = SOCK_STREAM;
  if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
     
    }
  return res;

}

int main (int argc, char * argv [])
{	
	
	char buf[MAXDATASIZE];
	pid_t childpid;
	pthread_t rThread;  
	int sockfd;
	uintptr_t new_fd;
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr;
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int rv, ret;

	memset(&hints, 0, sizeof (hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE; // use my IP

  if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

  for(p = servinfo; p != NULL; p = p->ai_next) {
  			// create a socket here
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

  			if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        ret = bind(sockfd, p->ai_addr, p->ai_addrlen);

        if (ret == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
  }

	  if (p == NULL)  {
	        fprintf(stderr, "server: failed to bind\n");
	        return 2;
	    }



    
    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    sin_size = sizeof(their_addr);
  	new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);

        if (new_fd == -1) {
            perror("accept");
            
        }

  			inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
       

        memset(buf, 0, MAXDATASIZE);

 				 char host[1024];
         char their_host[1024];
         char service[20];
         char their_service[20];
         void *addr;
         void *their_addr_void;

 				const struct sockaddr *ip;
 				ip = servinfo->ai_addr;

 				getnameinfo(ip, sizeof(addr), host, sizeof(host), service, sizeof(service), 0);
 						char *response = " Simple Mail Transfer Service Ready";
            char *codeAndResponse = concat("220 ", host);
            char *ready = concat(codeAndResponse, response);

            int a, b;
            for (a = 0; a < N; a++)
            {
              strcpy(mails_present[a].hostname, host);
            }

            strcpy(mails_present[0].name,"Bill");
            strcpy(mails_present[1].name,"Kevin");
            strcpy(mails_present[2].name,"Tod");

 				if (send(new_fd, ready, strlen(ready), 0) == -1)
 				{
 					perror("send");
 				}



 				// lets not create a thread 
 				//  ret = pthread_create(&rThread, NULL, receiveMsg, (void *)new_fd);

     //    if (ret) 
     //    {  
	  		// 	printf("ERROR: Return Code from pthread_create() is %d\n", ret);  
	  		// 	exit(1);  
 				// }


 				bool await = true;
 				bool notify = true;
 				char *saveptr;
 				char *first;
 				char *second;
 				char *check_ip;
 				

 				while (1) {  
  				
  				while(await == true)
  				{	 
  						
        //      
  					ret = recvfrom(new_fd, buf, MAXDATASIZE, 0, NULL, NULL);
  					fputs(buf, stdout);

  					if (strlen(buf) > 2)
            { 
             
               if (strstr(buf, "DATA") == 0)
               {
  	  					first = strtok_r(buf, " ", &saveptr);
  	  					second = strtok_r(NULL, " ", &saveptr);
  	  					check_ip = concat(s, "\n");
                
                }
            }

  					
  					if (strcmp("HELO", first) == 0)
  					{
  						if (strcmp(check_ip, second) == 0)
  						{	

  							// memset(codeAndResponse, 0, MAXDATASIZE);
  							codeAndResponse = concat("250 ", host);
  							
	  							if (send(new_fd, codeAndResponse, strlen(codeAndResponse), 0) == -1)
 									{	
 												perror("send");
 									}
                  buf[0] = '\0';
	  							
  							
  						}
  					}

  					if (strcmp("MAIL", first) == 0)
  					{      

  								codeAndResponse = concat("250 ", "OK");
                  memset(buf, 0, MAXDATASIZE);
  								
	  							if (send(new_fd, codeAndResponse, strlen(codeAndResponse), 0) == -1)
 									{	
 												perror("send");
 									}
                  buf[0] = '\0';
  					}

  					if (strcmp("RCPT", first) == 0)
  					{
  							
                char *host_space = check_self_mail(second);
                char *name_space = check_name_present(second);
                int a;
               
                for (a = 0; a < N; a++)
                {
                    if ((strcmp(mails_present[a].name, name_space) == 0) && (strcmp(mails_present[a].hostname, host_space) == 0))
                    {
                        codeAndResponse = concat("250 ", "OK");
                        
                      if (send(new_fd, codeAndResponse, strlen(codeAndResponse), 0) == -1)
                      { 
                          perror("send");
                      }
                      break;
                    }

                    else  
                    { 

                      if (a == N - 1)
                      {
                        codeAndResponse = concat("550 ", "No such user here");
                         
                        if (send(new_fd, codeAndResponse, strlen(codeAndResponse), 0) == -1)
                        { 
                            perror("send");
                        }
                    }
                    }
                    codeAndResponse[0] = '\0';
                }	 


  					}

  					if (strstr(buf, "DATA") != 0)
  					{  
                bool wait_for_end = true;
  						  codeAndResponse = "354 Start mail input; end with <CRLF>.<CRLF>";
  						if (send(new_fd, codeAndResponse, strlen(codeAndResponse), 0) == -1)
 									{	
 												perror("send");
 									}
                  codeAndResponse = "";
                  while(wait_for_end == true)
                  {
                      ret = recvfrom(new_fd, buf, MAXDATASIZE, 0, NULL, NULL);
                      
                      // substitute receiver with actual file name
                      
                      if (strstr(buf, ".") != NULL)
                      {

                        
                        codeAndResponse = concat("250 ", "OK");

                        
                        if (send(new_fd, codeAndResponse, strlen(codeAndResponse), 0) == -1)
                        { 
                            perror("send");
                        }
                       
                         write_to_file("receiver.txt", buf);
                         wait_for_end = false;

                    }

                   
                  }
  					}  					
  					
  				}


 					

  				ret = send(new_fd, buf, MAXDATASIZE, 0);
  				if (ret < 0) {    
   				printf("Error sending data!\n");    
   				exit(1);  
  					}  
 				}     

 				close(new_fd);
 				close(sockfd);
 				pthread_exit(NULL);
        freeaddrinfo(servinfo);



return 0;
}