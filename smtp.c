#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "pthread.h"
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

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
    char *result = malloc(strlen(s1)+strlen(s2)+1);
    
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}

char * cut_after_dot(char * value)
{
  const char *v2 = strstr(value, ".")+1;
  const char *v1 = value;
  size_t length = v2 - v1;
  char *result = (char*)malloc(sizeof(char)*(length + 1));
  strncpy(result, v1, length);
  return result;
}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// print list of debugging purposes
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

void write_to_file(const char * file_path, char * message)
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

char * send_data(const char * file_name)
{

 FILE *fp;
 fp = fopen(file_name, "r");
 char * line = NULL;
 size_t len = 0;
 ssize_t read;
 char * msg = malloc(10000);
 
 while((read = getline(&line, &len, fp)) != -1)
  { 
    if (strstr(line, ".") == NULL)
    {
      strcat(msg,line);
    }

    else
    {
      char * end = cut_after_dot(line);
      strcat(msg, end);
    }

  }
  
  return msg;
}

int main (int argc, char *argv[])
{
	// server and client flags and declarations:
	bool sender_mode = false;
	bool receiver_mode = false;
	const char *file_name;
	char buf[MAXDATASIZE];
	int count;
	struct addrinfo hints, *servinfo, *p;
  struct addrinfo myhints, *myservinfo, *myp;

	int rv, ret, sv;
	char host[1024];
	char service[20];
	char s[INET6_ADDRSTRLEN];
	void *addr;
  void *their_addr_void;

	// server declarations:
	pid_t childpid;
	pthread_t rThread;  
	int sockfd;
	uintptr_t new_fd;
	struct sockaddr_storage their_addr;
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	bool await = true;
 	bool notify = true;
 	char *saveptr;
 	char *first;
 	char *second;
 	char *check_ip;
  char their_host[1024];
  char their_service[20];

 	// client declaration:
 	int numbytes;
 	char second_buf[MAXDATASIZE];


 	const char *node; // argv[2] is assigned to it

	if (argc < 2)
	{
			fprintf(stderr, "Usage: %s [-s | --send] [-r | --recv] [hostname] [-f | --fname filename]\n", argv[0]);
			exit(1);
	}

	else
	{
		for (count = 1; count < argc; count++)
		{
			if (strcmp(argv[count], "-s") == 0 || strcmp(argv[count], "--send") == 0)
			{
					sender_mode = true;
					printf("The program runs in sender mode.\n");
			}
			

			else if (strcmp(argv[count], "-r") == 0 || strcmp(argv[count], "--recv") == 0)
			{
					receiver_mode = true;
					printf("The program runs in receiver mode.\n");
			}

			if (sender_mode == true)
			{
				if (argv[++count] !=  NULL)
				{
					node = argv[count];
				}

				else
				{
					printf("Error assigning hostname.\n");
					exit(1);
				}
				count++;
				
			}

			if (receiver_mode == true)
			{
				// do nothing
			}

		if (strcmp(argv[count], "-f") == 0 || strcmp(argv[count], "--fname") == 0)
			{	
				if (sender_mode == true)
				{
					if (argv[++count] != NULL)
					{
						file_name = argv[count];
					}
				}

				if (receiver_mode == true)
				{
					if (argv[++count] != NULL)
					{
						file_name = argv[count];
					}
				}

				if (receiver_mode == true && sender_mode == true)
				{
					printf("It is impossible to run in both modes.\n");
					exit(1);
				}

			}


		}


		if (sender_mode == true)
		{

      gethostname(host, 1023);
			// since now on the sender code applies
			memset(&hints, 0, sizeof hints);
    	hints.ai_family = AF_UNSPEC;
    	hints.ai_socktype = SOCK_STREAM;
      hints.ai_flags = AI_CANONNAME;

      myhints.ai_family = AF_UNSPEC;
      myhints.ai_socktype = SOCK_STREAM;
      myhints.ai_flags = AI_CANONNAME;

    	if ((rv = getaddrinfo(node, PORT, &hints, &servinfo)) != 0) 
    	{
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    	}

      if ((sv = getaddrinfo(host, PORT, &myhints, &myservinfo)) != 0)
      {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
      }

    	for(p = servinfo; p != NULL; p = p->ai_next) 
    	{
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }

        ret = connect(sockfd, p->ai_addr, p->ai_addrlen);
        if (ret == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }

        break;
    	}

      // printf("my canon name: '%s'\n", myservinfo->ai_canonname);


    	if (p == NULL) 
    	{
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    	}

    	memset(buf, 0, MAXDATASIZE);
    	memset(second_buf, 0, MAXDATASIZE);

    	inet_ntop(p->ai_family, 
    		get_in_addr((struct sockaddr *)p->ai_addr),
        s, sizeof s);

    	if ((numbytes = recv(sockfd, buf, MAXDATASIZE, 0)) == -1) 
    	{
        perror("recv");

        exit(1);
    	}

    const struct sockaddr *ip;
    ip = servinfo->ai_addr;

    //getnameinfo(ip, sizeof(addr), host, sizeof(host), service, sizeof(service), 0);

    char *HELO = "HELO ";
    char *codeAndResponse = concat(HELO, myservinfo->ai_canonname);
    codeAndResponse = concat(codeAndResponse, "\n");
    char code[4];
    bool entry_code = false;
    bool handshake_code = false;
    const char *ready_code = "220";
    strncpy(code, buf, 3);
    fputs(buf, stdout);
    fputs("\n", stdout);
    
    char *saveptr;
    char *first;
    char *second;
    char *check_ip;

    if (strcmp(code, ready_code) == 0)
    {
        entry_code = true;

    }

    while(entry_code == true)
    {      
        
        while(strstr(buf, codeAndResponse) == 0)
        {   
            fgets(buf, MAXDATASIZE, stdin);
            if (strstr(buf, codeAndResponse) == 0)
                printf("Code expected: '%s'\n", codeAndResponse);
            //printVariations(code);
            
        }

        send(sockfd, buf, MAXDATASIZE, 0);
        entry_code = false;
        
        
        entry_code = false;
    }

    if ((numbytes = recv(sockfd, second_buf, MAXDATASIZE, 0) == -1))
    {
        perror("recv");

        exit(1);
    }

      fputs(second_buf, stdout);
     char holder[INET6_ADDRSTRLEN];
   
     strcpy(holder, second_buf);
     
     char *their_host = get_host_string(holder);
     first = strtok_r(second_buf, " ", &saveptr);
     second = strtok_r(NULL, " ", &saveptr);

     if (strcmp("250", first) == 0)
     {
       fputs("\n", stdout);
     }

     char* prev_checker;
     char* resp_checker;

     bool sender_flag = true;
     bool mail_flag = false;
     bool data_flag = false;
     bool end_of_msg_flag = false;

     while(sender_flag == true)
    {       
            fgets(buf, MAXDATASIZE, stdin);
            
            if (strstr(buf, "QUIT") != 0)
                {
                    ret = send(sockfd, buf, MAXDATASIZE, 0);
                    if ((numbytes = recv(sockfd, second_buf, MAXDATASIZE, 0) == -1))
                     {
                        perror("recv");
                     }

                     if ((numbytes = recv(sockfd, second_buf, MAXDATASIZE, 0) == -1))
                     {
                        perror("recv");
                     }

                    fputs(second_buf, stdout);
                    fputs("\n", stdout);

                     if (strstr (second_buf, "221") != 0)
                     {  

                        sender_flag = false;
                     }

                }

            if (strstr(buf, "MAIL") != 0)
            {   
                
                char * result = check_self_mail(buf);
                
                // MAIL FROM:<Smith@hostname>
                


                if ((strstr(buf, "MAIL") != 0) && (strcmp(myservinfo->ai_canonname, result) == 0)) // if "MAIL" is substr of buf and s equals to result
                {    
                     result[0] = '\0'; // clean string
                    
                     ret = send(sockfd, buf, MAXDATASIZE, 0);
                     memset(second_buf, 0, MAXDATASIZE);
                     if ((numbytes = recv(sockfd, second_buf, MAXDATASIZE, 0) == -1))
                     {
                        perror("recv");
                     }
                     

                    fputs(second_buf, stdout);
                    fputs("\n", stdout);
                    
                    if (strstr("250", second_buf) == 0)
                    {
                        mail_flag = true;
                        memset(buf, 0, MAXDATASIZE);
                    while(mail_flag == true)
                    {   
                        
                        
                        fgets(buf, MAXDATASIZE, stdin);
                        
                       
                        if (strstr(buf, "DATA") == NULL)
                            result = check_self_mail(buf);
                        
                        if ((strstr(buf, "RCPT") != 0) && (strcmp(result, their_host) == 0)) // if buf contains RCPT and result is their host
                        {   
                            
                            ret = send(sockfd, buf, MAXDATASIZE, 0);
                            // should get code back to proceed
                            if ((numbytes = recv(sockfd, second_buf, MAXDATASIZE, 0) == -1))
                            {
                                perror("recv");

                                exit(1);
                            }

                            fputs(second_buf, stdout); // if 250 he is added to list
                            printf("\n");
                            // if 550 he is not
                            memset(second_buf, 0, MAXDATASIZE);

                        }

                        else if (strstr(buf, "DATA") != 0) 
                        {   // ALSO CHECK THAT HE ENTERED AT LEAST ONE RCPT
                            
                            ret = send(sockfd, buf, MAXDATASIZE, 0);
                            if ((numbytes = recv(sockfd, second_buf, MAXDATASIZE, 0) == -1))
                            {
                                perror("recv");

                                exit(1);
                            }

                            fputs(second_buf, stdout); // start data flag
                            fputs("\n", stdout);
                            data_flag = true;

                            // allows to send data in one attached file
                            if (strstr(second_buf, "354") != NULL)
                            {   
                                memset(second_buf,0,MAXDATASIZE); // ?
                                while (data_flag == true)
                                {
                                    fgets(buf, MAXDATASIZE, stdin);

                                    if (strstr(buf, "Send") != NULL)
                                    {   
                                        // only email of 1000 chars allowed. 
                                        char * mail = send_data(file_name);
                                        
                                        ret = send(sockfd, mail, MAXDATASIZE,0);

                                        if ((numbytes = recv(sockfd, second_buf, MAXDATASIZE, 0) == -1))
                                        {
                                            perror("recv");

                                            exit(1);
                                        }
                                        fputs(second_buf, stdout);
                                        fputs("\n", stdout);

                                        if (strstr(second_buf, "250") != NULL)
                                        {
                                            data_flag = false;
                                            mail_flag = false;
                                        }

                                    }

                                    else
                                    {
                                        printf("Type: 'Send' to send prepared email to the recipients.");
                                    }

                                }
                            }

                        }
                        

                        else
                        {
                            printf("The format is: RCPT TO:<name@host>\n");
                        }

                        
                        
                    }

                    }

                }


            }


    }

    close(sockfd);
    freeaddrinfo(servinfo); // all done with this structure

		}

		if (receiver_mode == true)
		{ 

      gethostname(host, 1023);
			// since now on the receiver code applies
			memset(&hints, 0, sizeof (hints));
  		hints.ai_family = AF_UNSPEC;
  		hints.ai_socktype = SOCK_STREAM;
  		hints.ai_flags = AI_CANONNAME; // use my IP

  		if ((rv = getaddrinfo(host, PORT, &hints, &servinfo)) != 0) 
  		{
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    	}

    	for(p = servinfo; p != NULL; p = p->ai_next) 
    	{
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

        if (ret == -1) 
        {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
  		}

  		if (p == NULL)  
  		{
	        fprintf(stderr, "server: failed to bind\n");
	        return 2;
	    }

	    // listen for incoming connections
	    if (listen(sockfd, BACKLOG) == -1) 
	    {
        perror("listen");
        exit(1);
    	}

    	sa.sa_handler = sigchld_handler; // reap all dead processes
    	sigemptyset(&sa.sa_mask);
    	sa.sa_flags = SA_RESTART;

    	if (sigaction(SIGCHLD, &sa, NULL) == -1) 
    	{
        perror("sigaction");
        exit(1);
    	}

    	sin_size = sizeof(their_addr);
  		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);

  		if (new_fd == -1) 
  		{
            perror("accept");
            
      }

  		inet_ntop(their_addr.ss_family,
      	get_in_addr((struct sockaddr *)&their_addr),
      	s, sizeof s);



  		memset(buf, 0, MAXDATASIZE);

  		const struct sockaddr *ip;
 			ip = servinfo->ai_addr;

 			//getnameinfo(ip, sizeof(addr), host, sizeof(host), service, sizeof(service), 0);
 			char *response = " Simple Mail Transfer Service Ready";
 			char *codeAndResponse = concat("220 ", p->ai_canonname);
 			char *ready = concat(codeAndResponse, response);
 			int a, b;

 			for (a = 0; a < N; a++)
      {
      	strcpy(mails_present[a].hostname, host);
      }

      // are assumed to be present on the receiver
      strcpy(mails_present[0].name,"Bill");
      strcpy(mails_present[1].name,"Kevin");
      strcpy(mails_present[2].name,"Tod");

      if (send(new_fd, ready, strlen(ready), 0) == -1)
 			{
 					perror("send");
 			}

 			while (receiver_mode == true) 
 			{  
  				
  				while(await == true)
  				{	 
  						
        //      
  					ret = recvfrom(new_fd, buf, MAXDATASIZE, 0, NULL, NULL);
  					fputs(buf, stdout);

  					if (strlen(buf) > 2)
            { 
             
               if (strstr(buf, "DATA") == 0 || strstr(buf, "QUIT") == 0)
               {
  	  					first = strtok_r(buf, " ", &saveptr);
  	  					second = strtok_r(NULL, " ", &saveptr);
  	  					check_ip = concat(s, "\n");
                
                }
            }

  					
  					if (strcmp("HELO", first) == 0)
  					{
  						  
  							// memset(codeAndResponse, 0, MAXDATASIZE);
  							codeAndResponse = concat("250 ", host);
  							
	  							if (send(new_fd, codeAndResponse, strlen(codeAndResponse), 0) == -1)
 									{	
 												perror("send");
 									}
                  buf[0] = '\0';
	  								
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

  					if (strstr(buf, "QUIT") != 0)
  					{
  						codeAndResponse = concat("221 ", host);
  						response = " Service closing transmission channel";
  						codeAndResponse = concat(codeAndResponse, response);

  						if (send(new_fd, codeAndResponse, strlen(codeAndResponse), 0) == -1)
 							{	
 								perror("send");
 							}
 							await = false;
 							receiver_mode = false;

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
                      
                      
                      if (strstr(buf, ".") != NULL)
                      {

                        
                        codeAndResponse = concat("250 ", "OK");


                        if (send(new_fd, codeAndResponse, strlen(codeAndResponse), 0) == -1)
                        { 
                            perror("send");
                        }
                       
                         write_to_file(file_name, buf);
                         wait_for_end = false;

                    }

                   
                  }
  					}  					
  					
  				}

 				}     

 				close(new_fd);
 				close(sockfd);
 				freeaddrinfo(servinfo);

		}
	}
	


	return 0;
}



