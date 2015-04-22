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

typedef enum { false, true } bool;

#define PORT "35325" // the port client will be connecting to 

#define MAXDATASIZE 200000 // max number of bytes we can get at once 

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

char* concat(char *s1, char *s2)
{
    char *result = malloc(strlen(s1)+strlen(s2)+1);//+1 for the zero-terminator
    //in real code you would check for errors in malloc here
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

char * get_host_string(char * second_buf)
{
  char * ptr;
  ptr = strtok(second_buf, " ");
  int count = 0;
  while (count != 1)
  { 
    ptr = strtok (NULL, " ");
    count++;

  }
  return ptr;
 
}

void * receiveMsg(void * socket) {  
 int sockfd, ret;  
 char buffer[MAXDATASIZE];   
 sockfd = (int) socket;  
 memset(buffer, 0, MAXDATASIZE);    
 for (;;) {  
  ret = recvfrom(sockfd, buffer, MAXDATASIZE, 0, NULL, NULL);    
  if (ret < 0) {    
   printf("Error receiving data!\n");      
  } else {  
   
  // fputs(buffer, stdout);  
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

void printVariations(char * code)
{   
    const char *ready_code = "220";

    if (strcmp(code, ready_code) == 0)
    {
        printf("usage: HELO <hostname>\n");
    }
}

// pass it local mail name - get its context
char * send_data(char * file_name)
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



int main(int argc, char *argv[])
{
    int ret, numbytes;
    uintptr_t sockfd;
    char buf[MAXDATASIZE];
    char second_buf[MAXDATASIZE];
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];
    pthread_t rThread;
    if (argc != 2) {
        fprintf(stderr,"usage: client hostname\n");
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }


    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
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

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    }

    memset(buf, 0, MAXDATASIZE);
    memset(second_buf, 0, MAXDATASIZE);
    // later
    //ret = pthread_create(&rThread, NULL, receiveMsg, (void *) sockfd);  

    // if (ret) {  
    // printf("ERROR: Return Code from pthread_create() is %d\n", ret);  
    // exit(1);  
    // }  

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);
    //printf("client: connecting to %s\n", s);

    if ((numbytes = recv(sockfd, buf, MAXDATASIZE, 0)) == -1) {
        perror("recv");

        exit(1);
    }


    char host[1024];
    char service[20];
    void *addr;

    const struct sockaddr *ip;
    ip = servinfo->ai_addr;

    getnameinfo(ip, sizeof(addr), host, sizeof(host), service, sizeof(service), 0);

    char *HELO = "HELO ";
    char *codeAndResponse = concat(HELO, s);
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
        
        while(strcmp(buf, codeAndResponse) != 0)
        {   
            fgets(buf, MAXDATASIZE, stdin);
            if (strcmp(buf, codeAndResponse) != 0)
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


        bool mail_flag = false;
        bool data_flag = false;
        bool end_of_msg_flag = false;

    while(1)
    {       
            //memset(second_buf, 0, MAXDATASIZE);
           
            fgets(buf, MAXDATASIZE, stdin);
            
            if (strlen(buf) > 0 && strlen(second_buf) > 0)
            {   
                
                char * result = check_self_mail(buf);
                
                // MAIL FROM:<Smith@hostname>
                
                if ((strstr(buf, "MAIL") != 0) && (strcmp(s, result) == 0)) // if "MAIL" is substr of buf and s equals to result
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
                                        // test.txt substitute with appropriate file_name attached
                                        // email should have '.', otherwise reciever will not recognize it
                                        // only email of 1000 chars allowed. 
                                        char * mail = send_data("test.txt");
                                        
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

    while (fgets(buf, MAXDATASIZE, stdin) != NULL) {  
    

    ret = send(sockfd, buf, MAXDATASIZE, 0);
  if (ret < 0) {    
   printf("Error sending data!\n\t-%s", buf);    
    }  
    }  

        

    

    close(sockfd);
    freeaddrinfo(servinfo); // all done with this structure
    pthread_exit(NULL);
    return 0;
}