#include"stdio.h"  
#include"stdlib.h"  
#include"sys/types.h"  
#include"sys/socket.h"  
#include"string.h"  
#include"netinet/in.h"  
#include"pthread.h"  
  
#define PORT 4444  
#define BUF_SIZE 2000  
#define CLADDR_LEN 100  
  
void * receiveMessage(void * socket) {  
 int sockfd, ret;  
 char buffer[BUF_SIZE];   
 sockfd = (int) socket;  
 memset(buffer, 0, BUF_SIZE);    
 for (;;) {  
  ret = recvfrom(sockfd, buffer, BUF_SIZE, 0, NULL, NULL);    
  if (ret < 0) {    
   printf("Error receiving data!\n");      
  } else {  
   printf("client: ");  
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
    printf ("%s\n",ptr);
    ptr = strtok (NULL, " ");
    count++;

  }
  return ptr;
 
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


char * send_data(char * file_name)
{
  FILE *fp;
 fp = fopen(file_name, "r");
 char * line = NULL;
 size_t len = 0;
 ssize_t read;
 char * msg = malloc(1000);
 
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

  printf("here: '%s'\n", msg);
  
  return msg;
}
  
  int main(int argc, char * argv []) {  
 
 
  char * message = send_data("test.txt");
  write_to_file("receiver.txt", message);
  return 0;
 }   
  
