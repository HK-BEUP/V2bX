#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
static volatile sig_atomic_t stopping=0;
static void stop(int sig) { stopping=1; }
int main(int argc,char **argv) {
 if(argc==2 && !strcmp(argv[1],"version")) {
  printf("v25.12.2-beup-alpine-qa fixture-%d\n",BUILD);return 0;
 }
 int s=socket(AF_INET,SOCK_STREAM,0),yes=1;
 setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
 struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(49091),.sin_addr={.s_addr=htonl(INADDR_LOOPBACK)}};
 if(bind(s,(void*)&a,sizeof(a)) || listen(s,8)) return 2;
 signal(SIGTERM,stop);while(!stopping) pause();
 sleep(7);close(s);return 0;
}
