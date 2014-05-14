# include <unistd.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <string.h>
# include <netinet/in.h>
# include <stdio.h>
# include <stdlib.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# define  BUFF_MAX_SIZE 8192

// PACKET COUNTER
int icmp=0,others=0,total=0;

// Direcciones IP relacionadas a un RS
struct sockaddr_in cliaddr ;
struct sockaddr_in servaddr;

//Definicion de funciones
void handleErrors(char*);
void ProcessPacket(unsigned char* , int);
void extractdata_icmp(unsigned char*  , int);
void print_ip_header  (unsigned char* , int);
void print_icmp_packet(unsigned char* , int);
void hex_ascii_print  (unsigned char* , int);

/* Core functions      */
int  sniffpackets(void);

main(){
	sniffpackets();
}
//Sniff packets
int sniffpackets(void){
  	char buf[BUFF_MAX_SIZE]; 
  	socklen_t clilen = sizeof(struct sockaddr_in);    
	int sock;// Representa un File Descriptor
	int n;   // El tamaño del buffer leido por un paquete recibido
  	int i;
	//Generamos un RAW SOCKET
  	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  	if (sock < 0)
		handleErrors("ERROR: Creacion de socket\n");
 		
  	while(1){
    		n=recvfrom(sock,buf,BUFF_MAX_SIZE,0,(struct sockaddr *)&cliaddr,&clilen);
    		if(n<0 )
        		handleErrors("ERROR: Al recibir el paquete \n");
		//Now process the packet
     		ProcessPacket(buf , n);
  	}
	return 1;
}

void ProcessPacket(unsigned char* buffer, int size)
{
    
    //Get the IP Header part of this packet
    struct iphdr *iph = (struct iphdr*)buffer;
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++icmp;
	    extractdata_icmp(buffer,size);
	    //imprime a detalle  los campos del paquete ICMP
            //print_icmp_packet(buffer,size);
            break;
        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
}
void extractdata_icmp(unsigned char* buffer, int Size){
	int i;
    	unsigned char *sequence=(unsigned char*)malloc(sizeof(unsigned char)*2);
	unsigned char *id      =(unsigned char*)malloc(sizeof(unsigned char)*2);
	unsigned char *data    ;
	struct iphdr *iph = (struct iphdr *)buffer;
   	//Internet Header Length is the length of the internet header in 32 bit words.
    	unsigned short iphdrlen = iph->ihl*4;
     	struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen);     
 
	id[0]=buffer[iphdrlen + sizeof(icmph)]; 
    	id[1]=buffer[iphdrlen + sizeof(icmph)+1];
	sequence[0]=buffer[iphdrlen + sizeof(icmph)+2]; 
    	sequence[1]=buffer[iphdrlen + sizeof(icmph)+3];
    	data= (unsigned char*)malloc(sizeof(unsigned char)*(Size -sizeof(icmph)-iph->ihl*4-4));
	for(i=0;i<(Size -sizeof(icmph)-iph->ihl*4-4);i++)
		data[i]=buffer[i+iphdrlen+sizeof(icmph)+4];
    	//
	printf("\nICMP Header [TYPE CODE CHECKS] \n");
    	hex_ascii_print(buffer + iphdrlen , sizeof(icmph));
        printf("ID\n");
	hex_ascii_print(id,2);
        printf("Sequence\n");
	hex_ascii_print(sequence,2);
	printf("Data TEXT\n");  
	hex_ascii_print(data , (Size -4- sizeof(icmph) - iph->ihl * 4));
     	//
}
// Imprimimos el contenido del pacquete ICMP 
void print_icmp_packet(unsigned char* buffer , int Size)
{
    	struct iphdr *iph = (struct iphdr *)buffer;
   	//Internet Header Length is the length of the internet header in 32 bit words.
    	unsigned short iphdrlen = iph->ihl*4;
     	struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen);     
    	printf("\n\n***********************ICMP Packet*************************\n");   
    	printf(" Rec'd %d bytes\n",Size);
    	print_ip_header(buffer , Size);     
    	printf("\n");
    	printf("ICMP Header\n");
    	printf("   |-Type : %d",(unsigned int)(icmph->type));     
    	if((unsigned int)(icmph->type) == 11) 
        	printf("  (TTL Expired)\n");
    	else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY) 
        	printf("  (ICMP Echo Reply)\n");
    	printf("   |-Code : %d\n",(unsigned int)(icmph->code));
    	printf("   |-Checksum : %d\n",ntohs(icmph->checksum));
    	printf("   |-ID       : %d\n",ntohs(icmph->un.echo.id));
    	printf("   |-Sequence : %d\n",ntohs(icmph->un.echo.sequence));
    	printf("\n");
 
    	printf("IP Header\n");
    	hex_ascii_print(buffer,iphdrlen);
         
    	printf("ICMP Header\n");
    	hex_ascii_print(buffer + iphdrlen , sizeof(icmph));
         
    	printf("Data Payload\n");  
    	hex_ascii_print(buffer + iphdrlen + sizeof(icmph) , (Size - sizeof(icmph) - iph->ihl * 4));
     
    	printf("\n###########################################################");
}

void print_ip_header(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen =iph->ihl*4;
    // Direccion de origen 
    memset(&cliaddr, 0, sizeof(cliaddr));
    cliaddr.sin_addr.s_addr = iph->saddr;
    //Direccion destino 
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_addr.s_addr = iph->daddr;
     
    printf("\n");
    printf("IP Header\n");
    printf("   |-IP Version        : %d\n",(unsigned int)iph->version);
    printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    printf("   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    printf("   |-Identification    : %d\n",ntohs(iph->id));
    printf("   |-TTL      : %d\n",(unsigned int)iph->ttl);
    printf("   |-Protocol : %d\n",(unsigned int)iph->protocol);
    printf("   |-Checksum : %d\n",ntohs(iph->check));
    printf("   |-Source IP        : %s\n",inet_ntoa(cliaddr.sin_addr));
    printf("   |-Destination IP   : %s\n",inet_ntoa(servaddr.sin_addr));
}

void handleErrors(char *msg){
    	perror(msg);
    	exit(EXIT_FAILURE);
}
// Imprimimos la informacion HEX y ASCII
void hex_ascii_print (unsigned char* data , int Size)
{
     	int i=0,j=0;
    	for(i=0 ; i < Size ; i++)
    	{	//ASCII
        	if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        	{
            		printf("         ");
            		for(j=i-16 ; j<i ; j++)
            		{
                		if(data[j]>=32 && data[j]<=128)
                    			printf("%c",(unsigned char)data[j]); //if its a number or alphabet     
                		else 
					printf("."); 			     //otherwise print a dot
           		 }		
            		printf("\n");
       		}		 
        	if(i%16==0) 
			printf("   ");
            	printf(" %02X",(unsigned int)data[i]);
        	if( i==Size-1)  //print the last spaces
        	{
            		for(j=0;j<15-i%16;j++) printf("   "); //extra spaces
             
            			printf("         ");
             
            		for(j=i-i%16 ; j<=i ; j++)
            		{
                		if(data[j]>=32 && data[j]<=128) 
					printf("%c",(unsigned char)data[j]);
                		else 
					printf(".");
            		}
            		printf("\n");
        	}
    	}
}
