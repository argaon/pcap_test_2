#include <arpa/inet.h>//ip -> bin
#include <cstdio>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <regex>

using namespace std;

#define PCAP_OPENFLAG_PROMISCUOUS 1   // Even if it isn't my mac, receive packet

struct ether_header *eh;
struct ip *iph;
struct tcphdr *tcph;
struct pcap_pkthdr *pkt_header;
char errbuf[PCAP_ERRBUF_SIZE];


int main(int argc, char **argv)
{
    char *dev;

    dev = argv[1];
    if(argc < 2)
    {
        printf("Input argument error!\n");
        if (dev == NULL)
        {
            printf("Your device is : %s\n",dev);
            exit(1);
        }
    }
    else
    printf("DEV : %s\n", dev);

    pcap_t *fp;
    if((fp= pcap_open_live(dev, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS , 1, errbuf)) == NULL)
    {
        fprintf(stderr,"Unable to open the adapter. %s is not supported by Pcap\n", dev);
    }
    const u_char *pkt_data;
    int res;

    while(1)
    {
        while((res=pcap_next_ex(fp,&pkt_header,&pkt_data))>=0)
        {
            int ehcnt;
            int length = pkt_header->len;
            if(res== 0)continue;
            eh = (struct ether_header*)pkt_data;
            u_char *mac = eh->ether_dhost;
            printf("Ethernet Header\n");
            printf("Dst Mac : ");
            for(ehcnt=0;ehcnt<6;ehcnt++)
                printf("%02x ",(*mac++));
            mac = eh->ether_shost;
            printf("\n");
            printf("Src Mac : ");
            for(ehcnt=0;ehcnt<6;ehcnt++)
                printf("%02x ",(*mac++));
            printf("\n");
            ehcnt = 0;

            pkt_data += sizeof(struct ether_header);
            length -= sizeof(struct ether_header);

            uint16_t etype = ntohs(eh->ether_type);
            if(etype == ETHERTYPE_IP)
            {
                iph = (struct ip *)pkt_data;
                char cip[INET_ADDRSTRLEN];
                printf("IP Header\n");
                inet_ntop(AF_INET,&iph->ip_src,cip,sizeof(cip));
                printf("Src Address : %s\n", cip);
                inet_ntop(AF_INET,&iph->ip_dst,cip,sizeof(cip));
                printf("Dst Address : %s\n", cip);
                pkt_data += iph->ip_hl*4;
                length -= iph->ip_hl*4;

                if(iph->ip_p == IPPROTO_TCP)
                {
                    tcph = (struct tcphdr*)pkt_data;
                    int jtotd = (tcph->doff *4);
                    pkt_data += jtotd;     //jump to tcp data
                    length -= jtotd;      //pkt length - jump length
                    if(length > 0)
                    {
                        printf("Have TCP DATA !\n");
                        string output( reinterpret_cast<char const*>(pkt_data), length) ;
                        regex re("Host: ([^\n]*)");
                        smatch m;
                        regex_search(output,m,re);
                        cout<<m[1]<<endl;
                    }
                    else
                        printf("No have TCP DATA !\n");
                }
            }
        }
    }
    return 0;
}

