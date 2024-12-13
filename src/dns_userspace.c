#include "dns.skel.h"
#include "dns.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/stat.h>
#include <regex.h>
#include <stdio.h>
#include <getopt.h>

static const char *standard_database = "./data/database";
static const char *data_dir = "./data";

static const char *standard_recursive_server = "8.8.8.8";

void convert_mac_to_bytes(const char *mac_str, unsigned char mac_bytes[6]) {

    char hex[2];

    hex[0] = mac_str[0];
    hex[1] = mac_str[1];

    char *end;

    mac_bytes[0] = strtol(hex, &end, 16);


    for( uint8_t i = 1; i < 6; i++ )
    {
        hex[0] = mac_str[2*i + i];
        hex[1] = mac_str[2*i + i + 1];
        mac_bytes[i] = strtol(hex, &end, 16);
    }
}

int validate_ipv4(const char *ip_str) {
    regex_t regex;
    int reti;
    
    char *ipv4_pattern = "^([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})$";
    
    reti = regcomp(&regex, ipv4_pattern, REG_EXTENDED);
    if (reti) {
        printf("Error: it wasn't possible to compile regex\n");
        return 0;
    }

    reti = regexec(&regex, ip_str, 0, NULL, 0);
    if (!reti) {
        regfree(&regex);
        return 1;
    }
    
    else if (reti == REG_NOMATCH) {
        printf("%s isn't a valid IPv4 address\n", ip_str);
    }

    else 
        printf("Error: regex error\n");
    

    regfree(&regex);
    return 0;
}


void tutorial() {
    printf("AtesN-DS\n");
    printf("Usage: sudo ./atesnds [options]\n");
    printf("  -h\tShow a help message\n");
    printf("  \t-i\t interface where attach the dns\n");
    printf("  \t-s\t the root dns server\n");
}

int main(int argc, char *argv[]) {

    struct dns *skel;
    skel = dns__open();

    if(!skel)
        goto cleanup;
    printf("opened\n");

    if(dns__load(skel))
        goto cleanup;

    printf("loaded\n");

    if (argc >= 2)
    {
    
        if (argc == 3 || argc == 5)
        {
            int opt, index;

            char recursive[MAX_IP_STRING_LENGTH];

            strcpy(recursive, standard_recursive_server);

            optind = 2;

            while ((opt = getopt(argc, argv, "i:s:")) != -1) {
                switch (opt) {
                case 'i':
                    index = if_nametoindex(optarg);
                    break;
                case 's':
                    strcpy(recursive, optarg);
                    break;
                default:
                    tutorial();
                    return 1;
                }
            }

            if (index == 0)
            {
                printf("interface where the program will be attached is requeried \n");
                goto cleanup;
            }

            if(!validate_ipv4(recursive))
            {
                printf("Invalid recursive server\n");
                goto cleanup;
            }

            inet_pton(AF_INET, recursive, &skel->bss->recursive_server_ip);

            if(bpf_program__attach_xdp(skel->progs.dns_filter, index) < 0)
            {
                printf("it was not possiblle to attach the program \n");
                goto cleanup;
            }

            printf("attached\n");

            printf("make debug to see the progam running\n");
            printf("CTRL + C to stop\n");


            for ( ; ; )
            {
                sleep(1);
            }

            save_records(skel->maps.dns_records);

            goto cleanup;
        }

        else if (!strcmp(argv[1], "-h") && argc == 2)
            tutorial();

        else
            tutorial();

        goto cleanup;
    }

    else
        tutorial();
    
cleanup: 
    dns__destroy(skel);
    return 0;
}