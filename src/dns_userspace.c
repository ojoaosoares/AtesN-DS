#include "dns.skel.h"
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

#define MAX_IP_STRING_LENGTH 16

static const char *standard_recursive_server = "8.8.8.8";

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
    printf("  \t-a\t ip address of your dev interface\n");
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

    int opt, index = 0;

    char recursive[MAX_IP_STRING_LENGTH];

    strcpy(recursive, standard_recursive_server);

    __u32 myip;

    optind = 1;

    while ((opt = getopt(argc, argv, "a:i:s:h")) != -1) {
        switch (opt) {
        case 'a':
            inet_pton(AF_INET, optarg, &skel->bss->serverip);
            break;
        case 'i':
            index = if_nametoindex(optarg);
            break;
        case 's':
            strcpy(recursive, optarg);
            break;
        case 'h':
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

    struct {
        int key;
        struct bpf_program *prog;
    } programs[] = {
        {0, skel->progs.dns_process_response},
        {1, skel->progs.dns_jump_query},
        {2, skel->progs.dns_create_new_query},
        {3, skel->progs.dns_back_to_last_query},
        {4, skel->progs.dns_save_ns_cache},
        {5, skel->progs.dns_check_subdomain},
        {6, skel->progs.dns_error}
    };
    
    for (size_t i = 0; i < sizeof(programs) / sizeof(programs[0]); i++) {
        int fd = bpf_program__fd(programs[i].prog);
        bpf_map__update_elem(skel->maps.tail_programs, &programs[i].key, sizeof(programs[i].key), &fd, sizeof(fd), 0);
    }

    printf("%s\n", recursive);

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
    
cleanup: 
    dns__destroy(skel);
    return 0;
}
