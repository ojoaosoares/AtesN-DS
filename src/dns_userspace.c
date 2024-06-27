#include "dns.skel.h"
#include "dns.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>

static const char *a_records_map_path = "/sys/fs/bpf/xdp/globals/dns_records";

int main(int argc, char *argv[]) {

    
    if (argc == 2)
    {
        int index = if_nametoindex(argv[1]);

        struct dns *skel;
        skel = dns__open();

        if(!skel)
            goto cleanup;
        printf("opened\n");

        if(dns__load(skel))
            goto cleanup;

        printf("loaded\n");
        
        if(bpf_program__attach_xdp(skel->progs.dns, index) < 0)
            goto cleanup;
        
        printf("attached\n");

        printf("make debug to see the progam running\n");
        printf("CTRL + C to stop\n");

        for ( ; ; )
        {
            sleep(1);
        }
    }

    else if (argv[1] == 'a' && argc == 5)
    {

        struct dns_query dns_key;
        memset(dns_key.name, 0, MAX_DNS_NAME_LENGTH);

        dns.class = 1;
        dns.record_type = 1;

        strcpy(dns_key.name, argv[2]);

        struct a_record value;

        inet_pton(AF_INET, argv[3], &value.ip_addr);
        value.ttl = atoi(argv[4])

        bpf_map__update_elem(skel->maps.dns_records, &dns, sizeof(struct dns_query), &value, sizeof(struct a_record), 0);
    }

    else if (argv[1] == 'd' && argc == 3)
    {
        struct dns_query dns_key;
        memset(dns_key.name, 0, MAX_DNS_NAME_LENGTH);

        dns.class = 1;
        dns.record_type = 1;

        strcpy(dns_key.name, argv[2]);

        bpf_map__delete_elem(skel->maps.dns_records, &dns, 0);
    }


    else
    {
        printf("%d\n", argc);
        printf("interface where the program will be attached is requeried \n");
        return 0;
    }
    
    
cleanup: 
    dns__destroy(skel);
    return 0;
}