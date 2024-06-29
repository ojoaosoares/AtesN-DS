#include "dns.skel.h"
#include "dns.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <regex.h>
#include <sys/stat.h>  

int create_directory(const char *folder) {
    struct stat st = {0};

    if (stat(folder, &st) == -1) {
        if (mkdir(folder, 0777) != 0) {
            printf("Error: it wasn't possible to create de directory '%s'\n", folder);
            return 0;
        }
    }
    return 1;
}

int validate_ipv4(const char *ip_str) {
    regex_t regex;
    int reti;
    
    char *ipv4_pattern = "^([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})$";
    
    reti = regcomp(&regex, ipv4_pattern, REG_EXTENDED);
    if (reti) {
        fprintf(stderr, "Error: it wasn't possible to compile regex\n");
        return 0;
    }

    reti = regexec(&regex, ip_str, 0, NULL, 0);
    if (!reti) {
        printf("%s is a valid IPv4 address\n", ip_str);
        regfree(&regex);
        return 1;
    }
    
    else if (reti == REG_NOMATCH) {
        printf("%s isn't a valid IPv4 address\n", ip_str);
    }

    else {
        char error_message[100];
        regerror(reti, &regex, error_message, sizeof(error_message));
        fprintf(stderr, "Error: regex error: %s\n", error_message);
    }

    regfree(&regex);
    return 0;
}

static const char *a_records_map_path = "/sys/fs/bpf/xdp/globals/dns_records";

int main(int argc, char *argv[]) {

    struct dns *skel;
    skel = dns__open();

    if(!skel)
        goto cleanup;
    printf("opened\n");

    if(dns__load(skel))
        goto cleanup;

    printf("loaded\n");
    
    if (argc == 2)
    {
        int index = if_nametoindex(argv[1]);

        
        if(bpf_program__attach_xdp(skel->progs.dns, index) < 0)
            goto cleanup;
        
        printf("attached\n");

        printf("make debug to see the progam running\n");
        printf("CTRL + C to stop\n");

        for ( ; ; )
        {
            sleep(1);
        }

        goto retrive;
    }

    else if (!strcmp(argv[1], "a") && argc == 5)
    {

        struct dns_query dns_key;
        memset(dns_key.name, 0, MAX_DNS_NAME_LENGTH);

        dns_key.class = 1;
        dns_key.record_type = 1;

        strcpy(dns_key.name, argv[2]);

        struct a_record ip_address_value;

        if (!validate_ipv4(argv[3]))
            goto cleanup;
        
        inet_pton(AF_INET, argv[3], &ip_address_value.ip_addr);
        ip_address_value.ttl = atoi(argv[4]);

        if(bpf_map__update_elem(skel->maps.dns_records, &dns_key, sizeof(struct dns_query), &ip_address_value, sizeof(struct a_record), 0))
        {
            printf("Eror: the elemente couldn't be created/updated\n");
            goto cleanup;
        }
        printf("Map element created/updated\n");

        goto retrive;
    }

    else if (!strcmp(argv[1], "d") && argc == 3)
    {
        struct dns_query dns_key;
        memset(dns_key.name, 0, MAX_DNS_NAME_LENGTH);

        dns_key.class = 1;
        dns_key.record_type = 1;

        strcpy(dns_key.name, argv[2]);

        if(bpf_map__delete_elem(skel->maps.dns_records, &dns_key, sizeof(struct dns_query), 0))
        {
            printf("Eror: the elemente couldn't be removed or the element doesn't exist\n");
            goto cleanup;
        }

        printf("Map element deleted\n");

        goto retrive;
    }

    else if (!strcmp(argv[1], "r") && argc == 3)
    {
        FILE *fp;
        fp = fopen(argv[2], "r");

        char line[276];

        struct dns_query dns_key;
        memset(dns_key.name, 0, MAX_DNS_NAME_LENGTH);

        dns_key.class = 1;
        dns_key.record_type = 1;

        struct a_record ip_address_value;

        int item = 0, cont = 0;


        while (fgets(line, sizeof(line), fp) != NULL) {
            
            item = 0;
            for (char *p = strtok(line ,"|"); p != NULL; p = strtok(NULL, "|"))
            {
                if (item == 0)
                {
                    strcpy(dns_key.name, p);
                    item++;
                }

                else if (item == 1)
                {
                    if (!validate_ipv4(p))
                        goto cleanup;

                    inet_pton(AF_INET, p, &ip_address_value.ip_addr);

                    item++;
                }

                else if (item == 2)
                {
                    ip_address_value.ttl = atoi(p);
                    item++;
                }
            }

            if(bpf_map__update_elem(skel->maps.dns_records, &dns_key, sizeof(struct dns_query), &ip_address_value, sizeof(struct a_record), 0))
            {
                printf("Eror: the elemente couldn't be created/updated\n");
                goto cleanup;
            }

            cont++;
            
        }

        printf("File read, %d records created\n", cont);

        fclose(fp);

        goto retrive;
    }

    else if (!strcmp(argv[1], "p") && argc == 3)
    {

        if (!strcmp(argv[2], "all"))
        {
            struct dns_query dns_key, dns_next_key;

            struct a_record ip_address_value;

            char ip[15];

            while (bpf_map__get_next_key(skel->maps.dns_records, &dns_key, &dns_next_key, sizeof(struct dns_query)) == 0)
            {
                if(bpf_map__lookup_elem(skel->maps.dns_records, &dns_next_key, sizeof(struct dns_query), &ip_address_value, sizeof(struct a_record), 0))
                {
                    printf("Error: the elemente doesn't exist\n");
                    goto cleanup;
                }

                if((inet_ntop(AF_INET, &ip_address_value.ip_addr, ip, INET_ADDRSTRLEN)) == NULL)
                {
                    printf("Error: the ip couldn't be converted\n");
                    goto cleanup;
                }

                printf("%s: %s\n", dns_next_key.name, ip);

                dns_key = dns_next_key;                
            }
            
            
        }

        

        else
        {
            struct dns_query dns_key;
            memset(dns_key.name, 0, MAX_DNS_NAME_LENGTH);

            dns_key.class = 1;
            dns_key.record_type = 1;

            strcpy(dns_key.name, argv[2]);

            struct a_record ip_address_value;

            if(bpf_map__lookup_elem(skel->maps.dns_records, &dns_key, sizeof(struct dns_query), &ip_address_value, sizeof(struct a_record), 0))
            {
                printf("Error: the elemente doesn't exist\n");
                goto cleanup;
            }

            char ip[15];

            if((inet_ntop(AF_INET, &ip_address_value.ip_addr, ip, INET_ADDRSTRLEN)) == NULL)
            {
                printf("Error: the ip couldn't be converted\n");
                goto cleanup;
            }

            printf("%s: %s\n", dns_key.name, ip);
        }
        
        goto cleanup;
    }

    else
    {
        printf("interface where the program will be attached is requeried \n");
        goto cleanup;
    }
    
retrive:

    if(!create_directory("./data/"))
        goto cleanup;

    FILE *fp;

    fp = fopen("./data/database", "w");

    struct dns_query dns_key, dns_next_key;

    struct a_record ip_address_value;

    char ip[15];

    while (bpf_map__get_next_key(skel->maps.dns_records, &dns_key, &dns_next_key, sizeof(struct dns_query)) == 0)
    {
        if(bpf_map__lookup_elem(skel->maps.dns_records, &dns_next_key, sizeof(struct dns_query), &ip_address_value, sizeof(struct a_record), 0))
        {
            printf("Error: the elemente doesn't exist\n");
            goto cleanup;
        }

        if((inet_ntop(AF_INET, &ip_address_value.ip_addr, ip, INET_ADDRSTRLEN)) == NULL)
        {
            printf("Error: the ip couldn't be converted\n");
            goto cleanup;
        }

        fprintf(fp, "%s|%s|%d\n", dns_next_key.name, ip, ip_address_value.ttl);

        dns_key = dns_next_key;                
    }

    fclose(fp);

cleanup: 
    dns__destroy(skel);
    return 0;
}