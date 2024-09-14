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

void convert_mac_to_bytes(const char *mac_str, unsigned char *mac_bytes) {

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

int add_record(const struct bpf_map *map, const char *domain, const char* ip, int ttl)
{
    struct dns_query dns_key;
    memset(dns_key.name, 0, MAX_DNS_NAME_LENGTH);

    dns_key.class = 1; dns_key.record_type = 1;

    strcpy(dns_key.name, domain);

    struct a_record ip_address_value;

    if (!validate_ipv4(ip))
        return 0;
    
    inet_pton(AF_INET, ip, &ip_address_value.ip_addr);

    if (ttl <= 0)
    {
        printf("%d isn't a valid ttl value\n", ttl);
        return 0;
    }

    ip_address_value.ttl = ttl;

    if(bpf_map__update_elem(map, &dns_key, sizeof(struct dns_query), &ip_address_value, sizeof(struct a_record), 0))
        return 0;

    return 1;
}

int delete_record(const struct bpf_map *map, const char *domain)
{
    struct dns_query dns_key;
    memset(dns_key.name, 0, MAX_DNS_NAME_LENGTH);

    dns_key.class = 1;
    dns_key.record_type = 1;

    strcpy(dns_key.name, domain);

    if(bpf_map__delete_elem(map, &dns_key, sizeof(struct dns_query), 0))
        return 0;

    return 1;
}

int read_file(const char *filepath, const struct bpf_map *map)
{
    FILE *fp;
    fp = fopen(filepath, "r");

    char line[300], domain[256], ip[16];

    int cont = 0, ttl;

    while (fgets(line, sizeof(line), fp) != NULL)
    {    
        char *tok_string = strtok(line ,"|");
        strcpy(domain, tok_string);

        tok_string = strtok(NULL, "|");
        strcpy(ip, tok_string);

        tok_string = strtok(NULL, "|");
        ttl = atoi(tok_string);

        if(!add_record(map, domain, ip, ttl))
            return -1;
        
        cont++;
    }

    fclose(fp);

    return cont;
}

int save_records(const struct bpf_map *map)
{
    if(!create_directory(data_dir))
        return 0;

    FILE *fp;

    fp = fopen(standard_database, "w");

    struct dns_query dns_key, dns_next_key;
    
    struct a_record ip_address_value;

    char ip[16];

    while (bpf_map__get_next_key(map, &dns_key, &dns_next_key, sizeof(struct dns_query)) == 0)
    {
        if(bpf_map__lookup_elem(map, &dns_next_key, sizeof(struct dns_query), &ip_address_value, sizeof(struct a_record), 0))
        {
            printf("Error: the elemente doesn't exist\n");
            return 0;
        }

        if((inet_ntop(AF_INET, &ip_address_value.ip_addr, ip, INET_ADDRSTRLEN)) == NULL)
        {
            printf("Error: the ip couldn't be converted\n");
            return 0;
        }

        fprintf(fp, "%s|%s|%d\n", dns_next_key.name, ip, ip_address_value.ttl);

        dns_key = dns_next_key;                
    }

    fclose(fp);

    return 1;
}

int print_record(struct dns_query dns_key, struct a_record ip_address_value) 
{   
    char ip[16];

    if((inet_ntop(AF_INET, &ip_address_value.ip_addr, ip, INET_ADDRSTRLEN)) == NULL)
    {
        printf("Error: the ip couldn't be converted\n");
        return 0;
    }

    printf("%s: %s\n", dns_key.name, ip);

    return 1;
}

void tutorial() {
    printf("AtesN-DS\n");
    printf("Usage: sudo ./atesnds [options]\n");
    printf("  -h\tShow a help message\n");
    printf("  -e [options]\tExecute the program\n");
    printf("  \t-i\t interface where attach the dns\n");
    printf("  \t-m\t your mac address\n");
    printf("  \t-s\t the dns server to execute recursive queries\n");
    printf("  -a [options]\tAdd a dns record\n");
    printf("  \t-d\t domain to be added\n");
    printf("  \t-i\t respective ip\n");
    printf("  \t-t\t respective time to live\n");
    printf("  -d [domain/all]\tDelete dns record's\n");
    printf("  -p [domain/all]\tPrint dns record's\t\n");
    printf("  -r [filepath]\t read a file containing dns records\n");

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
    
        if (!strcmp(argv[1], "-e") && (argc == 6 || argc == 8))
        {
            int opt, index;

            char mac_address[MAX_MAC_STRING_LENGTH], recursive[MAX_IP_STRING_LENGTH];

            strcpy(recursive, standard_recursive_server);

            optind = 2;

            while ((opt = getopt(argc, argv, "i:m:s:")) != -1) {
                switch (opt) {
                case 'i':
                    index = if_nametoindex(optarg);
                    break;
                case 'm':
                    strcpy(mac_address, optarg);                    
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
            convert_mac_to_bytes(mac_address, &skel->bss->recursive_server_mac);
            skel->bss->device = index;

            // if(bpf_program__attach_xdp(skel->progs.dns_filter, index) < 0)
            // {
            //     printf("it was not possiblle to attach the program \n");
            //     goto cleanup;
            // }

            LIBBPF_OPTS(bpf_tcx_opts, optl);

            if(bpf_program__attach_tcx(skel->progs.dns_tc, index, &optl) < 0)
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

        else if (!strcmp(argv[1], "-d") && argc == 3)
        {
            if (!strcmp(argv[2], "all"))
            {
                struct dns_query dns_key;
                struct dns_query dns_next_key;

                while (bpf_map__get_next_key(skel->maps.dns_records, &dns_key, &dns_next_key, sizeof(struct dns_query)) == 0)
                {
                    if(!delete_record(skel->maps.dns_records, dns_next_key.name))
                    {
                        printf("Error: the elemente couldn't be removed or the element doesn't exist\n");
                        goto cleanup;
                    }
                }   

                printf("All elements deleted\n");
            }

            else
            {
                if(!delete_record(skel->maps.dns_records, argv[2]))
                {
                    printf("Error: the elemente couldn't be removed or the element doesn't exist\n");
                    goto cleanup;
                }

                printf("Map element deleted\n");

                
            }

            save_records(skel->maps.dns_records); 
        }

        else if (!strcmp(argv[1], "-r") && argc == 3)
        {
            int answer = read_file(argv[2], skel->maps.dns_records);

            if (answer > 0)
                printf("%d records were added by the file\n", answer);
            
            else if (answer == 0)
                printf("The file was empty\n");
            
            else
            {
                printf("Error: An error occurred");
                goto cleanup;
            }
            
            save_records(skel->maps.dns_records);

        }
    
        else if (!strcmp(argv[1], "-p") && argc == 3)
        {
            struct dns_query dns_key;
            struct a_record ip_address_value;

            if (!strcmp(argv[2], "all"))
            {
                struct dns_query dns_next_key;

                while (bpf_map__get_next_key(skel->maps.dns_records, &dns_key, &dns_next_key, sizeof(struct dns_query)) == 0)
                {
                    if(bpf_map__lookup_elem(skel->maps.dns_records, &dns_next_key, sizeof(struct dns_query), &ip_address_value, sizeof(struct a_record), 0))
                    {
                        printf("Error: the elemente doesn't exist\n");
                        goto cleanup;
                    }

                    if(!print_record(dns_next_key, ip_address_value))
                        goto cleanup;

                    dns_key = dns_next_key;                
                }   
            }

            else
            {            
                memset(dns_key.name, 0, MAX_DNS_NAME_LENGTH);

                dns_key.class = 1; dns_key.record_type = 1;

                strcpy(dns_key.name, argv[2]);

                if(bpf_map__lookup_elem(skel->maps.dns_records, &dns_key, sizeof(struct dns_query), &ip_address_value, sizeof(struct a_record), 0))
                {
                    printf("Error: the elemente doesn't exist\n");
                    goto cleanup;
                }

                if(!print_record(dns_key, ip_address_value))
                    goto cleanup;
            }   
        }
    
        else if (!strcmp(argv[1], "-a") && argc == 8)
        {
            int opt, ttl;

            char domain[MAX_DNS_NAME_LENGTH], ip[MAX_IP_STRING_LENGTH];

            optind = 2;

            while ((opt = getopt(argc, argv, "d:i:t:")) != -1) {
                switch (opt) {
                case 'd':
                    strcpy(domain, optarg);
                    break;
                case 'i':
                    strcpy(ip, optarg);
                    break;
                case 't':
                    ttl = atoi(optarg);
                    break;
                default:
                    tutorial();
                    return 1;
                }
            }

            if (!add_record(skel->maps.dns_records, domain, ip, ttl))
            {
                printf("Error: the elemente couldn't be created/updated\n");
                goto cleanup;
            }

            printf("Map element created/updated\n");
                
            save_records(skel->maps.dns_records);
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