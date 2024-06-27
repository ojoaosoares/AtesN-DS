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

    if (argc != 2)
    {
        printf("%d\n", argc);
        printf("interface where the program will be attached is requeried \n");
        return 0;
    }

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
    
    
cleanup: 
    dns__destroy(skel);
    return 0;
}