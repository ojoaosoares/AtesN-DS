#include "dns.skel.h"

int main() {

    struct dns *skel;
    skel = dns__open();

    if(!skel)
        goto cleanup;

    int index = 0;
    
    if(bpf_map__update_elem(skel->maps.progs, &index, sizeof(__u8), (void*) bpf_program__fd(skel->progs.dns), sizeof(__u8), 0))
        goto cleanup;

    printf("Deu certo\n");

cleanup: 
    dns__destroy(skel);
    return 0;
}