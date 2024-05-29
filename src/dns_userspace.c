#include "dns.skel.h"

int main() {

    struct dns *skel;
    skel = dns__open();

    if(!skel)
        goto cleanup;
    printf("Abriu\n");

    if(dns__load(skel))
        goto cleanup;

    printf("Carregou\n");
    if(dns__attach(skel))
        goto cleanup;

    printf("Anexou\n");
    bpf_program__attach(skel->progs.dns);

    __u32 index = 0;
    __u32 fd = bpf_program__fd(skel->progs.dns);
    
    if(bpf_map__update_elem(skel->maps.progs, &index, sizeof(__u32), &fd, sizeof(__u32), 0))
        goto cleanup;

    printf("Deu certo\n");

cleanup: 
    dns__destroy(skel);
    return 0;
}