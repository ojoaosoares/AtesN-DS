// SPDX-License-Identifier: GPL-2.0
/*
 * time_updater.c — Userspace daemon que atualiza o mapa BPF "time_map"
 * com o timestamp Unix atual a cada segundo.
 *
 * Compilação:
 *   gcc -O2 -Wall -o time_updater time_updater.c -lbpf
 *
 * Uso:
 *   sudo ./time_updater [caminho_do_pinned_map]
 *
 * Se nenhum caminho for passado, usa o padrão /sys/fs/bpf/time_map.
 * Para fazer pin do mapa no seu programa XDP, adicione ao carregamento:
 *   bpf_obj_pin(map_fd, "/sys/fs/bpf/time_map");
 * Ou use bpftool:
 *   sudo bpftool map pin id <ID> /sys/fs/bpf/time_map
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define DEFAULT_PIN_PATH    "/sys/fs/bpf/time_map"
#define UPDATE_INTERVAL_SEC  5          /* intervalo de atualização em segundos */
#define TIME_MAP_KEY         0          /* única entrada: índice 0 (BPF_MAP_TYPE_ARRAY) */

static volatile int running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

/*
 * Abre o mapa pelo caminho pinned e retorna o fd, ou -1 em erro.
 */
static int open_time_map(const char *pin_path)
{
    int fd = bpf_obj_get(pin_path);
    if (fd < 0) {
        fprintf(stderr, "[erro] Não foi possível abrir o mapa em '%s': %s\n",
                pin_path, strerror(errno));
        fprintf(stderr,
                "  Dica: faça o pin do mapa primeiro:\n"
                "    sudo bpftool map pin id <ID> %s\n", pin_path);
    }
    return fd;
}

/*
 * Retorna o timestamp Unix atual em segundos (32 bits).
 * Usa time() — ANSI C, sem necessidade de feature macros POSIX.
 * Coerente com wall clock, que é o que os TTLs DNS requerem.
 */
static uint32_t current_unix_seconds(void)
{
    time_t now = time(NULL);
    if (now == (time_t)-1) {
        perror("[erro] time");
        return 0;
    }
    return (uint32_t)now;
}

int main(int argc, char *argv[])
{
    const char *pin_path = (argc > 1) ? argv[1] : DEFAULT_PIN_PATH;

    /* captura Ctrl+C e SIGTERM para encerrar limpo */
    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    printf("[time_updater] Iniciando — mapa: %s\n", pin_path);
    printf("[time_updater] Pressione Ctrl+C para encerrar.\n");

    int map_fd = open_time_map(pin_path);
    if (map_fd < 0)
        return EXIT_FAILURE;

    uint32_t key = TIME_MAP_KEY;

    while (running) {
        uint32_t now = current_unix_seconds();

        if (bpf_map_update_elem(map_fd, &key, &now, BPF_ANY) != 0) {
            fprintf(stderr, "[erro] bpf_map_update_elem falhou: %s\n",
                    strerror(errno));
            /*
             * Se o mapa sumiu (ex.: programa XDP descarregado),
             * tenta reabrir. Aguarda 1 s antes de tentar de novo.
             */
            close(map_fd);
            sleep(UPDATE_INTERVAL_SEC);
            map_fd = open_time_map(pin_path);
            if (map_fd < 0) {
                fprintf(stderr, "[aviso] Aguardando o mapa ficar disponível...\n");
            }
            continue;
        }

        printf("[time_updater] time_map[0] = %u\n", now);
        sleep(UPDATE_INTERVAL_SEC);
    }

    printf("\n[time_updater] Encerrando.\n");
    if (map_fd >= 0)
        close(map_fd);

    return EXIT_SUCCESS;
}