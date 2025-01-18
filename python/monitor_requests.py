import dns.resolver
import time
import csv
import argparse
from datetime import datetime
import asyncio
import random

# Função para fazer a requisição DNS e registrar os tempos
async def make_dns_request(domain, resolver, output_file, iterations):
    for _ in range(iterations):
        start_time = time.time()  # Timestamp de início

        # Realizando a requisição DNS
        try:
            answers = resolver.resolve(domain, 'A')
            end_time = time.time()  # Timestamp de chegada

            # Calculando a diferença de tempo (em segundos)
            time_diff = (end_time - start_time) * 1000  # Diferença em milissegundos

            # Salvando os dados no arquivo CSV
            with open(output_file, mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([start_time, end_time, time_diff])

        except Exception as e:
            # Caso ocorra um erro na requisição (ignorando o erro, mas pode ser logado)
            end_time = time.time()
            time_diff = (end_time - start_time) * 1000
            with open(output_file, mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([start_time, end_time, time_diff])


# Função principal para gerenciar a execução de múltiplos clientes DNS
async def main(server_ip, domains, output_file, num_clients, queries_per_client, iterations):
    # Resolver para enviar requisições
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [server_ip]  # Definindo o servidor DNS

    # Garantir que o arquivo de saída tenha cabeçalho
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Timestamp de Início', 'Timestamp de Chegada', 'Diferença (ms)'])

    # Lista de tarefas para realizar as requisições
    tasks = []

    for client in range(num_clients):
        for query_count in range(queries_per_client):
            # Escolhe um domínio aleatório
            domain = random.choice(domains)
            tasks.append(make_dns_request(domain, resolver, output_file, iterations))

    # Executa as requisições de DNS
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitorar requisições DNS.")
    parser.add_argument('server_ip', help='IP do servidor DNS para as requisições')
    parser.add_argument('domains_file', help='Arquivo de domínios a serem consultados')
    parser.add_argument('output_file', help='Arquivo de saída para registrar os dados')
    parser.add_argument('num_clients', type=int, help='Número de clientes (requisições paralelas)')
    parser.add_argument('queries_per_client', type=int, help='Número de requisições por cliente')
    parser.add_argument('iterations', type=int, help='Número de iterações por cliente')

    args = parser.parse_args()

    # Carregar domínios do arquivo
    with open(args.domains_file, 'r') as f:
        domains = [line.strip() for line in f.readlines()]

    # Iniciar o monitoramento de DNS
    asyncio.run(main(args.server_ip, domains, args.output_file, args.num_clients, args.queries_per_client, args.iterations))
