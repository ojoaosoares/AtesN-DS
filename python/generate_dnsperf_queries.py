import sys
import random

def generate_queries(domain_file, num_queries, output_file, seed):
    # Ler os domínios do arquivo
    with open(domain_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]
    
    if not domains:
        print("O arquivo de domínios está vazio!")
        return
    
    # Configurar a seed para gerar resultados consistentes
    random.seed(seed)
    
    # Gerar as queries repetindo e misturando aleatoriamente
    queries = []
    for _ in range(num_queries):
        domain = random.choice(domains)  # Escolhe um domínio aleatório
        queries.append(f"{domain} A")
    
    # Embaralhar as queries geradas
    random.shuffle(queries)
    
    # Escrever as queries no arquivo de saída
    with open(output_file, 'w') as f:
        f.write('\n'.join(queries))
    
    print(f"{num_queries} queries geradas e salvas em '{output_file}'.")

if __name__ == "__main__":
    # Verificar os argumentos da linha de comando
    if len(sys.argv) != 5:
        print("Uso: python script.py <arquivo_de_dominios> <quantidade_de_queries> <arquivo_de_saida> <seed>")
        sys.exit(1)
    
    # Atribuir os parâmetros
    domain_file = sys.argv[1]
    num_queries = int(sys.argv[2])
    output_file = sys.argv[3]
    seed = int(sys.argv[4])
    
    # Executar a função principal
    generate_queries(domain_file, num_queries, output_file, seed)
