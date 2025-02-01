import random
import string

def generate_random_subdomain(length=5):
    """Gera um subdomínio aleatório com caracteres alfanuméricos."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def combine_domains(domain1, domain2):
    """Combina partes de dois domínios, colocando um ponto entre os nomes."""
    # Pega a parte do subdomínio do primeiro domínio
    subdomain1 = domain1.split('.')[0]
    # Pega a parte do subdomínio do segundo domínio
    subdomain2 = domain2.split('.')[0]
    
    # Combina as partes dos subdomínios e o domínio, colocando um ponto entre eles
    new_subdomain = f"{subdomain1}.{subdomain2}"  # Ponto entre os subdomínios
    new_domain = f"{new_subdomain}.{domain1.split('.')[1]}"  # Usando o TLD do primeiro domínio
    
    return new_domain

def create_new_domains(existing_domains, num_new_domains):
    """Gera novos domínios a partir de uma lista existente, criando variações."""
    new_domains = []
    
    for _ in range(num_new_domains):
        # Escolhe dois domínios existentes aleatoriamente para combinar
        domain1 = random.choice(existing_domains)
        domain2 = random.choice(existing_domains)
        
        # Cria um novo domínio fundindo os dois
        new_domain = combine_domains(domain1, domain2)
        
        new_domains.append(new_domain)
    
    return new_domains

def load_domains_from_file(file_path):
    """Carrega domínios de um arquivo, um por linha."""
    with open(file_path, 'r') as f:
        domains = [line.strip() for line in f.readlines()]
    return domains

def save_domains_to_file(domains, file_path):
    """Salva os domínios em um arquivo, um por linha."""
    with open(file_path, 'w') as f:
        for domain in domains:
            f.write(domain + '\n')

def main(input_file_1, input_file_2, output_file, num_new_domains):
    # Carregar domínios dos dois arquivos de entrada
    domains_1 = load_domains_from_file(input_file_1)
    domains_2 = load_domains_from_file(input_file_2)
    
    # Combinar os domínios existentes
    combined_domains = domains_1 + domains_2
    
    # Gerar novos domínios
    new_domains = create_new_domains(combined_domains, num_new_domains)
    
    # Manter os domínios originais e adicionar os novos
    all_domains = combined_domains + new_domains
    
    # Salvar os domínios no arquivo de saída
    save_domains_to_file(all_domains, output_file)
    print(f"Domínios originais e novos salvos em {output_file}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Gerar novos domínios fundindo dois arquivos de entrada.")
    parser.add_argument('input_file_1', help='Primeiro arquivo de domínios existentes')
    parser.add_argument('input_file_2', help='Segundo arquivo de domínios existentes')
    parser.add_argument('output_file', help='Arquivo de saída contendo os domínios originais e novos')
    parser.add_argument('num_new_domains', type=int, help='Número de novos domínios a serem gerados')

    args = parser.parse_args()

    main(args.input_file_1, args.input_file_2, args.output_file, args.num_new_domains)
