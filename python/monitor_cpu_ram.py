import psutil
import time
import csv
import argparse
import os
from datetime import datetime

def monitor_cpu_memory(output_file):
    try:
        # Verificando se o diretório para salvar o arquivo existe
        if not os.path.exists(os.path.dirname(output_file)) and os.path.dirname(output_file) != '':
            raise ValueError(f"O diretório para o arquivo '{output_file}' não existe.")

        # Abrindo o arquivo CSV para gravar os dados
        with open(output_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            # Escrevendo o cabeçalho do CSV
            writer.writerow(['Timestamp', 'Uso de CPU (%)', 'Uso de Memória (GB)', 'Uso de Memória (%)'])

            while True:
                # Monitorando a CPU
                cpu_usage = psutil.cpu_percent(interval=1)  # Percentual de uso da CPU

                # Monitorando a memória RAM
                memory = psutil.virtual_memory()
                memory_used = memory.used / (1024 ** 3)  # Convertendo de bytes para GB
                memory_percentage = memory.percent  # Percentual de uso da memória

                # Obtendo o timestamp atual no formato preciso
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')

                # Escrevendo os dados no arquivo CSV
                writer.writerow([timestamp, cpu_usage, memory_used, memory_percentage])

                # Pausa de 1 segundo antes de mostrar novamente
                time.sleep(1)

    except ValueError as e:
        print(f"Erro: {e}")
    except Exception as e:
        print(f"Ocorreu um erro inesperado: {e}")

def main():
    # Configuração de Argumentos
    parser = argparse.ArgumentParser(description="Monitora o uso de CPU e memória e grava os dados em um arquivo CSV.")
    parser.add_argument('output_file', type=str, help="Nome do arquivo CSV de saída")
    args = parser.parse_args()

    # Verificando se o nome do arquivo foi passado corretamente
    if not args.output_file:
        print("Erro: Você precisa fornecer um nome de arquivo para gravar os dados.")
        return

    # Inicia o monitoramento
    monitor_cpu_memory(args.output_file)

if __name__ == "__main__":
    main()
