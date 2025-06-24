#!/bin/bash
export PATH=$PATH:/home/kali/.pdtm/go/bin

# Verifica se os comandos necessários estão instalados
for scanner in naabu nuclei python3; do
    if ! command -v $scanner &> /dev/null; then
        echo "$scanner não encontrado! Instale-o antes de executar este script."
        exit 1
    fi
done

TARGET=$1
if [ -z "$TARGET" ]; then
    echo "Uso: $0 <IP-alvo>"
    exit 1
fi

echo "[+] Iniciando escaneamento com Naabu no alvo: $TARGET (timeout: 120s)"

timeout 120s naabu -host $TARGET -p 80,139,445,10000,20000 -rate 100 -silent > ports.txt
NAABU_EXIT=$?

if [ $NAABU_EXIT -eq 124 ]; then
    echo "[!] O Naabu atingiu o tempo limite de 120 segundos e foi interrompido."
elif [ $NAABU_EXIT -ne 0 ]; then
    echo "[!] O Naabu encontrou um erro (código de saída $NAABU_EXIT)."
fi

if [ ! -s ports.txt ]; then
    echo "[!] Nenhuma porta encontrada ou erro durante o escaneamento."
    exit 1
fi

echo "[+] Portas encontradas:"
cat ports.txt

WEB_PORTS=(80 10000 20000)
COMMON_PATHS=("/" "/login" "/admin" "/dashboard" "/webmin")

> targets.txt
while read line; do
    IP=$(echo "$line" | cut -d':' -f1)
    PORT=$(echo "$line" | cut -d':' -f2)

    if [[ " ${WEB_PORTS[@]} " =~ " $PORT " ]]; then
        for proto in http https; do
            for path in "${COMMON_PATHS[@]}"; do
                echo "$proto://$IP:$PORT$path" >> targets.txt
            done
        done
    fi
done < ports.txt

if [ ! -s targets.txt ]; then
    echo "[!] Nenhum serviço web identificado para análise com Nuclei."
    exit 1
fi

echo "[+] Rodando o Nuclei nos alvos encontrados..."
nuclei -l targets.txt -severity low,medium,high,critical -o nuclei_results.txt -silent

if [ ! -s nuclei_results.txt ]; then
    echo "[*] Nenhuma vulnerabilidade encontrada ou erro ao gerar resultados."
    exit 0
fi

echo "[+] Convertendo nuclei_results.txt para nuclei_results.json e gerando scan_report.txt..."

python3 - << 'EOF'
import json
import re

txt_file = "nuclei_results.txt"
json_file = "nuclei_results.json"
report_file = "scan_report.txt"

def parse_nuclei_txt_line(line):
    # Exemplo da saída nuclei txt:
    # [templateid] [category] [severity] url - outras infos (não padronizado)
    # Tentaremos extrair os campos básicos entre colchetes e o alvo
    pattern = r"\[(.*?)\]\s\[(.*?)\]\s\[(.*?)\]\s(\S+)(.*)"
    m = re.match(pattern, line)
    if not m:
        return None
    vuln, category, severity, target, rest = m.groups()
    # Tenta extrair detalhes entre aspas no resto da linha (se existir)
    details = re.findall(r'\"([^\"]+)\"', rest)
    return {
        "vulnerability": vuln,
        "category": category,
        "severity": severity,
        "target": target,
        "details": details
    }

with open(txt_file, 'r', encoding='utf-8') as f:
    lines = f.read().strip().split('\n')

results = []
for line in lines:
    parsed = parse_nuclei_txt_line(line)
    if parsed:
        results.append(parsed)

# Salva JSON
with open(json_file, 'w', encoding='utf-8') as jf:
    json.dump(results, jf, indent=2, ensure_ascii=False)

# Gera relatório resumido
counts = {"critical":0, "high":0, "medium":0, "low":0, "info":0}
for r in results:
    sev = r["severity"].lower()
    if sev in counts:
        counts[sev] += 1
    else:
        counts["info"] += 1

with open(report_file, 'w', encoding='utf-8') as rf:
    rf.write(f"Relatório resumido do scan nuclei para alvo\n")
    rf.write(f"Total de vulnerabilidades encontradas: {len(results)}\n\n")
    for sev in ["critical", "high", "medium", "low", "info"]:
        rf.write(f"{sev.capitalize()}: {counts[sev]}\n")
    rf.write("\nDetalhes das vulnerabilidades:\n\n")
    for r in results:
        rf.write(f"- Vulnerabilidade: {r['vulnerability']}\n")
        rf.write(f"  Severidade: {r['severity']}\n")
        rf.write(f"  Categoria: {r['category']}\n")
        rf.write(f"  Alvo: {r['target']}\n")
        if r['details']:
            rf.write(f"  Detalhes: {', '.join(r['details'])}\n")
        rf.write("\n")

print(f"JSON salvo em {json_file}")
print(f"Relatório salvo em {report_file}")
EOF

echo "[+] Processo concluído."
