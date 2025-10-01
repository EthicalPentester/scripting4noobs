#!/usr/bin/env bash
set -euo pipefail

# multi_phase_nmap.sh
# Uso:
#   ./multi_phase_nmap.sh subnet1 [subnet2 ...]
#   o ./multi_phase_nmap.sh -f subnets.txt
#
# Fase 1: escaneo ICMP (-PE) y ARP (-PR) para identificar hosts "Up"
# Fase 2: escaneo de puertos -sS -p- -n -Pn --min-rate 5000 -> guarda CSV y greppable
# Fase 3: para cada host, toma sus puertos y corre -sCV --script vuln -n -Pn -p <puertos> -> guarda -oN por host
#
# Salidas:
#   results/<timestamp>/phase1_hosts.oG    -> greppable con hosts detectados
#   results/<timestamp>/hosts_list.txt    -> lista única de IPs
#   results/<timestamp>/phase2_ports.oG    -> greppable del escaneo de puertos
#   results/<timestamp>/ports.csv         -> CSV host,port,proto,state,service
#   results/<timestamp>/per-host/host_PORTS.grep -> greppable con puertos por host (formato IP:ports)
#   results/<timestamp>/per-host/<ip>_nmap.txt -> salida nmap -oN del escaneo de scripts (fase3)
#
# Nota: ARP (-PR) solo funciona en la misma LAN física; si escaneas subredes remotas no recibirás respuestas ARP.

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTDIR="results/${TIMESTAMP}"
PER_HOST_DIR="${OUTDIR}/per-host"
mkdir -p "${PER_HOST_DIR}"

# Configurables (modifica si quieres)
NMAP=${NMAP:-nmap}
MIN_RATE=${MIN_RATE:-5000}
SYN_SCAN_OPTS="-sS -p- -n -Pn --min-rate ${MIN_RATE}"
SCRIPTS_SCAN_OPTS="-sCV --script vuln -n -Pn"

# Parse args
if [[ $# -lt 1 ]]; then
  cat <<USAGE
Uso:
  $0 subnet1 [subnet2 ...]
  $0 -f subnets.txt   # fichero con una subred por línea

Ejemplo:
  $0 192.168.1.0/24 10.0.0.0/24
USAGE
  exit 1
fi

# If -f provided
if [[ "$1" == "-f" ]]; then
  if [[ $# -lt 2 ]]; then
    echo "Debe indicar fichero tras -f"
    exit 1
  fi
  SUBNETS_FILE="$2"
  if [[ ! -f "$SUBNETS_FILE" ]]; then
    echo "Fichero no existe: $SUBNETS_FILE"
    exit 1
  fi
  mapfile -t SUBNETS < "$SUBNETS_FILE"
else
  SUBNETS=("$@")
fi

# check nmap exists
if ! command -v "${NMAP}" >/dev/null 2>&1; then
  echo "nmap no encontrado en PATH. Instala nmap y vuelve a intentarlo."
  exit 1
fi

echo "==> Resultados en: ${OUTDIR}"
echo "==> Subredes a escanear: ${SUBNETS[*]}"

##########
# FASE 1 #
##########
phase1_grep="${OUTDIR}/phase1_hosts.oG"
phase1_hosts_txt="${OUTDIR}/hosts_list.txt"

echo
echo "[FASE 1] Identificando hosts activos (ICMP + ARP)"
echo " - Generando output greppable: ${phase1_grep}"
echo

# Combine both scans into a single greppable file (append)
> "${phase1_grep}"
for net in "${SUBNETS[@]}"; do
  echo "  -> Escaneando ${net} : ping (ICMP) -PE"
  # ICMP ping scan
  ${NMAP} -sn -PE -oG - "${net}" >> "${phase1_grep}" 2>/dev/null || true

  echo "  -> Escaneando ${net} : ARP discovery (-PR) (solo LAN)"
  # ARP ping scan (local networks only)
  ${NMAP} -sn -PR -oG - "${net}" >> "${phase1_grep}" 2>/dev/null || true
done

# parse greppable to extract unique IPs that are Up
awk '/^Host:/{ if ($3 == "Status:") { ip=$2; for(i=1;i<=NF;i++){ if($i=="Status:"){ if($(i+1)=="Up") { print ip } } } } }' "${phase1_grep}" | sort -u > "${phase1_hosts_txt}"

# fallback parsing (if format differs)
if [[ ! -s "${phase1_hosts_txt}" ]]; then
  # Try simpler extraction: look for "Up" lines
  grep -E "Status: Up" "${phase1_grep}" | awk '{print $2}' | sort -u > "${phase1_hosts_txt}" || true
fi

echo
echo "[FASE 1] Hosts detectados guardados en: ${phase1_hosts_txt}"
echo "  -> $(wc -l < "${phase1_hosts_txt}") hosts encontrados (líneas)"

##########
# FASE 2 #
##########
echo
echo "[FASE 2] Escaneo de puertos completos (-sS -p- -n -Pn --min-rate ${MIN_RATE})"
phase2_grep="${OUTDIR}/phase2_ports.oG"
phase2_csv="${OUTDIR}/ports.csv"
> "${phase2_grep}"
> "${phase2_csv}"

# CSV header
echo "host,port,proto,state,service" > "${phase2_csv}"

if [[ ! -s "${phase1_hosts_txt}" ]]; then
  echo "[FASE 2] ATENCIÓN: no hay hosts detectados en fase 1. Abortando fase 2."
else
  # For performance, scan per-subnet rather than per-host to use -p- efficiently.
  # But user requested: "fase 2 toma los hosts activos" -> we'll scan the hosts specifically (by list)
  # nmap supports -iL <file>, so use that.
  echo "  -> Ejecutando nmap para lista de hosts: ${phase1_hosts_txt}"
  ${NMAP} ${SYN_SCAN_OPTS} -iL "${phase1_hosts_txt}" -oG - 2>/dev/null | tee "${phase2_grep}" >/dev/null || true

  # Parse phase2 greppable for ports lines. Example Ports field: Ports: 22/open/tcp//ssh///
  # We'll extract host and ports and write to CSV as individual lines.
  awk '
    /^Host: / {
      host=$2;
      # find "Ports:" field in line
      ports_field="";
      for(i=1;i<=NF;i++){
        if ($i == "Ports:") {
          # join rest of fields to ports string
          ports_field = "";
          for(j=i+1;j<=NF;j++){
            ports_field = ports_field " " $j
          }
        }
      }
      if (ports_field != "") {
        # ports_field contains comma-separated port entries, remove leading space
        gsub(/^ /,"",ports_field);
        # split by comma
        n = split(ports_field, arr, ",");
        for(k=1;k<=n;k++){
          line = arr[k];
          # example: 22/open/tcp//ssh///
          # split by slash
          split(line, p, "/");
          port = p[1];
          state = p[2];
          proto = p[3];
          service = p[5];
          if (port ~ /^[0-9]+$/) {
            printf "%s,%s,%s,%s,%s\n", host, port, proto, state, service;
          }
        }
      }
    }
  ' "${phase2_grep}" >> "${phase2_csv}" || true

  # Create per-host ports greppable (IP:comma-separated-ports), used in fase3
  awk -F, 'NR>1 { host=$1; port=$2; arr[host]=(arr[host]==""?port:arr[host]","port) }
            END { for (h in arr) print h":"arr[h] }' "${phase2_csv}" > "${OUTDIR}/host_ports.grep"
  echo
  echo "[FASE 2] CSV de puertos: ${phase2_csv}"
  echo "[FASE 2] Greppable host:ports: ${OUTDIR}/host_ports.grep"
fi

##########
# FASE 3 #
##########
echo
echo "[FASE 3] Escaneando vulnerabilidades por host y puertos detectados"
echo "  -> Usando opciones: ${SCRIPTS_SCAN_OPTS}"
echo

host_ports_file="${OUTDIR}/host_ports.grep"
if [[ ! -s "${host_ports_file}" ]]; then
  echo "[FASE 3] No hay puertos detectados para escanear (archivo ${host_ports_file} vacío). Abortando fase 3."
  exit 0
fi

# Iterate lines like: 192.168.1.10:22,80,443
while IFS= read -r line; do
  # skip empty
  [[ -z "$line" ]] && continue
  host="${line%%:*}"
  ports="${line#*:}"
  # sanitize
  host=$(echo "${host}" | tr -d '[:space:]')
  ports=$(echo "${ports}" | tr -d '[:space:]')
  if [[ -z "${ports}" || "${ports}" == "${host}" ]]; then
    echo "  - Saltando ${host} (sin puertos)."
    continue
  fi

  echo "  - [${host}] Ejecutando escaneo de vulnerabilidades sobre puertos: ${ports}"
  out_file="${PER_HOST_DIR}/${host}_nmap.txt"
  # run final scan with -oN (normal)
  ${NMAP} ${SCRIPTS_SCAN_OPTS} -p "${ports}" -oN "${out_file}" "${host}" 2>/dev/null || true
  echo "    -> Resultado guardado en: ${out_file}"
done < "${host_ports_file}"

echo
echo "==> Escaneo completado. Resultados en ${OUTDIR}"
echo " - Fase1 greppable: ${phase1_grep}"
echo " - Hosts list: ${phase1_hosts_txt}"
echo " - Fase2 greppable: ${phase2_grep}"
echo " - Puertos CSV: ${phase2_csv}"
echo " - Host:ports greppable: ${OUTDIR}/host_ports.grep"
echo " - Salidas por host en: ${PER_HOST_DIR}"
