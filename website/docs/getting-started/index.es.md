# Primeros pasos

## Requisitos previos

| Requisito                             | Detalles                                           |
|---------------------------------------|----------------------------------------------------|
| **Docker**                            | Docker Desktop o Docker Engine + Compose v2        |
| **make**                              | GNU Make (preinstalado en macOS)                   |
| **Recursos**                          | 16 GB de RAM como mínimo, se recomienda SSD        |
| **Registros de CloudTrail**           | Archivos `.json` o `.json.gz` exportados desde AWS |
| *(Opcional)* **Instantáneas de AWS Config** | Archivos `.json` o `.json.gz` para el grafo de recursos de AWS |
| *(Opcional)* **Clave de API de OpenAI**     | Requerida para la generación de consultas con IA |
| *(Opcional)* **MaxMind GeoLite2**     | Archivos `.mmdb` para el enriquecimiento con GeoIP |

---

## Inicio rápido

**Paso 1.** Descarga los registros de CloudTrail desde S3.

```bash
aws s3 cp s3://<your-bucket-prefix> <local-output-dir>/ --recursive --include "*.json.gz"
```

**Paso 2.** Clona el repositorio, ingiere los registros e inicia todos los servicios.

```bash
# Clone the repository
git clone https://github.com/Yamato-Security/senrigan.git
cd senrigan

# Place the downloaded logs into the Docker logs directory
cp -r <local-output-dir>/ docker/logs/

# Ingest CloudTrail logs into DuckDB
make ingest

# Start all services (agent + dashboard)
make up
```

**Paso 3.** 🪽 ¡Abre tu navegador y comienza a cazar!🪽

- http://localhost:8501 — Consultas integradas y AI Chat
- http://localhost:8088 — Panel (`admin` / `admin`)
- http://localhost:8502 — Grafo de recursos de AWS Config

**(Opcional)** Enriquecimiento con GeoIP.
Coloca los [archivos `.mmdb` de GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) en `docker/data/geoip/`, luego:

```bash
make ingest-geoip
```

**(Opcional)** Ingesta de instantáneas de AWS Config para la visualización del grafo de recursos.
Coloca los archivos de instantáneas de AWS Config en `docker/logs/config/`, luego:
```bash
make ingest-config
```
---

## Proxy corporativo / Certificado CA personalizado

Si te encuentras detrás de un proxy corporativo que inspecciona TLS, consulta [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) para obtener instrucciones de configuración.
