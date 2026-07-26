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

**Paso 2.** Clona el repositorio y coloca tus datos.

```bash
# Clone the repository
git clone https://github.com/Yamato-Security/senrigan.git
cd senrigan

# Place the downloaded CloudTrail logs here
cp -r <local-output-dir>/ docker/logs/
```

Los dos directorios opcionales siguientes se detectan automáticamente. Rellénalos **antes** del siguiente paso: no hay ningún comando adicional que ejecutar.

| Directorio | Contenido | Qué añade |
|---|---|---|
| `docker/data/geoip/` | [GeoLite2 `.mmdb`](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | Resuelve las IP de origen a país, ciudad y ASN |
| `docker/data/config-snapshots/` | Archivos `.json` de instantáneas de AWS Config | Construye el grafo de recursos de AWS Config |

**Paso 3.** Ingiere los registros e inicia los servicios.

```bash
make ingest
make up
```

**Paso 4.** 🪽 ¡Abre tu navegador y comienza a cazar!🪽

- http://localhost:8501 — Consultas integradas y AI Chat
- http://localhost:8088 — Panel (`admin` / `admin`)
- http://localhost:8502 — Grafo de recursos de AWS Config

---

## Comandos de uso diario

`make` sin argumentos imprime esta lista. `make help-all` muestra todos los objetivos.

| Comando | Qué hace |
|---|---|
| `make ingest` | Cargar los registros de CloudTrail de `docker/logs/` en DuckDB |
| `make up` | Iniciar la interfaz, el panel y el grafo de recursos |
| `make down` | Detener todo |
| `make logs` | Seguir los registros de los servicios (`SERVICE=agent` para uno solo) |
| `make reset` | Eliminar la base de datos y empezar de nuevo |

---

## Proxy corporativo / Certificado CA personalizado

Si te encuentras detrás de un proxy corporativo que inspecciona TLS, consulta [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) para obtener instrucciones de configuración.
