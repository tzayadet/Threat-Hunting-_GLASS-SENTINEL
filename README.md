# Glass Sentinel | Threat Hunting Lab

Ejercicio de detección en Python que correlaciona fallos de autenticación con exportaciones de datos grandes y no aprobadas.

[![Tests](https://github.com/tzayadet/Threat-Hunting-_GLASS-SENTINEL/actions/workflows/tests.yml/badge.svg)](https://github.com/tzayadet/Threat-Hunting-_GLASS-SENTINEL/actions/workflows/tests.yml)

**Demo:** [showcase estático](docs/index.html) · **Código:** [glass_sentinel.py](glass_sentinel.py)

La demo utiliza eventos sintéticos. El programa procesa un CSV local y no se conecta a endpoints, recopila telemetría ni envía datos por red.

## Regla de detección

Se genera una alerta cuando coinciden estas condiciones:

1. El evento corresponde a una exportación.
2. La exportación no está marcada como aprobada.
3. El volumen alcanza el umbral configurado (50 MB por defecto).
4. El mismo usuario y la misma IP registraron un inicio de sesión correcto durante los 10 minutos anteriores.
5. Antes de ese acceso correcto se registraron al menos dos fallos de autenticación para ese usuario e IP dentro de la ventana configurada.

Los umbrales pueden modificarse desde la línea de comandos.

## Requisitos y uso

Python 3.10 o superior. No necesita dependencias externas.

```bash
python glass_sentinel.py
python glass_sentinel.py path/to/events.csv
python glass_sentinel.py --minimum-mb 100 --window-minutes 15
```

El conjunto de datos predeterminado está en `data/sample_events.csv` y utiliza direcciones reservadas para documentación (RFC 5737).

## Formato CSV

| Campo | Descripción |
|---|---|
| `ts` | Marca temporal ISO 8601 |
| `user` | Cuenta asociada al evento |
| `ip` | Dirección IP de origen |
| `event` | `login_fail`, `login_success` o `export` |
| `bytes` | Volumen transferido en bytes |
| `approved` | Estado de aprobación |

## Pruebas

```bash
python -m unittest discover -s tests -v
```

## Publicar el showcase

El showcase estático se encuentra en [docs/index.html](docs/index.html) y utiliza eventos sintéticos. Para publicarlo:

1. En **Settings → Pages**, selecciona **GitHub Actions** como origen.
2. En **Settings → Secrets and variables → Actions → Variables**, crea `ENABLE_PAGES` con valor `true`.
3. Ejecuta **Deploy Threat-Hunting-_GLASS-SENTINEL showcase to GitHub Pages** desde Actions.

La página no se conecta a endpoints ni recopila telemetría. El programa procesa un CSV local.

## Limitaciones

La correlación utiliza coincidencia exacta de usuario e IP. NAT, VPN, proxies y cuentas compartidas pueden afectar al resultado. Una alerta es un indicio para investigar, no una prueba de exfiltración ni de actividad maliciosa.

Para uso real harían falta parsers adaptados a cada fuente, control de integridad, deduplicación de alertas y ajuste de umbrales con datos representativos.

## Licencia

Consulta [LICENSE](LICENSE).
