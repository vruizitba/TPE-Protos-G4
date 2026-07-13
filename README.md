# TPE Protocolos de Comunicación — Proxy SOCKS5

Trabajo Práctico Especial 2026/1 del Grupo 4. El proyecto implementa un proxy
SOCKS v5 no bloqueante, un servicio de administración y monitoreo, un cliente de
línea de comandos, métricas operativas, registro de accesos y apagado ordenado.

La plataforma de compilación y entrega soportada es **Linux** con interfaces
POSIX. El servidor y el cliente principal también compilan
en macOS, pero los targets `test` y `stress` no se consideran portables a esa
plataforma; véase [Limitaciones](#limitaciones-conocidas).

## Material entregado

| Material | Ubicación |
|---|---|
| Código del servidor | `src/server/` |
| Código del cliente administrativo | `src/client/` |
| Componentes compartidos | `src/shared/` |
| Pruebas unitarias | `test/*_test.c` |
| Prueba de stress autocontenida | `test/stress/` |
| Informe de entrega | `informe.txt` |
| Documento de diseño | `docs/design.md` |
| Especificación del protocolo administrativo | `docs/management-protocol.md` |
| Atribuciones de material docente | `NOTICE` |

Los artefactos generados por la compilación se guardan en `bin/` y los objetos
intermedios en `obj/`. Ambos directorios pueden eliminarse con `make clean`.

## Requisitos

- Linux con headers POSIX, sockets IPv4/IPv6 y soporte de `pthread`.
- Compilador de C11 disponible como `gcc`.
- GNU Make.
- Para `make test`: framework **Check** y biblioteca **Subunit** con sus headers
  de desarrollo.
- Para los ejemplos manuales: `curl`.
- Para análisis opcional de memoria: Valgrind.

En Debian/Ubuntu, las dependencias usuales se instalan con:

```sh
sudo apt update
sudo apt install build-essential check libsubunit-dev curl valgrind
```

## Compilación y verificación

Desde la raíz del repositorio:

```sh
make clean
make
```

Esto genera:

- `bin/socks5d`: proxy SOCKS5 y servicio administrativo.
- `bin/client`: cliente de configuración y monitoreo.

Targets adicionales:

```sh
make test       # compila y ejecuta las pruebas unitarias
make clean && make sanitize  # compila con AddressSanitizer y UBSan
make clean && make stress    # abre 500 túneles por defecto
```

`make sanitize` construye los binarios instrumentados; para ejercerlos hay que
ejecutar luego los escenarios deseados. La cantidad de túneles y los puertos de
stress pueden ajustarse mediante `STRESS_N`, `STRESS_SOCKS_PORT`,
`STRESS_MNG_PORT` y `STRESS_ECHO_PORT`:

```sh
STRESS_N=500 make stress
```

## Servidor

Uso general:

```sh
./bin/socks5d [opciones]
```

| Opción | Significado | Valor por defecto |
|---|---|---|
| `-h` | Muestra la ayuda y termina. | — |
| `-l <dirección>` | Dirección IP literal del listener SOCKS5 (no nombres de host). | `0.0.0.0` |
| `-p <puerto>` | Puerto del listener SOCKS5. | `1080` |
| `-L <dirección>` | Dirección IP literal del servicio administrativo (no nombres de host). | `127.0.0.1` |
| `-P <puerto>` | Puerto del servicio administrativo. | `8080` |
| `-u <usuario>:<clave>` | Usuario SOCKS; repetible hasta 10 veces. | Sin usuarios |
| `-a <secreto>` | Secreto del servicio administrativo. | Sin configurar |
| `-m <cantidad>` | Máximo de conexiones SOCKS activas; `0` deshabilita el límite. | `0` |
| `-t <segundos>` | Timeout total de negociación; `0` lo deshabilita. | `0` |
| `-c <segundos>` | Timeout de conexión al origen; `0` lo deshabilita. | `0` |
| `-i <segundos>` | Timeout de inactividad del túnel; `0` lo deshabilita. | `0` |
| `-o <archivo>` | Archivo append-only para el access log. | `stderr` |
| `-v` | Muestra la versión y termina. | — |

Si se configura al menos un usuario con `-u`, el proxy exige autenticación
usuario/contraseña de RFC 1929. Sin usuarios acepta el método SOCKS5 sin
autenticación. Para administrar el proceso debe configurarse un secreto con
`-a`; de lo contrario los comandos protegidos responden `-ERR auth required`.

Ejemplo:

```sh
./bin/socks5d \
  -u pablito:1234 \
  -a secreto-admin \
  -p 1080 -P 8080 \
  -m 500 -t 30 -c 15 -i 300 \
  -o /tmp/socks5-access.log
```

### Uso del proxy

Resolución del nombre en el cliente:

```sh
curl --proxy socks5://127.0.0.1:1080 \
  --proxy-user pablito:1234 \
  http://127.0.0.1:8000/
```

Resolución del FQDN a cargo del proxy:

```sh
curl --proxy socks5h://127.0.0.1:1080 \
  --proxy-user pablito:1234 \
  http://example.com/
```

El comando SOCKS implementado es `CONNECT`, para destinos IPv4, IPv6 y FQDN.
`BIND` y `UDP ASSOCIATE` se rechazan con los códigos definidos por RFC 1928.

## Cliente administrativo

Uso:

```sh
./bin/client [-L dirección] [-P puerto] [-a secreto] <comando>
```

`-L` y `-P` valen por defecto `127.0.0.1` y `8080`. El cliente abre una
conexión TCP, envía primero `AUTH` cuando se proporciona `-a`, ejecuta un único
comando, imprime la respuesta y termina.

Ejemplos:

```sh
./bin/client -a secreto-admin stats
./bin/client -a secreto-admin users
./bin/client -a secreto-admin user set nuevo clave123
./bin/client -a secreto-admin user delete nuevo
./bin/client -a secreto-admin config get
./bin/client -a secreto-admin config set idle-timeout 60
./bin/client -a secreto-admin config set max-connections 500
```

Los nombres de usuario, claves y secreto no admiten espacios. La especificación
completa del protocolo se encuentra en
[`docs/management-protocol.md`](docs/management-protocol.md).

## Registro de accesos

Cada línea del access log es TSV:

```text
timestamp\tusuario\tdestino:puerto\tbytes_c2o\tbytes_o2c\tevento
```

Los eventos son:

- `OPEN`: el túnel quedó establecido; los campos de bytes valen `-`.
- `CLOSE`: terminó un túnel que había sido abierto e incluye los bytes enviados
  en cada dirección.
- `FAIL: <motivo>`: la sesión falló antes de abrir el túnel; los bytes valen `-`.

El timestamp está expresado en UTC con formato ISO 8601. El usuario vale `-`
cuando el proxy opera sin autenticación.

## Apagado ordenado

Al recibir `SIGINT` o `SIGTERM`, el servidor cierra los dos listeners, deja de
aceptar conexiones nuevas y espera a que terminen las sesiones SOCKS y
administrativas existentes. Una segunda señal fuerza la salida:

```sh
kill -TERM <pid>
```

## Limitaciones conocidas

- El selector docente usa `select(2)` y `FD_SETSIZE=1024`. Como cada túnel
  consume dos descriptores, el techo práctico observado es de aproximadamente
  510–512 túneles simultáneos, además de los listeners y descriptores internos.
- `make stress` usa `pthread_barrier_t`, disponible en la plataforma Linux de
  entrega pero no en macOS. Las pruebas unitarias también presuponen Check y
  Subunit instalados en las rutas del sistema Linux.
- La resolución DNS tiene un único worker; una consulta lenta puede demorar las
  consultas posteriores y no se cancela durante la espera.
- La inspección de POP3 y el registro de credenciales corresponden a una segunda
  entrega y no forman parte de este proyecto.

## Documentación adicional

- [Diseño y arquitectura](docs/design.md)
- [Protocolo de administración y monitoreo](docs/management-protocol.md)
- [Informe de entrega](informe.txt)
- [Atribuciones](NOTICE)
