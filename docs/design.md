# Diseño y arquitectura

## 1. Objetivo y alcance

El sistema implementa un proxy SOCKS v5 para el comando TCP `CONNECT`, con
autenticación usuario/contraseña, resolución IPv4/IPv6/FQDN, métricas, access
log, configuración dinámica y graceful shutdown. En el mismo proceso se ofrece
un servicio TCP separado para administración y un cliente de terminal.

El diseño prioriza que toda la I/O de red del servidor sea no bloqueante y esté
multiplexada en un único event loop. La única tarea delegada a otro thread es
`getaddrinfo`, que puede bloquear por causas externas.

## 2. Componentes

### 2.1 Servidor y listeners

`src/server/main.c` interpreta los argumentos, crea el estado compartido y abre
dos sockets pasivos:

- SOCKS5, por defecto en `0.0.0.0:1080`.
- Administración, por defecto en `127.0.0.1:8080`.

Ambos listeners y todas las conexiones aceptadas se registran en el mismo
selector. El loop llama a `selector_select()` y luego revisa los timeouts de las
sesiones SOCKS.

### 2.2 Selector y máquinas de estados

El selector provisto por la cátedra abstrae el registro de descriptores, sus
intereses de lectura/escritura y callbacks. Su implementación actual utiliza
`select(2)`.

Cada conexión SOCKS tiene una instancia de `struct socks5`, dos buffers de 4096
bytes y una máquina de estados. La sesión avanza por:

```text
HELLO_READ -> HELLO_WRITE
                  |
                  +-> AUTH_READ -> AUTH_WRITE
                  |
                  +-> REQUEST_READ -> REQUEST_RESOLV -> CONNECTING
                                            |               |
                                            +---------------+
                                                    |
                                              REQUEST_WRITE
                                                    |
                                                   COPY
                                                    |
                                               DONE / ERROR
```

`REQUEST_RESOLV` solo se utiliza para FQDN. Las direcciones literales pasan
directamente a `CONNECTING`. Los estados finales liberan los descriptores y
devuelven la estructura de sesión a un pool acotado para reutilización.

El servicio administrativo utiliza una máquina de sesión más simple dentro de
`mng.c`: acumula una línea, ejecuta un comando, conserva la respuesta pendiente
y alterna el interés del selector entre lectura y escritura.

## 3. Negociación SOCKS5

### 3.1 Selección de método

El parser de HELLO consume mensajes incluso cuando llegan fragmentados. La
selección de método depende de si el store contiene usuarios:

- Con usuarios configurados, el servidor exige usuario/contraseña: elige `0x02`
  si el cliente lo ofrece, y responde `0xFF` (sin métodos aceptables) si no.
- Sin usuarios, el servidor no requiere autenticación: elige `0x00` si el
  cliente lo ofrece, y responde `0xFF` si el cliente solo ofrece `0x02`.

Cuando el método elegido es `0xFF`, el servidor envía esa respuesta al cliente y
recién entonces cierra la sesión. De este modo un cliente sin método en común
recibe el rechazo del protocolo antes del cierre.

Los bytes que pertenecen al siguiente mensaje y llegan en el mismo `recv` se
conservan en el buffer. Una rutina de bombeo continúa el estado siguiente sin
esperar otra vuelta del selector.

### 3.2 Autenticación

La subnegociación sigue RFC 1929. Usuario y clave se validan contra un store en
memoria de hasta 10 entradas. Una autenticación fallida incrementa la métrica
`auth-fail` y la sesión termina después de enviar la respuesta de rechazo.

### 3.3 Request

Se admite únicamente `CONNECT`. El parser reconoce IPv4, IPv6 y FQDN. Los
comandos o tipos de dirección no soportados generan `0x07` y `0x08`. Los fallos
de red se traducen a los códigos SOCKS5 disponibles (`network unreachable`,
`host unreachable`, `connection refused`, `TTL expired` o fallo general).

## 4. Resolución DNS y conexión al origen

### 4.1 Worker DNS

Los requests FQDN se encolan en un worker dedicado. Ese thread realiza
exclusivamente `getaddrinfo`, escribe el resultado asociado a la sesión y
despierta al selector mediante `selector_notify_block`. La sesión mantiene una
referencia adicional mientras el trabajo está en vuelo para que su memoria no
sea reutilizada antes de recibir el resultado.

Existe una única cola y un único worker. Esto evita incorporar sincronización en
el event loop, a costa de serializar las resoluciones.

Por esta misma referencia cruda, el barrido de timeouts nunca fuerza el cierre de
una sesión en `REQUEST_RESOLV`. Mientras el worker conserva el puntero a la
sesión, cerrar y reciclar su descriptor abriría una carrera de reutilización de
fd que el contador de referencias no cubre por completo, de modo que ese estado
queda deliberadamente excluido del deadline.

### 4.2 Conexión no bloqueante

Para cada dirección candidata se crea un socket no bloqueante y se invoca
`connect`. `EINPROGRESS` registra el descriptor con interés de escritura. Cuando
el selector lo informa listo, `SO_ERROR` determina el resultado.

Si una dirección proveniente de un FQDN falla, la implementación intenta la
siguiente. Solo cuando se agota la lista se responde el último error al cliente.
El timeout `connect-timeout` cancela el descriptor activo y devuelve `TTL
expired`.

La respuesta SOCKS utiliza actualmente `0.0.0.0:0` como dirección y puerto
asociados (`BND.ADDR`/`BND.PORT`), independientemente del socket local elegido.

## 5. Relay y control de flujo

Al establecerse el túnel, `COPY` configura dos direcciones independientes:

- cliente a origen, usando el buffer de lectura;
- origen a cliente, usando el buffer de escritura.

Cada dirección lee solo si su buffer tiene espacio y escribe solo si contiene
datos. Después de una lectura o escritura parcial se recalculan los intereses de
ambos descriptores. Este mecanismo aplica backpressure sin reservar memoria en
función del tamaño total del flujo.

Cuando `recv` devuelve EOF, el lado opuesto se mantiene abierto hasta drenar el
buffer y luego recibe `shutdown(SHUT_WR)`. El túnel termina cuando ambas
direcciones completaron ese half-close. Los bytes se contabilizan al ser
efectivamente enviados, no al ser recibidos.

`idle-timeout` se compara contra la última lectura con datos en estado `COPY`.
Un timeout cierra la sesión y registra el cierre del túnel.

## 6. Estado compartido y observabilidad

### 6.1 Usuarios

El store de usuarios vive en memoria. El servidor lo inicializa con cada `-u` y
el protocolo administrativo puede agregar, reemplazar, listar o eliminar
entradas. Los cambios no persisten luego de reiniciar el proceso.

### 6.2 Configuración

Los timeouts y el máximo de conexiones se almacenan en un `config_t` compartido.
`CONFIG SET` modifica ese objeto en el mismo thread del selector, por lo que no
requiere locks. Las sesiones nuevas toman el timeout de negociación vigente; el
idle timeout se consulta dinámicamente y el connect timeout se fija al entrar en
`CONNECTING`.

### 6.3 Métricas

Los contadores son volátiles y se modifican desde el event loop. Incluyen
conexiones aceptadas, activas y rechazadas; fallos de autenticación; conexiones
a origen exitosas/fallidas; bytes por dirección y sesiones administrativas
activas. `STATS` toma un snapshot consistente al procesar el comando.

### 6.4 Access log

El lifecycle SOCKS centraliza la emisión del log:

- `OPEN` al entrar en `COPY`.
- `CLOSE` al terminar una sesión que alcanzó `COPY`, con sus bytes acumulados.
- `FAIL: <motivo>` si se conoció un destino pero el túnel nunca abrió.

El archivo se abre una vez en modo append, se escribe como TSV y se hace
`fflush` después de cada evento. Con `-o` omitido se usa `stderr`.

## 7. Administración

El listener administrativo es no bloqueante y forma parte del selector. Cada
sesión mantiene buffers acotados, estado de autenticación y un contador de
fallos. Luego de tres secretos inválidos responde `-ERR locked` y cierra.

Los comandos acceden directamente a usuarios, métricas y configuración porque
se ejecutan en el mismo event loop. El cliente `bin/client` puede usar I/O
bloqueante por ser una aplicación separada y de una sola operación. El protocolo
completo se define en `management-protocol.md`.

## 8. Apagado y liberación de recursos

Los handlers de `SIGINT` y `SIGTERM` solo incrementan un contador de tipo
`sig_atomic_t`. El loop observa la primera señal, desregistra y cierra ambos
listeners, y entra en modo draining. No se aceptan conexiones nuevas y el
proceso espera hasta que las sesiones SOCKS y administrativas lleguen a cero.

Una segunda señal interrumpe la espera. La limpieza detiene y une el worker DNS,
destruye el selector, libera pools, usuarios, métricas y access log, y cierra
cualquier listener restante.

## 9. Escalabilidad y stress

La prueba `make stress` levanta un echo server dual-stack, el proxy y un cliente
con un thread por túnel. Una barrera asegura que los túneles estén abiertos al
mismo tiempo antes del round-trip. Los destinos se reparten entre IPv4, IPv6 y
FQDN.

Con 500 túneles se observaron 500/500 operaciones exitosas, apertura promedio de
37–46 ms, máximo de 76–96 ms y tiempo total cercano a 0,1 s en el entorno Linux
utilizado. El backlog del listener se configuró en 1024 para soportar la ráfaga.

La principal restricción no es la STM sino `select(2)`: `FD_SETSIZE=1024` limita
el conjunto total y cada túnel utiliza dos descriptores. El techo práctico es de
aproximadamente 510–512 túneles, con poco margen sobre los 500 requeridos. El
costo de escanear el conjunto también es O(n). Reemplazar el backend por
`poll`/`epoll` permitiría superar ese límite sin cambiar la máquina de estados.

## 10. Limitaciones y decisiones pendientes

- La plataforma de entrega es Linux. El fixture de stress usa
  `pthread_barrier_t`, no implementado por macOS.
- El worker DNS es único, no posee timeout propio y una consulta en curso no se
  cancela.
- El barrido de timeouts corre una vez por retorno de `selector_select`. Sin
  tráfico ese retorno ocurre como mucho cada `SELECTOR_TIMEOUT_SECS` (10 s), por
  lo que un timeout configurado por debajo de ese valor puede dispararse con
  hasta ~10 s de retraso.
- Las credenciales y el protocolo administrativo viajan sin cifrado; por eso el
  listener administrativo se restringe a loopback por defecto.
- La configuración, usuarios y métricas son volátiles.
- No se implementan `BIND`, `UDP ASSOCIATE` ni captura de credenciales POP3.
