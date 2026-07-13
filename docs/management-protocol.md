# Protocolo de administración y monitoreo

## 1. Introducción

Este documento especifica el protocolo de aplicación utilizado para consultar
métricas, administrar usuarios SOCKS y modificar parámetros del proxy en tiempo
de ejecución. La descripción es independiente del lenguaje de implementación.

Las palabras **DEBE**, **NO DEBE**, **DEBERÍA**, **NO DEBERÍA** y **PUEDE** se
interpretan según RFC 2119.

## 2. Transporte, codificación y sesión

El protocolo utiliza una conexión TCP. El endpoint predeterminado es
`127.0.0.1:8080`, configurable al iniciar el servidor.

Los mensajes son líneas de texto compatibles con ASCII. Cada pedido y cada
respuesta termina con `LF` (`0x0A`). El servidor descarta cualquier `CR`
(`0x0D`) recibido, por lo que acepta terminadores `LF` y `CRLF`.

Una línea de pedido PUEDE contener espacios o tabulaciones al principio y al
final. Los argumentos se separan por uno o más caracteres reconocidos como
espacio por la plataforma. No existen comillas ni secuencias de escape: nombres,
claves y secretos no pueden contener espacios. Los comandos, subcomandos y
claves de configuración son sensibles a mayúsculas y se escriben exactamente
como aparecen en este documento.

La longitud máxima aceptada para el contenido de una línea es 1023 bytes, sin
contar `LF`. Una línea mayor produce:

```text
-ERR line too long
```

El servidor procesa un pedido y escribe su respuesta antes de procesar el
siguiente. Un cliente conforme DEBE esperar la respuesta antes de enviar otro
pedido. La implementación conserva datos ya recibidos y tolera varias líneas
coalescidas, pero esa forma de pipelining no forma parte del contrato.

El servidor puede cerrar la conexión si el peer termina, ocurre un error de I/O,
se ejecuta `QUIT`, se alcanza el límite de fallos de autenticación o se fuerza el
apagado del proceso.

## 3. Forma de los mensajes

La gramática se expresa con la siguiente notación:

```text
SP       = uno o más espacios o tabulaciones
TOKEN    = uno o más bytes ASCII no blancos
UINT     = uno o más dígitos decimales, valor entre 0 y 2147483647
pedido   = comando LF
respuesta = (éxito / error) LF
éxito    = "+OK" [SP texto]
error    = "-ERR" [SP texto]
```

Todas las respuestas ocupan una sola línea. Una respuesta que excedería 4095
bytes se reemplaza por:

```text
-ERR response too large
```

## 4. Autenticación administrativa

Salvo `AUTH` y `QUIT`, todos los comandos requieren que la sesión se encuentre
autenticada. El secreto administrativo se configura al iniciar `socks5d` con
`-a <secreto>` y es independiente de los usuarios SOCKS.

### 4.1 AUTH

```text
AUTH SP secreto
```

Si el secreto coincide exactamente:

```text
+OK authenticated
```

Si no coincide:

```text
-ERR invalid credentials
```

Cada sesión cuenta sus fallos consecutivos. Un `AUTH` correcto reinicia el
contador. Al tercer fallo, el servidor responde y luego cierra la conexión:

```text
-ERR locked
```

Si el proceso fue iniciado sin un secreto administrativo no es posible
autenticar la sesión:

```text
-ERR auth required
```

Una forma inválida del comando produce:

```text
-ERR usage AUTH <secret>
```

Un comando protegido antes de autenticar también produce:

```text
-ERR auth required
```

## 5. Comandos

### 5.1 STATS

```text
STATS
```

Devuelve todas las métricas en una única línea:

```text
+OK conn-accepted=<n> conn-active=<n> conn-rejected=<n> auth-fail=<n> origin-ok=<n> origin-fail=<n> bytes-c2o=<n> bytes-o2c=<n> admin-sessions=<n>
```

Semántica de los campos:

| Campo | Significado |
|---|---|
| `conn-accepted` | Conexiones SOCKS admitidas desde el inicio del proceso. |
| `conn-active` | Conexiones SOCKS actualmente activas. |
| `conn-rejected` | Conexiones SOCKS rechazadas por límite o fallo de preparación. |
| `auth-fail` | Autenticaciones SOCKS usuario/clave fallidas. No cuenta fallos de `AUTH` administrativo. |
| `origin-ok` | Conexiones a origen establecidas. |
| `origin-fail` | Intentos de conexión a origen que terminaron sin destino disponible. |
| `bytes-c2o` | Bytes enviados efectivamente desde clientes hacia orígenes. |
| `bytes-o2c` | Bytes enviados efectivamente desde orígenes hacia clientes. |
| `admin-sessions` | Sesiones administrativas actualmente activas, incluida la que consulta. |

Si las métricas no están disponibles:

```text
-ERR metrics unavailable
```

### 5.2 USERS

```text
USERS
```

Devuelve los nombres de los usuarios SOCKS separados por comas. Nunca devuelve
claves:

```text
+OK users=ana,beto
```

Si no hay usuarios:

```text
+OK users=-
```

El orden es interno y puede cambiar luego de eliminar usuarios. Si el store no
está disponible se responde `-ERR users unavailable`.

### 5.3 USER SET

```text
USER SP SET SP nombre SP clave
```

Agrega un usuario SOCKS o reemplaza la clave de uno existente:

```text
+OK user set
```

El store admite hasta 10 usuarios. Nombres y claves se almacenan con un máximo
de 255 bytes cada uno; valores más largos son truncados por la implementación.
Si se intenta agregar un usuario cuando el store está lleno:

```text
-ERR user limit reached
```

Una forma inválida produce:

```text
-ERR usage USER SET <name> <pass>
```

### 5.4 USER DELETE

```text
USER SP DELETE SP nombre
```

Si el usuario existía:

```text
+OK user deleted
```

Si no existía:

```text
-ERR user not found
```

Una forma inválida produce:

```text
-ERR usage USER DELETE <name>
```

Un subcomando `USER` desconocido produce `-ERR unknown USER command`. Omitir el
subcomando produce:

```text
-ERR usage USER SET <name> <pass> | USER DELETE <name>
```

### 5.5 CONFIG GET

```text
CONFIG SP GET
```

Devuelve los valores vigentes:

```text
+OK negotiation-timeout=<n> connect-timeout=<n> idle-timeout=<n> max-connections=<n>
```

Los timeouts están expresados en segundos. El valor `0` deshabilita cada
timeout. `max-connections=0` significa que no se aplica un límite configurable,
sin eliminar los límites propios del selector y del sistema operativo.

Argumentos adicionales producen `-ERR usage CONFIG GET`.

### 5.6 CONFIG SET

```text
CONFIG SP SET SP clave SP UINT
```

Las claves válidas y sus unidades son:

- `negotiation-timeout` — **segundos**. Timeout total de la negociación SOCKS.
- `connect-timeout` — **segundos**. Timeout de conexión al origen.
- `idle-timeout` — **segundos**. Timeout de inactividad del túnel.
- `max-connections` — **cantidad** de conexiones simultáneas (no es una unidad de tiempo).

En los tres timeouts, el valor `0` deshabilita el control. `max-connections=0`
significa que no se aplica un límite configurable.

El cambio se aplica en memoria y no persiste al reiniciar el proceso:

```text
+OK config set
```

Una forma inválida produce `-ERR usage CONFIG SET <key> <value>`. Un valor fuera
del rango de `UINT` produce `-ERR invalid value`. Una clave desconocida produce
`-ERR unknown config key`.

Omitir el subcomando `CONFIG` produce:

```text
-ERR usage CONFIG GET | CONFIG SET <key> <value>
```

Un subcomando desconocido produce `-ERR unknown CONFIG command`. Si el objeto de
configuración no está disponible se responde `-ERR config unavailable`.

### 5.7 QUIT

```text
QUIT
```

No requiere autenticación. El servidor responde y luego cierra la conexión:

```text
+OK bye
```

Argumentos adicionales producen `-ERR usage QUIT` y mantienen la conexión.

## 6. Errores generales

Una línea vacía produce:

```text
-ERR empty command
```

Un comando de primer nivel desconocido, después de autenticar, produce:

```text
-ERR unknown command
```

La implementación actual acepta e ignora tokens adicionales en `STATS` y
`USERS`; los clientes conformes NO DEBEN enviarlos. Los demás comandos validan
su aridad como se indicó anteriormente.

## 7. Ejemplo completo

```text
C: AUTH secreto-admin
S: +OK authenticated
C: STATS
S: +OK conn-accepted=8 conn-active=2 conn-rejected=0 auth-fail=1 origin-ok=6 origin-fail=1 bytes-c2o=4096 bytes-o2c=8192 admin-sessions=1
C: CONFIG SET idle-timeout 60
S: +OK config set
C: USER SET invitado clave123
S: +OK user set
C: USERS
S: +OK users=pablito,invitado
C: QUIT
S: +OK bye
```

Los prefijos `C:` y `S:` son explicativos y no forman parte de los bytes
intercambiados.

## 8. Consideraciones de seguridad

El protocolo no cifra el transporte ni protege el secreto contra observadores.
Por defecto escucha únicamente en loopback y DEBERÍA conservarse así. Si debe
administrarse desde otra máquina, se RECOMIENDA transportar la conexión por un
canal seguro externo, restringir el listener mediante firewall y usar un secreto
no reutilizado. El servidor no devuelve contraseñas SOCKS en `USERS`.
