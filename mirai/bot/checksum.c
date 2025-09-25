/***************************************************************************
 * Archivo: checksum.c
 * 
 * Descripción: Implementación de cálculo de checksums para protocolos de red
 * Este módulo provee funciones para calcular:
 * - Checksums genéricos para cualquier buffer
 * - Checksums específicos para TCP/UDP con pseudo-cabecera IP
 * 
 * Referencias:
 * - RFC 1071 (Computing the Internet Checksum)
 * - RFC 793 (TCP)
 * - RFC 768 (UDP)
 * 
 * Notas de implementación:
 * - Optimizado para arquitecturas de 16/32 bits
 * - Maneja correctamente alineamiento de datos
 * - Soporta diferentes endianness
 ***************************************************************************/

/* Habilitar extensiones GNU */
#define _GNU_SOURCE

/* Cabeceras del sistema */
#include <arpa/inet.h>   /* htons(), prototipos de red */
#include <linux/ip.h>    /* struct iphdr */

/* Cabeceras locales */
#include "includes.h"    /* Definiciones comunes */
#include "checksum.h"    /* Prototipos de checksum */

/**
 * Calcula el checksum genérico de un buffer de datos
 * 
 * Esta función implementa el algoritmo estándar de Internet Checksum:
 * 1. Suma palabras de 16 bits como enteros de 32 bits
 * 2. Maneja bytes impares al final
 * 3. Añade el acarreo de vuelta al resultado
 * 4. Retorna el complemento a uno
 * 
 * Algoritmo basado en RFC 1071:
 * - Trata los datos como secuencia de palabras de 16 bits
 * - Acumula suma en registro de 32 bits para evitar overflow
 * - Maneja correctamente arquitecturas big/little endian
 * 
 * @param addr    Puntero al inicio del buffer (alineado a 16 bits)
 * @param count   Número de bytes a procesar
 * @return        Checksum calculado (complemento a 1 de 16 bits)
 */
uint16_t checksum_generic(uint16_t *addr, uint32_t count)
{
    /* Usar register para optimizar acceso */
    register unsigned long sum = 0;

    /* Sumar palabras de 16 bits */
    for (sum = 0; count > 1; count -= 2)
        sum += *addr++;           /* Acumular y avanzar puntero */
    
    /* Manejar byte final si count es impar */
    if (count == 1)
        sum += (char)*addr;      /* Añadir último byte */

    /* Añadir acarreos de vuelta al resultado
     * 1. Sumar parte alta (bits 31-16) a parte baja (bits 15-0)
     * 2. Si genera nuevo acarreo, sumarlo también
     */
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    /* Retornar complemento a uno del resultado */
    return ~sum;
}

/**
 * Calcula el checksum TCP/UDP incluyendo la pseudo-cabecera IP
 * 
 * Esta función implementa el cálculo de checksum específico para TCP/UDP que:
 * 1. Incluye campos de la pseudo-cabecera IP:
 *    - IP origen
 *    - IP destino
 *    - Protocolo
 *    - Longitud TCP/UDP
 * 2. Suma los campos del segmento TCP o UDP
 * 3. Maneja alineamiento y bytes impares
 * 
 * Formato de pseudo-cabecera (RFC 793/768):
 * +--------+--------+--------+--------+
 * |           IP Origen           |
 * +--------+--------+--------+--------+
 * |           IP Destino          |
 * +--------+--------+--------+--------+
 * | Zero   |  Prot  |   Longitud    |
 * +--------+--------+--------+--------+
 * 
 * @param iph       Puntero a la cabecera IP
 * @param buff      Puntero al segmento TCP/UDP
 * @param data_len  Longitud del segmento en bytes
 * @param len       Longitud total a procesar
 * @return          Checksum calculado (complemento a 1 de 16 bits)
 */
uint16_t checksum_tcpudp(struct iphdr *iph, void *buff, uint16_t data_len, int len)
{
    /* Preparar punteros y variables */
    const uint16_t *buf = buff;           /* Buffer de datos como palabras de 16 bits */
    uint32_t ip_src = iph->saddr;         /* IP origen */
    uint32_t ip_dst = iph->daddr;         /* IP destino */
    uint32_t sum = 0;                     /* Acumulador de suma */
    int length = len;                     /* Copia de longitud para preservar original */
    
    /* Sumar el contenido del segmento TCP/UDP en palabras de 16 bits */
    while (len > 1)
    {
        sum += *buf;                      /* Acumular palabra de 16 bits */
        buf++;                            /* Avanzar puntero */
        len -= 2;                         /* Actualizar contador */
    }

    /* Manejar byte final si la longitud es impar */
    if (len == 1)
        sum += *((uint8_t *) buf);        /* Añadir último byte */

    /* Sumar campos de la pseudo-cabecera IP
     * - Dividir IPs en palabras de 16 bits
     * - Convertir protocolo a network byte order
     * - Añadir longitud del segmento
     */
    sum += (ip_src >> 16) & 0xFFFF;      /* IP origen (high word) */
    sum += ip_src & 0xFFFF;              /* IP origen (low word) */
    sum += (ip_dst >> 16) & 0xFFFF;      /* IP destino (high word) */
    sum += ip_dst & 0xFFFF;              /* IP destino (low word) */
    sum += htons(iph->protocol);         /* Protocolo (TCP = 6, UDP = 17) */
    sum += data_len;                     /* Longitud del segmento */

    /* Añadir los acarreos de vuelta hasta que no haya más */
    while (sum >> 16) 
        sum = (sum & 0xFFFF) + (sum >> 16);

    /* Retornar complemento a uno del resultado */
    return ((uint16_t) (~sum));
}
