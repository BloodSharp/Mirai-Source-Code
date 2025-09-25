/***************************************************************************
 * Archivo: checksum.h
 * 
 * Descripción: Interfaz para el cálculo de checksums de protocolos de red
 * Este header define las funciones necesarias para:
 * - Calcular checksums genéricos para cualquier buffer
 * - Calcular checksums específicos para TCP/UDP con pseudo-cabecera IP
 * 
 * Protocolos soportados:
 * - TCP (RFC 793)
 * - UDP (RFC 768)
 * - IP (RFC 791)
 * 
 * Algoritmos implementados según:
 * - RFC 1071 (Computing the Internet Checksum)
 ***************************************************************************/

/* Prevenir inclusión múltiple */
#pragma once

/* Cabeceras del sistema */
#include <stdint.h>     /* uint16_t, uint32_t */
#include <linux/ip.h>   /* struct iphdr */

/* Cabeceras locales */
#include "includes.h"    /* Definiciones comunes */

/**
 * Calcula el checksum genérico de un buffer de datos
 * 
 * Esta función implementa el algoritmo estándar de Internet Checksum
 * para cualquier bloque de datos.
 * 
 * @param buffer   Puntero al buffer de datos (alineado a 16 bits)
 * @param length   Longitud del buffer en bytes
 * @return         Checksum calculado (complemento a 1 de 16 bits)
 */
uint16_t checksum_generic(uint16_t *buffer, uint32_t length);

/**
 * Calcula el checksum TCP/UDP incluyendo la pseudo-cabecera IP
 * 
 * Esta función calcula el checksum específico para segmentos TCP/UDP,
 * incluyendo los campos de la pseudo-cabecera IP requerida:
 * - IP origen
 * - IP destino
 * - Protocolo
 * - Longitud del segmento
 * 
 * @param iph       Puntero a la cabecera IP
 * @param segment   Puntero al segmento TCP/UDP
 * @param len       Longitud de los datos TCP/UDP
 * @param total_len Longitud total a procesar
 * @return          Checksum calculado (complemento a 1 de 16 bits)
 */
uint16_t checksum_tcpudp(struct iphdr *iph, void *segment, uint16_t len, int total_len);
