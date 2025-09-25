/**
 * @file protocol.h
 * @brief Definiciones de estructuras y constantes para protocolos de red
 *
 * Este archivo contiene las estructuras de datos y constantes necesarias para:
 * - Generación de paquetes DNS
 * - Encapsulación GRE (Generic Routing Encapsulation)
 * - Opciones TCP
 * 
 * Las estructuras están diseñadas para coincidir exactamente con los
 * formatos de paquete de red estándar.
 */

#pragma once  // Previene inclusiones múltiples del encabezado

#include <stdint.h>    // Para tipos de datos de ancho fijo (uint16_t, etc.)
#include "includes.h"  // Definiciones comunes del bot

/**
 * @struct dnshdr
 * @brief Cabecera de paquete DNS (RFC 1035)
 *
 * Estructura que representa la cabecera de un paquete DNS.
 * Todos los campos son de 16 bits en orden de red (big-endian).
 */
struct dnshdr {
    uint16_t id;       //!< Identificador de la consulta
    uint16_t opts;     //!< Banderas y códigos de operación
    uint16_t qdcount;  //!< Número de entradas en la sección de pregunta
    uint16_t ancount;  //!< Número de RRs en la sección de respuesta
    uint16_t nscount;  //!< Número de RRs en la sección de autoridad
    uint16_t arcount;  //!< Número de RRs en la sección adicional
};

/**
 * @struct dns_question
 * @brief Estructura de pregunta DNS
 *
 * Representa la sección de pregunta en un paquete DNS.
 * La parte del nombre de dominio se maneja por separado.
 */
struct dns_question {
    uint16_t qtype;    //!< Tipo de consulta (A, AAAA, MX, etc.)
    uint16_t qclass;   //!< Clase de consulta (típicamente IN para Internet)
};

/**
 * @struct dns_resource
 * @brief Registro de recurso DNS
 *
 * Estructura para registros de recurso (RR) DNS.
 * Se usa tanto para respuestas como para secciones adicionales.
 */
struct dns_resource {
    uint16_t type;     //!< Tipo de registro (A, AAAA, MX, etc.)
    uint16_t _class;   //!< Clase del registro (típicamente IN)
    uint32_t ttl;      //!< Tiempo de vida en segundos
    uint16_t data_len; //!< Longitud de los datos del registro
} __attribute__((packed));  // Asegura que no haya relleno entre campos

/**
 * @struct grehdr
 * @brief Cabecera de encapsulación GRE
 *
 * Generic Routing Encapsulation (GRE) es un protocolo de tunelización
 * que puede encapsular una amplia variedad de protocolos de capa 3.
 */
struct grehdr {
    uint16_t opts;      //!< Opciones y banderas de GRE
    uint16_t protocol;  //!< Tipo de protocolo encapsulado
};

/**
 * @name Constantes de Protocolo DNS
 * @{
 * Valores estándar para consultas DNS tipo A (IPv4)
 * @} */
#define PROTO_DNS_QTYPE_A       1    //!< Tipo de consulta DNS para registros A (dirección IPv4)
#define PROTO_DNS_QCLASS_IP     1    //!< Clase de consulta DNS para Internet

/**
 * @name Opciones TCP
 * @{
 * Valores para las opciones de cabecera TCP según RFC 793
 * @} */
#define PROTO_TCP_OPT_NOP   1    //!< No Operation - usado para relleno
#define PROTO_TCP_OPT_MSS   2    //!< Maximum Segment Size
#define PROTO_TCP_OPT_WSS   3    //!< Window Scale Size
#define PROTO_TCP_OPT_SACK  4    //!< Selective Acknowledgment permitted
#define PROTO_TCP_OPT_TSVAL 8    //!< Timestamp Value

/**
 * @name Constantes de Protocolo GRE
 * @{
 * Valores de protocolo para encapsulación GRE
 * @} */
#define PROTO_GRE_TRANS_ETH 0x6558  //!< Valor para encapsulación de tramas Ethernet
