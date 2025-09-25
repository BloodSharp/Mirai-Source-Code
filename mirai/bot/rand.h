/**
 * @file rand.h
 * @brief Interfaz del generador de números pseudoaleatorios
 *
 * Este archivo define la interfaz pública del generador de números
 * pseudoaleatorios (PRNG) basado en xorshift. Proporciona funciones
 * para:
 * - Inicialización del generador
 * - Generación de números aleatorios
 * - Generación de cadenas aleatorias
 * - Generación de cadenas alfanuméricas
 */

#pragma once  // Previene inclusiones múltiples del encabezado

#include <stdint.h>  // Para tipos enteros de ancho fijo

/**
 * @def PHI
 * @brief Constante PHI (razón áurea) en formato hexadecimal
 *
 * El valor 0x9e3779b9 es una aproximación de PHI * 2^32.
 * Se usa como constante mágica en el generador por sus
 * propiedades matemáticas que ayudan a mejorar la distribución
 * de los números aleatorios generados.
 */
#define PHI 0x9e3779b9

/**
 * @brief Inicializa el generador de números aleatorios
 *
 * Debe llamarse antes de usar cualquier otra función del generador.
 * Inicializa el estado interno usando múltiples fuentes de entropía:
 * - Tiempo actual
 * - PIDs del proceso
 * - Estado del reloj del sistema
 */
void rand_init(void);

/**
 * @brief Genera el siguiente número pseudoaleatorio
 *
 * @return uint32_t Número aleatorio de 32 bits
 *
 * Implementa el algoritmo xorshift con período 2^96-1.
 * Es rápido y tiene buenas propiedades estadísticas,
 * pero no es criptográficamente seguro.
 */
uint32_t rand_next(void);

/**
 * @brief Genera un buffer de bytes aleatorios
 *
 * @param str Puntero al buffer donde se escribirán los datos
 * @param len Longitud del buffer a generar
 *
 * Llena el buffer con bytes completamente aleatorios (0-255).
 * Optimizado para generar grandes cantidades de datos aleatorios.
 * NOTA: Los datos generados pueden no ser imprimibles.
 */
void rand_str(char *str, int len);

/**
 * @brief Genera una cadena alfanumérica aleatoria
 *
 * @param str Puntero al buffer donde se escribirá la cadena
 * @param len Longitud de la cadena a generar
 *
 * Genera una cadena usando solo letras minúsculas y números.
 * Es más lenta que rand_str() pero garantiza que la cadena
 * resultante sea imprimible y válida para nombres de archivo
 * o identificadores.
 */
void rand_alphastr(uint8_t *str, int len);
