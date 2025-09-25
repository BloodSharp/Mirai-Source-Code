/**
 * @file rand.c
 * @brief Implementación de generador de números pseudoaleatorios
 *
 * Este archivo implementa un generador de números pseudoaleatorios (PRNG)
 * basado en el algoritmo "xorshift" de George Marsaglia. Características:
 * - Período largo (2^96-1)
 * - Rápido y ligero
 * - Buena distribución estadística
 * - No criptográficamente seguro
 */

#define _GNU_SOURCE  // Habilita características GNU extendidas

#include <stdint.h>  // Para tipos enteros de ancho fijo
#include <unistd.h>  // Para getpid(), getppid()
#include <stdlib.h>  // Para funciones estándar
#include <time.h>    // Para time() y clock()

#include "includes.h"  // Definiciones comunes
#include "rand.h"      // Prototipos de funciones

/**
 * @brief Variables de estado del generador
 * 
 * El generador usa cuatro variables de 32 bits para mantener su estado interno.
 * Esto proporciona 128 bits de estado total, necesarios para el período largo.
 */
static uint32_t x, y, z, w;  // Estado del generador xorshift128

/**
 * @brief Inicializa el generador de números aleatorios
 * 
 * Inicializa el estado del PRNG usando múltiples fuentes de entropía:
 * - Tiempo actual en segundos
 * - PIDs del proceso actual y su padre
 * - Valor del reloj del sistema
 * 
 * La combinación de estas fuentes ayuda a asegurar que cada instancia
 * del bot tenga una secuencia aleatoria única.
 */
void rand_init(void)
{
    x = time(NULL);                // Tiempo Unix actual
    y = getpid() ^ getppid();     // XOR de PID actual y PID del padre
    z = clock();                   // Ticks de CPU desde el inicio
    w = z ^ y;                     // Mezcla adicional de fuentes
}

/**
 * @brief Genera el siguiente número pseudoaleatorio de 32 bits
 * 
 * @return uint32_t Número pseudoaleatorio de 32 bits
 * 
 * Implementa el algoritmo xorshift con período 2^96-1. El algoritmo:
 * 1. Realiza operaciones XOR con desplazamientos en una variable temporal
 * 2. Rota las variables de estado
 * 3. Actualiza w usando más operaciones XOR
 * 
 * Esta implementación proporciona una buena distribución estadística
 * y es muy rápida, requiriendo solo operaciones básicas de CPU.
 */
uint32_t rand_next(void)
{
    uint32_t t = x;               // Guarda el primer valor de estado
    t ^= t << 11;                // XOR con desplazamiento izquierdo
    t ^= t >> 8;                 // XOR con desplazamiento derecho
    x = y; y = z; z = w;         // Rota las variables de estado
    w ^= w >> 19;                // XOR con desplazamiento derecho en w
    w ^= t;                      // XOR final con el valor transformado
    return w;                    // Retorna el nuevo valor aleatorio
}

/**
 * @brief Genera un buffer de bytes aleatorios
 * 
 * @param str Puntero al buffer donde se escribirán los datos aleatorios
 * @param len Longitud del buffer a generar
 * 
 * Esta función llena un buffer con bytes aleatorios, optimizando la
 * generación escribiendo valores de 32 o 16 bits cuando es posible.
 * Los bytes generados pueden tener cualquier valor (0-255), por lo
 * que la cadena resultante puede no ser imprimible.
 * 
 * Optimizaciones:
 * - Escribe 4 bytes a la vez cuando es posible
 * - Usa escrituras de 2 bytes para restos >= 2
 * - Cae a escrituras byte a byte solo al final
 */
void rand_str(char *str, int len)
{
    while (len > 0)
    {
        if (len >= 4)  // Si quedan 4 o más bytes
        {
            *((uint32_t *)str) = rand_next();         // Escribe 4 bytes
            str += sizeof (uint32_t);                 // Avanza el puntero
            len -= sizeof (uint32_t);                 // Actualiza longitud
        }
        else if (len >= 2)  // Si quedan 2 o 3 bytes
        {
            *((uint16_t *)str) = rand_next() & 0xFFFF;  // Escribe 2 bytes
            str += sizeof (uint16_t);                    // Avanza el puntero
            len -= sizeof (uint16_t);                    // Actualiza longitud
        }
        else  // Si queda 1 byte
        {
            *str++ = rand_next() & 0xFF;               // Escribe 1 byte
            len--;                                      // Actualiza longitud
        }
    }
}

/**
 * @brief Genera una cadena aleatoria alfanumérica
 * 
 * @param str Puntero al buffer donde se escribirá la cadena
 * @param len Longitud de la cadena a generar
 * 
 * Esta función genera una cadena alfanumérica aleatoria usando un conjunto
 * limitado de caracteres (letras minúsculas y dígitos). Es más costosa
 * computacionalmente que rand_str() porque:
 * 1. Requiere mapeo a un conjunto limitado de caracteres
 * 2. Procesa cada byte individualmente
 * 3. Realiza más operaciones por byte
 */
void rand_alphastr(uint8_t *str, int len)
{
    // Conjunto de caracteres permitidos: letras minúsculas y dígitos
    const char alphaset[] = "abcdefghijklmnopqrstuvw012345678";

    while (len > 0)
    {
        if (len >= sizeof (uint32_t))  // Procesa 4 bytes a la vez
        {
            int i;
            uint32_t entropy = rand_next();  // Obtiene 32 bits de entropía

            // Procesa cada byte de los 32 bits
            for (i = 0; i < sizeof (uint32_t); i++)
            {
                uint8_t tmp = entropy & 0xff;  // Extrae byte menos significativo

                entropy = entropy >> 8;        // Desplaza para siguiente byte
                tmp = tmp >> 3;               // Reduce a 5 bits (32 posibilidades)

                *str++ = alphaset[tmp];       // Mapea a carácter permitido
            }
            len -= sizeof (uint32_t);
        }
        else  // Procesa bytes restantes uno a uno
        {
            *str++ = alphaset[rand_next() % (sizeof (alphaset))];
            len--;
        }
    }
}
