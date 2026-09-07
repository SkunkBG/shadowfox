#ifndef SHADOWFOX_PROC_H
#define SHADOWFOX_PROC_H

#include <stddef.h>

/* Запускает argv, собирает stdout и stderr в out и ждёт завершения.

   timeout_sec > 0 — по истечении процесс убивается: висящий xray на
   проверке конфига заблокировал бы демона навсегда.

   Возвращает код возврата процесса, 128+сигнал если убит по сигналу,
   либо -1 если запустить не удалось. */
int proc_run(char *const argv[], char *out, size_t out_size, int timeout_sec);

/* То же, но input подаётся программе на stdin и поток закрывается.
   Нужно, чтобы кормить `ipset restore` пачкой команд разом вместо
   запуска отдельного процесса на каждый адрес. */
int proc_run_input(char *const argv[], const char *input,
                   char *out, size_t out_size, int timeout_sec);

/* То же, что proc_run, но сообщает, поместился ли вывод. Обычный
   proc_run молча роняет то, что не влезло, и разбор получает обрезанный
   текст, ничего об этом не зная — а решение по нему принимается как по
   целому. Для всего, что разбирает вывод, нужен этот вариант. */
int proc_run_capture(char *const argv[], char *out, size_t out_size,
                     int timeout_sec, int *truncated);

#endif /* SHADOWFOX_PROC_H */
