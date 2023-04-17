# ports_scan
## Формулировка
Написать сканер TCP- и UDP-портов удалённого компьютера. <br/>
Вход: адрес хоста и диапазон портов <br/>
Выход: итоговая оценка складывается как сумма: <br/>
[1-2 балла] список открытых TCP-портов, <br/>
[1-4 балла] список открытых UDP-портов, <br/>
[1-3 балла] многопоточность, <br/>
[1-6 балла] распознать прикладной протокол по сигнатуре (NTP/DNS/SMTP/POP3/IMAP/HTTP). <br/>

### Формат ввода-вывода
Параметры: <br/>
-t - сканировать tcp <br/>
-u - сканировать udp <br/>
-p N1 N2, --ports N1 N2 - диапазон портов <br/>

### Вывод: 
В одной строке информация об одном открытом порте (через пробел): <br/>
TCP 80 HTTP <br/> 
UDP 128 <br/>
UDP 123 SNTP <br/>

Если протокол не распознали, то пишем только TCP/UDP и номер порта. <br/>
Если нужно больше прав при запуске, то стоит вежливо об этом сказать, а не громко падать. <br/>