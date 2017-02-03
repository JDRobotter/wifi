function _plug_normal(_pl) {if (_tm.indexOf(_pl) != -1 && (navigator.mimeTypes[_pl].enabledPlugin != null))return '1';return '0';}
function _plug_ie(_pl){pk_found = false;if (pk_found) return '1';return '0';}

var _jav = '0'; if(navigator.javaEnabled()) _jav='1';
var _agent = navigator.userAgent.toLowerCase();
var _moz = (navigator.appName.indexOf("Netscape") != -1);
var _ie = (_agent.indexOf("msie") != -1);
var _win = ((_agent.indexOf("win") != -1) || (_agent.indexOf("32bit") != -1));
var _cookie = (navigator.cookieEnabled)? '1' : '0';

if((typeof (navigator.cookieEnabled) == "undefined") && (_cookie == '0')) {document.cookie="_testcookie";_cookie=(document.cookie.indexOf("_testcookie")!=-1)? '1' : '0';}

var _dir='0',_fla='0',_pdf='0',_qt = '0',_rea = '0',_wma='0'; 
if (_win && _ie){
	_dir = _plug_ie("SWCtl.SWCtl.1");
	_fla = _plug_ie("ShockwaveFlash.ShockwaveFlash.1");
	if (_plug_ie("PDF.PdfCtrl.1") == '1' || _plug_ie('PDF.PdfCtrl.5') == '1' || _plug_ie('PDF.PdfCtrl.6') == '1') _pdf = '1';
	_qt = _plug_ie("Quicktime.Quicktime"); // Old : "QuickTimeCheckObject.QuickTimeCheck.1"
	_rea = _plug_ie("rmocx.RealPlayer G2 Control.1");
	_wma = _plug_ie("wmplayer.ocx"); // Old : "MediaPlayer.MediaPlayer.1"
} else {
	var _tm = '';
	for (var i=0; i < navigator.mimeTypes.length; i++)
		_tm += navigator.mimeTypes[i].type.toLowerCase();
	_dir = _plug_normal("application/x-director");
	_fla = _plug_normal("application/x-shockwave-flash");
	_pdf = _plug_normal("application/pdf");
	_qt  = _plug_normal("video/quicktime");
	_rea = _plug_normal("audio/x-pn-realaudio-plugin");
	_wma = _plug_normal("application/x-mplayer2");
}

var Nav = {
	Browser: {
		IE:     !!(window.attachEvent && !window.opera),
		Opera:  !!window.opera,
		Android: navigator.userAgent.indexOf('Android') > -1 && navigator.userAgent.indexOf('AppleWebKit/') > -1,
		Gecko:  navigator.userAgent.indexOf('Gecko') > -1 && navigator.userAgent.indexOf('KHTML') == -1,
		MobileSafari: !!navigator.userAgent.match(/Apple.*Mobile.*Safari/),
		WebKit: navigator.userAgent.indexOf('AppleWebKit/') > -1
	  }
};
function NavName(){
	var ieversion = 0;
		if (navigator.appVersion.indexOf('MSIE') != -1) {
			t = navigator.appVersion.split('MSIE');
			ieversion = parseFloat(t[1]);
		}
		
		if (Nav.Browser.IE) {
			if (ieversion == 7) {
				return "ie7";
			}
			else if (ieversion == 6) {
				return "ie6";
			} else {
				return "ie8";
			}
		} else if (Nav.Browser.Android){
			return "android";
		} else if (Nav.Browser.MobileSafari){
			return "iphone";
		} else if (Nav.Browser.WebKit) {
			return "safari";
		} else if (Nav.Browser.Opera){
			return "opera";
		} else if (Nav.Browser.Gecko){
			return "firefox";
		}
}
var _mac = '';
if (urlParams['mac']) _mac = urlParams['mac'];
var _nasid = '';
if (urlParams['nasid']) _nasid = urlParams['nasid'];
var OSName="Unknown OS";
if (navigator.appVersion.indexOf("Win")!=-1) OSName="Windows";
if (navigator.appVersion.indexOf("Mac")!=-1) OSName="MacOS";
if (navigator.appVersion.indexOf("X11")!=-1) OSName="UNIX";
if (navigator.appVersion.indexOf("Linux")!=-1) OSName="Linux";

var num_error = 0;
var _user_id;
var date=new Date;
var time = date.getTime();
_user_id = "user:"+_mac+","+time; // OU LIRE COOKIE

var _page ="";

if (urlParams['res'] == "notyet"){
	_page = "Accueil-"+NavName();
} else if (urlParams['res'] == "failed"){
	_page = "AuthentKO";
} else if (urlParams['res'] == "success"){
	_page = "AuthentOK";
}
document.getElementById("tracking").innerHTML = "<img src='i/track.php?"
                                                    + "DOM=WiFi"
                                                    + "&SITE=PCNB4"
                                                    + "&GRP=PortailCaptif"
                                                    + "&CHAN=Authent"
                                                    + "&PAGE="+_page
                                                    + "&RES="+urlParams['res']
                                                    + "&JAVA="+_jav
                                                    + "&USER_AGENT="+escape(_agent)
                                                    + "&MAC="+_mac
                                                    + "&USERID="+_user_id
                                                    + "&ERROR="+num_error
                                                    + "&NASID="+_nasid
                                                    + "&COOKIE="+_cookie
                                                    + "&DIR="+_dir
                                                    + "&FLA="+_fla
                                                    + "&PDF="+_pdf
                                                    + "&QT="+_qt
                                                    + "&REA="+_rea
                                                    + "&WMA="+_wma
                                                    + "&RES="+screen.width+'x'+screen.height
                                                    + "&COLOR_DEPTH="+screen.colorDepth
                                                    + "&NAVNAME="+NavName()
                                                    + "&OS_NAME="+OSName
                                                    + "&OS_VERSION="+escape(navigator.appVersion)+"'>";