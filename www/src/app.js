
function AppController($http, $scope, $mdDialog, $sce, ansi2html) {
  var self = this;

  var refresh_timeout_ms = 2000;
  var clients_timeout_s = 10*60;

  break_refresh_loop = false;

  
  $scope.logs = [];
  $scope.server_version = ''
  $http.get('/api/version').then(response => {
    $scope.server_version = response.data.version;
  },
  function errorCallback(response) {
    console.log(response);
  });

  $scope.switches = {
    http: true,
    https: true,
    dns: false,
    smb: true,
  };

  $scope.showRequestDetailsDialog = function(ev, request) {
    console.log(ev);
    console.log(request);
    $mdDialog.show({
      controller: ShowRequestDetailsController,
      templateUrl: 'templates/show_request.html',
      parent: angular.element(document.body),
      targetEvent: ev,
      clickOutsideToClose: true,
      locals: {
        request : request
      }
    })
    .then(function(answer) {
      // XXX TBD
    }, function() {
      // XXX TBD
    });
  };

  $scope.set_secure = function(iface, secure) {
    $http.get('/api/secure?iface='+iface+'&secure='+secure).then(response => {
    },
    function errorCallback(response) {
      console.log(response);
    }); 
  }
  
	$scope.changeSSID = function(ev) {
	};

  $scope.showChangeSSIDDialog = function(ev) {
    $mdDialog.show({
      controller: ChangeSSIDDialogController,
      templateUrl: 'templates/change_ssid.html',
      parent: angular.element(document.body),
      targetEvent: ev,
      clickOutsideToClose:true,
    })
    .then(function(answer) {
			// XXX TBD
    }, function() {
			// XXX TBD
    });
  };

  $scope.getIconFromIWInfos = function(iwinfos) {
    var srssi = iwinfos.signal.split(' ')[0];
    var rssi = parseInt(srssi);
    console.log(rssi,iwinfos);
    if(rssi < -100) {
      return 'assets/signal_wifi_0_bar_24px.svg';
    }
    else if(rssi < -90) {
      return 'assets/signal_wifi_statusbar_1_bar_26x24px.svg';
    }
    else if(rssi < -80) {
      return 'assets/signal_wifi_statusbar_2_bar_26x24px.svg';
    }
    else if(rssi < -70) {
      return 'assets/signal_wifi_statusbar_3_bar_26x24px.svg';
    }
    return 'assets/signal_wifi_statusbar_4_bar_26x24px.svg';
  }

  $scope.getIconFromDevice = function(device) {
    if(device == undefined) {
      return 'star';
    }
    else {
      if(device.brand == "Apple") {
        if(device.model.startsWith("iPad")) {
          return "tablet_mac";
        }
        else {
          return "phone_iphone";
        }
      }
      else {
        return "phone_android";
      }
      return "phone"
    }
  }

  $scope.getColorFromRequest = function(r) {
    if(r.service_name == 'HTTP') {
      return '#4caf50';
    }else if(r.service_name == 'DNS') {
      return '#00bcd4';
    }
  }
  
  $scope.getIconFromRequest = function(r) {
    if(r.service_name == 'HTTP') {
      return 'http';
    }
    else if(r.service_name == 'DNS') {
      return 'dns';
    }
    else {
      return 'play_arrow';
    }
  }
  $scope.getIconFromService = function(name,infos) {
    if(name == 'facebook-messenger') {
      return {"type":"md-icon","src":"assets/facebook-messenger.svg"}
    }
    else if(name == 'imap-gmail') {
      return {"type":"md-icon","src":"assets/gmail.svg"}
    }
    else if(name == 'smb') {
      return {"type":"md-icon","src":"assets/smb.svg"}
    }
    else if(name == 'Mobile Safari' || name == 'Safari' || name == 'Mobile Safari UI/WKWebView') {
      return {"type":"md-icon","src":"assets/safari.svg"}
    }
    else if(name == 'Chrome' || name == 'Chrome Mobile' || name == 'Chromium' ) {
      return {"type":"md-icon","src":"assets/chrome.svg"}
    }
    else if(name == 'Firefox' ) {
      return {"type":"md-icon","src":"assets/firefox.svg"}
    }
    else if(name == 'IE' || name == 'IE Mobile') {
      return {"type":"md-icon","src":"assets/ie.svg"}
    }
    else if(name == 'facebook') {
      return {"type":"md-icon","src":"assets/facebook.svg"}
    }
    else if(name == 'bitdefender') {
      return {"type":"md-icon","src":"assets/Bitdefender.svg"}
    }
    else if(name == 'avast') {
      return {"type":"md-icon","src":"assets/avast.svg"}
    }
    else if(name == 'Apache-HttpClient') {
      return {"type":"md-icon","src":"assets/apache_http.svg"}
    }
    else if(name == 'gtalk') {
      return {"type":"img","src":"assets/hangout.png"}
    }
    else if(name == 'openweathermap') {
      return {"type":"img","src":"assets/openweathermap.png"}
    }
    else if(name == 'instagram') {
      return {"type":"md-icon","src":"assets/instagram.svg"}
    }
    else if(name == 'windows') {
      return {"type":"md-icon","src":"assets/windows.svg"}
    }
    else if(name == 'windows10') {
      return {"type":"md-icon","src":"assets/windows.svg"}
    }
    else if(name == 'skype') {
      return {"type":"md-icon","src":"assets/skype.svg"}
    }
    else if(name == 'waze') {
      return {"type":"md-icon","src":"assets/waze.svg"}
    }
    else if(name == 'airbnb') {
      return {"type":"md-icon","src":"assets/airbnb.svg"}
    }
    else if(name == 'dailymotion') {
      return {"type":"md-icon","src":"assets/dailymotion.svg"}
    }
    else if(name == 'dropbox') {
      return {"type":"md-icon","src":"assets/dropbox.svg"}
    }
    else if(name == 'whatsapp') {
      return {"type":"md-icon","src":"assets/whatsapp.svg"}
    }
    else if(name == 'spotify') {
      return {"type":"md-icon","src":"assets/spotify.svg"}
    }
    else if(name == 'voyages-sncf') {
      return {"type":"md-icon","src":"assets/sncf.svg"}
    }
    else if(name == 'deezer') {
      return {"type":"md-icon","src":"assets/deezer.svg"}
    }
    else if(name == 'teamviewer') {
      return {"type":"md-icon","src":"assets/teamviewer.svg"}
    }
    else if(name == 'theguardian') {
      return {"type":"md-icon","src":"assets/The_Guardian.svg"}
    }
    else if(name == 'lemonde') {
      return {"type":"md-icon","src":"assets/Le_Monde.svg"}
    }
    else if(name == 'leparisien') {
      return {"type":"md-icon","src":"assets/le_parisien.svg"}
    }
    else if(name == 'snapchat') {
      return {"type":"md-icon","src":"assets/snapchat.svg"}
    }
    else if(name == 'tinder') {
      return {"type":"md-icon","src":"assets/tinder.svg"}
    }
    else if(name == 'candycrush') {
      return {"type":"md-icon","src":"assets/candycrush.svg"}
    }
    else if(name == 'outlook') {
      return {"type":"md-icon","src":"assets/outlook.svg"}
    }
    else if(name == 'orange') {
      return {"type":"md-icon","src":"assets/orange.svg"}
    }
    else if(name == 'linkedin') {
      return {"type":"md-icon","src":"assets/linkedin.svg"}
    }
    else if(name == 'soundcloud') {
      return {"type":"md-icon","src":"assets/soundcloud.svg"}
    }
    else if(name == 'Python-urllib') {
      return {"type":"md-icon","src":"assets/Python.svg"}
    }
    else if(name == 'Android') {
      return {"type":"md-icon","src":"assets/android.svg"}
    }
    else if(name == 'CFNetwork') {
      return {"type":"md-icon","src":"assets/apple.svg"}
    }
    else if(infos.type == 'browser') {
      return {"type":"i","src":"picture_in_picture"}
    }
    else {
      return {"type":"i","src":"help"}
    }
  }
  
  $scope.colorize = function (text) {
    return $sce.trustAsHtml(ansi2html.toHtml(text));
  }
 
  $scope.refresh = function() {

    // fetch status
    $http.get('/api/status').then(response => {

        $scope.status = response.data;
   
        var nclients=0;
        // update services with corresponding icons
        angular.forEach($scope.status.aps, function(iface,k) {
          angular.forEach(iface["clients"], function(client,k) {

            // do not show old clients
            if(client.inactivity > clients_timeout_s) {
              delete iface["clients"][k];
            }
            else {
              nclients++;
            }
          });
        });

        $scope.nclients = nclients;
        if(!break_refresh_loop) {
          setTimeout($scope.refresh, refresh_timeout_ms);
        }
      },
      function errorCallback(response) {
        console.log(response);
        if(!break_refresh_loop) {
          setTimeout($scope.refresh, refresh_timeout_ms);
        }
      });
  }
  
  $scope.refresh_query = function() {
    $http.get('/api/query?q=all&n=50').then(response => {
      console.log("up");
      $scope.requests = response.data;
      if(!break_refresh_loop) {
        setTimeout($scope.refresh_query, refresh_timeout_ms);
      }
    },
    function errorCallback(response) {
      console.log(response);
      if(!break_refresh_loop) {
        setTimeout($scope.refresh_query, refresh_timeout_ms);
      }
    });
  }
  
  
  $scope.refresh_logs = function(full) {
    
    var uri = '/api/logs';
    if(full) {
      uri += '?full=true';
    }
    // fetch status
    $http.get(uri).then(response => {
      if(full) {
        $scope.logs = [];
      }
      $scope.logs.push.apply($scope.logs, response.data)
      if(!break_refresh_loop) {
        setTimeout($scope.refresh_logs, refresh_timeout_ms);
      }
    },
    function errorCallback(response) {
      console.log(response);
      if(!break_refresh_loop) {
        setTimeout(function() {$scope.refresh_logs(true)}, refresh_timeout_ms);
      }
    });
  }
  
  $scope.refresh();
  $scope.refresh_query();
  $scope.refresh_logs(true);

}

function ShowRequestDetailsController($scope, $mdDialog, request) {
  $scope.request = request;

  $scope.hide = function() {
    $mdDialog.hide();
  };

  $scope.cancel = function() {
    $mdDialog.cancel();
  };
}

function ChangeSSIDDialogController($scope, $mdDialog) {
  $scope.hide = function() {
    $mdDialog.hide();
  };

  $scope.cancel = function() {
    $mdDialog.cancel();
  };

  $scope.answer = function(answer) {
    $mdDialog.hide(answer);
  };
}

var app = angular.module( 'starter-app', ['ngMaterial','ui.router', 'ansiToHtml'])
  .config(['$stateProvider','$urlRouterProvider', 
    function($stateProvider,$urlRouterProvider) {

      $urlRouterProvider.otherwise('/');

      $stateProvider
        .state('home', {
          url:'/',
          templateUrl:'templates/home.html',
        })
        .state('aps', {
          url:'/aps',
          templateUrl:'templates/aps.html',
        })
        .state('clients', {
          url:'/clients',
          templateUrl:'templates/clients.html',
        })
        .state('requests', {
          url:'/requests',
          templateUrl:'templates/requests.html',
        })
        .state('infos', {
          url:'/infos',
          templateUrl:'templates/infos.html',
        })
        .state('logs', {
          url:'/logs',
          templateUrl:'templates/logs.html',
        })
    }])
  .config(function($mdThemingProvider) {
      $mdThemingProvider.theme('default')
          .primaryPalette('blue-grey')
          .accentPalette('orange');
    })
  .controller('AppController', AppController);
