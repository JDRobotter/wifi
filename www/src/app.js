
function AppController($http, $scope, $mdDialog) {
  var self = this;

  var refresh_timeout_ms = 2000;
  var clients_timeout_s = 10*60;

  break_refresh_loop = false;

  $scope.server_version = ''
  $http.get('/version.json').then(response => {
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

	$scope.changeSSID = function(ev) {
	}
  $scope.showChangeSSIDDialog = function(ev) {
    $mdDialog.show({
      controller: ChangeSSIDDialogController,
      templateUrl: 'templates/change_ssid.html',
      parent: angular.element(document.body),
      targetEvent: ev,
      clickOutsideToClose:true,
      fullscreen: $scope.customFullscreen // Only for -xs, -sm breakpoints.
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
  getIconFromService = function(name,infos) {
    if(name == 'facebook-messenger') {
      return {"type":"md-icon","src":"assets/facebook-messenger.svg"}
    }
    else if(name == 'imap-gmail') {
      return {"type":"md-icon","src":"assets/gmail.svg"}
    }
    else if(name == 'facebook') {
      return {"type":"md-icon","src":"assets/facebook.svg"}
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
    else if(infos.type == 'browser') {
      return {"type":"i","src":"picture_in_picture"}
    }
    else {
      return {"type":"i","src":"help"}
    }
  }
 
  $scope.refresh = function() {

    // fetch status
    $http.get('/status.json').then(response => {

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
              angular.forEach(client["services"], function(sinfos,sname) {
                sinfos.icon = getIconFromService(sname,sinfos);
              });
              nclients++;
            }
          });
        });

        $scope.nclients = nclients;
      },
      function errorCallback(response) {
        console.log(response);
      });

    $http.get('/query.json?q=all&n=50').then(response => {
        console.log("up");
        $scope.requests = response.data;
      },
      function errorCallback(response) {
        console.log(response);
    });

    if(!break_refresh_loop) {
      setTimeout($scope.refresh, refresh_timeout_ms);
    }
  }
  $scope.refresh();
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

var app = angular.module( 'starter-app', ['ngMaterial','ui.router'])
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
    }])
  .config(function($mdThemingProvider) {
      $mdThemingProvider.theme('default')
          .primaryPalette('blue-grey')
          .accentPalette('orange');
    })
  .controller('AppController', AppController);
