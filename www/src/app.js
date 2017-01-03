
function AppController($http, $scope, $mdDialog) {
  var self = this;

  var refresh_timeout_ms = 2000;

  break_refresh_loop = false;

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
          return "tablet_android";
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
        angular.forEach($scope.status, function(iface,k) {
          angular.forEach(iface["clients"], function(client,k) {
            angular.forEach(client["services"], function(sinfos,sname) {
              sinfos.icon = getIconFromService(sname,sinfos);
            });
            nclients++;
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
  .controller('AppController', AppController);
