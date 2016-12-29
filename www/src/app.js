
function AppController($http, $scope, $mdDialog) {
  var self = this;

  var refresh_timeout_ms = 2000;

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

  $scope.refresh = function() {
    $http.get('status.json').then(response => {

        $scope.status = response.data;

        setTimeout($scope.refresh, refresh_timeout_ms);
      },
      function errorCallback(response) {
        console.log(response);
        setTimeout($scope.refresh, refresh_timeout_ms);
      });

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

function HomePageController($scope) {

}

function APsPageController($scope) {

}

function ClientsPageController($scope) {

}

function InfosPageController($scope) {

}

var app = angular.module( 'starter-app', ['ngMaterial','ui.router'])
  .config(['$stateProvider','$urlRouterProvider', 
    function($stateProvider,$urlRouterProvider) {

      $urlRouterProvider.otherwise('/');

      $stateProvider
        .state('home', {
          url:'/',
          templateUrl:'templates/home.html',
          controller:'HomePageController'
        })
        .state('aps', {
          url:'/aps',
          templateUrl:'templates/aps.html',
          controller:'APsPageController'
        })
        .state('clients', {
          url:'/clients',
          templateUrl:'templates/clients.html',
          controller:'ClientsPageController'
        })
        .state('infos', {
          url:'/infos',
          templateUrl:'templates/infos.html',
          controller:'InfosPageController'
        })
    }])
  .controller('AppController', AppController)
  .controller('HomePageController', HomePageController)
  .controller('APsPageController', APsPageController)
  .controller('ClientsPageController', ClientsPageController)
  .controller('InfosPageController', InfosPageController);
