app.controller("indexController", function($http, $scope, $location) {
    $scope.status = {};
    
    var refresh_timeout = 2000;
    
    $scope.create = function() {
      console.log("CREATE");
      var data = {
        essid: $scope.create_essid,
        timeout: $scope.create_timeout,
        wpa: $scope.create_password,
      };
      
      var config = {
        headers : {
          'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8;'
        }
      }
      
      $http.post('/create.json', data, config)
      .success(function (data, status, headers, config) {
        console.log("success");
      })
      .error(function (data, status, header, config) {
        console.log("error");
      });
    }
    
    $scope.refresh = function () {
        $http.get('/status.json').then(response => {
            
            $scope.status = response.data;
            setTimeout($scope.refresh, refresh_timeout)
        }, function errorCallback(response) {
            console.log(response)
            setTimeout($scope.refresh, refresh_timeout)
        });
    }
    $scope.refresh();
    
    
});
