app.controller("indexController", function($http, $scope, $location) {
    $scope.status = {};
    $scope.total_clients = 0;
    $scope.showdns = false;
    var refresh_timeout = 2000;
    
    $scope.create = function() {
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
    
    $scope.getid = function(mac) {
      return mac.replace(/:/g , "_");
    }
    
    $scope.toggle_dns = function(mac) {
      var id = $scope.getid(mac);
      $("#dns_"+id).toggle();
    }
    
    $scope.toggle_client = function(mac) {
      var id = $scope.getid(mac);
      $("#client_"+id).toggle();
    }
    
    $scope.iface_toggle = function(mac) {
      var id = $scope.getid(mac);
      $("#iface_"+id).toggle();
    }
    
    $scope.delete = function(essid) {
      var data = {
        essid: essid
      };
      
      var config = {
        headers : {
          'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8;'
        }
      }
      
      $http.post('/delete.json', data, config)
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
            $scope.total_clients = 0;
            for( i in $scope.status) {
              $scope.total_clients += $scope.status[i].count
            }
            setTimeout($scope.refresh, refresh_timeout)
        }, function errorCallback(response) {
            console.log(response)
            setTimeout($scope.refresh, refresh_timeout)
        });
    }
    $scope.refresh();
    
    
});
