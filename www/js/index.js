app.controller("indexController", function($http, $scope, $location) {
    $scope.status = {};
    
    var refresh_timeout = 2000;
    
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
