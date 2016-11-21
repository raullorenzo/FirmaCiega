
blind.config(function ($stateProvider, $urlRouterProvider, $locationProvider) {

    $urlRouterProvider.otherwise("/");

    $stateProvider
        .state('/', {
            url: "/"
            , templateUrl: "index.html"
        }).state('/pseudonimo', {
            url: "/pseudonimo",
            templateUrl: "views/pseudonimo.html"
        });
});
