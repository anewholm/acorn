<?php
use Illuminate\Broadcasting\BroadcastController;
use Illuminate\Http\Request;
use Acorn\Controllers\DB;
use Acorn\Controllers\Names;
use Acorn\Controllers\Tasks;
use BeyondCode\LaravelWebSockets\Dashboard\Http\Controllers\ShowDashboard;

class AuthWrapper
{
    public function authenticate(Request $request){
        $request->setUserResolver(function($guard){
            return \BackendAuth::user();
        });
        $bc = new BroadcastController();
        return $bc->authenticate($request);
    }
}

Event::listen('system.route', function () {
    Event::fire('acorn.beforeRoute');

    if (env('ENABLE_ACORN_API')) {
        // -------------------------------- WebSockets infrastructure
        Route::get('/api/datachange', DB::class . '@datachange');
        // TODO: Route::get('/laravel-dashboard', ShowDashboard::class);

        Route::match(
            ['get', 'post'], '/broadcasting/auth',
            '\\'.AuthWrapper::class.'@authenticate'
        )->middleware('web');

        Route::get( '/api/comment', DB::class . '@comment');
        Route::post('/api/comment', DB::class . '@comment');

        // -------------------------------- Views
        Route::get( '/backend/acorn/names', Names::class . '@index');
        Route::get( '/backend/acorn/tasks', Tasks::class . '@index');

        Event::fire('acorn.route');
    }
}, PHP_INT_MIN);
