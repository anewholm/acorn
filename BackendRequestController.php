<?php namespace Acorn;

use Request;
use Exception;
use Config;
use Backend\Classes\Controller;
use Backend\Classes\BackendController;

// Helper class to allow access to the requested controller
class BackendRequestController extends BackendController {
    static $cache = array();

    // Refuse instantiation
    protected function __construct() {}

    public static function getControllerInfo(?string $url = NULL): ?array {
        if (!$url) $url = Request::url();
        $url = trim($url, '/');
        
        if (isset(self::$cache[$url]))   {
            $controllerInfo = self::$cache[$url];
        } else { 
            // Copied from BackendController
            $pathParts = explode('/', str_replace(Request::root() . '/', '', $url));
            // Drop off preceding backend URL part if needed
            if (!empty(Config::get('cms.backendUri', 'backend'))) array_shift($pathParts);
            $path = implode('/', $pathParts);

            // Call the protected method on the base class
            //   'controller' => $controllerObj, (existing only)
            //   'action'     => $action,
            //   'params'     => $controllerParams
            $brc            = new self();
            $controllerInfo = $brc->getRequestedController($path); // => findController()
            
            // Actually an array of controller info
            self::$cache[$url] = $controllerInfo;
        }

        return $controllerInfo;
    }

    protected function findController($controller, $action, $inPath)
    {
        // We only accept already instantiated controllers
        // that is, the one that is already accepting the request
        // For performance reasons
        // and we do not want to run the request twice
        // So this may return NULL
        if (!$this->requestedController)
            throw new Exception("No controller available during findController()");
        return $this->requestedController;
    }

    public static function getController(?string $url = NULL): ?Controller {
        $controllerInfo = self::getControllerInfo($url);
        return (isset($controllerInfo['controller']) ? $controllerInfo['controller'] : NULL);
    }

    public static function isUpdate(?string $url = NULL): bool {
        $controllerInfo = self::getControllerInfo($url);
        return (isset($controllerInfo['action']) && $controllerInfo['action'] == 'update');
    }
}
