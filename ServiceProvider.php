<?php namespace Acorn;

use DB;
use Arr;
use App;
use Lang;
use Event;
use Exception;
use BackendAuth;
use BackendMenu;
use Url;
use Backend\Classes\Controller as BackendController;
use Backend\Models\User;
use Backend\Models\UserRole;
use System\Classes\CombineAssets;
use Backend\Classes\WidgetManager;
use Acorn\ReportWidgets\DocumentStore;
use Acorn\ReportWidgets\Olap;
use Acorn\ReportWidgets\GlobalScopesPreview;
use System\Classes\MarkupManager;
use System\Classes\SettingsManager;
use Backend\Classes\FormTabs;
use Acorn\FormWidgets\QrCode;
use SimpleSoftwareIO\QrCode\Facades\QrCode as SimpleSoftwareQrCode;
use Backend\Widgets\Lists as BackendLists;
use Backend\Widgets\Filter;
use Backend\Classes\FilterScope;

use Winter\Storm\Support\ModuleServiceProvider;
use BeyondCode\LaravelWebSockets\Console\StartWebSocketServer;
use \System\Controllers\Updates;
use Acorn\Models\InterfaceSetting;
use Acorn\Console\SetConfig;
use Acorn\Console\ConfigPlugin;
use Acorn\Console\Seed;
use Acorn\Console\GenerateSeed;
use Acorn\Console\PermissionGrant;
use Acorn\Console\PermissionRevoke;
use Acorn\Console\CreateSystem\CommentShow;
use Acorn\Console\CreateSystem\CommentSet;
use Acorn\Console\CreateSystem\CommentExclude;
use Acorn\Scopes\GlobalChainScope;

/**
 * data_get() that can tell a MISSING key from a NULL value.
 *
 * Laravel's cannot, and on an Eloquent model that is not a nuance -- it is
 * wrong. data_get() tests presence with Arr::exists()/isset(), Arr::exists()
 * on an ArrayAccess calls offsetExists(), and Eloquent's offsetExists() is
 * `! is_null($this->getAttribute($offset))` (Model.php:2246). So a column that
 * is present and NULL reports as absent, indistinguishable from a typo.
 *
 * The cost of that conflation is not the wrong answer, it is the DEFENCE
 * against it: a mapping author marks the path optional to stop a legitimate
 * NULL aborting the run, and the same mark then also swallows a misspelt path,
 * which resolves to NULL and silently sends an empty field.
 *
 * So the three outcomes Laravel collapses into one are kept apart, and each
 * has its own reaction. Whatever a handler returns is returned from here.
 *
 *   | outcome                        | reaction     | default              |
 *   |--------------------------------|--------------|----------------------|
 *   | key does not exist             | $keyNotFound | throws               |
 *   |                                |              | DataGetKeyNotFound   |
 *   | a link resolves NULL part-way  | $segmentNull | throws               |
 *   |   (`salesperson_code.code`)    |              | DataGetSegmentNull   |
 *   | the FINAL value is NULL        | $default     | NULL                 |
 *
 *   $keyNotFound(string $segment, array|string $path, mixed $subject): mixed
 *   $segmentNull(string $segment, array|string $path, mixed $subject): mixed
 *
 * Both handlers default to THROWING, which is the strict reading: say what you
 * meant. A caller that wants Laravel's old silence passes
 * `fn() => NULL` for either. That is the call FieldMappings will have to make
 * per mapping -- a `?`-marked path wants NULL, an unmarked one wants the throw.
 *
 * NAMESPACED. This file is `namespace Acorn`, so this is
 * \Acorn\acorn_data_get() and callers elsewhere must qualify it. The guard
 * below says so too -- function_exists() with a bare name only ever tests the
 * GLOBAL table, so it would never have matched this definition.
 */
if (! function_exists('Acorn\acorn_data_get')) {
    class DataGetKeyNotFound extends Exception {}
    class DataGetSegmentNull extends DataGetKeyNotFound {}

    // The default reaction: an unknown key is an author error, so it is loud.
    // Takes the full $keyNotFound signature rather than just the segment --
    // PHP would tolerate the extra arguments silently, but the path and the
    // class it failed ON are the two things that make the message diagnosable.
    // $exception is ::class, NOT the bare string 'DataGetKeyNotFound'. PHP
    // resolves a DYNAMIC class name against the GLOBAL namespace, never the
    // current one, so `new $exception` on a bare string dies with
    // Class "DataGetKeyNotFound" not found -- and only at the moment a key
    // first goes missing, which is the worst time to discover it.
    function acorn_data_get_throw($segment, $path, $subject,
                                  string $exception = DataGetKeyNotFound::class,
                                  string $problem   = 'not found') {
        $pathString = (is_array($path) ? implode('.', $path) : $path);
        $on         = (is_object($subject) ? get_class($subject) : gettype($subject));
        throw new $exception("'$segment' of '$pathString' $problem on $on");
    }

    // NULLable, not a string default: PHP refuses a string default on a
    // callable-typed parameter outright ("Cannot use string as default value
    // for parameter of type callable"), and it is a COMPILE-time rule, so the
    // whole module fails to load rather than failing on use. The first-class
    // callable below also resolves in THIS namespace -- a bare
    // 'acorn_data_get_throw' string would be looked up globally and never
    // found, since the function is Acorn\acorn_data_get_throw.
    function acorn_data_get($target, $key, $default = NULL, ?callable $keyNotFound = NULL, ?callable $segmentNull = NULL)
    {
        $keyNotFound ??= acorn_data_get_throw(...);
        // A CLOSURE, not the bare first-class callable: the default has to
        // carry the other exception class and the other wording, and
        // "not found" would be actively wrong here -- the segment WAS found,
        // it holds NULL.
        $segmentNull ??= fn($segment, $path, $subject) => acorn_data_get_throw(
            $segment, $path, $subject, DataGetSegmentNull::class, 'resolved to NULL part-way along');

        if (is_null($key)) {
            return $target;
        }

        $path = $key;
        $key  = is_array($key) ? $key : explode('.', $key);

        foreach ($key as $i => $segment) {
            unset($key[$i]);

            if (is_null($segment)) {
                return $target;
            }

            if ($segment === '*') {
                // Fully qualified: in this namespace a bare Collection would
                // be Acorn\Collection and miss a plain Illuminate one.
                if ($target instanceof \Illuminate\Support\Collection) {
                    $target = $target->all();
                } elseif (! is_iterable($target)) {
                    return $keyNotFound($segment, $path, $target);
                }

                $result = [];

                foreach ($target as $item) {
                    // ALL THREE passed on. With $keyNotFound in the third slot
                    // it landed in $default, so a missing key under a wildcard
                    // threw the built-in instead of calling the caller's
                    // handler, and the caller's own $default was discarded.
                    $result[] = acorn_data_get($item, $key, $default, $keyNotFound, $segmentNull);
                }

                return in_array('*', $key) ? Arr::collapse($result) : $result;
            }

            // $subject, not $target: the destructure below overwrites $target,
            // and the object the lookup FAILED ON is the useful half of any
            // message $keyNotFound wants to build.
            $subject          = $target;
            [$found, $target] = acorn_data_get_segment($target, $segment);

            if (! $found) {
                return $keyNotFound($segment, $path, $subject);
            }

            // A NULL part-way along is its OWN outcome, distinct from both a
            // bad path and a NULL final value. `salesperson_code.code` on an
            // order with no salesperson is an empty chain, not a typo: the
            // relation is declared, it simply resolves to no row. So the walk
            // stops here rather than reporting the tail as missing, and
            // $segmentNull decides what that means to the caller.
            //
            // $subject is the object the chain broke ON; $segment is the link
            // that came back NULL; $key still holds the unwalked remainder.
            if (is_null($target) && $key) {
                return $segmentNull($segment, $path, $subject);
            }
        }

        // Default only takes effect if the target key is found
        // and the value is null
        if (is_null($target)) $target = $default;

        return $target;
    }

    function acorn_data_get_segment($target, $segment): array
    {
        $notFound = [FALSE, NULL];

        // ---- Eloquent/Winter model: the case Laravel gets wrong.
        if ($target instanceof \Illuminate\Database\Eloquent\Model) {
            // A loaded column, NULL included. getAttribute() rather than the
            // raw array so casts and accessors still apply.
            if (array_key_exists($segment, $target->getAttributes()))
                return [TRUE, $target->getAttribute($segment)];

            // An already-loaded relation, including one that loaded as NULL.
            if ($target->relationLoaded($segment))
                return [TRUE, $target->getRelation($segment)];

            // A DECLARED relation, loaded here. Winter declares relations in
            // $belongsTo/$hasMany/... arrays rather than as methods, so
            // hasRelation() is the only reliable test -- isRelation() reads
            // methods and answers FALSE for every relation in this codebase.
            if (method_exists($target, 'hasRelation') && $target->hasRelation($segment))
                return [TRUE, $target->{$segment}];

            // A computed attribute. Present even when it returns NULL, which
            // is exactly the case isset() would have hidden.
            if ($target->hasGetMutator($segment)
             || (method_exists($target, 'hasAttributeMutator') && $target->hasAttributeMutator($segment)))
                return [TRUE, $target->getAttribute($segment)];

            return $notFound;
        }

        // ---- Arrays and other ArrayAccess. Arr::exists() uses
        // array_key_exists() for a real array, which is already NULL-correct;
        // only Eloquent's own offsetExists() was the liar.
        if (Arr::accessible($target)) {
            if (Arr::exists($target, $segment))
                return [TRUE, $target[$segment]];

            // An out-of-range NUMERIC index on a container that EXISTS is the
            // chain running out, not a bad path -- `edges.0.node.id` where
            // Shopify answered `edges: []`, or `...__product.0.sku` on one of
            // the 61 variant-less products. Reported as present-and-NULL so
            // the walk above turns it into a segment-NULL (mid-path) or plain
            // NULL (last segment), both of which `?` covers. A NAMED key that
            // is absent still falls through to notFound and stays an error.
            if (is_numeric($segment))
                return [TRUE, NULL];
        }

        // ---- Plain object. property_exists(), not isset(), so a declared
        // property holding NULL counts as present.
        if (is_object($target) && property_exists($target, $segment))
            return [TRUE, $target->{$segment}];

        // Last resort for a magic __get with no backing property.
        if (is_object($target) && isset($target->{$segment}))
            return [TRUE, $target->{$segment}];

        return $notFound;
    }
}

class ServiceProvider extends ModuleServiceProvider
{
    public function boot()
    {
        // Register localization
        Lang::addNamespace('acorn', realpath('modules/acorn/lang'));

        // -------------------------------------- Global CSS
        if (self::isDebugAny()) {
            Event::listen('backend.page.beforeDisplay', function ($controller, $action, $params) {
                $controller->addCss('~/modules/acorn/assets/css/debug.css');
                $controller->addJs( '~/modules/acorn/assets/js/debug.js');
            });
        }
        Event::listen('backend.page.beforeDisplay', function ($controller, $action, $params) {
            $controller->addCss('~/modules/acorn/assets/css/module.css');
            $controller->addJs('~/modules/acorn/assets/js/acornassociated.js');
            $controller->addJs('~/modules/acorn/assets/js/html5-qrcode.js');
            $controller->addJs('~/modules/acorn/assets/js/findbyqrcode.js');
            $controller->addJs('~/modules/acorn/assets/js/forms.js');
            $controller->addJs('~/modules/acorn/assets/js/tabbing.js');
            $controller->addJs('~/modules/acorn/assets/js/lang/lang.'.App::getLocale().'.js');//Translate JS [en][ar][ku]

            if (InterfaceSetting::get('enable_websockets')) $controller->addJs('~/modules/acorn/assets/js/acorn.websocket.js', array('type' => 'module'));
        });

        Event::listen('backend.form.extendFields', function ($widget) {
            // Ensure the Acorn module's partials directory is registered before any
            // partial-type fields are created, so Partial widgets can resolve paths
            // during their init() in WinterCMS dev-develop (which resolves eagerly).
            $widget->addViewPath('~/modules/acorn/partials');

            if (property_exists($widget->config, 'tertiaryTabs')) {
                $tabConfig      = &$widget->config->tertiaryTabs;

                // Add the fields to the outside and allFields section
                $count          = count($widget->getFields());
                $widget->addFields($tabConfig['fields']);
                $allFields      = $widget->getFields();
                $tertiaryFields = array_splice($allFields, $count);

                // Create a new Tertiary area FormTab for reference
                // Use of a form-with-sidebar layout is necessary to show this area
                // using formTertiaryTabs()
                $allTabs = $widget->getTabs();
                $allTabs->tertiary = new FormTabs('tertiary', $tabConfig);
                foreach ($tertiaryFields as $name => &$field) {
                    $allTabs->tertiary->addField($name, $field);
                    // Remove the fields from the outside area
                    $allTabs->outside->removeField($name);
                }
            }
        });

        // --------------------------------------------- acorn_infrastructure
        Event::listen('backend.menu.extendItems', function (&$navigationManager) {
            // TODO: Maybe we can get pluginFlags from PluginManager
            $mainMenuItems = $navigationManager->listMainMenuItems();
            $pluginFlags   = DB::select('select * from public.system_plugin_versions');
            foreach ($pluginFlags as $plugin) {
                if (property_exists($plugin, 'acorn_infrastructure') && $plugin->acorn_infrastructure) {
                    foreach ($mainMenuItems as $mainMenu) {
                        if ($plugin->code == $mainMenu->owner)
                            $navigationManager->removeMainMenuItem($plugin->code, $mainMenu->code);
                    }
                }
            }
        });

        Event::listen('backend.filter.extendQuery', function (Filter $filterWidget, $query, FilterScope $scope) {
            // 1to1 filter search term support
            // nameFrom: indicates the name of the item in the list
            // AND the column to search. That does not work with 1to1
            // So we allow an injection of a SQL statement during term search
            // For example:
            //   label: acorn.university::lang.models.course.label_plural
            //   conditions: 'exists(select * from acorn_user_user_group_version ugv inner join acorn_university_hierarchies hi on hi.user_group_version_id = ugv.user_group_version_id where hi.entity_id in(:filtered) and ugv.user_id = acorn_university_students.user_id)'
            //   modelClass: Acorn\University\Models\Entity
            //   searchNameSelect: select ugs.name from acorn_user_user_groups ugs where ugs.id = acorn_university_entities.user_group_id
            if (isset($scope->config['searchNameSelect'])) {
                $searchNameSelect = $scope->config['searchNameSelect'];
                $scope->nameFrom  = "($searchNameSelect)";
            }
        });

        Updates::extendListColumns(function ($widget, $model) {
            // We need to be careful when using the database
            // during migrations, tables may not exist
            $widget->getController()->addViewPath('modules/acorn/partials');
            $widget->addColumns([
                'acorn_infrastructure' => [
                    'label'   => 'acorn::lang.settings.infrastructure',
                    'type'    => 'partial',
                    'path'    => 'is_infrastructure',
                ],
                'acorn_seeding' => [
                    'label'   => 'acorn::lang.settings.seeding_functions',
                    'type'    => 'partial',
                    'path'    => 'seeding_functions',
                ],
            ]);
        });

        BackendAuth::registerCallback(function ($manager) {
            $manager->registerPermissions('Acorn', [
                'acorn.advanced' => [
                    'label' => 'acorn::lang.permissions.view_advanced_fields',
                    'tab'   => 'acorn::lang.permissions.tab',
                ],
                'acorn.manage_interface' => [
                    'label' => 'acorn::lang.settings.interface.menu_label',
                    'tab'   => 'acorn::lang.permissions.tab',
                ],
                'acorn.php_info' => [
                    'label' => 'acorn::lang.settings.phpinfo.menu_label',
                    'tab'   => 'acorn::lang.permissions.tab',
                ],
                'acorn.view_names' => [
                    'label' => 'acorn::lang.models.name.label_plural',
                    'tab'   => 'acorn::lang.permissions.tab',
                ],
                'acorn.view_qrcode' => [
                    'label' => 'acorn::lang.permissions.view_qrcode',
                    'tab'   => 'acorn::lang.permissions.tab',
                ],
                'acorn.scan_qrcode' => [
                    'label' => 'acorn::lang.permissions.scan_qrcode',
                    'tab'   => 'acorn::lang.permissions.tab',
                ],
            ]);
        });

        BackendMenu::registerCallback(function ($manager) {
            $user = BackendAuth::user();
            if ($user && $user->is_superuser) {
                $requestPath = request()->path();
                $manager->registerQuickActions('Acorn', [
                    'counts' => [
                        'label'      => 'acorn::lang.models.general.counts',
                        'icon'       => 'icon-dice',
                        'url'        => Url::to("$requestPath?count=1"),
                        'order'      => 100,
                    ],
                    'orders' => [
                        'label'      => 'acorn::lang.models.general.orders',
                        'icon'       => 'icon-sort',
                        'url'        => Url::to("$requestPath?order=1"),
                        'order'      => 110,
                    ],
                    'debug' => [
                        'label'      => 'acorn::lang.models.general.debug',
                        'icon'       => 'icon-question',
                        'url'        => Url::to("$requestPath?debug=1"),
                        'order'      => 120,
                    ],
                ]);
            }
        });

        Event::listen('backend.partials.menuTop.extend', function(BackendController $controller, string $menuLocation, string $iconLocation) {
            $globalScopes = GlobalChainScope::allUserSettings(TRUE);
            foreach ($globalScopes as $name => $details) {
                // Theme from Model
                $class       = $details['modelClass'];
                $modelId     = $details['setting'];
                if ($model = $class::withoutGlobalScopes()->find($modelId)) {
                    $cssClass    = str_replace('_', '--', preg_replace('/_id$/', '', $details['userField']));
                    print("<div class='global-scope $cssClass'>$model->name</div>");
                }
            }
        });

        // VERSION: Winter 1.2.6: send also parameter ('acorn');
        // But does not seem to cause a problem if ommitted
        parent::boot();

        $this->registerBackendReportWidgets();
    }

    protected function registerBackendReportWidgets()
    {
        WidgetManager::instance()->registerReportWidgets(function ($manager) {
            $manager->registerReportWidget(DocumentStore::class, [
                'label'   => 'acorn::lang.dashboard.documentstore.widget_title_default',
                'context' => 'dashboard'
            ]);
            $manager->registerReportWidget(Olap::class, [
                'label'   => 'acorn::lang.dashboard.olap.widget_title_default',
                'context' => 'dashboard'
            ]);
            $manager->registerReportWidget(GlobalScopesPreview::class, [
                'label'   => 'acorn::lang.dashboard.globalscopespreview.widget_title_default',
                'context' => 'dashboard'
            ]);
        });
    }

    protected function missingServices(): array
    {
        // -------------------------------------- Daemons manager
        // We do not want our artisan commands below to also run this!
        // continuous loop would it be
        // TODO: Alert administrator to any missing commands
        // TODO: Allow plugins to register there own persistent commands
        // using an interface and a call in their Plugin.php
        // maybe inheriting from AA Command that can run itself
        if (!$this->app->runningInConsole() && self::isDebug()) {
            $commands = array(
                'messaging:run'    => '',
                'websockets:serve' => '--port 6001',
                //'calendar:run' => FALSE,
            );

            // Check for running commands
            $running = array();
            $ps      = exec('ps ax | grep -v grep | grep artisan', $running);
            foreach ($running as $line) {
                $pdetails = preg_split('/\s+/', trim($line));
                if (isset($pdetails[6])) {
                    //$id      = $pdetails[0];
                    //$artisan = $pdetails[5];
                    $command = $pdetails[6];
                    $options = implode(' ', array_slice($pdetails, 7));
                    if (isset($commands[$command])) unset($commands[$command]);
                }
            }
        }

        return $commands;
    }

    public function register()
    {
        // When the Winter Translate plugin is absent, alias its behavior base class so that
        // Acorn\Behaviors\TranslatableModel (which extends it) can still be autoloaded.
        if (!class_exists('Winter\Translate\Behaviors\TranslatableModel', false)) {
            class_alias(\Winter\Storm\Extension\ExtensionBase::class, 'Winter\Translate\Behaviors\TranslatableModel');
        }

        parent::register();

        $this->registerConsoleCommand('acorn.set-config', SetConfig::class);
        $this->registerConsoleCommand('acorn.config-plugin', ConfigPlugin::class);
        $this->registerConsoleCommand('acorn.seed', Seed::class);
        $this->registerConsoleCommand('acorn.generate-seed', GenerateSeed::class);
        $this->registerConsoleCommand('acorn.permission-grant', PermissionGrant::class);
        $this->registerConsoleCommand('acorn.permission-revoke', PermissionRevoke::class);
        $this->registerConsoleCommand('acorn.cs.comment-show', CommentShow::class);
        $this->registerConsoleCommand('acorn.cs.comment-set', CommentSet::class);
        $this->registerConsoleCommand('acorn.cs.exclude', CommentExclude::class);

        // Settings placeholders
        SettingsManager::instance()->registerCallback(function ($manager) {
            $manager->registerSettingItems('Acorn.Module', [
                'interface' => [
                    'label'       => 'acorn::lang.settings.interface.menu_label',
                    'description' => 'acorn::lang.settings.interface.menu_description',
                    'category'    => 'Acorn',
                    'icon'        => 'icon-paint-brush',
                    'class'       => 'Acorn\Models\InterfaceSetting',
                    'permissions' => ['acorn.manage_interface'],
                    'order'       => 500,
                    'keywords'    => 'interface'
                ],
                'phpinfo' => [
                    'label'       => 'acorn::lang.settings.phpinfo.menu_label',
                    'description' => 'acorn::lang.settings.phpinfo.menu_description',
                    'category'    => 'Acorn',
                    'icon'        => 'icon-chart-simple',
                    'class'       => 'Acorn\Models\PhpInfo',
                    'permissions' => ['acorn.php_info'],
                    'order'       => 500,
                    'keywords'    => 'reporting'
                ],
                'names' => [
                    'label'       => 'acorn::lang.models.name.label_plural',
                    'description' => 'acorn::lang.models.name.settings_description',
                    'category'    => 'Acorn',
                    'url'         => '/backend/acorn/names',
                    'icon'        => 'icon-search',
                    'permissions' => ['acorn.view_names'],
                    'order'       => 500,
                    'keywords'    => 'search names content'
                ],
                'tasks' => [
                    'label'       => 'acorn::lang.models.task.label_plural',
                    'description' => 'acorn::lang.models.task.settings_description',
                    'category'    => 'Acorn',
                    'url'         => '/backend/acorn/tasks',
                    'icon'        => 'icon-screwdriver',
                    'permissions' => ['acorn.view_tasks'],
                    'order'       => 500,
                    'keywords'    => 'tasks'
                ],
            ]);
        });

        // Register FormWidgets
        WidgetManager::instance()->registerFormWidgets(function($manager) {
            $manager->registerFormWidget('Acorn\FormWidgets\QrScan', [
                'label' => 'QR Scan Field',
                'code'  => 'qrscan'
            ]);
            $manager->registerFormWidget('Acorn\FormWidgets\QrCode', [
                'label' => 'QR Generate Field',
                'code'  => 'qrcode'
            ]);
        });
    }

    // ---------------------------------------- Status helpers
    static public function isDebugAny(): bool
    {
        $isDebugAny = FALSE;
        if (env('APP_DEBUG')) {
            foreach (get() as $name => $value) {
                if (substr($name, 0, 5) == 'debug') $isDebugAny = TRUE;
            }
        }
        return $isDebugAny;
    }

    static public function isDebug(string $type = ''): bool
    {
        return (env('APP_DEBUG') && (get("debug-$type") || get('debug-all')));
    }

    static protected function isAJAX(): bool
    {
        return isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] == 'XMLHttpRequest';
    }
}
