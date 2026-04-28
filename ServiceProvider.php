<?php namespace Acorn;

use DB;
use App;
use Lang;
use Event;
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
use Acorn\Scopes\GlobalChainScope;

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
            $controller->addJs('~/modules/acorn/assets/js/acorn.js');
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
        if (!class_exists('Winter\Translate\Behaviors\TranslatableModel')) {
            class_alias(\Winter\Storm\Extension\ExtensionBase::class, 'Winter\Translate\Behaviors\TranslatableModel');
        }

        parent::register();

        $this->registerConsoleCommand('acorn.set-config', SetConfig::class);
        $this->registerConsoleCommand('acorn.config-plugin', ConfigPlugin::class);
        $this->registerConsoleCommand('acorn.seed', Seed::class);
        $this->registerConsoleCommand('acorn.generate-seed', GenerateSeed::class);

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
