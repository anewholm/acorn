<?php namespace Acorn\Traits;

use Acorn\Behaviors\RelationController;
use Winter\Storm\Database\Traits\Nullable;
use Winter\Storm\Html\Helper as HtmlHelper;
use Winter\Storm\Database\Relations\BelongsTo;
use Illuminate\Support\Facades\Session;
use Acorn\Models\InterfaceSetting;
use \GuzzleHttp\Psr7\Uri;
use \Exception;
use BackendAuth;
use Str;
use DB;
// For debug output
use Yaml;
use File;
use Winter\Storm\Database\Model;
use Acorn\User\Models\User;

Trait MorphConfig
{
    use PathsHelper;

    protected function appendClass(array &$fieldConfig, string $newClass): void
    {
        $cssClass   = (isset($fieldConfig['cssClass']) ? $fieldConfig['cssClass'] : '');
        $cssClasses = explode(' ', $cssClass);
        array_push($cssClasses, $newClass);
        $fieldConfig['cssClass'] = implode(' ', $cssClasses);
    }

    public function makeConfig($configFile = [], $requiredConfig = [])
    {
        $debugOutput       = FALSE;
        $config            = parent::makeConfig($configFile, $requiredConfig);
        // This can be called from on Form|ListControllers and main Controllers
        // RelationManager aware
        // TODO: Rationalise the model, controller model ideas
        $isRelationManager = ($this instanceof RelationController);
        $modelClass        = ($isRelationManager && $this->relationModel
            ? get_class($this->relationModel) 
            : $this->getConfig('modelClass')
        );
        $controllerModel   = 
            (isset($this->relationModel) ? $this->relationModel :
            (isset($this->model) ? $this->model :
            (isset($this->controller->widget->form->model) ? $this->controller->widget->form->model : 
            (isset($this->controller->widget->list->model) ? $this->controller->widget->list->model : 
            NULL
        ))));
        $controllerModelClass = ($controllerModel ? get_class($controllerModel) : NULL);
        // Popup situations, with parent model context
        $parentModel       = post(RelationController::PARAM_PARENT_MODEL);
        $parentModelId     = post(RelationController::PARAM_PARENT_MODEL_ID);
        $user              = BackendAuth::user();
        $context           = (property_exists($this, 'context') ? $this->context : NULL);
        $isPopup           = (bool) $parentModel;

        if (is_string($configFile) && $configFile) {
            $configFileParts = explode('/', $configFile);
            $configFileName  = last($configFileParts);
            $configRole      = explode('.', $configFileName)[0];

            switch ($configRole) {
                case 'config_filter':
                    if (property_exists($config, 'scopes') && is_array($config->scopes)) {
                        $removeRmUserFilters = InterfaceSetting::get('remove_rm_user_filters');
                        foreach ($config->scopes as $name => &$filterConfig) {
                            // ----------------------------- Remove filters that are equal to the parent screen
                            // RelationManager setup: 1 for 1 update screen
                            // This is important because they are expensive
                            if ($isRelationManager) {
                                if (isset($filterConfig['modelClass'])
                                    && trim($filterConfig['modelClass'], '\\') == $controllerModelClass
                                ) {
                                    unset($config->scopes[$name]);
                                }
                                else if (isset($filterConfig['noRelationManager']) && $filterConfig['noRelationManager']) {
                                    unset($config->scopes[$name]);
                                } else if ($removeRmUserFilters
                                    && class_exists(User::class) 
                                    && isset($filterConfig['modelClass'])
                                ) {
                                    // Also expensive: all users
                                    // Will include created_by_user & updated_by_user
                                    $filterModel = new $filterConfig['modelClass'];
                                    if (is_a($filterModel, User::class)) {
                                        unset($config->scopes[$name]);
                                    } else if (property_exists($filterModel, 'belongsTo') 
                                        && is_array($filterModel->belongsTo)
                                    ) {
                                        foreach ($filterModel->belongsTo as $relationConfig) {
                                            if (isset($relationConfig[0]) 
                                                && $relationConfig[0] == User::class
                                                && isset($relationConfig['type'])
                                                && in_array($relationConfig['type'], array('1to1', 'Leaf'))
                                            ) {
                                                unset($config->scopes[$name]);
                                                break;
                                            }
                                        }
                                    }
                                }
                            }

                            // ----------------------------- Class-exists removal
                            // Auto-remove scopes whose modelClass plugin is not installed,
                            // and explicit class-exists: directives in the scope config.
                            // Autoloading must stay enabled here (no `, false`) -- this is
                            // meant to answer "does this class exist at all", but disabling
                            // autoload makes it answer "has something else already loaded
                            // this class by coincidence", which silently removes a perfectly
                            // valid scope whenever nothing earlier in the request happened
                            // to reference its modelClass first.
                            if (isset($filterConfig['modelClass']) && !class_exists($filterConfig['modelClass'])) {
                                unset($config->scopes[$name]);
                                continue;
                            }

                            // ----------------------------- Settings / Env removal
                            if (
                                   self::classExistsRemove($filterConfig)
                                || self::settingRemove($filterConfig, $modelClass)
                                || self::envRemove($filterConfig, $modelClass)
                            ) unset($config->scopes[$name]);
                        }
                    }

                    // --------------------------- Advanced
                    if (   !Session::get('advanced')
                        && property_exists($config, 'scopes') 
                        && is_array($config->scopes)
                    ) {
                        foreach ($config->scopes as $name => &$filterConfig) {
                            if (isset($filterConfig['advanced']) && $filterConfig['advanced'])
                                unset($config->scopes[$name]);

                            // Always advanced
                            if (isset($filterConfig['modelClass'])
                                && trim($filterConfig['modelClass'], '\\') == 'Acorn\Models\Server'
                            ) unset($config->scopes[$name]);
                        }
                    }

                    break;
                case 'config_form':
                    // ------------------------------------------------- Action functions
                    if (property_exists($this->controller, 'actionFunctions') && property_exists($config, 'actionFunctions'))
                        $this->controller->actionFunctions = $config->actionFunctions;
                    break;

                case 'fields':
                    // ------------------------------------------------- Process comments for translate
                    if (isset($config->fields)) {
                        foreach ($config->fields as &$fieldConfig) self::processCommentEmbeddedTranslationKeys($fieldConfig);
                    }
                    if (isset($config->tabs['fields'])) {
                        foreach ($config->tabs['fields'] as &$fieldConfig) self::processCommentEmbeddedTranslationKeys($fieldConfig);
                    }
                    if (isset($config->secondaryTabs['fields'])) {
                        foreach ($config->secondaryTabs['fields'] as &$fieldConfig) self::processCommentEmbeddedTranslationKeys($fieldConfig);
                    }
                    if (isset($config->tertiaryTabs['fields'])) {
                        foreach ($config->tertiaryTabs['fields'] as &$fieldConfig) self::processCommentEmbeddedTranslationKeys($fieldConfig);
                    }

                    // ------------------------------------------------- Comment Add-ins
                    // Actions: View all, Goto selected, Create new popup, Debug
                    if (isset($config->fields)) {
                        foreach ($config->fields as &$fieldConfig) self::adornFieldWithActions($fieldConfig, $controllerModel);
                    }
                    if (isset($config->tabs['fields'])) {
                        foreach ($config->tabs['fields'] as &$fieldConfig) self::adornFieldWithActions($fieldConfig, $controllerModel);
                    }
                    if (isset($config->secondaryTabs['fields'])) {
                        foreach ($config->secondaryTabs['fields'] as &$fieldConfig) self::adornFieldWithActions($fieldConfig, $controllerModel);
                    }
                    if (isset($config->tertiaryTabs['fields'])) {
                        foreach ($config->tertiaryTabs['fields'] as &$fieldConfig) self::adornFieldWithActions($fieldConfig, $controllerModel);
                    }

                    // ------------------------------------------------- Defaults for drop-downs
                    // For some reason they do not work, maybe because of UUIDs
                    // So forms.js supports select[@default] HTML attribute
                    if (isset($config->fields)) {
                        foreach ($config->fields as &$fieldConfig) {
                            if (   isset($fieldConfig['type']) 
                                && $fieldConfig['type'] == 'dropdown' 
                                && isset($fieldConfig['default'])
                            ) {
                                $default = $fieldConfig['default'];
                                if (isset($fieldConfig['attributes'])) {
                                    $fieldConfig['attributes']['default'] = $default;
                                } else {
                                    $fieldConfig['attributes'] = array('default' => $default);
                                }
                            }
                        }
                    }
                    
                    if (isset($config->tabs['fields'])) {
                        foreach ($config->tabs['fields'] as $name => &$fieldConfig) {
                            if (   isset($fieldConfig['type']) 
                                && $fieldConfig['type'] == 'dropdown' 
                                && isset($fieldConfig['default'])
                            ) {
                                $default = $fieldConfig['default'];
                                if (isset($fieldConfig['attributes'])) {
                                    $fieldConfig['attributes']['default'] = $default;
                                } else {
                                    $fieldConfig['attributes'] = array('default' => $default);
                                }
                            }
                        }
                    }

                    // ------------------------------------------------- Advanced fields toggle
                    if ($advancedGet = get('advanced')) Session::put('advanced', ($advancedGet == '1'));
                    $advanced = Session::get('advanced');
                    
                    if (isset($config->fields)) {
                        foreach ($config->fields as $name => &$fieldConfig) {
                            if (isset($fieldConfig['advanced']) && $fieldConfig['advanced']) {
                                if ($advanced) {
                                    $this->appendClass($fieldConfig, 'advanced');
                                } else {
                                    unset($config->fields[$name]);
                                }
                            }
                        }
                    }
                    if (isset($config->tabs['fields'])) {
                        foreach ($config->tabs['fields'] as $name => &$fieldConfig) {
                            if (isset($fieldConfig['advanced']) && $fieldConfig['advanced']) {
                                if ($advanced) {
                                    $this->appendClass($fieldConfig, 'advanced');
                                } else {
                                    unset($config->tabs['fields'][$name]);
                                }
                            }
                        }
                    }
                    if (isset($config->secondaryTabs['fields'])) {
                        foreach ($config->secondaryTabs['fields'] as $name => &$fieldConfig) {
                            if (isset($fieldConfig['advanced']) && $fieldConfig['advanced']) {
                                if ($advanced) {
                                    $this->appendClass($fieldConfig, 'advanced');
                                } else {
                                    unset($config->secondaryTabs['fields'][$name]);
                                }
                            }
                        }
                    }
                    if (isset($config->tertiaryTabs['fields'])) {
                        foreach ($config->tertiaryTabs['fields'] as $name => &$fieldConfig) {
                            if (isset($fieldConfig['advanced']) && $fieldConfig['advanced']) {
                                if ($advanced) {
                                    $this->appendClass($fieldConfig, 'advanced');
                                } else {
                                    unset($config->tertiaryTabs['fields'][$name]);
                                }
                            }
                        }
                    }

                    // ------------------------------- Auto-hide and set parent model drop-down
                    // TODO: This does not work if the parent field is 1-1 nested
                    // e.g. Student.user[languages] => user_user_language.user (student)
                    if ($isPopup && $parentModel) {
                        foreach ($config->fields as $fieldName => &$fieldConfig) {
                            // Look for a parent model selector
                            $dropDownModel = NULL;
                            
                            // type: dropdown + options call
                            // Create-system standard drop-down specification
                            // options: Acorn\University\Models\Student::dropdownOptions
                            if (isset($fieldConfig['type']) 
                                && $fieldConfig['type'] == 'dropdown'
                                && isset($fieldConfig['options'])
                                && is_string($fieldConfig['options'])
                            ) {
                                $optionsParts  = explode('::', $fieldConfig['options']);
                                $dropDownModel = $optionsParts[0];
                            } 

                            // Yaml configs often use type: relation
                            // type: relation
                            else if (isset($fieldConfig['type']) 
                                && $fieldConfig['type'] == 'relation'
                                && $modelClass 
                            ) {
                                $model = new $modelClass();
                                if ($model->hasRelation($fieldName)
                                    && ($relation = $model->$fieldName())
                                    && ($relation instanceof BelongsTo)
                                ) {
                                    $dropDownModel = get_class($relation->getRelated());
                                }
                            }

                            if ($dropDownModel) { 
                                // Set and hide parentModel
                                // can be useful in nested popups
                                // Morph type to text to prevent option loads
                                if ($dropDownModel == $parentModel) {
                                    $fieldConfig['type']      = 'text';
                                    $this->appendClass($fieldConfig, 'hidden');
                                    $fieldConfig['default']   = $parentModelId;
                                } 
                                
                                // Set and hide the main controllerModel
                                else if ($controllerModel 
                                    && $dropDownModel == get_class($controllerModel)
                                ) {
                                    $fieldConfig['type']      = 'text';
                                    $this->appendClass($fieldConfig, 'hidden');
                                    $fieldConfig['default']   = $controllerModel->id;
                                }
                                
                                // Set and hide common singular parent BelongsTo models
                                // Student->user has common with UserUserLanguage->user
                                // when adding XfromXSemi languages
                                // We need the actual controller object
                                // Avoid early-stage hydration __get()
                                else if ($controllerModel
                                    && $controllerModel->hasRelation($fieldName)
                                    && ($relation = $controllerModel->$fieldName())
                                    && ($relation instanceof BelongsTo)
                                    && ($controllerFieldModel = $relation->first())
                                ) {
                                    $this->appendClass($fieldConfig, 'hidden');
                                    $fieldConfig['type']      = 'text';
                                    $fieldConfig['default']   = $controllerFieldModel->id;
                                }
                            }
                        }
                        
                        // ------------------------------------- Auto-hide parent model reverse relation managers
                        // so that X-X relations do not have repeating relationmanager popup loops
                        if (isset($config->tabs['fields'])) {
                            foreach ($config->tabs['fields'] as $fieldName => &$fieldConfig) {
                                if (   isset($fieldConfig['type']) 
                                    && isset($fieldConfig['relatedModel'])
                                    && $fieldConfig['type'] == 'relationmanager'
                                    && $fieldConfig['relatedModel'] == $parentModel
                                ) {
                                    unset($config->tabs['fields'][$fieldName]);
                                }
                            }
                        }
                        if (isset($config->secondaryTabs['fields'])) {
                            foreach ($config->secondaryTabs['fields'] as $fieldName => &$fieldConfig) {
                                if (   isset($fieldConfig['type']) 
                                    && isset($fieldConfig['relatedModel'])
                                    && $fieldConfig['type'] == 'relationmanager'
                                    && $fieldConfig['relatedModel'] == $parentModel
                                ) {
                                    unset($config->secondaryTabs['fields'][$fieldName]);
                                }
                            }
                        }
                        if (isset($config->tertiaryTabs['fields'])) {
                            foreach ($config->tertiaryTabs['fields'] as $fieldName => &$fieldConfig) {
                                if (   isset($fieldConfig['type']) 
                                    && isset($fieldConfig['relatedModel'])
                                    && $fieldConfig['type'] == 'relationmanager'
                                    && $fieldConfig['relatedModel'] == $parentModel
                                ) {
                                    unset($config->tertiaryTabs['fields'][$fieldName]);
                                }
                            }
                        }
                    }
                        
                    // ------------------------------------------------- Popup update without list-editable
                    // When updating a record from a list view, list-editable fields are not necessary
                    // because they can be more easily changed in the list view
                    // so we can reduce clutter in the popup
                    // Just hide them in case they are required
                    if ($isPopup) {
                        // TODO: Rationalise model knowledge
                        if (property_exists($this, 'eventTarget')) {
                            // TODO: relationModel does not exist during update ????
                            $popupContext = ($this->eventTarget == 'button-create' ? 'create' : 'update');
                            if ($popupContext == 'update') {
                                foreach ($config->fields as $fieldName => &$fieldConfig) {
                                    if (isset($fieldConfig['listEditable']) && $fieldConfig['listEditable']) {
                                        $this->appendClass($fieldConfig, 'hidden');
                                    }
                                }
                                if (isset($config->tabs['fields'])) {
                                    foreach ($config->tabs['fields'] as $fieldName => &$fieldConfig) {
                                        if (isset($fieldConfig['listEditable']) && $fieldConfig['listEditable']) {
                                            $this->appendClass($fieldConfig, 'hidden');
                                        }
                                    }
                                }
                                if (isset($config->secondaryTabs['fields'])) {
                                    foreach ($config->secondaryTabs['fields'] as $fieldName => &$fieldConfig) {
                                        if (isset($fieldConfig['listEditable']) && $fieldConfig['listEditable']) {
                                            $this->appendClass($fieldConfig, 'hidden');
                                        }
                                    }
                                }
                                if (isset($config->tertiaryTabs['fields'])) {
                                    foreach ($config->tertiaryTabs['fields'] as $fieldName => &$fieldConfig) {
                                        if (isset($fieldConfig['listEditable']) && $fieldConfig['listEditable']) {
                                            $this->appendClass($fieldConfig, 'hidden');
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // ------------------------------------------------- Popup tertiary fields
                    // Move these fields in to the main area
                    // because the popup has no tertiary area
                    if ($isPopup && isset($config->tertiaryTabs['fields'])) {
                        $first = TRUE;
                        foreach ($config->tertiaryTabs['fields'] as $fieldName => &$fieldConfig) {
                            if ($fieldName != '_qrcode') {
                                if ($first) {
                                    $this->appendClass($fieldConfig, 'new-row');
                                }
                                $config->fields[$fieldName] = $fieldConfig;
                                $first = FALSE;
                            }
                        }
                        unset($config->tertiaryTabs);
                    }

                    // ------------------------------------------------- Context sensitive settings
                    // e.g. readOnly: true@update
                    foreach ($config->fields as $fieldName => &$fieldConfig) {
                        foreach ($fieldConfig as $name => &$value) {
                            if (is_string($value)) {
                                $valueParts = explode('@', $value);
                                if (count($valueParts) == 2) {
                                    $settingContext = $valueParts[1];
                                    if (in_array($settingContext, array('create', 'update', 'preview'))) {
                                        if ($settingContext == $context) $value = $valueParts[0];
                                        else unset($fieldConfig[$name]);
                                    }
                                }
                            }
                        }
                    }
                    
                    // ------------------------------------------------- class-exists (unconditional — modelClass not needed)
                    // Run before the modelClass guard so widgets without a modelClass (e.g. Calendars)
                    // still have optional-plugin fields stripped before dropdown options are resolved.
                    foreach ($config->fields as $fieldName => &$fieldConfig) {
                        if (self::classExistsRemove($fieldConfig)) unset($config->fields[$fieldName]);
                    }
                    if (isset($config->tabs['fields'])) {
                        foreach ($config->tabs['fields'] as $fieldName => &$fieldConfig) {
                            if (self::classExistsRemove($fieldConfig)) unset($config->tabs['fields'][$fieldName]);
                        }
                    }
                    if (isset($config->secondaryTabs['fields'])) {
                        foreach ($config->secondaryTabs['fields'] as $fieldName => &$fieldConfig) {
                            if (self::classExistsRemove($fieldConfig)) unset($config->secondaryTabs['fields'][$fieldName]);
                        }
                    }
                    if (isset($config->tertiaryTabs['fields'])) {
                        foreach ($config->tertiaryTabs['fields'] as $fieldName => &$fieldConfig) {
                            if (self::classExistsRemove($fieldConfig)) unset($config->tertiaryTabs['fields'][$fieldName]);
                        }
                    }

                    // ------------------------------------------------- setting, env, conditions
                    // This allows fields to be conditionally shown
                    // in the same way as permissions
                    // setting: my_setting
                    // where my_setting must be valid on a local Plugin Setting[s] class
                    if ($modelClass) {
                        foreach ($config->fields as $fieldName => &$fieldConfig) {
                            if (
                                   self::settingRemove($fieldConfig, $modelClass)
                                || self::envRemove($fieldConfig, $modelClass)
                                || self::conditionRemove($fieldConfig, $controllerModel)
                            ) unset($config->fields[$fieldName]);
                        }
                        if (isset($config->tabs['fields'])) {
                            foreach ($config->tabs['fields'] as $fieldName => &$fieldConfig) {
                                if (
                                        self::settingRemove($fieldConfig, $modelClass)
                                     || self::envRemove($fieldConfig, $modelClass)
                                     || self::conditionRemove($fieldConfig, $controllerModel)
                                ) unset($config->tabs['fields'][$fieldName]);
                            }
                        }
                        if (isset($config->secondaryTabs['fields'])) {
                            foreach ($config->secondaryTabs['fields'] as $fieldName => &$fieldConfig) {
                                if (
                                        self::settingRemove($fieldConfig, $modelClass)
                                     || self::envRemove($fieldConfig, $modelClass)
                                     || self::conditionRemove($fieldConfig, $controllerModel)
                                ) unset($config->secondaryTabs['fields'][$fieldName]);
                            }
                        }
                        if (isset($config->tertiaryTabs['fields'])) {
                            foreach ($config->tertiaryTabs['fields'] as $fieldName => &$fieldConfig) {
                                if (
                                        self::settingRemove($fieldConfig, $modelClass)
                                     || self::envRemove($fieldConfig, $modelClass)
                                     || self::conditionRemove($fieldConfig, $controllerModel)
                                ) unset($config->tertiaryTabs['fields'][$fieldName]);
                            }
                        }
                    }

                    // ------------------------------------------------- permission-settings
                    // The permission name can be qualified _or_ un-qualified
                    // If it is un-qualified then the permission is understood as from this plugin
                    // permission-settings:
                    //     NOT=legalcases__legalcase_type_id__update@update:
                    //         field:
                    //              readOnly: true
                    //              disabled: true
                    //              type: dropdown
                    //         labels:
                    //              en: My Permission
                    if (property_exists($config, 'fields')) {
                        foreach ($config->fields as $fieldName => &$fieldConfig) {
                            if (isset($fieldConfig['permissionSettings'])) {
                                foreach ($fieldConfig['permissionSettings'] as $permissionDirective => &$permissionSettings) {
                                    $typeParts = explode('=', $permissionDirective);
                                    $negation  = FALSE;
                                    if (count($typeParts) == 2) {
                                        if ($typeParts[0] == 'NOT') $negation = TRUE;
                                        $permissionDirective = $typeParts[1];
                                    }
                                    $contextParts = explode('@', $permissionDirective);
                                    $permContext  = NULL;
                                    if (count($contextParts) == 2) {
                                        $permContext         = $contextParts[1];
                                        $permissionDirective = $contextParts[0];
                                    }

                                    // Conditionally qualify the permission name
                                    // $qualifiedPermissionName = $permissionDirective;
                                    // $isQualifiedName = (strstr($qualifiedPermissionName, '.') !== FALSE);
                                    // if (!$isQualifiedName) {
                                    //     $pluginDotPath = $modelClass::pluginAuthorDotPlugin();
                                    //     $qualifiedPermissionName = "$pluginDotPath.$qualifiedPermissionName";
                                    // }

                                    // Check access
                                    $hasAccess = $user->hasAccess($permissionDirective);
                                    $isContext = (is_null($permContext) || $permContext == $context);

                                    if ($isContext && ($negation ? !$hasAccess : $hasAccess)) {
                                        if (isset($permissionSettings['field'])) {
                                            foreach ($permissionSettings['field'] as $setting => $value) {
                                                $setting = preg_replace('/^field-/', '', $setting);
                                                $setting = Str::camel($setting);
                                                $fieldConfig[$setting] = $value;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Query string values
                    foreach (get() as $getName => $getValue) {
                        if (isset($config->fields[$getName])) {
                            if ($getValue == '<referrer>') {
                                $referrerUri   = new Uri(request()->headers->get('referer'));
                                $referrerParts = explode('/', $referrerUri->getPath());
                                if (count($referrerParts) > 2) {
                                    $getValue = end($referrerParts);
                                }
                            }
                            $field = &$config->fields[$getName];
                            // $field['type']     = 'text';
                            $field['readOnly'] = TRUE;
                            $field['default']  = $getValue;
                        }
                    }

                    break;

                case 'columns':
                    // ------------------------------------------------- setting: and env: directives
                    // This allows fields to be conditionally shown
                    // in the same way as permissions
                    // setting: my_setting
                    // where my_setting must be valid on a local Plugin Setting[s] class
                    if ($modelClass) {
                        foreach ($config->columns as $fieldName => &$fieldConfig) {
                            if (
                                   self::settingRemove($fieldConfig, $modelClass)
                                || self::envRemove($fieldConfig, $modelClass)
                            ) unset($config->columns[$fieldName]);
                        }
                    }

                    break;
            }
        }

        if (env('APP_DEBUG') && \is_string($configFile) && $debugOutput) {
            // Copied from parent::makeConfig()
            if (isset($this->controller) && method_exists($this->controller, 'getConfigPath')) {
                $configFile = $this->controller->getConfigPath($configFile);
            }
            else {
                $configFile = $this->getConfigPath($configFile);
            }

            $configFile = str_replace('.yaml', '_morphed.yaml', $configFile);
            try {
                File::put($configFile, Yaml::render((array)$config));
            } catch (Exception $ex) {}

            // Debug checks, e.g. relation validity
            if ($modelClass) {
                $model = new $modelClass(); 
                $validRelations = array_merge($model->belongsTo, $model->hasMany);
                if (property_exists($model, 'hasManyDeep')) 
                    $validRelations = array_merge($validRelations, $model->hasManyDeep);
                $fieldList = array();
                if (property_exists($config, 'columns')) $fieldList = $config->columns;
                if (property_exists($config, 'fields'))  $fieldList = $config->fields;
                foreach ($fieldList as $fieldName => $fieldConfig) {
                    if (isset($fieldConfig['relation'])) {
                        $relationName = $fieldConfig['relation'];
                        if (strstr($relationName, '[') !== FALSE)
                            throw new Exception("[$modelClass] config contains a [$relationName] nested syntax relation name");
                        if (!isset($validRelations[$relationName]))
                            throw new Exception("[$modelClass] class does not have a [$relationName] relation");
                    }
                }
            }
        }

        return $config;
    }

    protected static function array_insert(&$array, $positionKey, $insert)
    {
        // In-place!
        if (is_int($positionKey)) {
            array_splice($array, $positionKey, 0, $insert);
        } else {
            $posNum = ($positionKey ? array_search($positionKey, array_keys($array)) : 0);
            $array  = array_merge(
                array_slice($array, 0, $posNum),
                $insert,
                array_slice($array, $posNum)
            );
        }
    }

    protected static function getSettingsModel(string $modelClass): string|NULL
    {
        // TODO: This will fail for create-system embedded 1-1 fields
        // inherited from a belongsTo Model
        // like Student belongsTo User with password: setting: has_front_end
        $settingsClass = NULL;
        $modelClassParts = explode('\\', $modelClass);
        array_pop($modelClassParts);

        array_push($modelClassParts, 'Settings');
        $class = implode('\\', $modelClassParts);
        if (class_exists($class)) $settingsClass = $class;
        array_pop($modelClassParts);

        array_push($modelClassParts, 'Setting');
        $class = implode('\\', $modelClassParts);
        if (class_exists($class)) $settingsClass = $class;

        return $settingsClass;
    }

    protected static function getSetting(string $settingCaluse, string $modelClass): bool
    {
        // setting: can include the model also
        // setting: \Acorn\Something\Settings::has_this
        $settingParts  = explode('::', $settingCaluse);
        $settingName   = (isset($settingParts[1]) ? $settingParts[1] : $settingParts[0]);
        if (count($settingParts) > 1) $modelClass = $settingParts[0];
        $settingsClass = self::getSettingsModel($modelClass);
        return ($settingsClass && $settingsClass::get($settingName) == '1');
    }

    protected static function settingRemove(array &$fieldConfig, string $modelClass): bool
    {
        $removeField = FALSE;

        if (isset($fieldConfig['setting'])) {
            $setting = self::getSetting($fieldConfig['setting'], $modelClass);
            if (!$setting) $removeField = TRUE;
        }
        if (isset($fieldConfig['settingNot'])) {
            $setting = self::getSetting($fieldConfig['settingNot'], $modelClass);
            if ($setting) $removeField = TRUE;
        }

        return $removeField;
    }

    protected static function envRemove(array &$fieldConfig, string $modelClass): bool
    {
        $removeField = FALSE;
        if (isset($fieldConfig['env'])) {
            $env         = env($fieldConfig['env']);
            $removeField = ($env != 1 && strtolower($env) != 'true' && strtolower($env) != 'yes');
        }
        return $removeField;
    }

    protected static function classExistsRemove(array $fieldConfig): bool
    {
        // class-exists: Acorn/User/Models/User  (slashes normalised to backslashes)
        if (isset($fieldConfig['class-exists'])) {
            $className = str_replace('/', '\\', $fieldConfig['class-exists']);
            if (!class_exists($className, false)) return TRUE;
        }
        return FALSE;
    }

    protected static function conditionRemove(array &$fieldConfig, Model|NULL $model): bool
    {
        $removeField = FALSE;
        if (isset($fieldConfig['condition']) || isset($fieldConfig['conditions'])) {
            $conditions      = (isset($fieldConfig['condition']) ? $fieldConfig['condition'] : $fieldConfig['conditions']);
            
            // Understand the type of SQL query
            $bareQuery       = trim($conditions, '( ');
            $sqlCommand      = explode(' ', $bareQuery)[0];
            $isAbsoluteQuery = ($sqlCommand == 'select');

            if ($isAbsoluteQuery) {
                // Generic, works with new Models
                // for example, global-scope situations
                $results     = DB::select($conditions);
                $removeField = (!isset($results[0]) || array_values((array)$results[0])[0] == 0);
            } else {
                // Specific to model
                // Winter does the following in initForm($model, $context = null)
                //   $config = $this->makeConfig($formFields); => call to here
                //   $config->model = $model;
                // it calls makeConfig() _before_ it sets the model, so we may have nothing
                // However, Acorn/FormController will set the model before calling here
                if ($model && $model->exists) {
                    $removeField = ($model::where('id', $model->id)->whereRaw($conditions)->count() == 0);
                }
            }
        }
        return $removeField;
    }

    /**
     * Process comments for translation
     *
     * @param array $fieldConfig
     */
    protected static function processCommentEmbeddedTranslationKeys(array &$fieldConfig): void
    {
        if (isset($fieldConfig['comment']) && is_string($fieldConfig['comment'])) {
            $fieldConfig['comment'] = preg_replace_callback(
                "/([a-zA-Z0-9_\.]+::lang\.[a-zA-Z0-9_\.\-]+)/",
                function ($matches) {
                    return trans($matches[1]) ?: $matches[1];
                },
                $fieldConfig['comment']
            );
        }
    }

    protected static function adornFieldWithActions(array &$fieldConfig, Model|NULL $controllerModel): void
    {
        if (isset($fieldConfig['actions']) && is_array($fieldConfig['actions'])) {
            $lis = '';
            foreach ($fieldConfig['actions'] as $name => $actionConfig) {
                // 3 styles of config are allowed:
                //   1: create-popup
                //   create-popup: true
                //   my-custom-action:
                //     labels: ...
                //     ...
                if (is_numeric($name)) {
                    $name = $actionConfig;
                    $actionConfig = TRUE;
                }
                if ($actionConfig === TRUE) $actionConfig = array();

                $localLabelKey = preg_replace('/[^a-z0-9]/', '', $name);
                $labelKey      = "acorn::lang.models.fieldactions.$localLabelKey";
                $labelEscaped  = e(trans($labelKey));

                // Pre-defined
                switch ($name) {
                    case 'create-popup':
                        if (!isset($actionConfig['control'])) 
                            $actionConfig['control'] = 'popup';
                        break;
                    case 'view-add-models':
                        if (is_string($actionConfig)) 
                            $actionConfig = array('href' => $actionConfig);
                        if (!isset($actionConfig['control'])) 
                            $actionConfig['control'] = 'newtab';
                        break;
                    case 'goto-form-group-selection':
                        if (is_string($actionConfig)) 
                            $actionConfig = array('href' => $actionConfig);
                        if (!isset($actionConfig['control'])) 
                            $actionConfig['control'] = 'newtab';
                        break;
                    case 'goto-event':
                        if (!isset($actionConfig['href'])) 
                            $actionConfig['href'] = '/backend/acorn/calendar/months#!/event/:event';
                        if (!isset($actionConfig['control'])) 
                            $actionConfig['control'] = 'newtab';
                        break;
                    case 'debug':
                        if (get('debug')) {
                            $actionConfig = array(
                                'content'  => "$labelEscaped$actionConfig",
                                'title'    => '',
                            );
                        } else {
                            $actionConfig = FALSE;
                        }
                        break;
                }

                // Direct Content custom actions
                if (is_string($actionConfig)) {
                    $actionConfig = array(
                        'content' => $actionConfig,
                    );
                }

                // HTML
                if ($actionConfig !== FALSE) {
                    $content      = (isset($actionConfig['content']) ? $actionConfig['content'] : $labelEscaped);
                    $titleEscaped = (isset($actionConfig['title']) ? e($actionConfig['title']) : $labelEscaped);
                    if (isset($actionConfig['href'])) {
                        $href    = ($controllerModel && $controllerModel->exists
                            ? self::tokenizeStringFromModel($actionConfig['href'], $controllerModel)
                            : $actionConfig['href']
                        );
                        $target  = ((isset($actionConfig['control']) && $actionConfig['control'] == 'newtab') ? '_blank' : '');
                        $content = "<a tabindex='-1' target='$target' href='$href'>$content</a>";
                    }
                    $lis .= "<li class='$name' title='$titleEscaped'>$content</li>";
                }
            }

            // Prepend to the comment
            if ($lis) {
                if (!isset($fieldConfig['comment'])) $fieldConfig['comment'] = '';
                if (!isset($fieldConfig['commentHtml']) || !$fieldConfig['commentHtml']) $fieldConfig['commentHtml'] = TRUE;
                $fieldConfig['comment'] = "<ul class='field-actions'>$lis</ul><p class='help-block'>$fieldConfig[comment]</p>";
            }
        }
    }

    protected static function arrayToName(array $fieldPath): string
    {
        $fieldName = $fieldPath[0];
        if (count($fieldPath) > 1) {
            $fieldNests = implode('][', array_slice($fieldPath, 1));
            $fieldName .= "[$fieldNests]";
        }
        return $fieldName;
    }

    protected static function nestField(string|array $nest, string|array $fieldName, int &$nestlevel = NULL): string
    {
        if (!is_array($nest))      $nest      = HtmlHelper::nameToArray($nest);
        if (!is_array($fieldName)) $fieldName = HtmlHelper::nameToArray($fieldName);
        $nestedFieldPath = array_merge($nest, $fieldName);
        $nestlevel       = count($nestedFieldPath);
        return self::arrayToName($nestedFieldPath);
    }

    protected static function isNested(string $fieldName): bool
    {
        return (count(HtmlHelper::nameToArray($fieldName)) > 1);
    }

    protected static function isPseudo(string $fieldName): bool
    {
        return ($fieldName && $fieldName[0] == '_');
    }

    protected static function processFields(array &$configFields, array &$subConfigFields, string $fieldName, string $modelClass = NULL): void
    {
        $inserts = array();
        foreach ($subConfigFields as $subFieldName => $subFieldConfig) {
            // TODO: Nested 1from1 relations
            $subType           = (isset($subFieldConfig['type']) ? $subFieldConfig['type'] : 'text');
            $includeContext    = (isset($subFieldConfig['includeContext']) ? $subFieldConfig['includeContext'] : 'include');
            $isPseudoFieldName = self::isPseudo($subFieldName);

            if ($subFieldName != 'id' && $includeContext != 'no-include') {
                // Config changes
                // TODO: support relation and fileupload fields on create
                // Currently relation & fileupload will crash 
                // because the relations are null on create
                if ($subType == 'relation') {
                    if (isset($subFieldConfig['options'])) {
                        // This relation has been designed for a dropdown scenario also
                        // by additionally indicating the options during create
                        // TODO: Can this be auto-generated? We have:
                        //   get_class((new $modelClass)->$fieldName()->getRelated()) . '::dropdownOptions'
                        $subFieldConfig['type'] = 'dropdown';
                    } else {
                        // We cannot support embedded relation fields in create mode
                        $subFieldConfig['context'] = array('update');
                    }
                }
                else if ($subType == 'fileupload') {
                    // TODO: support emedded fileupload fields on create
                    $subFieldConfig['context'] = array('update');
                }

                if (isset($subFieldConfig['dependsOn'])) {
                    $dependsOn = $subFieldConfig['dependsOn'];
                    foreach ($dependsOn as $i => $dependsOnField) {
                        $isDependsPseudoFieldName = self::isPseudo($dependsOnField);
                        if (!$isDependsPseudoFieldName)
                            $subFieldConfig['dependsOn'][$i] = self::nestField($fieldName, $dependsOnField);
                    }
                }

                // Nesting in to existing form
                $nestedFieldName   = ($isPseudoFieldName ? $subFieldName : self::nestField($fieldName, $subFieldName));
                $formNestLevel     = $subFieldConfig['nestLevel'] ?? 0;
                $subFieldConfig['nested']    = TRUE;
                $subFieldConfig['nestLevel'] = $formNestLevel+1;
                $subFieldConfig['included']  = TRUE;
                if (!$modelClass || !self::settingRemove($subFieldConfig, $modelClass))
                    $inserts[$nestedFieldName] = $subFieldConfig;
            }
        }

        // Insert before $fieldName
        self::array_insert($configFields, $fieldName, $inserts);
    }
}
