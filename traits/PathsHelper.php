<?php namespace Acorn\Traits;

use Str;
use Backend\Facades\Backend;
use Exception;
use Model;
use Controller;
use Winter\Storm\Html\Helper as HtmlHelper;

Trait PathsHelper {
    // This Trait can be added to either Model or Controller
    // And helps understand the other and directories

    protected function paths(Object $object = NULL): array
    {
        return array(
            'fullyQualifiedClassName' => $this->fullyQualifiedClassName($object),
            'unqualifiedClassName'    => $this->unqualifiedClassName($object),
            'pluginPathRelative'      => $this->pluginPathRelative($object),
            'pluginPathAbsolute'      => $this->pluginPathAbsolute($object),
            'modelClassPathAbsolute'  => $this->modelClassPathAbsolute($object),
            'controllerUrl'           => $this->controllerUrl($object),
            'tablePrefix'             => $this->tablePrefix($object),
            'tableMask'               => $this->tableMask($object),
        );
    }

    public static function tokenizeStringFromModel(string $str, Model $model): string
    {
        if (preg_match_all('/:([a-z0-9_]+)/', $str, $tokenMatches)) {
            $tokens = array();
            foreach ($tokenMatches[1] as $token) {
                if ($model->hasAttribute($token)) {
                    $tokens[$token] = $model->$token;
                } else if (isset($model->belongsTo[$token]) && $model->$token) {
                    $tokens[$token] = $model->$token->id;
                }
            }
            $str = self::tokenizeString($str, $tokens);
        }
        return $str;
    }

    public static function tokenizeString(string $str, array $tokens): string
    {
        // what:this
        // array('this' => 9)
        // what9
        $keyTokens = array();
        foreach ($tokens as $name => $value) $keyTokens[":$name"] = $value;
        $newStr = str_replace(array_keys($keyTokens), array_values($keyTokens), $str);
        if (strstr($newStr, ':') !== FALSE)
            throw new Exception("Failed to replace all tokens in [$newStr]");
        return $newStr;
    }

    // ----------------------------------------- Class & Plugin
    public function fullyQualifiedClassName(Object $object = NULL): string
    {
        // Short name for debugging output
        // Acorn\Lojistiks\Model\Area => Area
        if (is_null($object)) $object = $this;
        return get_class($object);
    }

    public function isOurs(Object $object = NULL): bool
    {
        $fqn        = $this->fullyQualifiedClassName($object);
        $classParts = explode('\\', $this->fullyQualifiedClassName($object));
        return ($classParts[0] == 'Acorn');
    }

    public function unqualifiedClassName(Object $object = NULL): string
    {
        // Short name for debugging output
        // Acorn\Lojistiks\Model\Area => Area
        $classParts = explode('\\', $this->fullyQualifiedClassName($object));
        return end($classParts);
    }

    public function qualifyClassName(string $className): string
    {
        $fullyQualifiedClassName = $className;
        $classNameParts = explode('\\', $className);
        if (count($classNameParts) == 1) {
            // Unqualified class name
            $thisClassParts = explode('\\', $this->fullyQualifiedClassName());
            array_pop($thisClassParts);
            array_push($thisClassParts, $className);
            $fullyQualifiedClassName = implode('\\', $thisClassParts);
        }
        return $fullyQualifiedClassName;
    }

    protected function dotName(bool $withModel = FALSE, Object $object = NULL): string
    {
        $class       = $this->fullyQualifiedClassName($object);
        $aClass      = explode('\\', $class);
        if (!$withModel) $aClass = array_filter($aClass, function($value){return $value != 'Models';});
        return strtolower(implode('.', $aClass));
    }

    protected function pluginPathPartAuthorPlugin(Object $object = NULL): string
    {
        $class       = $this->fullyQualifiedClassName();
        $aClass      = explode('\\', $class);
        $authorDirName = strtolower($aClass[0]);
        $pluginDirName = strtolower($aClass[1]);
        return "$authorDirName/$pluginDirName";
    }

    public function pluginAuthorDotPlugin(Object $object = NULL): string
    {
        $class       = $this->fullyQualifiedClassName();
        $aClass      = explode('\\', $class);
        $authorDirName = strtolower($aClass[0]);
        $pluginDirName = strtolower($aClass[1]);
        return "$authorDirName.$pluginDirName";
    }

    protected function pluginPathRelative(Object $object = NULL): string
    {
        $pluginPathPartAuthorPlugin = $this->pluginPathPartAuthorPlugin();
        return "plugins/$pluginPathPartAuthorPlugin";
    }

    protected function docRoot(): string
    {
        return base_path();
    }

    protected function pluginPathAbsolute(Object $object = NULL): string
    {
        $docRoot            = $this->docRoot();
        $pluginPathRelative = $this->pluginPathRelative();
        return "$docRoot/$pluginPathRelative";
    }

    // ----------------------------------------- Translation
    public function translationDomainModel(string $name = 'label', Model|NULL $model = NULL): string
    {
        if (is_null($model)) $model = &$this;
        $modelName = $this->lowerCaseName($model);
        $authorDotPlugin = $model->pluginAuthorDotPlugin(); // acorn.lojistiks
        return "$authorDotPlugin::lang.models.$modelName.$name";
    }

    public function translationDomainPlugin(string $name = 'label', Model|NULL $model = NULL): string
    {
        if (is_null($model)) $model = &$this;
        $authorDotPlugin = $model->pluginAuthorDotPlugin(); // acorn.lojistiks
        return "$authorDotPlugin::lang.plugin.$name";
    }

    public function translationDomainBackend(string $name): string
    {
        if ($name == 'update') $name = 'save';
        return "backend::lang.form.$name";
    }

    public function translateModelKey(string $name = 'label', Model|NULL $model = NULL): string
    {
        if (is_null($model)) $model = &$this;
        return trans($this->translationDomainModel($name, $model));
    }

    public function translateControllerKey(string $name = 'label_plural', Controller|NULL $controller = NULL): string
    {
        if (is_null($controller)) $controller = &$this;
        $modelName = strtolower($this->modelClassName($controller));
        $authorDotPlugin = $controller->pluginAuthorDotPlugin(); // acorn.lojistiks
        return trans("$authorDotPlugin::lang.models.$modelName.$name");
    }

    public function transBackend(string $name): string
    {
        return trans($this->translationDomainBackend($name));
    }

    // ----------------------------------------- Case & plurality
    public function pascalCaseName(Object $object = NULL): string
    {
        return $this->unqualifiedClassName($object);
    }

    public function snakeCaseName(Object $object = NULL): string
    {
        return Str::snake($this->unqualifiedClassName($object));
    }

    public function lowerCaseName(Object $object = NULL): string
    {
        return strtolower($this->unqualifiedClassName($object));
    }

    public function singularClassName(Object $object = NULL): string
    {
        return (property_exists($this, 'nameSingular') 
            ? Str::studly($this->nameSingular)
            : Str::singular($this->unqualifiedClassName($object))
        );
    }

    public function pluralClassName(Object $object = NULL): string
    {
        if (is_null($object)) $object = $this;
        return (property_exists($object, 'namePlural') 
            ? Str::studly($object->namePlural)
            : Str::plural($this->unqualifiedClassName($object))
        );
    }

    public function singularLowerCaseName(Object $object = NULL): string
    {
        return strtolower($this->singularClassName());
    }

    public function pluralLowerCaseName(Object $object = NULL): string
    {
        return strtolower($this->pluralClassName());
    }

    // ----------------------------------------- Models
    public function modelClassName(Object $object = NULL): string
    {
        return $this->singularClassName($object);
    }

    public function modelFullyQualifiedClass(Object $object = NULL): string
    {
        $fullyQualifiedClassName = $this->fullyQualifiedClassName();
        // Author\Plugin\<Type>\<Name>
        $parts  = explode('\\', $fullyQualifiedClassName);
        $author = $parts[0];
        $plugin = $parts[1];
        $type   = $parts[2];
        $name   = $this->modelClassName();

        return "$author\\$plugin\\Models\\$name";
    }

    public function modelDirectoryName(Object $object = NULL): string
    {
        return $this->singularLowerCaseName();
    }

    public function modelForeignFieldName(Object $object = NULL): string
    {
        // Without ID
        return Str::singular($this->snakeCaseName());
    }

    public function modelDirectoryPathRelative(string $file = NULL, ?Object $object = NULL): string
    {
        $pluginPathRelative = $this->pluginPathRelative($object);
        $modelDirectoryName = $this->modelDirectoryName($object);
        $path = "$pluginPathRelative/models/$modelDirectoryName";
        if ($file) $path .= "/$file";
        return $path;
    }

    public function modelClassPathRelative(Object $object = NULL): string
    {
        $pluginPathRelative = $this->pluginPathRelative();
        $modelClassName     = $this->modelClassName();
        return "$pluginPathRelative/models/$modelClassName.php";
    }

    public function modelClassPathAbsolute(Object $object = NULL): string
    {
        $pluginPathRelative     = $this->pluginPathRelative();
        $modelClassPathRelative = $this->modelClassPathRelative();
        return "$pluginPathRelative/$modelClassPathRelative";
    }

    // ----------------------------------------- Database
    public function tableName(Object $object = NULL): string
    {
        if (property_exists($this, 'table')) {
            $tableName = $this->table;
        } else {
            $modelClassName = $this->modelClassName();
            $model          = new $modelClassName;
            $tableName      = $model->table;
        }
        return $tableName;
    }

    public function tablePrefix(Object $object = NULL): string
    {
        $class         = $this->fullyQualifiedClassName();
        $aClass        = explode('\\', $class);
        $tablePrefix   = '';
        if (count($aClass) == 2) {
            $authorDirName = strtolower($aClass[0]);
            $pluginDirName = strtolower($aClass[1]);
            $tablePrefix   = "{$authorDirName}_{$pluginDirName}_";
        }
        return $tablePrefix;
    }

    public function tableMask(Object $object = NULL): string
    {
        return $this->tablePrefix() . '%';
    }

    public function functionPrefix(Object $object = NULL)
    {
        return 'fn_' . $this->tablePrefix();
    }

    public function hasFunctionPrefix(string $name, ?Object $object = NULL): bool
    {
        $functionPrefix = $this->functionPrefix();
        return (substr($name, 0, strlen($functionPrefix)) == $functionPrefix);
    }

    public function hasAggregatePrefix(string $name, ?Object $object = NULL): bool
    {
        $aggregatePrefix = $this->aggregatePrefix();
        return (substr($name, 0, strlen($aggregatePrefix)) == $aggregatePrefix);
    }

    public function aggregatePrefix(Object $object = NULL)
    {
        return 'agg_' . $this->tablePrefix();
    }

    public function triggerPrefix(Object $object = NULL)
    {
        return 'tr_' . $this->tablePrefix();
    }

    public function hasTriggerPrefix(string $name, ?Object $object = NULL): bool
    {
        $triggerPrefix = $this->triggerPrefix();
        return (substr($name, 0, strlen($triggerPrefix)) == $triggerPrefix);
    }

    // ----------------------------------------- Controllers
    public function controllerClassName(Object $object = NULL): string
    {
        return $this->pluralClassName($object);
    }

    public function controllerFullyQualifiedClass(Object $object = NULL): string
    {
        $fullyQualifiedClassName = $this->fullyQualifiedClassName($object);
        // Author\Plugin\<Type>\<Name>
        $parts  = explode('\\', $fullyQualifiedClassName);
        $author = $parts[0];
        $plugin = $parts[1];
        $type   = $parts[2];
        $name   = $this->pluralClassName($object);

        return "$author\\$plugin\\Controllers\\$name";
    }

    public function controllerDirectoryPathRelative(Object $object = NULL, bool $checkThrow = FALSE): ?string
    {
        $pluginPathRelative      = $this->pluginPathRelative();
        $controllerDirectoryName = $this->controllerDirectoryName();
        $path = "$pluginPathRelative/controllers/$controllerDirectoryName";
        if (!is_dir(base_path($path))) {
            if ($checkThrow) throw new Exception("Path [$path] does not exist");
            return null;
        }
        return $path;
    }

    public function controllerDirectoryName(Object $object = NULL): string
    {
        return $this->pluralLowerCaseName();
    }

    public function controllerUrl(string $action = NULL, $id = NULL, ?Object $object = NULL, bool $withBackend = TRUE, bool $throwIfMissing = FALSE): string
    {
        // TODO: Use $controller->actionUrl($action, $path)
        $pluginPathPartAuthorPlugin  = $this->pluginPathPartAuthorPlugin();
        $controllerDirectoryName     = $this->controllerDirectoryName();

        $url = NULL;
        // controllerDirectoryPathRelative() will check the directory exists and return NULL if not
        $controllerDirectoryRelative = $this->controllerDirectoryPathRelative();
        if ($controllerDirectoryRelative) {
            $url  = ($withBackend ? '/backend/' : '');
            $url .= "$pluginPathPartAuthorPlugin/$controllerDirectoryName";
            if ($action) {
                $url .= "/$action";
                if (is_null($id)) $id = $this->id;
                if ($id) $url .= "/$id";
            }
        } else if ($throwIfMissing) {
            throw new Exception("$controllerDirectoryRelative not found");
        }

        return $url;
    }

    public function absoluteControllerUrl(string $action = NULL, $id = NULL, ?Object $object = NULL): string
    {
        return Backend::url($this->controllerUrl($action, $id, $object, FALSE));
    }

    // ----------------------------------------- Reverse lookups
    public static function authorPascalCase(string $authorDirName): string
    {
        return ($authorDirName == 'acorn' ? 'Acorn' : ucfirst($authorDirName));
    }

    public static function fullyQualifiedModelClassFromTableName(string $tableName): string
    {
        $unqualifiedTableName = preg_replace('/^[^.]+\./', '', $tableName);
        $tableNameParts       = explode('_', $unqualifiedTableName);
        $authorDirName        = $tableNameParts[0];
        $pluginDirName        = $tableNameParts[1];
        $classSnakeCasePlural = implode('_', array_slice($tableNameParts, 2));
        $unqualifiedPascalClassName = Str::singular(Str::studly($classSnakeCasePlural)); // Pascal case
        $authorPascalCase     = self::authorPascalCase($authorDirName);
        $pluginPascalCase     = Str::studly($pluginDirName); // Pascal case

        return "$authorPascalCase\\$pluginPascalCase\\Models\\$unqualifiedPascalClassName";
    }

    public static function newModelFromTableName(string $tableName): Model
    {
        $class = self::fullyQualifiedModelClassFromTableName($tableName);
        $model = new $class;
        $fullyQualifiedClassTableName = $model->getTable();
        $unqualifiedClassTableName    = preg_replace('/^[^.]+\./', '', $fullyQualifiedClassTableName);
        $unqualifiedTableName         = preg_replace('/^[^.]+\./', '', $tableName);
        if ($unqualifiedClassTableName != $unqualifiedTableName) throw new Exception("$tableName => $class => $unqualifiedClassTableName does not match");
        return $model;
    }

    // ----------------------------------------- Permissions names
    public function permissionFQN(string|array $qualifier = NULL): string
    {
        if (is_array($qualifier)) $qualifier = implode('_', $qualifier);

        $permissionFQN = $this->dotName(); // Without Model
        if ($qualifier) $permissionFQN .= "_$qualifier";
        return $permissionFQN;
    }

    // ----------------------------------------- Column names
    // TODO: If this gets bigger it should be in its own HtmlHelper
    public static function backColumnName(string $columnName, bool $throwIfNotName = TRUE): string|null
    {
        $backFieldName = NULL;
        $fieldParts    = HtmlHelper::nameToArray($columnName);
        $finalField    = array_pop($fieldParts);
       
        if ($finalField == 'name') {
            // Back column name legalcase[owner_user_group]
            $backFieldName = $fieldParts[0];
            if (count($fieldParts) > 1) {
                $fieldNests     = implode('][', array_slice($fieldParts, 1));
                $backFieldName .= "[$fieldNests]";
            }
        } else if ($throwIfNotName) {
            throw new Exception("ListColumn field [$columnName] attribute is not name [$finalField] during backColumnName() calc");
        }

        return $backFieldName;
    }
}
