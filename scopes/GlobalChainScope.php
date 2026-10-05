<?php
namespace Acorn\Scopes;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Scope;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Session;
use Exception;
use DB;
use Str;
use \Acorn\User\Models\User;

class GlobalChainScope implements Scope
{
    // Creates a where (sub-query), joined from the single main table
    // to limit the scope
    // Main joins would cause hydration in-consistencies
    // that is, * would return several ID columns
    //
    // Collect builder joins on the way
    // and only applying them back at the root call if necessary
    //
    // It does this sub-query:
    //   SELECT "acorn_university_hierarchies".*
    //   FROM "acorn_university_hierarchies"
    //   WHERE acorn_university_hierarchies.id in(
    //     select acorn_university_hierarchies.id from acorn_university_hierarchies
    //     INNER JOIN "acorn_university_entities" ON "acorn_university_hierarchies"."entity_id" = "acorn_university_entities"."id"
    //     INNER JOIN "acorn_university_academic_years" ON "acorn_university_hierarchies"."academic_year_id" = "acorn_university_academic_years"."id"
    //     where FN_ACORNASSOCIATED_UNIVERSITY_SCOPE_ENTITIES (ACORNASSOCIATED_UNIVERSITY_ENTITIES.ID, '0d76ad75-f9d4-4d01-8045-331517709249')
    //   );
    //
    // Not this inner join, because of the multiple IDs it would return into the Model hydration process:
    //   SELECT "acorn_university_hierarchies".*
    //   FROM "acorn_university_hierarchies"
    //     INNER JOIN "acorn_university_entities" ON "acorn_university_hierarchies"."entity_id" = "acorn_university_entities"."id"
    //     INNER JOIN "acorn_university_academic_years" ON "acorn_university_hierarchies"."academic_year_id" = "acorn_university_academic_years"."id"
    //   WHERE FN_ACORNASSOCIATED_UNIVERSITY_SCOPE_ENTITIES (ACORNASSOCIATED_UNIVERSITY_ENTITIES.ID, '0d76ad75-f9d4-4d01-8045-331517709249');

    public const IS_THIS = TRUE;

    // ------------------------------------ Direct situation on this model
    public static function globalScopeRelationsOn(Model $model, ?string $flag = NULL): array
    {
        // flag can be 'hierarchy'. This is not used at the moment
        // These can branch in to a tree of multiple global scopes
        // because several > 1 relation may be a global_scope
        $globalScopeRelations = array();

        $relationConfigs = $model->belongsTo + $model->hasMany;
        foreach ($relationConfigs as $relationName => $relationConfig) {
            $flagCheck = (is_null($flag) || (isset($relationConfig['flags']) && in_array($flag, $relationConfig['flags'])));
            if (isset($relationConfig['global_scope']) && $relationConfig['global_scope'] && $flagCheck) {
                if (!isset($relationConfig[0]))
                    throw new Exception("global_scope $relationName has no 0 index class configured");
                $globalScopeRelations[$relationName] = $model->$relationName();
            }
        }

        return $globalScopeRelations;
    }

    protected static function ourGlobalChainScopesOn(Model $model): array
    {
        // Get _our_ GlobalChainScope scopes on this $model
        // Not recursive at all
        $chainScopes = array();
        if ($allChainScopes = $model->getGlobalScopes()) {
            foreach ($allChainScopes as $class => $chainScope) {
                if ($chainScope instanceof Closure) {
                    // We do not honour Closures
                    // $chainScope($builder);
                } else if ($chainScope instanceof GlobalChainScope) {
                    // We only honour Scopes that descend from our GlobalChainScope
                    $chainScopes[$class] = $chainScope;
                }
            }
        }

        if (count($chainScopes) > 1) {
            $class = get_class($model);
            throw new Exception("Multiple Scopes on $class not supported yet");
        }
        
        return $chainScopes;
    }

    public static function globalScopeUserSetting(User $user, Model $model): ?string {
        // Acorn/University/Models/Entity => global_scope_entity_id
        $globalScopeSetting = NULL;

        // Copied from create-system subNameSingular() & nameSingular()
        $tableNameParts  = explode('_', Str::singular($model->table));
        if (count($tableNameParts) >= 3) {
            $subName = implode('_', array_slice($tableNameParts, 2));

            // Copied from create-system adornOtherCustomPlugins()
            $usersColumnStub    = "global_scope_$subName"; 
            $usersColumnName    = "{$usersColumnStub}_id";
            
            // $user->global_scope_entity_id
            $globalScopeSetting = $user->{$usersColumnName};
        }

        return $globalScopeSetting;
    }

    public static function allUserSettings(bool $withSetting = TRUE, ?User $user = NULL): array
    {
        // Fast function to get settings from Session
        $names = array();
        if (!$user) {
            if (!class_exists('Acorn\User\Models\User')) return $names;
            $user = User::authUser();
        }
        if ($user) {
            foreach ($user->attributes as $fieldName => $setting) {
                if (preg_match('/^global_scope_/', $fieldName)) {
                    if (!$withSetting || $setting) {
                        // The relevant plugin will have boot() time added a belongsTo
                        // to the User object
                        $fieldStub = preg_replace('/_id$/', '', $fieldName);
                        if (isset($user->belongsTo[$fieldStub]) && isset($user->belongsTo[$fieldStub][0])) {
                            $belongsTo  = $user->belongsTo[$fieldStub];
                            $modelClass = $belongsTo[0];
                            $names[$fieldName] = array(
                                'userField'  => $fieldName,
                                'modelClass' => $modelClass,
                                'setting'    => $setting,
                            );
                        }
                    }
                }
            }
        }
        return $names;
    }

    public static function settingNameFor(Model $model): string
    {
        // For Session key
        // Acorn/University/Models/Entity::globalScope
        $class = get_class($model);
        return "$class::globalScope";
    }

    public static function getSettingFor(Model $model): ?string
    {
        // On User or Session
        $setting = NULL;

        if (class_exists('Acorn\User\Models\User') && ($user = User::authUser())) {
            $setting = self::globalScopeUserSetting($user, $model);
        }
        
        // An empty setting is no setting
        if (!$setting) {
            $settingName = self::settingNameFor($model);
            $setting     = Session::get($settingName);
        }
        
        return $setting;
    }

    public static function hasSessionFor(Model $model, bool $isThis = FALSE): bool
    {
        // Usually called with an apply() override:
        // public function shouldApply(Builder $builder, Model $model): bool {
        //     return self::hasSessionFor($builder, $model);
        // }
        // Returing TRUE causes the scope chain to be recursively applied
        $setting = self::getSettingFor($model);
        return ($isThis
            ? ($setting && $model->id == $setting) // _Same_ model that is making the request
            : (bool) $setting
        );
    }

    // --------------------------------------------- Recursive
    // Searching down global-scope relations to the end
    public static function endGlobalScopeClasses(Model $model, ?string $flag = NULL, ?array $fromEndChainModels = NULL): array
    {
        // Recursive
        // Get the (existing) Models on the ends of the global-scope relation chain(s)
        // Includes this $model parameter, if a $globalScope
        $endChainModels = array();
        if (property_exists($model, 'globalScope') && $model::$globalScope)
            $endChainModels[get_class($model)] = $model;
        
        $globalScopeRelations = self::globalScopeRelationsOn($model, $flag);
        foreach ($globalScopeRelations as $name => $relation) {
            // We attempt to follow exist models if possible
            // so that checks for equality can be made if necessary
            // relations might have NULL values
            $relatedModel = NULL;
            if ($model->exists) $relatedModel = $model->{$name}()->first();
            if (!$relatedModel) $relatedModel = $relation->getRelated();
            
            // Checks
            $relatedClass   = get_class($relatedModel);
            if (isset($fromEndChainModels[$relatedClass])) {
                $chain = implode(' => ', array_keys($fromEndChainModels));
                throw new Exception("Infinite global-scope recursion on $chain");
            }

            // Recurse to end
            $endChainModels = array_merge($endChainModels, self::endGlobalScopeClasses($relatedModel, $flag, $endChainModels));
        }

        return $endChainModels;
    }

    public static function isEndSelectedFrom(Model $model, ?string $flag = NULL): bool
    {
        // Test if THIS model is a selected scope model
        // Useful for display and structure
        // Used in hierarchies to return a NULL parent_id for scope models
        $isSelected     = FALSE;
        $endScopeModels = self::endGlobalScopeClasses($model, $flag);
        foreach ($endScopeModels as $scopeModel) {
            $isSelected = self::hasSessionFor($scopeModel, self::IS_THIS);
            if ($isSelected) break;
        }

        return $isSelected;
    }

    // --------------------------------------------- Application
    public static function applySession(Builder $builder, Model $model): bool 
    {
        // From this model only, Not recursive at all
        // Scope classes should apply() override:
        //   class EntityScope {
        //     public function apply(Builder $builder, Model $model): bool {
        //       return self::applySession($builder, $model);
        //     }
        //   }
        $setting   = self::getSettingFor($model);
        $query     = $builder->getQuery();
        $mainModel = $builder->getModel();

        if ($setting) {
            // Can be a direct where clause only
            $globalScopeSubQuery = &$builder;
            // Or an entire joined sub-query
            if ($model->globalScopeSubQuery) $globalScopeSubQuery = &$model->globalScopeSubQuery;
            
            // Finish off the sub-query|direct where clause
            // We have LEFT joined all the way
            if (isset($model::$globalScope::$scopingFunction)) {
                // ------------------ Boolean returning function() call
                $scopingFunction = $model::$globalScope::$scopingFunction;
                $settingEscaped  = str_replace("'", "\\'", $setting);
                $globalScopeSubQuery->whereRaw("$scopingFunction($model->table.id, '$settingEscaped')");
            } else if (isset($model::$globalScope::$scopingView)) {
                // ------------------ Special inner join view with only
                //   from_*_id
                //   to_*_id
                $scopingView     = $model::$globalScope::$scopingView;
                // from_entity_id => to_entity_id
                $modelParts = explode('\\', get_class($model));
                $shortClass = end($modelParts);
                $columnStub = Str::snake($shortClass);
                $globalScopeSubQuery->join($scopingView, "$model->table.id", '=', "$scopingView.from_{$columnStub}_id");
                $globalScopeSubQuery->where("$scopingView.to_{$columnStub}_id", '=', $setting);
            } else {
                // ------------------ Normal join to final table
                // These 2 wheres need to be grouped together
                // Or is NULL handles cases where the parent model global-scope id is NULL:
                //   Calculation.academic_year_id is NULL
                $groupWheres = array(
                    [
                        'column'   => "$model->table.id", 
                        'operator' => '=', 
                        'value'    => $setting,
                        'boolean'  => 'or'
                    ],
                    [
                        'column'   => "$model->table.id", 
                        'operator' => '=',
                        'value'    => NULL,
                        'boolean'  => 'or'
                    ]
                );
                
                // Users can always see the things they created
                // We want this to be the last where in the sub-query
                // We place it in every sub-query because there may be manu global-scopes AND'ed
                // and we don't want an OR
                if ($mainModel->hasRelation('created_by_user')) {
                    if (class_exists('Acorn\User\Models\User') && ($user = User::authUser())) {
                        array_push($groupWheres, array(
                            'column' => "$mainModel->table.created_by_user_id", 
                            'value' => $user->id,
                            'operator' => '='
                        ));
                    }
                }

                $globalScopeSubQuery->where($groupWheres);
            }

            if ($model->globalScopeSubQuery) {
                // Apply the sub-query to the main builder
                // This will translate the QueryBuilder in to a string Illuminate\Database\Query\Expression
                $builder->whereIn("$query->from.id", $model->globalScopeSubQuery, 'and');
            }

            // TODO: Allow NULLs on the first join to show Models without an explicit setting
            /*
            $query = $builder->getQuery();
            if (isset($query->joins[0])) {
                // Joins:
                // type     = "Column"
                // first    = "acorn_exam_calculations.academic_year_id"
                // operator = "="
                // second   = "acorn_university_academic_years.id"
                // boolean  = "and"
                $firstJoin = $query->joins[0];
                if (isset($firstJoin->wheres[0])) {
                    $firstWhere = $firstJoin->wheres[0];
                    $builder->orWhere($firstWhere['first'], '=', NULL);
                }
            }
            */
        } else {
            // To make sure the sub-query is reset
            // as the test is for a where below
            if ($model->globalScopeSubQuery) $model->globalScopeSubQuery->whereRaw('1=1');
        }

        return (bool) $setting;
    }

    public function apply(Builder $builder, Model $model): void {
        // Any point in the chain can override this standard WinterCMS apply() call
        // Scope classes should apply() override:
        //   class EntityScope {
        //     public function apply(Builder $builder, Model $model): bool {
        //       return self::applySession($builder, $model);
        //     }
        //   }
        $this->applyRecursiveMaybe($builder, $model);

        // Users can always see the things they created
        // We want this to be the last where
        if (   $model->hasRelation('created_by_user')
            && $model->globalScopeSubQuery
            && $model->globalScopeSubQuery->wheres
            && class_exists('Acorn\User\Models\User')
            && ($user = User::authUser())
        ) {
            $model->globalScopeSubQuery->orWhere("$model->table.created_by_user_id", $user->id);
        }
    }

    public function applyRecursiveMaybe(Builder $builder, Model $model): void {
        // We store the where on the model
        // because we must pass it down the overridden apply() chain
        // and we cannot add new parameters
        $topLevel = (!$model->globalScopeSubQuery || $model->globalScopeSubQuery->wheres);
        if ($topLevel) {
            // Begin our where sub-query
            // Table references are local to the sub-query
            // It returns a valid id list only without reference to the external query
            $query = $builder->getQuery();
            $model->globalScopeSubQuery = DB::table($query->from)
                ->select("$query->from.id")
                // This distinct makes a big difference. Not sure why...
                ->distinct();
        }

        $globalScopeRelations = self::globalScopeRelationsOn($model);
        foreach ($globalScopeRelations as $name => $relation) {
            // TODO: $relation->addConstraints();
            // TODO: At least $relation->getQualifiedForeignKeyName()
            // $relation->setQuery($builder);
            $relatedModel = $relation->getRelated();
            $reverse      = ($relation instanceof BelongsTo);
            $key          = $relation->getForeignKeyName();
            $columnFrom   = ($reverse ? $key : 'id');
            $columnTo     = ($reverse ? 'id' : $key);
            $fqTableFrom  = "$model->table.$columnFrom";
            $fqTableTo    = "$relatedModel->table.$columnTo";

            // Checks
            if (env('APP_DEBUG') && is_array($model->globalScopeSubQuery->joins)) {
                $mainTable = preg_replace('/ .*/', '', $model->globalScopeSubQuery->from);
                if ($mainTable == $relatedModel->table)
                    throw new Exception("Re-join to from");
                foreach ($model->globalScopeSubQuery->joins as $join) {
                    if ($join->table == $relatedModel->table)
                        throw new Exception("Double join");
                }
            }

            // LEFT Join in case we have a NULL
            // See ->orWhereNull() above
            $model->globalScopeSubQuery->leftJoin($relatedModel->table, $fqTableFrom, '=', $fqTableTo);
            
            // Chain all global_scope relations
            // For calling class
            $chainScopes  = self::ourGlobalChainScopesOn($relatedModel);
            foreach ($chainScopes as $chainScope) {
                // Inherit your Scope from GlobalChainScope to activate this chain
                // Any point in the chain can override-intercept this standard WinterCMS apply() call
                // Recursuve!
                // Pass down the globalScopeSubQuery
                $relatedModel->globalScopeSubQuery = $model->globalScopeSubQuery;
                $chainScope->apply($builder, $relatedModel);
            }
        }
    }
}
