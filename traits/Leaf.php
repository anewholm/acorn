<?php namespace Acorn\Traits;

use Backend\Facades\BackendAuth;
use Str;
use Acorn\Model;
use Exception;

trait Leaf
{
    // Star schema centre => leaf services
    public function getLeafTypeAttribute(?bool $throwIfNull = FALSE)
    {
        // ->leaf_type => "Company"
        // Useful for ListColumn display
        return $this->getLeafTypeModel($throwIfNull)?->unqualifiedClassName();
    }

    public function getLeafTableAttribute($value): string|NULL
    {
        // ->leaf_table => "Company"
        // Useful for ListColumn display
        $ret = NULL;
        if ($key = $this->getLeafTableTranslationKey($value)) {
            $ret = trans($key);
        } else {
            // Maybe not translated, but we will offer
            $ret = trans($this->getLeafTableCacheClass());
        }
        return $ret;
    }

    public function getLeafTableTranslationKey(string|NULL $value = NULL): string|NULL
    {
        $key = NULL;

        if (is_null($value) && isset($this->attributes['leaf_table']))
            $value  = $this->attributes['leaf_table'];

        if ($value) {
            $tableParts = explode('_', $value);
            if (isset($tableParts[2])) {
                $modelParts = array_slice($tableParts, 2);
                $localKey   = strtolower(Str::singular(implode('', $modelParts)));
                $key        = "$tableParts[0].$tableParts[1]::lang.models.$localKey.label";
            }
        }

        return $key;
    }

    public function getLeafTableCacheClass(bool $fqn = FALSE): string|NULL
    {
        // acorn_university_schools => Schools => Acorn\University\Models\School
        $class = NULL;
        if (isset($this->attributes['leaf_table'])) {
            $leafTable      = $this->attributes['leaf_table'];
            $leafTableParts = explode('_', $leafTable);
            array_shift($leafTableParts); // acorn
            array_shift($leafTableParts); // university
            $leafTableName = implode(' ', $leafTableParts); // schools
            $class         = Str::singular($leafTableName);
            $class         = Str::title($class);
            if ($fqn) {
                // Swap in last name for this FQN
                $class        = str_replace(' ', '', $class);
                $thisFQNParts = explode('\\', get_class($this));
                array_pop($thisFQNParts);
                array_push($thisFQNParts, $class);
                $class  = implode('\\', $thisFQNParts);
                if (!class_exists($class)) $class = NULL;
            }
        }
        return $class;
    }

    public function getLeafTableCacheModel(): Model|NULL
    {
        $leafObject = NULL;
        // This is faster because no SQL calls
        // Translate leaf_table (if available) to a Class
        // e.g. acorn_university_schools => Schools => Acorn\University\Models\School
        if ($leafModelFQN = $this->getLeafTableCacheClass(TRUE)) {
            // Check hasOne relations for this leaf model
            $relations = array_merge($this->hasOneThrough, $this->hasOne);
            foreach ($relations as $name => &$definition) {
                if (is_array($definition) && isset($definition[0]) && $definition[0] == $leafModelFQN) {
                    $this->load($name);
                    if ($leafObject = $this->$name) break;
                }
            }
        }
        return $leafObject;
    }

    public function getLeafHasOnesModel(bool $withoutGlobalScopes = FALSE): Model|NULL
    {
        $leafObject = NULL;
        $thisClass  = get_class($this);

        // Check each $hasOne relation for a reverse <-belongsTo leafs
        // PREFORMANCE: There may be very many!
        $relations  = array_merge($this->hasOneThrough, $this->hasOne);
        foreach ($relations as $name => $definition) {
            if (!is_array($definition)) continue;

            // $hasOne 1from1 can be marked as leaf for performance
            $type = $definition['type'] ?? NULL;
            $leaf = $definition['leaf'] ?? NULL;
            if ($type == '1from1' && $leaf) {
                $leafObject = ($withoutGlobalScopes
                    ? $this->$name()->withoutGlobalScopes()->first()
                    : $this->$name
                );
                if ($leafObject) break;
            }

            // Need to check the reverse <-belongsTo relation(s),
            // for a leaf to $this
            // TODO: Oustanding TODO in CS for 'leaf' => TRUE
            if (isset($definition[0])) {
                $relationTo = new $definition[0];
                if ($relationTo->belongsTo) {
                    foreach ($relationTo->belongsTo as $backName => $backDefinition) {
                        $backClass = $backDefinition[0]      ?? NULL;
                        $type      = $backDefinition['type'] ?? NULL;
                        $leaf      = $backDefinition['leaf'] ?? FALSE;
                        if ($backClass == $thisClass
                            && ($leaf || $type == 'Leaf')
                        ) {
                            $leafObject = ($withoutGlobalScopes
                                ? $this->$name()->withoutGlobalScopes()->first()
                                : $this->$name
                            );
                            if ($leafObject) break;
                        }
                    }
                }
            }
            if ($leafObject) break;
        }
        return $leafObject;
    }

    public function getLeafTypeModel(?bool $throwIfNull = FALSE, bool $withoutGlobalScopes = FALSE, bool $recursive = TRUE): Model|NULL
    {
        // For base tables that have multiple possible leaf detail tables in a star schema
        // we search the hasOne relations to determine which leaf table has the actual 1-1 object
        // For example: Person => Teacher & Student. We don't know from Person which it is
        // A trigger maintained Person.leaf_table is the standard cache mechanism
        // which uses the leaf_table and does not need to SQL call each and every $hasOne

        // Check for and use the leaf_table cache column
        $leafObject = $this->getLeafTableCacheModel();

        // If not, we need to check each relation 1 by 1 for an object
        if (!$leafObject) $leafObject = $this->getLeafHasOnesModel($withoutGlobalScopes);

        // This goes beyond the direct central table => star schema
        // it allows traversal of several 1-1 relations out to the central table and on to the star schema
        // if labelled as such
        //   domain_data (1-1)=> product (leaf)=> pa_measuring_tape
        //   domain_data (1-1)=> customer (1-1)=> company
        // The reason being that leaf is understood more as easily traversing to
        // the final actual derived Model
        if ($leafObject && $recursive) {
            while ($recursiveLeafObject = $leafObject->getLeafTypeModel($throwIfNull, $withoutGlobalScopes, $recursive)) {
                $leafObject = $recursiveLeafObject;
            }
        }

        // Required / optional
        if ($throwIfNull && !$leafObject) {
            $className = get_class($this);
            throw new Exception("Leaf $className not found for id($this->id)");
        }

        return $leafObject;
    }

    public function isLeafModel(?bool $throwIfNull = FALSE, bool $withoutGlobalScopes = FALSE, bool $recursive = TRUE): bool
    {
        // isLeaf() is implemented on NestedTree
        return is_null($this->getLeafTypeModel($throwIfNull, $withoutGlobalScopes, $recursive));
    }
}
