<?php namespace Acorn\Traits;

use \Exception;
use Winter\Storm\Database\TreeCollection;

Trait Dropdowns
{
    public static function dropdownOptions($form = NULL, $field = NULL, ?bool $withoutGlobalScopes = FALSE)
    {
        $name = (isset($field->config['nameFrom'])
            ? $field->config['nameFrom']
            : 'name'
        );

        // ----------------------------------- Builder construction
        $builder = static::select();
        if (!$builder->getModel()->belongsTo) {
            // Cannot select('id', $name) because the name might be a 1-1 FK field
            //   e.g. entity_id.name
            // But we can, if there are no belongsTo
            $builder->select('id', $name);
        }
        if ($withoutGlobalScopes || (isset($field->config['withoutGlobalScopes']) && $field->config['withoutGlobalScopes'])) 
            $builder->withoutGlobalScopes();
        if (isset($field->config['optionsWith'])) 
            $builder->with($field->config['optionsWith']);
        if ($builder->getModel()->hasRelation('translations'))
            $builder->with('translations');
        
        // optionsWhere:
        // Also implemented in filterFields() for during dependsOn refresh situations
        //   options: Acorn\Lojistiks\Models\ProductInstance::dropdownOptions
        //   optionsWhere:
        //     uses_quantity: false
        //     year_id: '@year_id' # Dynamic property
        //     ...
        if (isset($field->config['optionsWhere'])) {
            $whereProperties = $field->config['optionsWhere'];
            foreach ($whereProperties as $whereProperty => $whereClauses) {
                if (is_array($whereClauses)) {
                    // location: 
                    //   - @source_location
                    //   - sumink
                    // TODO: Relation Extended config options where clause
                    throw new Exception('Not implemented');
                } else {
                    $whereValue = $whereClauses;
                    if ($whereValue[0] == '@') {
                        if (is_null($form)) 
                            throw new Exception('Cannot use dynamic @values without a form');
                        $fieldName  = preg_replace('/_id$/', '', substr($whereValue, 1));
                        $whereField = $form->getField($fieldName);
                        if (is_null($whereField)) 
                            throw new Exception("Field [$fieldName] not found for dynamic @value");
                        $whereValue = $whereField->value;
                    }
                    if (!is_null($whereValue))
                        $builder->where($whereProperty, $whereValue);
                }
            }
        }
        $models = $builder->get();

        // ----------------------------------- Hierarchies
        //   hierarchy: false|true|reverse
        //   indentation_character: -
        //   start-model: x
        $hierarchical = (isset($field->config['hierarchical'])
            ? $field->config['hierarchical']
            : isset($models->first()?->hasMany['children'])
        );
        $indentationString = (isset($field->config['indentation-string'])
            ? $field->config['indentation-string']
            : "--&nbsp;"
        );
        $ancestor = (isset($field->config['ancestor'])
            ? $field->config['ancestor']
            : NULL
        );

        // Final lists array()
        if ($hierarchical) {
            if ($ancestor) $models = [$ancestor];
            $treeCollection = new TreeCollection($models);
            $nested = $treeCollection->toNested(FALSE);
            $list   = $treeCollection->listsNested($name, 'id', $indentationString);
        } else {
            $list = $models->lists($name, 'id');
        }

        return $list;
    }
}
