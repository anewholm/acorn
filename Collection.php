<?php

namespace Acorn;

use Winter\Storm\Database\Collection as StormDatabaseCollection;
use Winter\Storm\Html\Helper as HtmlHelper;

/**
 * @package acorn\builder
 * @author sz
 */
class Collection extends StormDatabaseCollection
{
    /**
     * Generate an associative array for a dropdown options.
     *
     * @param string $value The field to use as the dropdown value. Default is 'id'.
     * @param string $key   The field to use as the dropdown key. Default is 'name'.
     * @return array        An associative array where the keys are the values of the specified key field,
     *                      and the values are the values of the specified value field.
     */
    public function lists($value = 'name', $key = 'id')
    {
        // Instead of:
        //   return $this->pluck($value, $key)->all();
        $lists = array();

        // nameFrom: entity[user_group][name]
        $parts = HtmlHelper::nameToArray($value);
        $last  = array_pop($parts);
        foreach ($this as $model) {
            $id = $model->$key;
            foreach ($parts as $part) $model = $model->{$part};

            // hasAttribute() includes a hasGetMutator() check
            // $model->$last will go to a TranslateBackend::__get() process
            // which also now includes a hasGetMutator() check
            if ($model->hasAttribute($last)) $value = $model->$last;
            // TODO: Contentious failover to the name property:
            else $value = $model->name;

            $lists[$id] = $value;
        }

        return $lists;
    }

    public function ids()
    {
        return $this->pluck('id')->toArray();
    }
}
