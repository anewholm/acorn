<?php
use Illuminate\Database\Eloquent\Collection;
use Acorn\Traits\PathsHelper;
use Backend\Classes\ListColumn;
use \Carbon\CarbonInterval;

if (!isset($record)) throw new Exception("_multi.php is a column partial only");

// first_event_part[groups] => first-event-part-groups
$multiClass  = Str::kebab(trim(preg_replace('/[\]\[_]+/', '-', $column->columnName), '-'));
// <UUID>-first-event-part-groups
$multiId     = "$record->id-$multiClass";
$isNested    = (strstr($column->columnName, '[') !== FALSE);

// --------------------------- Custom config settings
$multiConfig = (isset($column->config['multi'])   ? $column->config['multi'] : array());
$sum         = (isset($multiConfig['sum'])        ? new ListColumn($multiConfig['sum'], '') : FALSE);
$limit       = (isset($multiConfig['limit'])      ? $multiConfig['limit']  : 4);
$cssClasses  = (isset($multiConfig['cssClasses']) ? $multiConfig['cssClasses']  : array());
$isHTML      = (isset($multiConfig['html']) && $multiConfig['html']);
$modelClass  = (isset($multiConfig['model'])      ? $multiConfig['model'] : NULL);
$multiPrefix = (isset($multiConfig['prefix'])     ? $multiConfig['prefix'] : NULL);
$multiSuffix = (isset($multiConfig['suffix'])     ? $multiConfig['suffix'] : NULL);
$prefix      = (isset($column->config['prefix'])  ? $column->config['prefix'] : NULL);
$suffix      = (isset($column->config['suffix'])  ? $column->config['suffix'] : NULL);

if (is_string($cssClasses)) $cssClasses = explode(' ', $cssClasses);
$cssClassesString = implode(' ', $cssClasses);

// TODO: Linked popups for list view are currently not being used
$useLinkedPopups = (isset($multiConfig['use-linked-popups']) ? $multiConfig['use-linked-popups'] : FALSE);
$action          = (isset($multiConfig['action']) ? $multiConfig['action'] : 'update');

// We do not respect the values passed in value
// instead, we create a collection and re-apply the valueFrom/select logic
// this is to standardise the Collection display
// When nested, the valueFrom is forced to the columnName
// so we introduce a non-standard option nestedValueFrom
// Value selection failover: nestedValueFrom, valueFrom, select, 'name'
// WinterCMS default behaviour with multi-level relations is to apply the valueFrom/select to the top level relation only
// we apply it to the final Collection result
$hasNestedDirective = ($isNested && isset($multiConfig['nestedValueFrom']));
$hasManyDirective   = isset($multiConfig['valueFrom']);
$valueFrom = (
    $hasManyDirective    ? $multiConfig['valueFrom'] :
    ($hasNestedDirective ? $multiConfig['nestedValueFrom'] :
    ($column->valueFrom  ? $column->valueFrom :
    ($column->sqlSelect  ? $column->sqlSelect :
    'name'
))));
$relation = $column->relation;

// --------------------------- The field name is the name of the Model relation
// so the relation is automatically used
// Some considered scenarios:
//   1) relation & valueFrom => array(id => valueFrom, ...)
//   2) valueFrom only => string
//   3) relation only  => Collection
//   4) no relation or valueFrom => Collection
// relation: directive is necessary for searcheable and sortable
// valueFrom: is honoured on the Collections below
if (is_null($value)) {
    // This can happen when we have a *Many collection with a [name] valueFrom
    // like legalcase[many-somethings][name]
    // which is a partial. So the valueFrom: name | [name] is resolved
    // before passing the value to the partial.
    // So the back-column legalcase[many-somethings] returns a collection, which has no name attribute
    // We try to strip the [name] to see what happens
    // TODO: We need to put more checks in this back-column attempt
    if ($backColumnName = PathsHelper::backColumnName($column->columnName, FALSE)) {
        $column         = new ListColumn($backColumnName, '');
        // If there is a problem this will just return NULL again
        $value          = $column->getValueFromData($record);
        if (!$value instanceof Collection) $value = NULL;
    } else {
        // Let's also try to get the raw column value
        // Without the [name] or valueFrom applied
        $value = $record->{$column->columnName};
    }
}

if (!is_null($value)) {
    if (is_string($value)) {
        $col   = $column->columnName;
        // The relation associated with the column is invoked ($record->$col()).
        // The related records are fetched as a Collection using the get() method.
        // and then the valueFrom is applied, essentially re-creating the same array or string indirectly
        $model = &$record;
        if ($relation && $model->hasRelation($relation)) {
            // Request the whole model, not the valueFrom or select string
            $model = $model->$relation()->first();
        }
        $value = $model->$col;
    } else if (is_array($value)) {
        // The $record is already the relation: model
        $col   = $column->columnName;
        $value = $record->$col;
    }

    // Maybe it is actually an array!
    if (is_array($value)) {
        $value = new Collection($value);
    }

    // Check that the value is now a collection
    if (!$value instanceof Collection) {
        $valueType = (is_object($value) ? get_class($value) : gettype($value));
        throw new Exception("$column->columnName has type [$valueType] which cannot be rendered by _multi");
    }

    // --------------------------- Main loop
    $total = NULL;
    $count = $value->count();
    if ($count) {
        $i          = 0;
        $firstItem  = $value[0];
        $itemClass  = NULL;
        if (is_object($firstItem)) {
            $classParts = explode('\\', get_class($firstItem));
            $itemClass  = Str::kebab(end($classParts));
        } else {
            $itemClass = gettype($firstItem);
        }
        if ($prefix) print(e(trans($prefix)));
        print("<ul id='$multiId' class='multi $multiClass $itemClass $cssClassesString'>");
        foreach ($value as $model) {
            // id array => models
            if ($modelClass) $model = $modelClass::find($model);

            if (is_null($model)) continue;

            // Name resolution
            $name = $model;
            if ($model instanceof Model) {
                if ($model->hasAttribute($valueFrom)) $name = $model->$valueFrom;
                if (!$name) {
                    $noname = trans('acorn::lang.models.general.noname');
                    $name   = "&lt;$noname&gt;";
                }
            }

            // Output LI item
            print('<li>');
            if ($model instanceof Model) {
                $controller  = $model->controllerFullyQualifiedClass();
                if ($useLinkedPopups) {
                    $dataRequestData = array(
                        'route'   => "$controller@$action",
                        'params'  => [$model->id],
                        'dataRequestUpdate' => array('multi' => $multiId),
                    );
                    $dataRequestDataEscaped = e(substr(json_encode($dataRequestData), 1, -1));
                    print("<a
                        data-handler='onPopupRoute'
                        data-request-data='$dataRequestDataEscaped'
                        data-control='popup'>"
                    );
                }
            }
            print($multiPrefix);
            print($isHTML ? $name : e($name));
            print($multiSuffix);
            if ($model instanceof Model && $useLinkedPopups) print('</a>');
            print('</li>');

            if ($sum) {
                $sumValue = $sum->getValueFromData($model);
                if (is_numeric($sumValue)) $total = ($total ?: 0) + $sumValue;
                else if ($sumValue instanceof CarbonInterval) $total = ($total ?: new CarbonInterval(0))->add($sumValue);
            }

            // False exists the loop
            // TODO: Continue when $sum
            $continue = (++$i < $limit);
            if (!$continue) break;
        };
        print('</ul>');
        if ($suffix) print(e(trans($suffix)));

        if ($count > $limit) {
            // Leave this "more" link to simply open the full record update screen
            $more = e(trans('more...'));
            print("<a class='more'>$more</a>");
        } else if ($count > 1 && $sum) {
            print("<div class='multi-total'>$total</div>");
        }
    } else {
        print('-');
    }
} else {
    print('-');
}
